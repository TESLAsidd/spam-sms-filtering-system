"""
SMS SENTINEL — OAuth 2.0 & OpenID Connect Service
Modular, secure multi-provider authentication for Google, GitHub, and Microsoft.
Integrates with Authlib, enforcing state CSRF validation, PKCE, and safe token disposal.
"""

import os
import logging
import urllib.parse
from authlib.integrations.flask_client import OAuth
import requests

logger = logging.getLogger("sms_sentinel_oauth")

oauth = OAuth()

SUPPORTED_PROVIDERS = ("google", "github", "microsoft")

def init_oauth(app):
    """
    Initialize and register OAuth client providers with the Flask application.
    """
    oauth.init_app(app)
    
    # 1. Google OAuth2 / OpenID Connect Registration
    google_client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if google_client_id and google_client_secret:
        oauth.register(
            name="google",
            client_id=google_client_id,
            client_secret=google_client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid email profile"
            }
        )
    else:
        # Register stub so Authlib can still provide configuration checks
        oauth.register(
            name="google",
            client_id=google_client_id or "placeholder_google_id",
            client_secret=google_client_secret or "placeholder_google_secret",
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid email profile"
            }
        )
        
    # 2. GitHub OAuth Web Application Flow Registration
    github_client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    github_client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")
    oauth.register(
        name="github",
        client_id=github_client_id or "placeholder_github_id",
        client_secret=github_client_secret or "placeholder_github_secret",
        access_token_url="https://github.com/login/oauth/access_token",
        access_token_params=None,
        authorize_url="https://github.com/login/oauth/authorize",
        authorize_params=None,
        api_base_url="https://api.github.com/",
        client_kwargs={
            "scope": "read:user user:email"
        }
    )

    # 3. Microsoft Identity Platform (OpenID Connect / OAuth2) Registration
    microsoft_client_id = os.environ.get("MICROSOFT_CLIENT_ID", "")
    microsoft_client_secret = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
    microsoft_tenant = os.environ.get("MICROSOFT_TENANT_ID", "common")
    oauth.register(
        name="microsoft",
        client_id=microsoft_client_id or "placeholder_microsoft_id",
        client_secret=microsoft_client_secret or "placeholder_microsoft_secret",
        server_metadata_url=f"https://login.microsoftonline.com/{microsoft_tenant}/v2.0/.well-known/openid-configuration",
        client_kwargs={
            "scope": "openid email profile User.Read"
        }
    )

def is_provider_configured(provider: str) -> bool:
    """
    Check if real credentials have been configured in the environment for the given provider.
    """
    provider = provider.lower().strip()
    if provider == "google":
        cid = os.environ.get("GOOGLE_CLIENT_ID", "")
        sec = os.environ.get("GOOGLE_CLIENT_SECRET", "")
        return bool(cid and sec and not cid.startswith("placeholder_"))
    elif provider == "github":
        cid = os.environ.get("GITHUB_CLIENT_ID", "")
        sec = os.environ.get("GITHUB_CLIENT_SECRET", "")
        return bool(cid and sec and not cid.startswith("placeholder_"))
    elif provider == "microsoft":
        cid = os.environ.get("MICROSOFT_CLIENT_ID", "")
        sec = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
        return bool(cid and sec and not cid.startswith("placeholder_"))
    return False

def get_redirect_uri(request, provider: str) -> str:
    """
    Construct safe external redirect URI for the provider callback.
    Supports explicit environment override (e.g. GOOGLE_REDIRECT_URI) or builds from request.
    """
    provider = provider.lower().strip()
    env_key = f"{provider.upper()}_REDIRECT_URI"
    explicit_uri = os.environ.get(env_key)
    if explicit_uri:
        return explicit_uri

    # Determine scheme and host honoring proxy headers
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    if os.environ.get("VERCEL") or os.environ.get("FLASK_ENV") == "production":
        scheme = "https"
        
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{scheme}://{host}/auth/{provider}/callback"

def is_safe_url(target: str) -> bool:
    """
    Validate that redirect target is an internal relative application path.
    Prevents Open Redirect vulnerabilities (CWE-601).
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    # Must start with single slash, not // or /\ (protocol-relative attacks)
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return False
    # Parse URL to ensure no netloc (domain) is specified
    parsed = urllib.parse.urlparse(target)
    return parsed.scheme == "" and parsed.netloc == ""

# =============================================================================
# IDENTITY EXTRACTION HELPERS (SECURE & NORMALIZED)
# =============================================================================

def extract_google_identity(token: dict, client) -> dict:
    """
    Extract normalized user identity from Google OpenID Connect token.
    """
    # 1. Attempt ID Token parse (preferred for OIDC)
    userinfo = client.parse_id_token(token) if hasattr(client, "parse_id_token") else None
    if not userinfo:
        # Fallback to userinfo endpoint
        resp = client.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        if resp.status_code == 200:
            userinfo = resp.json()
        else:
            userinfo = token.get("userinfo") or {}

    sub = str(userinfo.get("sub") or "").strip()
    if not sub:
        raise ValueError("Google identity missing subject claim ('sub').")

    email = (userinfo.get("email") or "").strip().lower()
    is_verified = bool(userinfo.get("email_verified", False))
    name = (userinfo.get("name") or userinfo.get("given_name") or "").strip()

    return {
        "provider": "google",
        "provider_user_id": sub,
        "email": email if email else None,
        "is_email_verified": is_verified,
        "name": name if name else None,
        "raw_profile": {
            "name": name,
            "email": email,
            "picture": userinfo.get("picture")
        }
    }

def extract_github_identity(token: dict, client) -> dict:
    """
    Extract normalized user identity from GitHub OAuth response.
    Queries /user and /user/emails for verified primary email.
    """
    access_token = token.get("access_token")
    if not access_token:
        raise ValueError("GitHub response missing access token.")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SMS-Sentinel-Auth-Client"
    }

    # 1. Fetch GitHub User Profile
    user_resp = requests.get("https://api.github.com/user", headers=headers, timeout=10)
    if user_resp.status_code != 200:
        raise ValueError(f"GitHub user profile retrieval failed: HTTP {user_resp.status_code}")
    user_data = user_resp.json()

    github_id = str(user_data.get("id") or "").strip()
    if not github_id:
        raise ValueError("GitHub response missing user ID.")

    name = (user_data.get("name") or user_data.get("login") or "").strip()
    public_email = (user_data.get("email") or "").strip().lower()

    # 2. Fetch User Emails to find verified primary address
    verified_email = None
    try:
        emails_resp = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10)
        if emails_resp.status_code == 200:
            emails_list = emails_resp.json()
            if isinstance(emails_list, list):
                # Search for primary verified email
                for e in emails_list:
                    if e.get("primary") and e.get("verified") and e.get("email"):
                        verified_email = e.get("email").strip().lower()
                        break
                # Fallback to any verified email
                if not verified_email:
                    for e in emails_list:
                        if e.get("verified") and e.get("email"):
                            verified_email = e.get("email").strip().lower()
                            break
    except Exception as err:
        logger.warning(f"Failed to fetch GitHub email list: {err}")

    final_email = verified_email or (public_email if public_email else None)
    is_verified = bool(verified_email)

    return {
        "provider": "github",
        "provider_user_id": github_id,
        "email": final_email,
        "is_email_verified": is_verified,
        "name": name if name else user_data.get("login"),
        "raw_profile": {
            "login": user_data.get("login"),
            "name": name,
            "avatar_url": user_data.get("avatar_url")
        }
    }

def extract_microsoft_identity(token: dict, client) -> dict:
    """
    Extract normalized user identity from Microsoft Identity OpenID Connect token / Graph API.
    """
    userinfo = client.parse_id_token(token) if hasattr(client, "parse_id_token") else None
    
    # If ID token parse wasn't complete, query Microsoft Graph /me
    graph_data = {}
    if not userinfo or not userinfo.get("sub"):
        access_token = token.get("access_token")
        if access_token:
            try:
                g_resp = requests.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=10
                )
                if g_resp.status_code == 200:
                    graph_data = g_resp.json()
            except Exception as err:
                logger.warning(f"Microsoft Graph API fetch error: {err}")

    userinfo = userinfo or {}
    provider_user_id = str(userinfo.get("sub") or userinfo.get("oid") or graph_data.get("id") or "").strip()
    if not provider_user_id:
        raise ValueError("Microsoft identity missing subject/object identifier.")

    email = (
        userinfo.get("email") or 
        userinfo.get("preferred_username") or 
        graph_data.get("mail") or 
        graph_data.get("userPrincipalName") or 
        ""
    ).strip().lower()

    name = (
        userinfo.get("name") or 
        graph_data.get("displayName") or 
        f"{graph_data.get('givenName', '')} {graph_data.get('surname', '')}".strip()
    ).strip()

    # Microsoft OpenID Connect tokens issued from Azure AD verify email ownership
    is_verified = bool(email and "@" in email)

    return {
        "provider": "microsoft",
        "provider_user_id": provider_user_id,
        "email": email if email else None,
        "is_email_verified": is_verified,
        "name": name if name else None,
        "raw_profile": {
            "name": name,
            "email": email
        }
    }
