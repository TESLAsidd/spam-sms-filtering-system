"""
SMS SENTINEL — COMPREHENSIVE OAUTH & SOCIAL AUTHENTICATION TEST SUITE
Validates Google, GitHub, and Microsoft login flows, state CSRF verification,
account linking, duplicate identity idempotency, user data isolation, and open redirect defense.
"""

import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from database.db import (
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_oauth_identity,
    link_oauth_identity,
    resolve_or_create_oauth_user,
    get_user_identities,
    save_analysis,
    get_analyses,
    get_insights_data
)
from auth.oauth_service import (
    is_safe_url,
    extract_google_identity,
    extract_github_identity,
    extract_microsoft_identity
)

class TestOAuthAuthenticationSuite(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        init_db()

    # =========================================================================
    # 1. URL & REDIRECT SECURITY TESTS (OPEN REDIRECT DEFENSE)
    # =========================================================================

    def test_01_open_redirect_protection(self):
        """Verify is_safe_url strictly rejects external and protocol-relative domains."""
        # Malicious targets
        self.assertFalse(is_safe_url("https://evil.com"))
        self.assertFalse(is_safe_url("http://attacker.org/steal"))
        self.assertFalse(is_safe_url("//evil.com/phish"))
        self.assertFalse(is_safe_url("/\\evil.com"))
        self.assertFalse(is_safe_url("javascript:alert(1)"))
        self.assertFalse(is_safe_url("data:text/html,malicious"))
        self.assertFalse(is_safe_url(""))
        self.assertFalse(is_safe_url(None))

        # Safe internal targets
        self.assertTrue(is_safe_url("/"))
        self.assertTrue(is_safe_url("/scan"))
        self.assertTrue(is_safe_url("/archive"))
        self.assertTrue(is_safe_url("/insights"))
        self.assertTrue(is_safe_url("/archive?search=test"))

    # =========================================================================
    # 2. PROVIDER CONFIGURATION & UNCONFIGURED FALLBACK
    # =========================================================================

    def test_02_unconfigured_provider_redirection(self):
        """Verify attempting login on unconfigured provider redirects with clear notification."""
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}, clear=False):
            response = self.client.get("/auth/google/login")
            self.assertEqual(response.status_code, 302)
            self.assertIn("/login", response.headers["Location"])
            self.assertIn("config_missing", response.headers["Location"])

    def test_03_unsupported_provider_rejection(self):
        """Verify attempting login with unsupported provider is cleanly rejected."""
        response = self.client.get("/auth/facebook/login")
        self.assertEqual(response.status_code, 302)
        self.assertIn("unsupported_provider", response.headers["Location"])

    # =========================================================================
    # 3. CSRF STATE & CALLBACK ERROR HANDLING
    # =========================================================================

    def test_04_callback_cancelled_by_user(self):
        """Verify user cancellation at provider returns clean cancelled message."""
        response = self.client.get("/auth/google/callback?error=access_denied&error_description=User+denied")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertIn("cancelled", response.headers["Location"])

    def test_05_callback_missing_authorization_code(self):
        """Verify callback with missing code is rejected."""
        response = self.client.get("/auth/github/callback")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertIn("missing_code", response.headers["Location"])

    # =========================================================================
    # 4. IDENTITY EXTRACTION HELPERS UNIT TESTS
    # =========================================================================

    def test_06_extract_google_identity(self):
        """Verify Google ID token extraction accurately normalizes user claims."""
        mock_client = MagicMock()
        mock_client.parse_id_token.return_value = {
            "sub": "google-user-12345",
            "email": "alex.google@example.com",
            "email_verified": True,
            "name": "Alex Carter",
            "picture": "https://lh3.googleusercontent.com/a/avatar"
        }
        token = {"access_token": "mock-token", "id_token": "mock-id-token"}
        
        identity = extract_google_identity(token, mock_client)
        self.assertEqual(identity["provider"], "google")
        self.assertEqual(identity["provider_user_id"], "google-user-12345")
        self.assertEqual(identity["email"], "alex.google@example.com")
        self.assertTrue(identity["is_email_verified"])
        self.assertEqual(identity["name"], "Alex Carter")

    @patch("requests.get")
    def test_07_extract_github_identity(self, mock_get):
        """Verify GitHub identity extractor fetches user profile and verified email."""
        # Mock /user response
        user_resp = MagicMock()
        user_resp.status_code = 200
        user_resp.json.return_value = {
            "id": 987654,
            "login": "octocat",
            "name": "The Octocat",
            "email": None,
            "avatar_url": "https://avatars.githubusercontent.com/u/987654"
        }
        
        # Mock /user/emails response
        emails_resp = MagicMock()
        emails_resp.status_code = 200
        emails_resp.json.return_value = [
            {"email": "unverified@example.com", "primary": False, "verified": False},
            {"email": "octocat.dev@example.com", "primary": True, "verified": True}
        ]
        
        mock_get.side_effect = [user_resp, emails_resp]
        mock_client = MagicMock()
        token = {"access_token": "gho_mock_access_token"}

        identity = extract_github_identity(token, mock_client)
        self.assertEqual(identity["provider"], "github")
        self.assertEqual(identity["provider_user_id"], "987654")
        self.assertEqual(identity["email"], "octocat.dev@example.com")
        self.assertTrue(identity["is_email_verified"])
        self.assertEqual(identity["name"], "The Octocat")

    def test_08_extract_microsoft_identity(self):
        """Verify Microsoft ID token extraction accurately normalizes user claims."""
        mock_client = MagicMock()
        mock_client.parse_id_token.return_value = {
            "sub": "ms-oid-998877",
            "preferred_username": "sarah.dev@outlook.com",
            "name": "Sarah Connor"
        }
        token = {"access_token": "mock-ms-token"}

        identity = extract_microsoft_identity(token, mock_client)
        self.assertEqual(identity["provider"], "microsoft")
        self.assertEqual(identity["provider_user_id"], "ms-oid-998877")
        self.assertEqual(identity["email"], "sarah.dev@outlook.com")
        self.assertTrue(identity["is_email_verified"])
        self.assertEqual(identity["name"], "Sarah Connor")

    # =========================================================================
    # 5. ACCOUNT CREATION & LINKING INTEGRATION TESTS
    # =========================================================================

    def test_09_new_oauth_user_auto_registration(self):
        """Verify new OAuth user gets created in SQLite with linked identity."""
        import uuid
        uid_key = uuid.uuid4().hex[:8]
        provider_id = f"google-sub-{uid_key}"
        email = f"new.user.{uid_key}@example.com"

        user, action = resolve_or_create_oauth_user(
            provider="google",
            provider_user_id=provider_id,
            email=email,
            name="New Google User",
            is_email_verified=True
        )
        self.assertEqual(action, "created_account")
        self.assertIsNotNone(user["id"])
        self.assertEqual(user["email"], email)

        # Verify identity link
        linked = get_user_by_oauth_identity("google", provider_id)
        self.assertIsNotNone(linked)
        self.assertEqual(linked["id"], user["id"])

    def test_10_duplicate_oauth_login_is_idempotent(self):
        """Verify logging in multiple times with the same provider identity resolves to the same account."""
        import uuid
        uid_key = uuid.uuid4().hex[:8]
        provider_id = f"gh-id-{uid_key}"
        email = f"dev.{uid_key}@example.com"

        user1, action1 = resolve_or_create_oauth_user(
            provider="github",
            provider_user_id=provider_id,
            email=email,
            name="Dev User",
            is_email_verified=True
        )
        self.assertEqual(action1, "created_account")

        user2, action2 = resolve_or_create_oauth_user(
            provider="github",
            provider_user_id=provider_id,
            email=email,
            name="Dev User",
            is_email_verified=True
        )
        self.assertEqual(action2, "existing_identity")
        self.assertEqual(user1["id"], user2["id"])

    def test_11_account_linking_with_existing_password_user(self):
        """Verify that when a verified social email matches an existing local account, it links seamlessly."""
        import uuid
        from werkzeug.security import generate_password_hash
        uid_key = uuid.uuid4().hex[:8]
        email = f"elena.{uid_key}@example.com"
        pwd_hash = generate_password_hash("SuperSecretPass123!")
        local_uid = create_user(f"Elena Fisher {uid_key}", email, pwd_hash)

        # 2. Elena logs in with Google which has verified email
        user, action = resolve_or_create_oauth_user(
            provider="google",
            provider_user_id=f"google-sub-{uid_key}",
            email=email,
            name="Elena Fisher",
            is_email_verified=True
        )
        self.assertEqual(action, "linked_account")
        self.assertEqual(user["id"], local_uid)

        # 3. Elena also logs in with Microsoft which has verified email
        user_ms, action_ms = resolve_or_create_oauth_user(
            provider="microsoft",
            provider_user_id=f"ms-oid-{uid_key}",
            email=email,
            name="Elena Fisher",
            is_email_verified=True
        )
        self.assertEqual(action_ms, "linked_account")
        self.assertEqual(user_ms["id"], local_uid)

        # 4. Verify all 2 identities linked to the single user
        identities = get_user_identities(local_uid)
        providers = [i["provider"] for i in identities]
        self.assertIn("google", providers)
        self.assertIn("microsoft", providers)
        self.assertEqual(len(identities), 2)

    def test_12_password_login_remains_functional_after_social_linking(self):
        """Verify account linking does not break traditional password login."""
        import uuid
        from werkzeug.security import generate_password_hash
        uid_key = uuid.uuid4().hex[:8]
        email = f"nathan.{uid_key}@example.com"
        pwd = "UnchartedPassword2026!"
        uid = create_user("Nathan Drake", email, generate_password_hash(pwd))

        # Link GitHub
        resolve_or_create_oauth_user(
            provider="github",
            provider_user_id=f"gh-nathan-{uid_key}",
            email=email,
            name="Nathan Drake",
            is_email_verified=True
        )

        # Now test password login endpoint
        login_res = self.client.post(
            "/api/auth/login",
            data=json.dumps({"email": email, "password": pwd}),
            content_type="application/json"
        )
        self.assertEqual(login_res.status_code, 200)
        data = login_res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["id"], uid)

    # =========================================================================
    # 6. USER DATA ISOLATION & ARCHIVE INTEGRATION
    # =========================================================================

    def test_13_user_data_isolation_between_social_and_password_users(self):
        """Verify strict database isolation between Google, GitHub, and Password accounts."""
        import uuid
        uid_key = uuid.uuid4().hex[:8]
        # Create User A (Google)
        user_a, _ = resolve_or_create_oauth_user("google", f"sub-a-{uid_key}", f"user_a_{uid_key}@test.com", "User A", True)
        # Create User B (GitHub)
        user_b, _ = resolve_or_create_oauth_user("github", f"sub-b-{uid_key}", f"user_b_{uid_key}@test.com", "User B", True)

        # User A performs 2 scans
        save_analysis({
            "message": "User A confidential security scan 1",
            "prediction": "NOT SPAM",
            "confidence": 99.0,
            "threat_score": 5,
            "is_spam": False
        }, user_id=user_a["id"])

        save_analysis({
            "message": "User A confidential security scan 2",
            "prediction": "SPAM",
            "confidence": 95.0,
            "threat_score": 85,
            "is_spam": True
        }, user_id=user_a["id"])

        # User B performs 1 scan
        save_analysis({
            "message": "User B confidential transaction scan",
            "prediction": "NOT SPAM",
            "confidence": 98.0,
            "threat_score": 10,
            "is_spam": False
        }, user_id=user_b["id"])

        # Verify User A Archive only has A's records
        analyses_a = get_analyses(user_id=user_a["id"])
        self.assertEqual(analyses_a["total"], 2)
        for rec in analyses_a["records"]:
            self.assertEqual(rec["user_id"], user_a["id"])

        # Verify User B Archive only has B's records
        analyses_b = get_analyses(user_id=user_b["id"])
        self.assertEqual(analyses_b["total"], 1)
        self.assertEqual(analyses_b["records"][0]["user_id"], user_b["id"])

        # Verify User A Insights only aggregates A's scans
        insights_a = get_insights_data(user_id=user_a["id"])
        self.assertEqual(insights_a["totals"]["analyses"], 2)
        self.assertEqual(insights_a["totals"]["spam"], 1)

        insights_b = get_insights_data(user_id=user_b["id"])
        self.assertEqual(insights_b["totals"]["analyses"], 1)
        self.assertEqual(insights_b["totals"]["spam"], 0)

    # =========================================================================
    # 7. SESSION & PROFILE API (GET /api/auth/me)
    # =========================================================================

    def test_14_api_auth_me_returns_unified_profile(self):
        """Verify GET /api/auth/me returns local user identity regardless of login method."""
        import uuid
        uid_key = uuid.uuid4().hex[:8]
        email = f"sam.{uid_key}@example.com"
        user, _ = resolve_or_create_oauth_user("google", f"sub-me-{uid_key}", email, "Sam Fisher", True)

        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["user_name"] = user["name"]
            sess["user_email"] = user["email"]
            sess["auth_provider"] = "google"

        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["user"]["id"], user["id"])
        self.assertEqual(data["user"]["email"], email)
        self.assertEqual(data["user"]["auth_provider"], "google")

    def test_15_logout_destroys_session(self):
        """Verify /api/auth/logout destroys the authenticated session."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["user_email"] = "auth@example.com"

        res = self.client.post("/api/auth/logout")
        self.assertEqual(res.status_code, 200)

        # Check me endpoint is unauthenticated
        res_me = self.client.get("/api/auth/me")
        self.assertEqual(res_me.get_json()["authenticated"], False)

    # =========================================================================
    # 8. END-TO-END HTTP CALLBACK FLOW & STATE CSRF TESTS
    # =========================================================================

    @patch("auth.oauth_service.oauth.create_client")
    def test_16_google_callback_e2e_http_flow(self, mock_create_client):
        """Verify end-to-end Google OAuth callback creates session and redirects to /."""
        mock_client = MagicMock()
        mock_client.authorize_access_token.return_value = {
            "access_token": "mock-google-access-token",
            "id_token": "mock-id-token"
        }
        mock_client.parse_id_token.return_value = {
            "sub": "google-oauth-flow-sub-900",
            "email": "agent.smith@matrix.com",
            "email_verified": True,
            "name": "Agent Smith"
        }
        mock_create_client.return_value = mock_client

        with self.client.session_transaction() as sess:
            sess["oauth_next_url"] = "/scan"

        res = self.client.get("/auth/google/callback?code=mock_google_code&state=mock_state")
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/scan")

        # Verify session has authenticated user
        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))
            self.assertEqual(sess.get("user_email"), "agent.smith@matrix.com")
            self.assertEqual(sess.get("auth_provider"), "google")

    @patch("auth.oauth_service.oauth.create_client")
    @patch("requests.get")
    def test_17_github_callback_e2e_http_flow(self, mock_get, mock_create_client):
        """Verify end-to-end GitHub OAuth callback creates session and redirects safely."""
        mock_client = MagicMock()
        mock_client.authorize_access_token.return_value = {
            "access_token": "gho_mock_access_token"
        }
        mock_create_client.return_value = mock_client

        # Mock GitHub API calls
        user_resp = MagicMock()
        user_resp.status_code = 200
        user_resp.json.return_value = {"id": 1234567, "login": "cyberdev", "name": "Cyber Dev"}

        emails_resp = MagicMock()
        emails_resp.status_code = 200
        emails_resp.json.return_value = [{"email": "cyberdev@example.org", "primary": True, "verified": True}]

        mock_get.side_effect = [user_resp, emails_resp]

        res = self.client.get("/auth/github/callback?code=mock_gh_code&state=mock_state")
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/")

        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))
            self.assertEqual(sess.get("user_email"), "cyberdev@example.org")
            self.assertEqual(sess.get("auth_provider"), "github")

    @patch("auth.oauth_service.oauth.create_client")
    def test_18_microsoft_callback_e2e_http_flow(self, mock_create_client):
        """Verify end-to-end Microsoft OAuth callback creates session and redirects."""
        mock_client = MagicMock()
        mock_client.authorize_access_token.return_value = {
            "access_token": "mock-ms-access-token"
        }
        mock_client.parse_id_token.return_value = {
            "sub": "ms-entra-sub-777",
            "preferred_username": "satya@microsoft.local",
            "name": "Satya Nadella"
        }
        mock_create_client.return_value = mock_client

        res = self.client.get("/auth/microsoft/callback?code=mock_ms_code&state=mock_state")
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/")

        with self.client.session_transaction() as sess:
            self.assertIsNotNone(sess.get("user_id"))
            self.assertEqual(sess.get("user_email"), "satya@microsoft.local")
            self.assertEqual(sess.get("auth_provider"), "microsoft")

    @patch("auth.oauth_service.oauth.create_client")
    def test_19_oauth_callback_invalid_state_csrf(self, mock_create_client):
        """Verify OAuth state mismatch / CSRF error redirects to login with invalid_state error."""
        mock_client = MagicMock()
        mock_client.authorize_access_token.side_effect = Exception("Mismatching_State: CSRF Warning")
        mock_create_client.return_value = mock_client

        res = self.client.get("/auth/google/callback?code=bad_code&state=forged_state")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/login", res.headers["Location"])
        self.assertIn("invalid_state", res.headers["Location"])

    def test_20_api_auth_providers_endpoint(self):
        """Verify /api/auth/providers returns boolean status for Google, GitHub, and Microsoft."""
        res = self.client.get("/api/auth/providers")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("google", data)
        self.assertIn("github", data)
        self.assertIn("microsoft", data)

    def test_21_api_auth_identities_endpoint(self):
        """Verify /api/auth/identities returns list of user's linked OAuth providers."""
        user, _ = resolve_or_create_oauth_user("google", "sub-ident-1", "ident@test.com", "Ident User", True)
        link_oauth_identity(user["id"], "github", "gh-ident-2", "ident@test.com")

        with self.client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess["user_email"] = user["email"]

        res = self.client.get("/api/auth/identities")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        providers = [i["provider"] for i in data["identities"]]
        self.assertIn("google", providers)
        self.assertIn("github", providers)


if __name__ == "__main__":
    unittest.main()
