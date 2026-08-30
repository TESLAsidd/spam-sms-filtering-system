"""
SMS SENTINEL — Authentication Package
"""
from .oauth_service import (
    init_oauth,
    oauth,
    SUPPORTED_PROVIDERS,
    is_provider_configured,
    get_redirect_uri,
    is_safe_url,
    extract_google_identity,
    extract_github_identity,
    extract_microsoft_identity
)
