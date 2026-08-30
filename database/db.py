"""
SMS SENTINEL — Unified Database Layer & Engine Router
Provides a minimal, robust database abstraction layer supporting both:
1. Local Development / Testing: SQLite (Zero-config, fast, self-healing)
2. Production Serverless: Supabase PostgreSQL (Durable, scalable, multi-instance persistent)

Database backend selection is controlled via the `DATABASE_TYPE` environment variable:
- DATABASE_TYPE="sqlite" (default for local development)
- DATABASE_TYPE="supabase" (for production deployment with SUPABASE_URL and SUPABASE_KEY)
"""

import os
import logging
from typing import Optional, Dict, Any, List, Tuple

from database import sqlite_backend
from database import supabase_backend

logger = logging.getLogger("sms_sentinel_db")


def get_active_database_type() -> str:
    """
    Determine the active database engine based on environment configuration.
    Returns 'supabase' or 'sqlite'.
    Strictly prohibits silent SQLite fallback when Supabase is requested or in production.
    """
    db_type = (os.environ.get("DATABASE_TYPE") or "").strip().lower()

    if db_type in ("supabase", "postgres", "postgresql"):
        if not supabase_backend.is_supabase_configured():
            raise RuntimeError(
                "DATABASE CONFIGURATION ERROR: DATABASE_TYPE is configured as 'supabase', "
                "but SUPABASE_URL or SUPABASE_KEY is missing or invalid. "
                "Production mode strictly prohibits silent fallback to SQLite."
            )
        return "supabase"

    if db_type == "sqlite":
        return "sqlite"

    # In production environments (Vercel / Cloud), require explicit configuration
    if os.environ.get("VERCEL") or os.environ.get("FLASK_ENV") == "production":
        if supabase_backend.is_supabase_configured():
            return "supabase"
        # If neither Supabase is configured nor DATABASE_TYPE=sqlite is explicitly set
        logger.warning(
            "Production environment detected without Supabase credentials. "
            "Using SQLite serverless temporary storage. Set DATABASE_TYPE=supabase with credentials for persistent storage."
        )
        return "sqlite"

    # Default for local development
    return "sqlite"


def get_backend():
    """Return the active database backend module."""
    if get_active_database_type() == "supabase":
        return supabase_backend
    return sqlite_backend


def init_db():
    """Initialize database schemas and indexes for the active engine."""
    backend_name = get_active_database_type()
    logger.info(f"Initializing SMS Sentinel database backend: [{backend_name.upper()}]")
    backend = get_backend()
    backend.init_db()


# =============================================================================
# USER AUTHENTICATION & MANAGEMENT (FACADE)
# =============================================================================

def create_user(name: str, email: str, password_hash: str = "") -> int:
    """Register a new user in the active database engine."""
    return get_backend().create_user(name=name, email=email, password_hash=password_hash)


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by email (case-insensitive) from active engine."""
    return get_backend().get_user_by_email(email=email)


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve user record by primary key ID (password omitted)."""
    return get_backend().get_user_by_id(user_id=user_id)


def get_user_by_oauth_identity(provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by linked OAuth identity."""
    return get_backend().get_user_by_oauth_identity(provider=provider, provider_user_id=provider_user_id)


def link_oauth_identity(user_id: int, provider: str, provider_user_id: str, email: str = None) -> int:
    """Link social OAuth identity to existing user in active engine."""
    return get_backend().link_oauth_identity(user_id=user_id, provider=provider, provider_user_id=provider_user_id, email=email)


def get_user_identities(user_id: int) -> List[Dict[str, Any]]:
    """Retrieve all linked social identities for user."""
    return get_backend().get_user_identities(user_id=user_id)


def resolve_or_create_oauth_user(
    provider: str,
    provider_user_id: str,
    email: str = None,
    name: str = None,
    is_email_verified: bool = False
) -> Tuple[Dict[str, Any], str]:
    """Execute deterministic OAuth user resolution and account linking."""
    return get_backend().resolve_or_create_oauth_user(
        provider=provider,
        provider_user_id=provider_user_id,
        email=email,
        name=name,
        is_email_verified=is_email_verified
    )


# =============================================================================
# ANALYSES CRUD WITH PER-USER DATA ISOLATION (FACADE)
# =============================================================================

def save_analysis(result: dict, user_id: int = None) -> int:
    """Store a complete analyzed SMS record in the active database engine."""
    return get_backend().save_analysis(result=result, user_id=user_id)


def get_analyses(
    search: str = "",
    prediction: str = "ALL",
    risk_level: str = "ALL",
    limit: int = 20,
    offset: int = 0,
    user_id: int = None
) -> dict:
    """Retrieve stored analyses with search, filtering, pagination, and user isolation."""
    return get_backend().get_analyses(
        search=search,
        prediction=prediction,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
        user_id=user_id
    )


def get_analysis_by_id(record_id: int, user_id: int = None) -> Optional[Dict[str, Any]]:
    """Retrieve full analysis details for a single record by primary key."""
    return get_backend().get_analysis_by_id(record_id=record_id, user_id=user_id)


def delete_analysis(record_id: int, user_id: int = None) -> bool:
    """Delete a single analysis record by ID with user ownership verification."""
    return get_backend().delete_analysis(record_id=record_id, user_id=user_id)


def clear_analyses(user_id: int = None) -> bool:
    """Clear analyses for a given user (or all if user_id is None)."""
    return get_backend().clear_analyses(user_id=user_id)


# =============================================================================
# ANALYTICAL TELEMETRY & INSIGHTS (FACADE)
# =============================================================================

def get_insights_data(user_id: int = None) -> dict:
    """Compile complete real-time Insights payload strictly from active database."""
    return get_backend().get_insights_data(user_id=user_id)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES
# =============================================================================

save_investigation = save_analysis
get_investigation_by_id = get_analysis_by_id
delete_investigation = delete_analysis
clear_investigations = clear_analyses


def get_investigations(
    search: str = "",
    risk_filter: str = "ALL",
    type_filter: str = "ALL",
    limit: int = 50,
    offset: int = 0,
    user_id: int = None
) -> list:
    res = get_analyses(
        search=search,
        risk_level=risk_filter,
        prediction=type_filter,
        limit=limit,
        offset=offset,
        user_id=user_id
    )
    return res.get("records", [])


# Auto-initialize database on module import
init_db()
