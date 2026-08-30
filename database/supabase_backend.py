"""
SMS SENTINEL — Supabase PostgreSQL Database Engine (Production Persistence)
Provides durable multi-instance persistence for users, OAuth identities, SMS analyses,
and real-time analytical telemetry via the official Supabase Python client.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("sms_sentinel_db_supabase")

# Cached Supabase client instance
_supabase_client = None


def get_supabase_config() -> Tuple[str, str]:
    """Retrieve Supabase URL and Key from environment variables."""
    url = (
        os.environ.get("SUPABASE_URL")
        or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
        or ""
    ).strip()

    key = (
        os.environ.get("SUPABASE_KEY")
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_SERVICE_KEY")
        or os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("SUPABASE_ANON_KEY")
        or ""
    ).strip()

    return url, key


def is_supabase_configured() -> bool:
    """Check if valid Supabase URL and Key are available."""
    url, key = get_supabase_config()
    return bool(url and key and url.startswith("http"))


def get_supabase_client():
    """
    Initialize or return cached Supabase Python client.
    Uses HTTPS REST (PostgREST) to eliminate serverless connection-pool exhaustion.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url, key = get_supabase_config()
    if not url or not key:
        raise RuntimeError(
            "Supabase is not configured. Please set SUPABASE_URL and SUPABASE_KEY environment variables."
        )

    try:
        from supabase import create_client, Client
        _supabase_client = create_client(url, key)
        logger.info(f"Supabase client initialized successfully for target: {url}")
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        raise


def init_db():
    """Verify Supabase connection on application startup."""
    if is_supabase_configured():
        try:
            client = get_supabase_client()
            logger.info("Supabase database connection verified.")
        except Exception as e:
            logger.warning(f"Supabase init check warning: {e}")


# =============================================================================
# DATA NORMALIZATION HELPERS
# =============================================================================

def _ensure_dict_or_list(val, default_factory):
    """Normalize JSON/JSONB field whether returned as string, dict, list, or None."""
    if val is None:
        return default_factory()
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return default_factory()
    return default_factory()


def _parse_analysis_record(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert Supabase row into standard analysis dictionary matching application contract."""
    if not row:
        return None

    signals = _ensure_dict_or_list(row.get("risk_signals"), list)
    stats = _ensure_dict_or_list(row.get("message_stats"), dict)
    terms = _ensure_dict_or_list(row.get("highlight_terms"), list)
    tokens = _ensure_dict_or_list(row.get("xray_tokens"), list)
    action = _ensure_dict_or_list(row.get("recommended_action"), dict)
    trace = _ensure_dict_or_list(row.get("pipeline_trace"), dict)

    if "character_count" in stats and "char_count" not in stats:
        stats["char_count"] = stats["character_count"]
    if "phone_number_count" in stats and "phone_count" not in stats:
        stats["phone_count"] = stats["phone_number_count"]

    created_at_raw = row.get("created_at") or ""
    created_str = str(created_at_raw)

    return {
        "id": row.get("id"),
        "user_id": row.get("user_id"),
        "message": row.get("message", ""),
        "raw_message": row.get("message", ""),
        "prediction": row.get("prediction", "NOT SPAM"),
        "confidence": float(row.get("confidence", 100.0)),
        "threat_score": int(row.get("threat_score", 0)),
        "threat_level": row.get("threat_level", "LOW RISK"),
        "is_spam": bool(row.get("is_spam")),
        "risk_signals": signals,
        "signals": signals,
        "message_stats": stats,
        "highlight_terms": terms,
        "xray_tokens": tokens,
        "recommended_action": action,
        "pipeline_trace": trace,
        "created_at": created_str
    }


# =============================================================================
# USER AUTHENTICATION & MANAGEMENT
# =============================================================================

def create_user(name: str, email: str, password_hash: str = "") -> int:
    """
    Register a new user in Supabase Postgres.
    Returns newly created user ID (int).
    """
    client = get_supabase_client()
    payload = {
        "name": name.strip(),
        "email": email.strip().lower(),
        "password_hash": password_hash or "",
        "created_at": datetime.utcnow().isoformat()
    }

    res = client.table("users").insert(payload).execute()
    if res.data and len(res.data) > 0:
        return res.data[0]["id"]
    raise RuntimeError("Failed to create user in Supabase.")


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieve user by email (case-insensitive) from Supabase."""
    if not email:
        return None
    client = get_supabase_client()
    clean_email = email.strip().lower()
    res = client.table("users").select("*").ilike("email", clean_email).limit(1).execute()
    if res.data and len(res.data) > 0:
        row = res.data[0]
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "password_hash": row.get("password_hash"),
            "created_at": str(row.get("created_at", ""))
        }
    return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve user by primary key ID from Supabase (password_hash omitted)."""
    if not user_id:
        return None
    client = get_supabase_client()
    res = client.table("users").select("id, name, email, created_at").eq("id", int(user_id)).limit(1).execute()
    if res.data and len(res.data) > 0:
        row = res.data[0]
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "created_at": str(row.get("created_at", ""))
        }
    return None


def get_user_by_oauth_identity(provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user by linked OAuth identity (provider + provider_user_id)."""
    if not provider or not provider_user_id:
        return None
    client = get_supabase_client()
    res = client.table("oauth_identities").select(
        "id, user_id, provider, provider_user_id, users(id, name, email, created_at)"
    ).ilike("provider", provider.strip()).eq("provider_user_id", str(provider_user_id).strip()).limit(1).execute()

    if res.data and len(res.data) > 0:
        identity = res.data[0]
        user_info = identity.get("users")
        if not user_info and identity.get("user_id"):
            user_info = get_user_by_id(identity["user_id"])

        if user_info:
            now_iso = datetime.utcnow().isoformat()
            try:
                client.table("oauth_identities").update({"last_login_at": now_iso}).eq("id", identity["id"]).execute()
            except Exception:
                pass

            return {
                "id": user_info["id"],
                "name": user_info["name"],
                "email": user_info["email"],
                "created_at": str(user_info.get("created_at", "")),
                "provider": identity["provider"],
                "provider_user_id": identity["provider_user_id"]
            }
    return None


def link_oauth_identity(user_id: int, provider: str, provider_user_id: str, email: str = None) -> int:
    """Link social identity (provider + provider_user_id) to an existing user."""
    client = get_supabase_client()
    now_iso = datetime.utcnow().isoformat()
    payload = {
        "user_id": int(user_id),
        "provider": provider.strip().lower(),
        "provider_user_id": str(provider_user_id).strip(),
        "email": (email.strip().lower() if email else None),
        "last_login_at": now_iso
    }

    # Check if identity exists for upsert
    existing = client.table("oauth_identities").select("id").ilike(
        "provider", payload["provider"]
    ).eq("provider_user_id", payload["provider_user_id"]).limit(1).execute()

    if existing.data and len(existing.data) > 0:
        ident_id = existing.data[0]["id"]
        client.table("oauth_identities").update(payload).eq("id", ident_id).execute()
        return ident_id
    else:
        payload["created_at"] = now_iso
        res = client.table("oauth_identities").insert(payload).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]["id"]
    return 1


def get_user_identities(user_id: int) -> List[Dict[str, Any]]:
    """Retrieve all linked OAuth identities for a user."""
    if not user_id:
        return []
    client = get_supabase_client()
    res = client.table("oauth_identities").select(
        "id, provider, provider_user_id, email, created_at, last_login_at"
    ).eq("user_id", int(user_id)).order("created_at", desc=False).execute()

    if res.data:
        return [
            {
                "id": r["id"],
                "provider": r["provider"],
                "provider_user_id": r["provider_user_id"],
                "email": r.get("email"),
                "created_at": str(r.get("created_at", "")),
                "last_login_at": str(r.get("last_login_at", ""))
            }
            for r in res.data
        ]
    return []


def resolve_or_create_oauth_user(
    provider: str,
    provider_user_id: str,
    email: str = None,
    name: str = None,
    is_email_verified: bool = False
) -> Tuple[Dict[str, Any], str]:
    """
    Deterministic Account Resolution & Linking Pipeline:
    1. Primary Lookup: Match by (provider, provider_user_id).
    2. Email Match & Linking: If verified email matches existing account, link identity.
    3. Auto-Registration: If no existing user, create local user and link identity.
    """
    provider = provider.strip().lower()
    provider_user_id = str(provider_user_id).strip()
    clean_email = email.strip().lower() if email else None

    # 1. Check if identity already linked
    existing_user = get_user_by_oauth_identity(provider, provider_user_id)
    if existing_user:
        return existing_user, "existing_identity"

    # 2. Check if verified email matches an existing account
    if clean_email and is_email_verified:
        matched_user = get_user_by_email(clean_email)
        if matched_user:
            link_oauth_identity(matched_user["id"], provider, provider_user_id, clean_email)
            return matched_user, "linked_account"

    # 3. Create new user
    display_name = (name or "").strip()
    if not display_name:
        if clean_email:
            display_name = clean_email.split("@")[0].replace(".", " ").title()
        else:
            display_name = f"{provider.capitalize()} User"

    account_email = clean_email or f"{provider}_{provider_user_id}@oauth.sentinel.local"
    existing_by_email = get_user_by_email(account_email)
    if existing_by_email:
        account_email = f"{account_email.split('@')[0]}_{provider_user_id[:6]}@{account_email.split('@')[-1]}"

    user_id = create_user(name=display_name, email=account_email, password_hash="")
    link_oauth_identity(user_id, provider, provider_user_id, clean_email)
    user_record = get_user_by_id(user_id)
    return user_record, "created_account"


# =============================================================================
# ANALYSES CRUD WITH PER-USER DATA ISOLATION
# =============================================================================

def save_analysis(result: dict, user_id: int = None) -> int:
    """Store a complete SMS analysis in Supabase Postgres."""
    client = get_supabase_client()

    raw_msg = result.get("raw_message") or result.get("message") or ""
    pred = result.get("prediction", "NOT SPAM")
    is_spam = 1 if result.get("is_spam") else 0
    threat_lvl = result.get("threat_level") or ("HIGH RISK" if is_spam else "LOW RISK")
    threat_score = int(result.get("threat_score", 0))
    conf = float(result.get("confidence", 100.0))

    signals = result.get("risk_signals") or result.get("signals") or []
    stats = result.get("message_stats") or result.get("stats") or {}
    terms = result.get("highlight_terms") or []
    tokens = result.get("xray_tokens") or []
    action = result.get("recommended_action") or {}
    trace = result.get("pipeline_trace") or {}

    payload = {
        "user_id": int(user_id) if user_id is not None else None,
        "message": raw_msg,
        "prediction": pred,
        "confidence": conf,
        "threat_score": threat_score,
        "threat_level": threat_lvl,
        "is_spam": is_spam,
        "risk_signals": signals,
        "message_stats": stats,
        "highlight_terms": terms,
        "xray_tokens": tokens,
        "recommended_action": action,
        "pipeline_trace": trace,
        "created_at": datetime.utcnow().isoformat()
    }

    res = client.table("analyses").insert(payload).execute()
    if res.data and len(res.data) > 0:
        return res.data[0]["id"]
    raise RuntimeError("Failed to save analysis to Supabase.")


def get_analyses(
    search: str = "",
    prediction: str = "ALL",
    risk_level: str = "ALL",
    limit: int = 20,
    offset: int = 0,
    user_id: int = None
) -> dict:
    """
    Retrieve stored analyses with search, filtering, pagination, and user isolation.
    """
    limit = min(max(1, int(limit)), 100)
    offset = max(0, int(offset))
    client = get_supabase_client()

    query = client.table("analyses").select("*", count="exact")

    if user_id is not None:
        query = query.eq("user_id", int(user_id))

    if search:
        query = query.ilike("message", f"%{search.strip()}%")

    if risk_level and risk_level.upper() != "ALL":
        query = query.ilike("threat_level", risk_level.upper())

    if prediction and prediction.upper() != "ALL":
        pred_clean = prediction.upper().strip()
        if pred_clean in ["SPAM", "1"]:
            query = query.eq("is_spam", 1)
        elif pred_clean in ["HAM", "NOT SPAM", "NOT_SPAM", "0"]:
            query = query.eq("is_spam", 0)

    query = query.order("id", desc=True).range(offset, offset + limit - 1)
    res = query.execute()

    total_count = res.count if res.count is not None else len(res.data or [])
    records = [_parse_analysis_record(r) for r in (res.data or [])]

    return {
        "total": total_count,
        "records": records,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(records)) < total_count
    }


def get_analysis_by_id(record_id: int, user_id: int = None) -> Optional[Dict[str, Any]]:
    """Retrieve full analysis details for a single record with user isolation."""
    client = get_supabase_client()
    query = client.table("analyses").select("*").eq("id", int(record_id))
    if user_id is not None:
        query = query.eq("user_id", int(user_id))
    res = query.limit(1).execute()
    if res.data and len(res.data) > 0:
        return _parse_analysis_record(res.data[0])
    return None


def delete_analysis(record_id: int, user_id: int = None) -> bool:
    """Delete a single analysis record by ID with user isolation."""
    client = get_supabase_client()
    query = client.table("analyses").delete().eq("id", int(record_id))
    if user_id is not None:
        query = query.eq("user_id", int(user_id))
    res = query.execute()
    return bool(res.data and len(res.data) > 0)


def clear_analyses(user_id: int = None) -> bool:
    """Clear analyses for a given user (or all if user_id is None)."""
    client = get_supabase_client()
    query = client.table("analyses").delete()
    if user_id is not None:
        query = query.eq("user_id", int(user_id))
    else:
        query = query.neq("id", 0)  # Delete all
    query.execute()
    return True


# =============================================================================
# REAL-TIME SUPABASE POSTGRES ANALYTICAL AGGREGATIONS (USER-ISOLATED)
# =============================================================================

def get_insights_data(user_id: int = None) -> dict:
    """
    Compile complete real-time Insights payload strictly from Supabase Postgres.
    Filtered by user_id for strict data isolation.
    """
    client = get_supabase_client()

    query = client.table("analyses").select(
        "id, message, prediction, confidence, threat_score, threat_level, is_spam, risk_signals, created_at"
    )
    if user_id is not None:
        query = query.eq("user_id", int(user_id))

    # Fetch recent analyses for aggregation (up to 1000 for high precision without memory overhead)
    res = query.order("id", desc=True).limit(1000).execute()
    rows = res.data or []

    total_count = len(rows)
    has_data = total_count > 0

    spam_count = 0
    not_spam_count = 0
    total_conf = 0.0
    total_threat = 0.0

    threat_dist = {"low": 0, "medium": 0, "high": 0}
    class_dist = {"spam": 0, "not_spam": 0}
    activity_map = {}
    signal_counts = {}
    signal_types = {}
    recent_activity = []

    for idx, r in enumerate(rows):
        is_spam = bool(r.get("is_spam") or (r.get("prediction") == "SPAM"))
        if is_spam:
            spam_count += 1
            class_dist["spam"] += 1
        else:
            not_spam_count += 1
            class_dist["not_spam"] += 1

        # Threat distribution (0-33, 34-66, 67-100)
        score = int(r.get("threat_score") or 0)
        total_threat += score
        if score <= 33:
            threat_dist["low"] += 1
        elif score <= 66:
            threat_dist["medium"] += 1
        else:
            threat_dist["high"] += 1

        # Confidence
        conf = float(r.get("confidence") or 0.0)
        if 0.0 < conf <= 1.0:
            conf = conf * 100.0
        total_conf += conf

        # Activity timeline (by date YYYY-MM-DD)
        created_str = str(r.get("created_at") or "")
        date_str = created_str[:10] if len(created_str) >= 10 else datetime.utcnow().strftime("%Y-%m-%d")
        if date_str not in activity_map:
            activity_map[date_str] = {"date": date_str, "total": 0, "spam": 0, "not_spam": 0}
        activity_map[date_str]["total"] += 1
        if is_spam:
            activity_map[date_str]["spam"] += 1
        else:
            activity_map[date_str]["not_spam"] += 1

        # Risk indicator aggregation
        sigs = _ensure_dict_or_list(r.get("risk_signals"), list)
        seen_in_msg = set()
        for s in sigs:
            if isinstance(s, dict):
                label = s.get("label") or "Unknown"
                sig_type = s.get("type") or "signal"
                if label not in seen_in_msg:
                    seen_in_msg.add(label)
                    signal_counts[label] = signal_counts.get(label, 0) + 1
                    signal_types[label] = sig_type

        # First 8 records for recent activity stream
        if idx < 8:
            recent_activity.append({
                "id": r.get("id"),
                "message": r.get("message", ""),
                "prediction": r.get("prediction", "NOT SPAM"),
                "threat_level": r.get("threat_level", "LOW RISK"),
                "threat_score": score,
                "confidence": round(conf, 1),
                "is_spam": is_spam,
                "created_at": created_str
            })

    # Averages
    spam_rate = round((spam_count / total_count * 100), 1) if total_count > 0 else 0.0
    avg_conf = round((total_conf / total_count), 1) if total_count > 0 else 0.0
    avg_threat = round((total_threat / total_count), 1) if total_count > 0 else 0.0

    # Activity list sorted chronologically
    sorted_activity = sorted(activity_map.values(), key=lambda x: x["date"])[-14:]

    # Sorted risk indicators
    sorted_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)
    indicators = [
        {"type": signal_types.get(k, "signal"), "label": k, "count": v}
        for k, v in sorted_signals
    ]

    totals = {
        "analyses": total_count,
        "spam": spam_count,
        "not_spam": not_spam_count,
        "spam_rate": spam_rate
    }
    averages = {
        "confidence": avg_conf,
        "threat_score": avg_threat
    }

    return {
        "has_data": has_data,
        "totals": totals,
        "threat_distribution": threat_dist,
        "classification_distribution": class_dist,
        "activity": sorted_activity,
        "risk_indicators": indicators,
        "averages": averages,
        "recent": recent_activity,
        # Flat legacy convenience fields
        "total_analyzed": totals["analyses"],
        "spam_detected": totals["spam"],
        "legitimate_detected": totals["not_spam"],
        "spam_rate": totals["spam_rate"],
        "avg_threat_score": averages["threat_score"],
        "avg_confidence": averages["confidence"],
        "timeline": sorted_activity,
        "risk_distribution": threat_dist,
        "top_signals": indicators,
        "recent_incidents": recent_activity
    }
