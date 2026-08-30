"""
SMS SENTINEL - SQLite Database Layer
Provides lightweight persistent storage, user authentication models,
indexing, retrieval, and real-time SQL aggregation with per-user data isolation.
"""

import os
import sqlite3
import json
from datetime import datetime

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "spamshield.db")

def _get_active_db_path():
    """Resolve database path, using /tmp on serverless environments where local filesystem is read-only."""
    if (
        os.environ.get("VERCEL")
        or os.environ.get("VERCEL_ENV")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("LAMBDA_TASK_ROOT")
    ):
        return os.path.join("/tmp", "spamshield.db")
    return DEFAULT_DB_PATH

DB_PATH = _get_active_db_path()

def _create_tables(conn):
    """Internal helper to create tables and indexes on a live connection."""
    cursor = conn.cursor()
    
    # 1. Create Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    
    # 2. Create OAuth Identities Table for Multi-Provider Account Linking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS oauth_identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL COLLATE NOCASE,
            provider_user_id TEXT NOT NULL,
            email TEXT COLLATE NOCASE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE (provider, provider_user_id)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_oauth_identities_user_id ON oauth_identities(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_oauth_identities_lookup ON oauth_identities(provider, provider_user_id)")
    
    # 3. Create Analyses Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            threat_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            is_spam INTEGER NOT NULL,
            risk_signals TEXT,
            message_stats TEXT,
            highlight_terms TEXT,
            xray_tokens TEXT,
            recommended_action TEXT,
            pipeline_trace TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # 4. Safe Schema Migration: Ensure user_id column exists if table was created in an earlier phase
    cursor.execute("PRAGMA table_info(analyses)")
    existing_columns = [col["name"] for col in cursor.fetchall()]
    if "user_id" not in existing_columns:
        cursor.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER REFERENCES users(id)")
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_id ON analyses(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_prediction ON analyses(prediction)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_threat_level ON analyses(threat_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_threat_score ON analyses(threat_score)")
    
    conn.commit()

def get_db_connection():
    """Establish a safe connection to the SQLite database with dict-like row access and schema verification."""
    active_path = _get_active_db_path()
    try:
        os.makedirs(os.path.dirname(active_path), exist_ok=True)
    except Exception:
        pass

    conn = sqlite3.connect(active_path, timeout=30.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000;")
    except Exception:
        pass
    conn.row_factory = sqlite3.Row

    # Self-healing: verify tables exist (crucial for ephemeral serverless /tmp filesystems)
    try:
        check_cursor = conn.cursor()
        check_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not check_cursor.fetchone():
            _create_tables(conn)
    except Exception:
        pass

    return conn

def init_db():
    """
    Initialize SQLite database schema and indexes on application startup.
    Ensures zero-config automatic creation and backward-compatible schema migrations.
    """
    conn = get_db_connection()
    _create_tables(conn)
    conn.close()

# =============================================================================
# USER AUTHENTICATION & MANAGEMENT
# =============================================================================

def create_user(name: str, email: str, password_hash: str = "") -> int:
    """
    Register a new user in the SQLite database.
    Returns the newly created user's primary key ID.
    Raises sqlite3.IntegrityError if email already exists.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (name, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        name.strip(),
        email.strip().lower(),
        password_hash or "",
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def get_user_by_email(email: str) -> dict:
    """
    Retrieve user record by email (case-insensitive).
    Returns dict containing id, name, email, password_hash, created_at or None.
    """
    if not email:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "password_hash": row["password_hash"],
            "created_at": str(row["created_at"])
        }
    return None

def get_user_by_id(user_id: int) -> dict:
    """
    Retrieve user record by primary key ID.
    Never exposes password_hash.
    """
    if not user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (int(user_id),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "created_at": str(row["created_at"])
        }
    return None

def get_user_by_oauth_identity(provider: str, provider_user_id: str) -> dict:
    """
    Retrieve user record by linked OAuth identity (provider + provider_user_id).
    Updates last_login_at timestamp if found.
    Returns user dict or None.
    """
    if not provider or not provider_user_id:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.name, u.email, u.created_at, oi.provider, oi.provider_user_id
        FROM users u
        JOIN oauth_identities oi ON u.id = oi.user_id
        WHERE LOWER(oi.provider) = LOWER(?) AND oi.provider_user_id = ?
    """, (provider.strip(), str(provider_user_id).strip()))
    row = cursor.fetchone()
    
    if row:
        user_id = row["id"]
        # Update last login timestamp for this identity
        cursor.execute("""
            UPDATE oauth_identities 
            SET last_login_at = ? 
            WHERE user_id = ? AND LOWER(provider) = LOWER(?)
        """, (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), user_id, provider.strip()))
        conn.commit()
        user_dict = {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "created_at": str(row["created_at"]),
            "provider": row["provider"],
            "provider_user_id": row["provider_user_id"]
        }
        conn.close()
        return user_dict
    conn.close()
    return None

def link_oauth_identity(user_id: int, provider: str, provider_user_id: str, email: str = None) -> int:
    """
    Link a social identity (provider + provider_user_id) to an existing user.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO oauth_identities (user_id, provider, provider_user_id, email, created_at, last_login_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider, provider_user_id) DO UPDATE SET
            user_id = excluded.user_id,
            email = excluded.email,
            last_login_at = excluded.last_login_at
    """, (
        int(user_id),
        provider.strip().lower(),
        str(provider_user_id).strip(),
        (email.strip().lower() if email else None),
        now_str,
        now_str
    ))
    identity_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return identity_id

def get_user_identities(user_id: int) -> list:
    """Retrieve all linked OAuth identities for a user."""
    if not user_id:
        return []
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, provider, provider_user_id, email, created_at, last_login_at
        FROM oauth_identities
        WHERE user_id = ?
        ORDER BY created_at ASC
    """, (int(user_id),))
    rows = cursor.fetchall()
    identities = [
        {
            "id": r["id"],
            "provider": r["provider"],
            "provider_user_id": r["provider_user_id"],
            "email": r["email"],
            "created_at": str(r["created_at"]),
            "last_login_at": str(r["last_login_at"])
        }
        for r in rows
    ]
    conn.close()
    return identities

def resolve_or_create_oauth_user(
    provider: str,
    provider_user_id: str,
    email: str = None,
    name: str = None,
    is_email_verified: bool = False
) -> tuple:
    """
    Deterministic Account Resolution & Linking Pipeline:
    1. Primary Lookup: Match by (provider, provider_user_id) in oauth_identities.
    2. Email Match & Linking: If verified email matches existing account in users, link identity.
    3. Auto-Registration: If no existing user, create local user and link identity.
    
    Returns: (user_dict, "existing_identity" | "linked_account" | "created_account")
    """
    provider = provider.strip().lower()
    provider_user_id = str(provider_user_id).strip()
    clean_email = email.strip().lower() if email else None
    
    # 1. Check if identity already linked
    existing_user = get_user_by_oauth_identity(provider, provider_user_id)
    if existing_user:
        return existing_user, "existing_identity"
    
    # 2. Check if verified email matches an existing local user account
    if clean_email and is_email_verified:
        matched_user = get_user_by_email(clean_email)
        if matched_user:
            # Link this social identity to the existing account
            link_oauth_identity(matched_user["id"], provider, provider_user_id, clean_email)
            return matched_user, "linked_account"
    
    # 3. Create new user
    display_name = (name or "").strip()
    if not display_name:
        if clean_email:
            display_name = clean_email.split("@")[0].replace(".", " ").title()
        else:
            display_name = f"{provider.capitalize()} User"
            
    # For email, if provider didn't return one, generate a placeholder
    account_email = clean_email or f"{provider}_{provider_user_id}@oauth.sentinel.local"
    
    # Ensure email uniqueness if collision occurs
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ? COLLATE NOCASE", (account_email,))
    if cursor.fetchone():
        account_email = f"{account_email.split('@')[0]}_{provider_user_id[:6]}@{account_email.split('@')[-1]}"
    conn.close()
    
    # Insert user (handle nullable password_hash)
    try:
        user_id = create_user(name=display_name, email=account_email, password_hash=None)
    except Exception:
        user_id = create_user(name=display_name, email=account_email, password_hash="")
        
    link_oauth_identity(user_id, provider, provider_user_id, clean_email)
    user_record = get_user_by_id(user_id)
    return user_record, "created_account"

# =============================================================================
# ANALYSES CRUD WITH PER-USER DATA ISOLATION
# =============================================================================

def row_to_analysis_dict(row) -> dict:
    """Convert SQLite row to clean analysis dictionary with deserialized JSON fields."""
    if not row:
        return None

    signals = json.loads(row["risk_signals"]) if row["risk_signals"] else []
    stats = json.loads(row["message_stats"]) if row["message_stats"] else {}
    terms = json.loads(row["highlight_terms"]) if row["highlight_terms"] else []
    tokens = json.loads(row["xray_tokens"]) if row["xray_tokens"] else []
    action = json.loads(row["recommended_action"]) if row["recommended_action"] else {}
    trace = json.loads(row["pipeline_trace"]) if row["pipeline_trace"] else {}

    if "character_count" in stats and "char_count" not in stats:
        stats["char_count"] = stats["character_count"]
    if "phone_number_count" in stats and "phone_count" not in stats:
        stats["phone_count"] = stats["phone_number_count"]

    created_str = str(row["created_at"])

    return {
        "id": row["id"],
        "user_id": row["user_id"] if "user_id" in row.keys() else None,
        "message": row["message"],
        "raw_message": row["message"],
        "prediction": row["prediction"],
        "confidence": row["confidence"],
        "threat_score": row["threat_score"],
        "threat_level": row["threat_level"],
        "is_spam": bool(row["is_spam"]),
        "risk_signals": signals,
        "signals": signals,
        "message_stats": stats,
        "highlight_terms": terms,
        "xray_tokens": tokens,
        "recommended_action": action,
        "pipeline_trace": trace,
        "created_at": created_str
    }

def save_analysis(result: dict, user_id: int = None) -> int:
    """
    Store a complete, successfully analyzed SMS record in SQLite.
    Associates the record with the authenticated user_id.
    Returns the auto-incremented primary key ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
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
    
    cursor.execute("""
        INSERT INTO analyses (
            user_id,
            message,
            prediction,
            confidence,
            threat_score,
            threat_level,
            is_spam,
            risk_signals,
            message_stats,
            highlight_terms,
            xray_tokens,
            recommended_action,
            pipeline_trace,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        raw_msg,
        pred,
        conf,
        threat_score,
        threat_lvl,
        is_spam,
        json.dumps(signals),
        json.dumps(stats),
        json.dumps(terms),
        json.dumps(tokens),
        json.dumps(action),
        json.dumps(trace),
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))
    
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return record_id

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
    Enforces maximum limit of 100 and orders newest first.
    """
    limit = min(max(1, int(limit)), 100)
    offset = max(0, int(offset))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    where_clauses = ["1=1"]
    params = []
    
    if user_id is not None:
        where_clauses.append("user_id = ?")
        params.append(int(user_id))
    
    if search:
        where_clauses.append("message LIKE ?")
        params.append(f"%{search.strip()}%")
        
    if risk_level and risk_level.upper() != "ALL":
        where_clauses.append("UPPER(threat_level) = ?")
        params.append(risk_level.upper())
        
    if prediction and prediction.upper() != "ALL":
        pred_clean = prediction.upper().strip()
        if pred_clean in ["SPAM", "1"]:
            where_clauses.append("is_spam = 1")
        elif pred_clean in ["HAM", "NOT SPAM", "NOT_SPAM", "0"]:
            where_clauses.append("is_spam = 0")
            
    where_sql = " AND ".join(where_clauses)
    
    cursor.execute(f"SELECT COUNT(*) as cnt FROM analyses WHERE {where_sql}", params)
    total_count = cursor.fetchone()["cnt"]
    
    query = f"SELECT * FROM analyses WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    query_params = list(params) + [limit, offset]
    
    cursor.execute(query, query_params)
    rows = cursor.fetchall()
    results = [row_to_analysis_dict(r) for r in rows]
    conn.close()
    
    return {
        "total": total_count,
        "records": results,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(results)) < total_count
    }

def get_analysis_by_id(record_id: int, user_id: int = None) -> dict:
    """
    Retrieve full analysis details for a single record by primary key.
    Enforces user data ownership to prevent Insecure Direct Object References (IDOR).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("SELECT * FROM analyses WHERE id = ? AND user_id = ?", (record_id, int(user_id)))
    else:
        cursor.execute("SELECT * FROM analyses WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_analysis_dict(row) if row else None

def delete_analysis(record_id: int, user_id: int = None) -> bool:
    """
    Delete a single analysis record by ID.
    Enforces user data ownership to prevent unauthorized deletion.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("DELETE FROM analyses WHERE id = ? AND user_id = ?", (record_id, int(user_id)))
    else:
        cursor.execute("DELETE FROM analyses WHERE id = ?", (record_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_analyses(user_id: int = None) -> bool:
    """Clear analyses for a given user (or all if user_id is None)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id is not None:
        cursor.execute("DELETE FROM analyses WHERE user_id = ?", (int(user_id),))
    else:
        cursor.execute("DELETE FROM analyses")
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='analyses'")
        except Exception:
            pass
    conn.commit()
    conn.close()
    return True

# =============================================================================
# REAL-TIME SQLITE ANALYTICAL AGGREGATIONS (USER-ISOLATED)
# =============================================================================

def get_total_stats(conn=None, user_id: int = None) -> dict:
    """Calculate total analyses count, spam count, not-spam count, and spam rate."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"""
        SELECT 
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
        {where_sql}
    """, params)
    row = cursor.fetchone()
    
    total = row["total"] or 0
    spam = row["spam"] or 0
    not_spam = row["not_spam"] or 0
    spam_rate = round((spam / total * 100), 1) if total > 0 else 0.0
    
    if close_conn:
        conn.close()
        
    return {
        "analyses": total,
        "spam": spam,
        "not_spam": not_spam,
        "spam_rate": spam_rate
    }

def get_threat_distribution(conn=None, user_id: int = None) -> dict:
    """
    Calculate threat distribution across documented score thresholds:
    0–33: Low Risk, 34–66: Medium Risk, 67–100: High Risk
    """
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"""
        SELECT
            COALESCE(SUM(CASE WHEN threat_score BETWEEN 0 AND 33 THEN 1 ELSE 0 END), 0) as low,
            COALESCE(SUM(CASE WHEN threat_score BETWEEN 34 AND 66 THEN 1 ELSE 0 END), 0) as medium,
            COALESCE(SUM(CASE WHEN threat_score >= 67 THEN 1 ELSE 0 END), 0) as high
        FROM analyses
        {where_sql}
    """, params)
    row = cursor.fetchone()
    
    dist = {
        "low": int(row["low"] or 0),
        "medium": int(row["medium"] or 0),
        "high": int(row["high"] or 0)
    }
    
    if close_conn:
        conn.close()
        
    return dist

def get_classification_distribution(conn=None, user_id: int = None) -> dict:
    """Calculate counts for SPAM vs NOT SPAM classification."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"""
        SELECT
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
        {where_sql}
    """, params)
    row = cursor.fetchone()
    
    dist = {
        "spam": int(row["spam"] or 0),
        "not_spam": int(row["not_spam"] or 0)
    }
    
    if close_conn:
        conn.close()
        
    return dist

def get_activity_data(conn=None, user_id: int = None) -> list:
    """Group analysis activity chronologically by date."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"""
        SELECT 
            SUBSTR(created_at, 1, 10) as scan_date,
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
        {where_sql}
        GROUP BY scan_date
        ORDER BY scan_date ASC
        LIMIT 14
    """, params)
    rows = cursor.fetchall()
    
    timeline = [
        {
            "date": r["scan_date"],
            "total": int(r["total"] or 0),
            "spam": int(r["spam"] or 0),
            "not_spam": int(r["not_spam"] or 0)
        }
        for r in rows
    ]
    
    if close_conn:
        conn.close()
        
    return timeline

def get_risk_indicator_counts(conn=None, user_id: int = None) -> list:
    """
    Aggregate frequencies of stored risk indicators across actual database analyses.
    """
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE risk_signals IS NOT NULL AND user_id = ?" if user_id is not None else "WHERE risk_signals IS NOT NULL"
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"SELECT risk_signals FROM analyses {where_sql}", params)
    rows = cursor.fetchall()
    
    signal_counts = {}
    signal_types = {}
    
    for r in rows:
        try:
            sigs = json.loads(r["risk_signals"]) if r["risk_signals"] else []
            seen_in_message = set()
            for s in sigs:
                label = s.get("label") or "Unknown"
                sig_type = s.get("type") or "signal"
                if label not in seen_in_message:
                    seen_in_message.add(label)
                    signal_counts[label] = signal_counts.get(label, 0) + 1
                    signal_types[label] = sig_type
        except Exception:
            continue
            
    sorted_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)
    
    indicators = [
        {
            "type": signal_types.get(k, "signal"),
            "label": k,
            "count": v
        }
        for k, v in sorted_signals
    ]
    
    if close_conn:
        conn.close()
        
    return indicators

def get_average_metrics(conn=None, user_id: int = None) -> dict:
    """Calculate actual average model confidence and average threat score from SQLite."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id),) if user_id is not None else ()
    
    cursor.execute(f"""
        SELECT
            COUNT(*) as total,
            COALESCE(AVG(confidence), 0.0) as avg_confidence,
            COALESCE(AVG(threat_score), 0.0) as avg_threat_score
        FROM analyses
        {where_sql}
    """, params)
    row = cursor.fetchone()
    
    total = row["total"] or 0
    if total == 0:
        res = {"confidence": 0.0, "threat_score": 0.0}
    else:
        avg_conf = float(row["avg_confidence"] or 0.0)
        if 0.0 < avg_conf <= 1.0:
            avg_conf = avg_conf * 100.0
        avg_threat = float(row["avg_threat_score"] or 0.0)
        
        res = {
            "confidence": round(avg_conf, 1),
            "threat_score": round(avg_threat, 1)
        }
        
    if close_conn:
        conn.close()
        
    return res

def get_recent_activity(limit: int = 8, conn=None, user_id: int = None) -> list:
    """Retrieve latest analyses for the recent activity stream."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    where_sql = "WHERE user_id = ?" if user_id is not None else ""
    params = (int(user_id), limit) if user_id is not None else (limit,)
    
    cursor.execute(f"""
        SELECT id, message, prediction, threat_level, threat_score, confidence, is_spam, created_at
        FROM analyses
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """, params)
    rows = cursor.fetchall()
    
    recent = []
    for r in rows:
        conf = float(r["confidence"] or 0.0)
        if 0.0 < conf <= 1.0:
            conf = round(conf * 100.0, 1)
        else:
            conf = round(conf, 1)
            
        recent.append({
            "id": r["id"],
            "message": r["message"],
            "prediction": r["prediction"],
            "threat_level": r["threat_level"],
            "threat_score": r["threat_score"],
            "confidence": conf,
            "is_spam": bool(r["is_spam"]),
            "created_at": str(r["created_at"])
        })
        
    if close_conn:
        conn.close()
        
    return recent

def get_insights_data(user_id: int = None) -> dict:
    """
    Compile complete real-time Insights payload strictly from SQLite.
    Filtered by user_id for strict data isolation.
    """
    conn = get_db_connection()
    
    totals = get_total_stats(conn, user_id=user_id)
    has_data = totals["analyses"] > 0
    
    threat_dist = get_threat_distribution(conn, user_id=user_id)
    class_dist = get_classification_distribution(conn, user_id=user_id)
    activity = get_activity_data(conn, user_id=user_id)
    risk_indicators = get_risk_indicator_counts(conn, user_id=user_id)
    averages = get_average_metrics(conn, user_id=user_id)
    recent = get_recent_activity(limit=8, conn=conn, user_id=user_id)
    
    conn.close()
    
    return {
        "has_data": has_data,
        "totals": totals,
        "threat_distribution": threat_dist,
        "classification_distribution": class_dist,
        "activity": activity,
        "risk_indicators": risk_indicators,
        "averages": averages,
        "recent": recent,
        # Flat legacy convenience fields for dashboard bindings
        "total_analyzed": totals["analyses"],
        "spam_detected": totals["spam"],
        "legitimate_detected": totals["not_spam"],
        "spam_rate": totals["spam_rate"],
        "avg_threat_score": averages["threat_score"],
        "avg_confidence": averages["confidence"],
        "timeline": activity,
        "risk_distribution": threat_dist,
        "top_signals": risk_indicators,
        "recent_incidents": recent
    }

# Backward compatibility aliases
save_investigation = save_analysis
get_investigation_by_id = get_analysis_by_id
delete_investigation = delete_analysis
clear_investigations = clear_analyses

def get_investigations(search: str = "", risk_filter: str = "ALL", type_filter: str = "ALL", limit: int = 50, offset: int = 0, user_id: int = None) -> list:
    res = get_analyses(search=search, risk_level=risk_filter, prediction=type_filter, limit=limit, offset=offset, user_id=user_id)
    return res["records"]

# Auto-initialize table schema on import
init_db()
