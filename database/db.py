"""
SMS SENTINEL - SQLite Database Layer (Phase 6 & 7)
Provides lightweight persistent storage, indexing, retrieval, and
real-time SQL aggregation for SMS threat analyses and telemetry insights.
"""

import os
import sqlite3
import json
from datetime import datetime

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "spamshield.db")

def _get_active_db_path():
    """Resolve database path, using /tmp on serverless environments where local filesystem is read-only."""
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return os.path.join("/tmp", "spamshield.db")
    return DEFAULT_DB_PATH

DB_PATH = _get_active_db_path()

def get_db_connection():
    """Establish a safe connection to the SQLite database with dict-like row access."""
    active_path = _get_active_db_path()
    try:
        os.makedirs(os.path.dirname(active_path), exist_ok=True)
    except Exception:
        pass
    conn = sqlite3.connect(active_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initialize SQLite database schema and indexes on application startup.
    Ensures zero-config automatic creation on clean installations.
    """
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_prediction ON analyses(prediction)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_threat_level ON analyses(threat_level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analyses_threat_score ON analyses(threat_score)")
    
    conn.commit()
    conn.close()

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

def save_analysis(result: dict) -> int:
    """
    Store a complete, successfully analyzed SMS record in SQLite.
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
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
    offset: int = 0
) -> dict:
    """
    Retrieve stored analyses with search, filtering, and pagination.
    Enforces maximum limit of 100 and orders newest first.
    """
    limit = min(max(1, int(limit)), 100)
    offset = max(0, int(offset))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    where_clauses = ["1=1"]
    params = []
    
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

def get_analysis_by_id(record_id: int) -> dict:
    """Retrieve full analysis details for a single record by primary key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row_to_analysis_dict(row) if row else None

def delete_analysis(record_id: int) -> bool:
    """Delete a single analysis record by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE id = ?", (record_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def clear_analyses() -> bool:
    """Clear all analysis records and reset sequence."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses")
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='analyses'")
    except Exception:
        pass
    conn.commit()
    conn.close()
    return True

# =============================================================================
# PHASE 7 — REAL-TIME SQLITE ANALYTICAL AGGREGATIONS
# =============================================================================

def get_total_stats(conn=None) -> dict:
    """Calculate total analyses count, spam count, not-spam count, and spam rate."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
    """)
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

def get_threat_distribution(conn=None) -> dict:
    """
    Calculate threat distribution across documented score thresholds:
    0–33: Low Risk
    34–66: Medium Risk
    67–100: High Risk
    """
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            COALESCE(SUM(CASE WHEN threat_score BETWEEN 0 AND 33 THEN 1 ELSE 0 END), 0) as low,
            COALESCE(SUM(CASE WHEN threat_score BETWEEN 34 AND 66 THEN 1 ELSE 0 END), 0) as medium,
            COALESCE(SUM(CASE WHEN threat_score >= 67 THEN 1 ELSE 0 END), 0) as high
        FROM analyses
    """)
    row = cursor.fetchone()
    
    dist = {
        "low": int(row["low"] or 0),
        "medium": int(row["medium"] or 0),
        "high": int(row["high"] or 0)
    }
    
    if close_conn:
        conn.close()
        
    return dist

def get_classification_distribution(conn=None) -> dict:
    """Calculate counts for SPAM vs NOT SPAM classification."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
    """)
    row = cursor.fetchone()
    
    dist = {
        "spam": int(row["spam"] or 0),
        "not_spam": int(row["not_spam"] or 0)
    }
    
    if close_conn:
        conn.close()
        
    return dist

def get_activity_data(conn=None) -> list:
    """Group analysis activity chronologically by date."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            SUBSTR(created_at, 1, 10) as scan_date,
            COUNT(*) as total,
            COALESCE(SUM(CASE WHEN is_spam = 1 THEN 1 ELSE 0 END), 0) as spam,
            COALESCE(SUM(CASE WHEN is_spam = 0 THEN 1 ELSE 0 END), 0) as not_spam
        FROM analyses
        GROUP BY scan_date
        ORDER BY scan_date ASC
        LIMIT 14
    """)
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

def get_risk_indicator_counts(conn=None) -> list:
    """
    Aggregate frequencies of stored risk indicators across actual database analyses.
    Represents the number of analyses containing each specific indicator.
    """
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("SELECT risk_signals FROM analyses WHERE risk_signals IS NOT NULL")
    rows = cursor.fetchall()
    
    signal_counts = {}
    signal_types = {}
    
    for r in rows:
        try:
            sigs = json.loads(r["risk_signals"]) if r["risk_signals"] else []
            # Count each indicator once per message
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

def get_average_metrics(conn=None) -> dict:
    """Calculate actual average model confidence and average threat score from SQLite."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            COUNT(*) as total,
            COALESCE(AVG(confidence), 0.0) as avg_confidence,
            COALESCE(AVG(threat_score), 0.0) as avg_threat_score
        FROM analyses
    """)
    row = cursor.fetchone()
    
    total = row["total"] or 0
    if total == 0:
        res = {"confidence": 0.0, "threat_score": 0.0}
    else:
        avg_conf = float(row["avg_confidence"] or 0.0)
        # Normalize if confidence is recorded as a decimal (<= 1.0)
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

def get_recent_activity(limit: int = 8, conn=None) -> list:
    """Retrieve latest 5-10 analyses for the recent activity stream."""
    close_conn = False
    if conn is None:
        conn = get_db_connection()
        close_conn = True
        
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, message, prediction, threat_level, threat_score, confidence, is_spam, created_at
        FROM analyses
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
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

def get_insights_data() -> dict:
    """
    Compile complete real-time Insights payload strictly from SQLite.
    Includes both the Phase 7 contract schema and backwards-compatible fields.
    """
    conn = get_db_connection()
    
    totals = get_total_stats(conn)
    has_data = totals["analyses"] > 0
    
    threat_dist = get_threat_distribution(conn)
    class_dist = get_classification_distribution(conn)
    activity = get_activity_data(conn)
    risk_indicators = get_risk_indicator_counts(conn)
    averages = get_average_metrics(conn)
    recent = get_recent_activity(limit=8, conn=conn)
    
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
        # Legacy/convenience flat fields for existing frontend telemetry bindings
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

def get_investigations(search: str = "", risk_filter: str = "ALL", type_filter: str = "ALL", limit: int = 50, offset: int = 0) -> list:
    res = get_analyses(search=search, risk_level=risk_filter, prediction=type_filter, limit=limit, offset=offset)
    return res["records"]

# Auto-initialize table schema on import
init_db()
