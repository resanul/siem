"""
OpenSOC Forge - RSA NetWitness 30-Day Telemetry & Session Storage.
Provides SQLite WAL-mode persistent storage, high-throughput batch ingestion,
fast indexed B-Tree search, automated 30-day rolling retention pruning,
and security alert filtering for enterprise NetWitness cluster logs and network sessions.
"""

import os
import sqlite3
import time
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("netwitness_storage")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DATA_DIR = os.path.join(REPO_ROOT, "data")
DEFAULT_DB_PATH = os.path.join(DATA_DIR, "netwitness_telemetry.db")
SYSTEM_DB_PATH = "/opt/opensoc-forge/data/netwitness_telemetry.db"


def _get_db_path() -> str:
    """Returns optimal writable database path on the 273GB root partition."""
    candidates = [SYSTEM_DB_PATH, DEFAULT_DB_PATH, "/tmp/netwitness_telemetry.db"]
    for path in candidates:
        parent = os.path.dirname(path)
        try:
            if not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            test_file = os.path.join(parent, ".nw_db_test")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            return path
        except Exception:
            continue
    return "/tmp/netwitness_telemetry.db"


def get_db_connection() -> sqlite3.Connection:
    """Opens a SQLite connection with WAL mode and optimal caching for high-speed SIEM querying."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -64000;")  # 64MB cache
        conn.execute("PRAGMA temp_store = MEMORY;")
    except Exception:
        pass
    return conn


def init_storage() -> None:
    """Initializes tables and high-speed B-Tree indexes for NetWitness 30-day telemetry."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS netwitness_events (
                    session_id TEXT NOT NULL,
                    endpoint_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    epoch_time INTEGER NOT NULL,
                    device_type TEXT DEFAULT 'unknown',
                    device_class TEXT DEFAULT 'unknown',
                    device_ip TEXT DEFAULT '',
                    device_host TEXT DEFAULT '',
                    source_ip TEXT DEFAULT '',
                    destination_ip TEXT DEFAULT '',
                    destination_port TEXT DEFAULT '',
                    action TEXT DEFAULT 'LOGGED',
                    user TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    severity TEXT DEFAULT 'LOW',
                    is_alert INTEGER DEFAULT 0,
                    raw_metas TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, endpoint_type)
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_epoch ON netwitness_events(epoch_time);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_endpoint_type ON netwitness_events(endpoint_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_device_type ON netwitness_events(device_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_action ON netwitness_events(action);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_is_alert ON netwitness_events(is_alert);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_source_ip ON netwitness_events(source_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nw_device_ip ON netwitness_events(device_ip);")
    except Exception as e:
        logger.error(f"Failed to initialize NetWitness database: {e}")
    finally:
        conn.close()


def _is_suspicious_event(ev: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluates whether an authentic NetWitness event is a genuine security alert or routine background noise.
    Filters out 'System.Normal Conditions' and normal traffic, while tagging real security warnings.
    """
    desc = str(ev.get("description") or "").lower()
    action = str(ev.get("action") or "").upper()
    dev_type = str(ev.get("device_type") or "").lower()

    # Explicit benign suppression
    if "normal condition" in desc or "system.normal" in desc:
        return False, "INFO"

    # Attack indicators / Warning patterns
    high_keywords = [
        "fail", "denied", "deny", "block", "drop", "unauthorized",
        "violation", "brute", "attack", "malware", "exploit", "cve",
        "rst", "tear", "scan", "flood", "spoof", "overflow", "rejected"
    ]
    for kw in high_keywords:
        if kw in desc or kw in action.lower():
            if "fail" in kw or "deny" in kw or "drop" in kw:
                return True, "HIGH"
            return True, "MEDIUM"

    if action in ("DENIED", "BLOCKED", "DROPPED", "FAILED", "REJECTED"):
        return True, "HIGH"

    if "firewall" in dev_type or "ciscoasa" in dev_type or "checkpoint" in dev_type:
        if "teardown" not in desc and "build" not in desc:
            return True, "MEDIUM"

    return False, "LOW"


def insert_events(events: List[Dict[str, Any]]) -> int:
    """
    Batch inserts or updates NetWitness events into persistent SQLite storage.
    Automatically assigns security severity, alert flags, and epoch timestamps.
    """
    if not events:
        return 0

    init_storage()
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    inserted_count = 0

    try:
        with conn:
            cursor = conn.cursor()
            for ev in events:
                sid = str(ev.get("session_id") or "")
                if not sid:
                    continue

                etype = str(ev.get("endpoint_type") or "log").lower()
                ts_str = str(ev.get("timestamp") or now_iso)

                # Parse epoch time
                epoch_time = int(time.time())
                try:
                    clean_ts = ts_str.replace("Z", "+00:00")
                    if len(clean_ts) >= 5 and clean_ts[-5] in ("+", "-") and clean_ts[-3] != ":":
                        clean_ts = clean_ts[:-2] + ":" + clean_ts[-2:]
                    dt = datetime.fromisoformat(clean_ts)
                    epoch_time = int(dt.timestamp())
                except Exception:
                    pass

                # Detect alert-worthiness
                is_alert, auto_sev = _is_suspicious_event(ev)
                severity = ev.get("severity") or auto_sev

                raw_metas = ev.get("raw_metas") or ev.get("metas") or {}
                if isinstance(raw_metas, (dict, list)):
                    raw_metas_str = json.dumps(raw_metas)
                else:
                    raw_metas_str = str(raw_metas)

                cursor.execute("""
                    INSERT INTO netwitness_events (
                        session_id, endpoint_type, timestamp, epoch_time,
                        device_type, device_class, device_ip, device_host,
                        source_ip, destination_ip, destination_port,
                        action, user, description, severity, is_alert,
                        raw_metas, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id, endpoint_type) DO UPDATE SET
                        timestamp = excluded.timestamp,
                        epoch_time = excluded.epoch_time,
                        description = excluded.description,
                        action = excluded.action,
                        severity = excluded.severity,
                        is_alert = excluded.is_alert,
                        raw_metas = excluded.raw_metas;
                """, (
                    sid,
                    etype,
                    ts_str,
                    epoch_time,
                    str(ev.get("device_type") or "unknown"),
                    str(ev.get("device_class") or "unknown"),
                    str(ev.get("device_ip") or ""),
                    str(ev.get("device_host") or ""),
                    str(ev.get("source_ip") or ""),
                    str(ev.get("destination_ip") or ""),
                    str(ev.get("destination_port") or ""),
                    str(ev.get("action") or "LOGGED"),
                    str(ev.get("user") or ""),
                    str(ev.get("description") or ""),
                    str(severity),
                    1 if is_alert else 0,
                    raw_metas_str,
                    now_iso
                ))
                inserted_count += 1
    except Exception as e:
        logger.error(f"Error inserting NetWitness batch: {e}")
    finally:
        conn.close()

    return inserted_count


def query_events(
    endpoint_type: Optional[str] = None,
    hours: int = 720,  # 30 days default
    limit: int = 50,
    offset: int = 0,
    search: str = "",
    device_type: str = "",
    is_alert_only: bool = False
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Executes fast indexed queries against 30 days of stored NetWitness events.
    Supports filtering by endpoint_type, time range, full text search, device_type, and alert level.
    """
    init_storage()
    conn = get_db_connection()
    events: List[Dict[str, Any]] = []
    total_count = 0

    now_epoch = int(time.time())
    from_epoch = now_epoch - (max(1, hours) * 3600)

    where_clauses = ["epoch_time >= ?"]
    params: List[Any] = [from_epoch]

    if endpoint_type and endpoint_type in ("log", "network"):
        where_clauses.append("endpoint_type = ?")
        params.append(endpoint_type)

    if device_type:
        where_clauses.append("device_type LIKE ?")
        params.append(f"%{device_type}%")

    if is_alert_only:
        where_clauses.append("is_alert = 1")

    if search and search.strip():
        term = f"%{search.strip()}%"
        where_clauses.append("(description LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR device_ip LIKE ? OR user LIKE ?)")
        params.extend([term, term, term, term, term])

    where_str = " AND ".join(where_clauses)

    try:
        # Count total matching rows
        count_cursor = conn.cursor()
        count_cursor.execute(f"SELECT COUNT(*) FROM netwitness_events WHERE {where_str};", params)
        row = count_cursor.fetchone()
        if row:
            total_count = row[0]

        # Fetch paginated rows ordered by newest first
        query_sql = f"""
            SELECT * FROM netwitness_events
            WHERE {where_str}
            ORDER BY epoch_time DESC, session_id DESC
            LIMIT ? OFFSET ?;
        """
        query_params = params + [max(1, min(limit, 500)), max(0, offset)]
        cursor = conn.cursor()
        cursor.execute(query_sql, query_params)

        for r in cursor.fetchall():
            raw_metas = {}
            try:
                if r["raw_metas"]:
                    raw_metas = json.loads(r["raw_metas"])
            except Exception:
                pass

            events.append({
                "session_id": r["session_id"],
                "endpoint_type": r["endpoint_type"],
                "timestamp": r["timestamp"],
                "source": "RSA NetWitness SIEM",
                "device_type": r["device_type"],
                "device_class": r["device_class"],
                "device_ip": r["device_ip"],
                "device_host": r["device_host"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "destination_port": r["destination_port"],
                "action": r["action"],
                "user": r["user"],
                "description": r["description"],
                "severity": r["severity"],
                "is_alert": bool(r["is_alert"]),
                "raw_metas": raw_metas,
                "created_at": r["created_at"]
            })
    except Exception as e:
        logger.error(f"Error querying NetWitness events: {e}")
    finally:
        conn.close()

    return events, total_count


def get_storage_stats() -> Dict[str, Any]:
    """Returns database size, record count, 30-day retention boundaries, and breakdown."""
    init_storage()
    conn = get_db_connection()
    stats = {
        "status": "ACTIVE",
        "retention_days": 30,
        "total_records": 0,
        "log_records": 0,
        "network_records": 0,
        "security_alerts": 0,
        "earliest_timestamp": None,
        "latest_timestamp": None,
        "db_size_mb": 0.0,
        "db_path": _get_db_path()
    }

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN endpoint_type = 'log' THEN 1 ELSE 0 END) as logs,
                SUM(CASE WHEN endpoint_type = 'network' THEN 1 ELSE 0 END) as nets,
                SUM(CASE WHEN is_alert = 1 THEN 1 ELSE 0 END) as alerts,
                MIN(timestamp) as earliest,
                MAX(timestamp) as latest
            FROM netwitness_events;
        """)
        row = cursor.fetchone()
        if row and row["total"]:
            stats["total_records"] = row["total"] or 0
            stats["log_records"] = row["logs"] or 0
            stats["network_records"] = row["nets"] or 0
            stats["security_alerts"] = row["alerts"] or 0
            stats["earliest_timestamp"] = row["earliest"]
            stats["latest_timestamp"] = row["latest"]

        # Calculate DB file size
        db_path = _get_db_path()
        if os.path.exists(db_path):
            stats["db_size_mb"] = round(os.path.getsize(db_path) / (1024 * 1024), 2)
    except Exception as e:
        logger.error(f"Error fetching storage stats: {e}")
    finally:
        conn.close()

    return stats


def enforce_retention(retention_days: int = 30) -> int:
    """
    Purges NetWitness records older than the configured rolling retention period (default 30 days).
    Guarantees storage remains bounded and within disk quota.
    """
    init_storage()
    conn = get_db_connection()
    purged_count = 0
    cutoff_epoch = int(time.time()) - (max(1, retention_days) * 86400)

    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM netwitness_events WHERE epoch_time < ?;", (cutoff_epoch,))
            purged_count = cursor.rowcount
            if purged_count > 0:
                logger.info(f"NetWitness retention policy enforced: purged {purged_count} records older than {retention_days} days.")
    except Exception as e:
        logger.error(f"Error enforcing NetWitness retention policy: {e}")
    finally:
        conn.close()

    return purged_count
