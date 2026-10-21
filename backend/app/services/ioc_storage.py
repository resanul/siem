"""
OpenSOC Forge - Persistent Offline Threat Intelligence IOC Database.
Stores all collected indicators in a local SQLite database for full offline
availability, indexing, fast search, and automated snapshot exports.
"""

import os
import json
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

DB_PERSISTENT_FILE = "/var/lib/opensoc/threat_intel_iocs.db"
DB_DEFAULT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "threat_intel_iocs.db")
DB_TEMP_FILE = "/tmp/threat_intel_iocs.db"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
EXPORT_JSON_FILE = os.path.join(REPO_ROOT, "data", "threat_intel_iocs.json")
BACKEND_DATA_JSON = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "threat_intel_iocs.json")

TALOS_SEED_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cisco_talos_iocs.json")


def _get_db_path() -> str:
    for candidate in [DB_PERSISTENT_FILE, DB_DEFAULT_FILE, DB_TEMP_FILE]:
        parent = os.path.dirname(candidate)
        try:
            if not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            # test writeability
            with open(os.path.join(parent, ".test_db"), "w") as f:
                f.write("ok")
            os.remove(os.path.join(parent, ".test_db"))
            return candidate
        except Exception:
            continue
    return DB_TEMP_FILE


def init_ioc_database() -> str:
    """Initializes tables and indexes for offline IOC storage."""
    db_path = _get_db_path()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                indicator TEXT PRIMARY KEY,
                type TEXT,
                reputation TEXT,
                confidence INTEGER,
                threat_actor TEXT,
                malware_family TEXT,
                source TEXT,
                first_seen TEXT,
                last_seen TEXT,
                ransomware_use TEXT,
                cvss_score TEXT,
                status TEXT,
                description TEXT,
                updated_at TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs (source)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs (type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_iocs_updated_at ON iocs (updated_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs (malware_family)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS github_sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_time TEXT,
                total_iocs INTEGER,
                action TEXT,
                commit_sha TEXT,
                status TEXT,
                message TEXT
            )
        """)
        conn.commit()

        # Auto-import latest threat intelligence dataset from Git if database has fewer IOCs
        c.execute("SELECT COUNT(*) FROM iocs")
        count = c.fetchone()[0]

        dataset_candidates = [
            EXPORT_JSON_FILE,
            BACKEND_DATA_JSON,
            os.path.join(REPO_ROOT, "data", "threat_intel_iocs.json"),
            "/opt/opensoc-forge/data/threat_intel_iocs.json",
            "/home/resanul/siem/data/threat_intel_iocs.json",
            "data/threat_intel_iocs.json"
        ]
        target_dataset = next((p for p in dataset_candidates if p and os.path.exists(p)), None)

        if target_dataset:
            try:
                with open(target_dataset, "r", encoding="utf-8") as f:
                    header = f.read(1024)
                    import re
                    m = re.search(r'"total_indicators":\s*(\d+)', header)
                    expected_total = int(m.group(1)) if m else 0
                    if expected_total > count or count == 0:
                        f.seek(0)
                        ds = json.load(f)
                        raw_items = ds.get("indicators", [])
                        if raw_items:
                            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            records = []
                            for item in raw_items:
                                ind = item.get("indicator")
                                if not ind:
                                    continue
                                records.append((
                                    str(ind).strip(),
                                    str(item.get("type", "IOC")),
                                    str(item.get("reputation", "MALICIOUS")),
                                    int(item.get("confidence", 90) or 90),
                                    str(item.get("threat_actor", "") or "Unknown"),
                                    str(item.get("malware_family", "") or "Unknown Malware"),
                                    str(item.get("source", "Threat Feed")),
                                    str(item.get("first_seen", "") or now_str),
                                    str(item.get("last_seen", "") or now_str),
                                    str(item.get("ransomware_use", "Unknown")),
                                    str(item.get("cvss_score", "MALICIOUS")),
                                    str(item.get("status", "ACTIVE")),
                                    str(item.get("description", "")),
                                    now_str
                                ))
                            c.executemany("""
                                INSERT INTO iocs (
                                    indicator, type, reputation, confidence, threat_actor, malware_family,
                                    source, first_seen, last_seen, ransomware_use, cvss_score, status,
                                    description, updated_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(indicator) DO UPDATE SET
                                    type=excluded.type,
                                    reputation=excluded.reputation,
                                    confidence=excluded.confidence,
                                    threat_actor=excluded.threat_actor,
                                    malware_family=excluded.malware_family,
                                    source=excluded.source,
                                    last_seen=excluded.last_seen,
                                    ransomware_use=excluded.ransomware_use,
                                    cvss_score=excluded.cvss_score,
                                    status=excluded.status,
                                    description=excluded.description,
                                    updated_at=excluded.updated_at
                            """, records)
                            conn.commit()
            except Exception as e:
                print(f"Error auto-syncing dataset: {e}")

        # Seed initial Talos data if database is empty and no dataset found
        c.execute("SELECT COUNT(*) FROM iocs")
        count = c.fetchone()[0]
        if count == 0 and os.path.exists(TALOS_SEED_FILE):
            try:
                with open(TALOS_SEED_FILE, "r", encoding="utf-8") as f:
                    seed_iocs = json.load(f)
                    if isinstance(seed_iocs, list) and len(seed_iocs) > 0:
                        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                        records = []
                        for item in seed_iocs:
                            ind = item.get("indicator")
                            if not ind:
                                continue
                            records.append((
                                ind,
                                item.get("type", "IOC"),
                                item.get("reputation", "MALICIOUS"),
                                item.get("confidence", 100),
                                item.get("threat_actor", "Cisco Talos Intelligence"),
                                item.get("malware_family", "Cisco Talos Feed"),
                                item.get("source", "Cisco Talos"),
                                item.get("last_seen", ""),
                                item.get("last_seen", ""),
                                item.get("ransomware_use", "Targeted Campaign"),
                                item.get("cvss_score", "100% CONFIRMED"),
                                item.get("status", "ACTIVE IOC"),
                                item.get("description", "Cisco Talos Intelligence"),
                                now_str
                            ))
                        c.executemany("""
                            INSERT OR IGNORE INTO iocs (
                                indicator, type, reputation, confidence, threat_actor, malware_family,
                                source, first_seen, last_seen, ransomware_use, cvss_score, status,
                                description, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, records)
                        conn.commit()
            except Exception:
                pass

        conn.close()
    except Exception as e:
        print(f"Error initializing IOC database: {e}")

    return db_path


def save_iocs_to_db(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Saves a batch of IOCs into the offline SQLite database.
    Updates existing indicators and inserts new ones.
    Exports snapshot to data/threat_intel_iocs.json.
    """
    if not items:
        return {"saved": 0, "total": get_total_ioc_count(), "new": 0}

    db_path = init_ioc_database()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    records = []
    for item in items:
        ind = item.get("indicator")
        if not ind:
            continue
        records.append((
            str(ind).strip(),
            str(item.get("type", "IOC")),
            str(item.get("reputation", "MALICIOUS")),
            int(item.get("confidence", 90) or 90),
            str(item.get("threat_actor", "") or "Unknown"),
            str(item.get("malware_family", "") or "Unknown Malware"),
            str(item.get("source", "Live Feed")),
            str(item.get("first_seen", "") or now_str),
            str(item.get("last_seen", "") or now_str),
            str(item.get("ransomware_use", "Unknown")),
            str(item.get("cvss_score", "MALICIOUS")),
            str(item.get("status", "ACTIVE")),
            str(item.get("description", "")),
            now_str
        ))

    saved_count = 0
    total_count = 0
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.executemany("""
            INSERT INTO iocs (
                indicator, type, reputation, confidence, threat_actor, malware_family,
                source, first_seen, last_seen, ransomware_use, cvss_score, status,
                description, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                type=excluded.type,
                reputation=excluded.reputation,
                confidence=excluded.confidence,
                threat_actor=excluded.threat_actor,
                malware_family=excluded.malware_family,
                source=excluded.source,
                last_seen=excluded.last_seen,
                ransomware_use=excluded.ransomware_use,
                cvss_score=excluded.cvss_score,
                status=excluded.status,
                description=excluded.description,
                updated_at=excluded.updated_at
        """, records)
        saved_count = len(records)
        conn.commit()

        c.execute("SELECT COUNT(*) FROM iocs")
        total_count = c.fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"Error saving IOCs to database: {e}")

    # Export snapshot to JSON file for GitHub backup
    export_iocs_snapshot()

    return {"saved": saved_count, "total": total_count}


def query_offline_iocs(
    source: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 250,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """Queries indicators directly from offline SQLite database."""
    db_path = init_ioc_database()
    results = []
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        query = "SELECT * FROM iocs"
        conditions = []
        params = []

        if source and source != "ALL":
            conditions.append("source LIKE ?")
            params.append(f"%{source}%")

        if search and search.strip():
            q = f"%{search.strip().lower()}%"
            conditions.append("(LOWER(indicator) LIKE ? OR LOWER(malware_family) LIKE ? OR LOWER(threat_actor) LIKE ? OR LOWER(description) LIKE ?)")
            params.extend([q, q, q, q])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        c.execute(query, params)
        for row in c.fetchall():
            results.append(dict(row))
        conn.close()
    except Exception as e:
        print(f"Error querying offline IOCs: {e}")

    return results


def get_total_ioc_count() -> int:
    """Returns total number of stored offline indicators."""
    db_path = init_ioc_database()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM iocs")
        cnt = c.fetchone()[0]
        conn.close()
        return cnt
    except Exception:
        return 0


def get_offline_db_stats() -> Dict[str, Any]:
    """Returns comprehensive statistics about offline stored indicators."""
    db_path = init_ioc_database()
    stats = {
        "total_iocs": 0,
        "database_path": db_path,
        "database_size_bytes": os.path.getsize(db_path) if os.path.exists(db_path) else 0,
        "by_source": {},
        "by_type": {},
        "last_updated": None,
        "last_github_sync": None
    }
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM iocs")
        stats["total_iocs"] = c.fetchone()[0]

        c.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC")
        for src, cnt in c.fetchall():
            stats["by_source"][src] = cnt

        c.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY COUNT(*) DESC LIMIT 8")
        for tp, cnt in c.fetchall():
            stats["by_type"][tp] = cnt

        c.execute("SELECT MAX(updated_at) FROM iocs")
        max_dt = c.fetchone()[0]
        stats["last_updated"] = max_dt

        # Check last GitHub sync
        c.execute("SELECT sync_time, total_iocs, action, commit_sha, status, message FROM github_sync_log ORDER BY id DESC LIMIT 1")
        last_log = c.fetchone()
        if last_log:
            stats["last_github_sync"] = {
                "sync_time": last_log[0],
                "total_iocs": last_log[1],
                "action": last_log[2],
                "commit_sha": last_log[3],
                "status": last_log[4],
                "message": last_log[5]
            }

        conn.close()
    except Exception as e:
        print(f"Error fetching DB stats: {e}")

    return stats


def export_iocs_snapshot(limit: int = 50000) -> str:
    """Exports indexed IOCs to data/threat_intel_iocs.json for GitHub sync and backup."""
    db_path = init_ioc_database()
    items = []
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator, type, reputation, confidence, threat_actor, malware_family, source, last_seen, ransomware_use, cvss_score, status, description FROM iocs ORDER BY updated_at DESC LIMIT ?", (limit,))
        for row in c.fetchall():
            items.append(dict(row))
        conn.close()
    except Exception:
        pass

    if not items:
        return ""

    payload = {
        "metadata": {
            "title": "OpenSOC Forge Threat Intelligence Indicators Dataset",
            "source_platforms": [
                "Cyble Vision (Dark Web & Threat Intel)",
                "abuse.ch ThreatFox",
                "abuse.ch URLhaus",
                "abuse.ch Feodo Tracker",
                "abuse.ch MalwareBazaar",
                "AlienVault OTX",
                "Proofpoint Emerging Threats",
                "CISA KEV",
                "Cisco Talos"
            ],
            "total_indicators": len(items),
            "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "schema_version": "1.0"
        },
        "indicators": items
    }

    target_files = [EXPORT_JSON_FILE, BACKEND_DATA_JSON]
    for target in target_files:
        try:
            if os.path.exists(target):
                # Safety guard: never downgrade a larger dataset file on disk
                try:
                    with open(target, "r", encoding="utf-8") as existing_f:
                        head = existing_f.read(1024)
                        import re
                        m = re.search(r'"total_indicators":\s*(\d+)', head)
                        if m and int(m.group(1)) > len(items):
                            continue
                except Exception:
                    pass
            parent = os.path.dirname(target)
            os.makedirs(parent, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    return EXPORT_JSON_FILE


def record_github_sync_log(total_iocs: int, action: str, commit_sha: str, status: str, message: str):
    """Records GitHub synchronization action into audit log table."""
    db_path = init_ioc_database()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("""
            INSERT INTO github_sync_log (sync_time, total_iocs, action, commit_sha, status, message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now_str, total_iocs, action, commit_sha, status, message))
        conn.commit()
        conn.close()
    except Exception:
        pass


def add_custom_ioc(item: Dict[str, Any]) -> Dict[str, Any]:
    """Adds or updates a single custom analyst IOC in the offline database."""
    ind = str(item.get("indicator", "")).strip()
    if not ind:
        raise ValueError("Indicator cannot be empty")

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    clean_item = {
        "indicator": ind,
        "type": str(item.get("type") or "IPv4").strip(),
        "reputation": str(item.get("reputation") or "MALICIOUS").strip(),
        "confidence": int(item.get("confidence") or 100),
        "threat_actor": str(item.get("threat_actor") or "Analyst Custom").strip(),
        "malware_family": str(item.get("malware_family") or "Custom IOC").strip(),
        "source": str(item.get("source") or "Custom / Analyst").strip(),
        "first_seen": str(item.get("first_seen") or now_str),
        "last_seen": str(item.get("last_seen") or now_str),
        "ransomware_use": str(item.get("ransomware_use") or "Targeted Threat / Investigation"),
        "cvss_score": str(item.get("cvss_score") or "CUSTOM IOC"),
        "status": str(item.get("status") or "ACTIVE IOC"),
        "description": str(item.get("description") or "Analyst manual threat entry").strip(),
    }
    res = save_iocs_to_db([clean_item])
    return {
        "status": "success",
        "indicator": ind,
        "total": res.get("total", get_total_ioc_count()),
        "ioc": clean_item
    }


def delete_ioc(indicator: str) -> bool:
    """Deletes an indicator from the offline database."""
    ind = indicator.strip()
    if not ind:
        return False
    db_path = init_ioc_database()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM iocs WHERE indicator = ?", (ind,))
        deleted = c.rowcount > 0
        conn.commit()
        conn.close()
        if deleted:
            export_iocs_snapshot()
        return deleted
    except Exception as e:
        print(f"Error deleting IOC: {e}")
        return False


def import_iocs_from_json(json_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Explicitly imports threat indicators from the Git dataset JSON file into SQLite.
    Updates existing indicators and inserts new ones.
    """
    candidates = [
        json_path,
        EXPORT_JSON_FILE,
        BACKEND_DATA_JSON,
        os.path.join(REPO_ROOT, "data", "threat_intel_iocs.json"),
        "/opt/opensoc-forge/data/threat_intel_iocs.json",
        "/home/resanul/siem/data/threat_intel_iocs.json",
        "data/threat_intel_iocs.json"
    ]
    target_file = next((p for p in candidates if p and os.path.exists(p)), None)

    if not target_file:
        return {"status": "error", "message": "threat_intel_iocs.json not found", "imported": 0}

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        indicators = data.get("indicators", [])
        if not indicators:
            return {"status": "empty", "message": "No indicators in file", "imported": 0}

        db_path = init_ioc_database()
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        records = []
        for item in indicators:
            ind = item.get("indicator")
            if not ind:
                continue
            records.append((
                str(ind).strip(),
                str(item.get("type", "IOC")),
                str(item.get("reputation", "MALICIOUS")),
                int(item.get("confidence", 90) or 90),
                str(item.get("threat_actor", "") or "Unknown"),
                str(item.get("malware_family", "") or "Unknown Malware"),
                str(item.get("source", "Threat Feed")),
                str(item.get("first_seen", "") or now_str),
                str(item.get("last_seen", "") or now_str),
                str(item.get("ransomware_use", "Unknown")),
                str(item.get("cvss_score", "MALICIOUS")),
                str(item.get("status", "ACTIVE")),
                str(item.get("description", "")),
                now_str
            ))

        conn = sqlite3.connect(db_path, timeout=30)
        c = conn.cursor()
        c.executemany("""
            INSERT INTO iocs (
                indicator, type, reputation, confidence, threat_actor, malware_family,
                source, first_seen, last_seen, ransomware_use, cvss_score, status,
                description, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                type=excluded.type,
                reputation=excluded.reputation,
                confidence=excluded.confidence,
                threat_actor=excluded.threat_actor,
                malware_family=excluded.malware_family,
                source=excluded.source,
                last_seen=excluded.last_seen,
                ransomware_use=excluded.ransomware_use,
                cvss_score=excluded.cvss_score,
                status=excluded.status,
                description=excluded.description,
                updated_at=excluded.updated_at
        """, records)
        conn.commit()

        c.execute("SELECT COUNT(*) FROM iocs")
        total_count = c.fetchone()[0]
        conn.close()

        return {
            "status": "success",
            "imported": len(records),
            "total_iocs": total_count,
            "source_file": target_file
        }
    except Exception as e:
        print(f"Error importing IOCs from JSON: {e}")
        return {"status": "error", "message": str(e), "imported": 0}

