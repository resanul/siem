"""
OpenSOC Forge - Persistent Endpoint Hosts & Wazuh Agent Fleet Storage.
Manages registered and discovered HIDS endpoints with SQLite persistence,
Wazuh Manager auto-discovery, manual host registration, and clean demo data purge.
"""

import os
import sqlite3
import time
import json
import base64
import urllib.request
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

DB_PERSISTENT_FILE = "/var/lib/opensoc/endpoint_hosts.db"
DB_DEFAULT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "endpoint_hosts.db")
DB_TEMP_FILE = "/tmp/endpoint_hosts.db"


def _get_db_path() -> str:
    for candidate in [DB_PERSISTENT_FILE, DB_DEFAULT_FILE, DB_TEMP_FILE]:
        parent = os.path.dirname(candidate)
        try:
            if not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(os.path.join(parent, ".test_db"), "w") as f:
                f.write("ok")
            os.remove(os.path.join(parent, ".test_db"))
            return candidate
        except Exception:
            continue
    return DB_TEMP_FILE


def init_host_database() -> str:
    db_path = _get_db_path()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                os_name TEXT,
                agent_version TEXT,
                fim_status TEXT DEFAULT 'Clean',
                status TEXT DEFAULT 'ONLINE',
                registered_at TEXT,
                last_keepalive TEXT,
                is_demo INTEGER DEFAULT 0,
                notes TEXT DEFAULT ''
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_os ON endpoints(os_name)")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error initializing host database at {db_path}: {e}")
    return db_path


def list_hosts(
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    include_demo: bool = False
) -> List[Dict[str, Any]]:
    """Returns list of registered endpoints."""
    db_path = _get_db_path()
    init_host_database()

    # Try sync from live Wazuh Manager if reachable
    try_sync_wazuh_agents()

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        query = "SELECT * FROM endpoints WHERE 1=1"
        params: List[Any] = []

        if not include_demo:
            query += " AND is_demo = 0"

        if status_filter and status_filter.upper() != "ALL":
            query += " AND status = ?"
            params.append(status_filter.upper())

        if search:
            query += " AND (hostname LIKE ? OR ip_address LIKE ? OR os_name LIKE ? OR id LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term, term])

        query += " ORDER BY registered_at DESC"
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "host": r["hostname"],
                "ip": r["ip_address"],
                "os": r["os_name"] or "Linux",
                "ver": r["agent_version"] or "4.8.2",
                "fim": r["fim_status"] or "Clean",
                "status": r["status"] or "ONLINE",
                "registered_at": r["registered_at"],
                "last_keepalive": r["last_keepalive"],
                "is_demo": bool(r["is_demo"]),
                "notes": r["notes"] or "",
            })
        return results
    except Exception as e:
        print(f"Failed to query endpoints database: {e}")
        return []


def add_host(
    hostname: str,
    ip_address: str,
    os_name: str = "Linux (Ubuntu/Debian)",
    agent_version: str = "4.8.2",
    fim_status: str = "Clean",
    status: str = "ONLINE",
    notes: str = "",
    host_id: Optional[str] = None,
    is_demo: bool = False
) -> Dict[str, Any]:
    """Adds or registers a new endpoint host in the inventory."""
    db_path = _get_db_path()
    init_host_database()

    conn = sqlite3.connect(db_path, timeout=10)
    c = conn.cursor()

    if not host_id:
        c.execute("SELECT COUNT(*) FROM endpoints")
        count = c.fetchone()[0] + 1
        host_id = f"{count:03d}"

    now_iso = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        INSERT OR REPLACE INTO endpoints 
        (id, hostname, ip_address, os_name, agent_version, fim_status, status, registered_at, last_keepalive, is_demo, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        host_id,
        hostname.strip(),
        ip_address.strip(),
        os_name.strip(),
        agent_version.strip(),
        fim_status.strip(),
        status.strip(),
        now_iso,
        now_iso,
        1 if is_demo else 0,
        notes.strip()
    ))
    conn.commit()
    conn.close()

    return {
        "status": "SUCCESS",
        "id": host_id,
        "host": hostname,
        "ip": ip_address,
        "os": os_name,
        "ver": agent_version,
        "fim": fim_status,
        "state": status
    }


def delete_host(host_id: str) -> bool:
    """Removes an endpoint host by ID."""
    db_path = _get_db_path()
    init_host_database()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM endpoints WHERE id = ?", (host_id,))
        deleted = c.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
    except Exception:
        return False


def clear_all_demo_hosts() -> Dict[str, Any]:
    """Clears all demo hosts from the database."""
    db_path = _get_db_path()
    init_host_database()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM endpoints WHERE is_demo = 1")
        deleted_count = c.rowcount
        conn.commit()
        conn.close()
        return {"status": "SUCCESS", "cleared": deleted_count}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


def clear_all_hosts() -> Dict[str, Any]:
    """Resets endpoint database to clean slate (0 hosts)."""
    db_path = _get_db_path()
    init_host_database()
    try:
        conn = sqlite3.connect(db_path, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM endpoints")
        deleted_count = c.rowcount
        conn.commit()
        conn.close()
        return {"status": "SUCCESS", "cleared": deleted_count}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}


def get_fleet_stats(include_demo: bool = False) -> Dict[str, int]:
    """Calculates active/disconnected fleet metrics."""
    hosts = list_hosts(include_demo=include_demo)
    total = len(hosts)
    active = sum(1 for h in hosts if h["status"] == "ONLINE")
    disconnected = total - active
    return {
        "total": total,
        "active": active,
        "disconnected": disconnected
    }


_last_wazuh_sync_time: float = 0.0


def try_sync_wazuh_agents(force: bool = False):
    """
    Attempts to query local Wazuh Manager database or API
    to auto-register newly joined HIDS agents.
    Throttled to run at most once every 10 seconds unless force=True.
    """
    global _last_wazuh_sync_time
    now = time.time()
    if not force and (now - _last_wazuh_sync_time < 3.0):
        return

    _last_wazuh_sync_time = now

    # 1. Fast local SQLite query directly against /var/ossec/queue/db/global.db (0ms)
    wazuh_db = "/var/ossec/queue/db/global.db"
    if os.path.exists(wazuh_db):
        try:
            wconn = sqlite3.connect(wazuh_db, timeout=1)
            wconn.row_factory = sqlite3.Row
            wc = wconn.cursor()
            wc.execute("SELECT id, name, ip, register_ip, os_name, os_version, version, connection_status FROM agent WHERE id >= 0")
            rows = wc.fetchall()
            found_agents = False
            for r in rows:
                found_agents = True
                raw_id = r["id"]
                ag_id = str(raw_id).zfill(3)
                h_name = r["name"] or f"agent-{ag_id}"
                if h_name in ("localhost", "localhost.localdomain"):
                    h_name = "dashboard-11"

                ip_addr = r["ip"] or ""
                if not ip_addr or ip_addr in ["any", "127.0.0.1"]:
                    if ag_id == "000":
                        ip_addr = "172.31.105.11"
                    elif r["register_ip"] and r["register_ip"] not in ["any", "127.0.0.1", ""]:
                        ip_addr = r["register_ip"]
                    else:
                        ip_addr = "Connecting (DHCP)"

                os_str = f"{r['os_name'] or ''} {r['os_version'] or ''}".strip()
                if ag_id == "000":
                    os_str = f"{os_str} (Central Manager)" if os_str else "Red Hat Enterprise Linux 9.8 (Central Manager)"
                elif not os_str:
                    os_str = "Windows (Syncing...)" if any(k in h_name.lower() for k in ["win", "desktop", "isrcd", "pc"]) else "Detecting OS..."

                conn_stat = (r["connection_status"] or "").lower()
                if conn_stat in ["active", "synced"]:
                    status_display = "ONLINE"
                elif conn_stat in ["pending", "never_connected"]:
                    status_display = "PENDING"
                else:
                    status_display = "OFFLINE"
                add_host(
                    hostname=h_name,
                    ip_address=ip_addr,
                    os_name=os_str,
                    agent_version=r["version"] or "4.14.9",
                    status=status_display,
                    host_id=ag_id,
                    is_demo=False
                )
            wconn.close()

            # Reconcile: Purge any endpoints that were deleted or removed from Wazuh
            if found_agents:
                active_agent_ids = {str(r["id"]).zfill(3) for r in rows}
                try:
                    db_path = _get_db_path()
                    conn = sqlite3.connect(db_path, timeout=5)
                    c = conn.cursor()
                    c.execute("SELECT id FROM endpoints WHERE is_demo = 0")
                    all_local_ids = [row[0] for row in c.fetchall()]
                    stale_ids = [lid for lid in all_local_ids if lid not in active_agent_ids]
                    for sid in stale_ids:
                        c.execute("DELETE FROM endpoints WHERE id = ?", (sid,))
                    if stale_ids:
                        conn.commit()
                    conn.close()
                except Exception:
                    pass
                return
        except Exception:
            pass

    # 2. Check /var/ossec/etc/client.keys directly (instant 0ms)
    client_keys_file = "/var/ossec/etc/client.keys"
    if os.path.exists(client_keys_file):
        try:
            with open(client_keys_file, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        ag_id = parts[0].zfill(3)
                        h_name = parts[1]
                        ip_addr = parts[2]
                        if ip_addr in ["any", "127.0.0.1"]:
                            ip_addr = "DHCP / Dynamic"
                        add_host(
                            hostname=h_name,
                            ip_address=ip_addr,
                            os_name="Linux / Windows",
                            agent_version="4.9.2",
                            status="ONLINE",
                            host_id=ag_id,
                            is_demo=False
                        )
        except Exception:
            pass


