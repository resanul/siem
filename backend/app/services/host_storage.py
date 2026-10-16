"""
OpenSOC Forge - Persistent Endpoint Hosts & Wazuh Agent Fleet Storage.
Manages registered and discovered HIDS endpoints with SQLite persistence,
Wazuh Manager auto-discovery, manual host registration, and clean demo data purge.
"""

import os
import sqlite3
import time
import json
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


def try_sync_wazuh_agents():
    """
    Attempts to query local Wazuh Manager API or local database
    to auto-register newly joined HIDS agents.
    """
    wazuh_api_url = os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000")
    wazuh_user = os.getenv("WAZUH_API_USER", "wazuh")
    wazuh_pass = os.getenv("WAZUH_API_PASSWORD", "OpenSocForge2026!")

    # Non-blocking best-effort check
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # 1. Login to Wazuh API
        auth_url = f"{wazuh_api_url}/security/user/authenticate"
        req = urllib.request.Request(
            auth_url,
            headers={
                "Authorization": f"Basic {urllib.request.base64.b64encode(f'{wazuh_user}:{wazuh_pass}'.encode()).decode()}"
            }
        )
        with urllib.request.urlopen(req, context=ctx, timeout=2) as resp:
            token = json.loads(resp.read().decode()).get("data", {}).get("token")

        if token:
            agents_url = f"{wazuh_api_url}/agents?select=id,name,ip,os,version,status,lastKeepAlive"
            req2 = urllib.request.Request(agents_url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req2, context=ctx, timeout=3) as resp2:
                agents_data = json.loads(resp2.read().decode()).get("data", {}).get("affected_items", [])
                for ag in agents_data:
                    # Skip manager agent 000
                    if ag.get("id") == "000":
                        continue
                    os_info = ag.get("os", {})
                    os_str = f"{os_info.get('name', 'Linux')} {os_info.get('version', '')}".strip()
                    add_host(
                        hostname=ag.get("name", "agent"),
                        ip_address=ag.get("ip", "unknown"),
                        os_name=os_str or "Linux",
                        agent_version=ag.get("version", "4.8.2"),
                        status="ONLINE" if ag.get("status") == "active" else "DISCONNECTED",
                        host_id=ag.get("id"),
                        is_demo=False
                    )
    except Exception:
        pass
