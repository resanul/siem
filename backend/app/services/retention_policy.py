"""
OpenSOC Forge - Data Retention & Lifecycle Policy Manager.
Provides enterprise data retention controls, index lifecycle pruning,
and automated purging of telemetry, alerts, and audit records based on configurable retention days.
"""

import os
import json
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "configs"
)
RETENTION_CONFIG_FILE = os.path.join(CONFIG_DIR, "retention_policy.json")
PERSISTENT_ALERTS_FILE = os.path.join(CONFIG_DIR, "persisted_alerts.json")

DEFAULT_POLICY: Dict[str, Any] = {
    "policy_name": "Standard SOC Compliance Data Retention",
    "retention_days": 7,  # Default 7 days retention
    "auto_purge_enabled": True,
    "hot_days": 7,
    "warm_days": 30,
    "cold_snapshot_days": 90,
    "netwitness_retention_days": 30,
    "purge_targets": {
        "elasticsearch_indices": True,
        "raw_sensor_logs": True,
        "synthetic_telemetry": True,
        "audit_logs": False
    },
    "last_enforced": None,
    "last_enforced_status": "COMPLIANT",
    "purged_records": 0,
    "status": "ACTIVE"
}


def load_retention_policy() -> Dict[str, Any]:
    """Loads current retention policy from config file or returns default 7-day policy."""
    if os.path.exists(RETENTION_CONFIG_FILE):
        try:
            with open(RETENTION_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                res = DEFAULT_POLICY.copy()
                res.update(saved)
                return res
        except Exception:
            pass
    return DEFAULT_POLICY.copy()


def save_retention_policy(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Saves updated retention policy settings."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    current = load_retention_policy()

    if "retention_days" in payload:
        try:
            current["retention_days"] = max(1, int(payload["retention_days"]))
            current["hot_days"] = current["retention_days"]
        except (ValueError, TypeError):
            pass

    if "auto_purge_enabled" in payload:
        current["auto_purge_enabled"] = bool(payload["auto_purge_enabled"])

    if "policy_name" in payload and str(payload["policy_name"]).strip():
        current["policy_name"] = str(payload["policy_name"]).strip()

    if "purge_targets" in payload and isinstance(payload["purge_targets"], dict):
        current["purge_targets"].update(payload["purge_targets"])

    current["updated_at"] = datetime.utcnow().isoformat() + "Z"

    with open(RETENTION_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)

    # Immediately enforce policy if auto-purge is enabled
    if current.get("auto_purge_enabled", True):
        try:
            enforce_retention_policy()
        except Exception:
            pass

    return current


def load_persisted_alerts() -> List[Dict[str, Any]]:
    """Loads alerts that persist across browser reloads and restarts."""
    if os.path.exists(PERSISTENT_ALERTS_FILE):
        try:
            with open(PERSISTENT_ALERTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
    return []


def save_persisted_alerts(alerts: List[Dict[str, Any]]) -> None:
    """Persists alert list to disk."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        with open(PERSISTENT_ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts[:500], f, indent=2)
    except Exception:
        pass


def enforce_retention_policy() -> Dict[str, Any]:
    """
    Evaluates current retention days policy and purges data older than the cutoff threshold.
    Default retention period is 7 days.
    """
    policy = load_retention_policy()
    retention_days = int(policy.get("retention_days", 7))
    cutoff_time = datetime.utcnow() - timedelta(days=retention_days)
    cutoff_iso = cutoff_time.isoformat()
    cutoff_ts = time.time() - (retention_days * 86400)

    purged_count = 0

    # 1. Prune persisted alerts older than retention_days
    current_alerts = load_persisted_alerts()
    kept_alerts = []
    for a in current_alerts:
        a_time_str = a.get("timestamp") or a.get("time") or ""
        keep = True
        try:
            if "T" in a_time_str:
                dt = datetime.fromisoformat(a_time_str.replace("Z", ""))
                if dt < cutoff_time:
                    keep = False
        except Exception:
            pass
        if keep:
            kept_alerts.append(a)
        else:
            purged_count += 1

    if len(kept_alerts) != len(current_alerts):
        save_persisted_alerts(kept_alerts)

    # 2. Prune in-memory LIVE_SIMULATION_ALERTS in live_telemetry
    try:
        from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
        before_len = len(LIVE_SIMULATION_ALERTS)
        LIVE_SIMULATION_ALERTS[:] = [
            a for a in LIVE_SIMULATION_ALERTS
            if getattr(a, "timestamp", "") >= cutoff_iso
        ]
        purged_count += (before_len - len(LIVE_SIMULATION_ALERTS))
    except Exception:
        pass

    # 3. Best-effort Elasticsearch index pruning for expired indices
    try:
        from backend.app.services.live_telemetry import _es_request
        indices = _es_request("/_cat/indices?format=json") or []
        for idx in indices:
            idx_name = idx.get("index", "")
            # Check pattern like suricata-YYYY.MM.DD or syslog-YYYY.MM.DD
            parts = idx_name.split("-")
            if len(parts) >= 2:
                date_part = parts[-1]
                try:
                    idx_date = datetime.strptime(date_part, "%Y.%m.%d")
                    if idx_date < cutoff_time:
                        _es_request(f"/{idx_name}", method="DELETE")
                        purged_count += int(idx.get("docs.count", 0) or 1)
                except Exception:
                    pass
    except Exception:
        pass

    # 4. Prune NetWitness 30-day persistent telemetry
    try:
        from backend.app.services.netwitness_storage import enforce_retention as enforce_nw_retention
        nw_days = int(policy.get("netwitness_retention_days", 30))
        nw_purged = enforce_nw_retention(nw_days)
        purged_count += nw_purged
    except Exception:
        pass

    # Update policy status
    policy["last_enforced"] = datetime.utcnow().isoformat() + "Z"
    policy["last_enforced_status"] = "COMPLIANT"
    policy["purged_records"] = policy.get("purged_records", 0) + purged_count
    
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(RETENTION_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)

    return {
        "status": "SUCCESS",
        "retention_days": retention_days,
        "cutoff_date": cutoff_iso,
        "purged_records": purged_count,
        "policy": policy
    }
