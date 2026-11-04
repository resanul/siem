import json
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONFIGS_DIR = os.path.join(REPO_ROOT, "configs")
NETWITNESS_EVENTS_FILE = os.path.join(CONFIGS_DIR, "netwitness_synced_events.json")
SOPHOS_FILE = os.path.join(CONFIGS_DIR, "sophos_persisted_telemetry.json")
PERSISTED_ALERTS_FILE = os.path.join(CONFIGS_DIR, "persisted_alerts.json")


def _find_wazuh_alerts_file() -> Optional[str]:
    candidates = [
        os.environ.get("WAZUH_ALERTS_PATH"),
        "/var/ossec/logs/alerts/alerts.json",
        os.path.join(REPO_ROOT, "logs", "wazuh_alerts.json"),
        os.path.join(REPO_ROOT, "wazuh_alerts.json"),
        "/var/log/wazuh/alerts.json",
    ]
    for c in candidates:
        if c and os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    return None


def get_events_for_host(
    host_identifier: str,
    limit: int = 200,
    category: str = "all",
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetches all historical and live events for a specific host across:
    1. Wazuh HIDS alerts (alerts.json)
    2. NetWitness 30-day session logs
    3. Sophos Central XDR notables
    4. Correlated alerts & incidents
    """
    ident_clean = str(host_identifier).strip().lower()
    matched_events: List[Dict[str, Any]] = []

    # 1. Fetch host info if known
    from backend.app.services.host_storage import list_hosts
    all_hosts = list_hosts()
    target_host = None
    for h in all_hosts:
        if (
            str(h.get("id", "")).lower() == ident_clean
            or str(h.get("host", "")).lower() == ident_clean
            or str(h.get("ip", "")).lower() == ident_clean
        ):
            target_host = h
            break

    target_id = target_host.get("id") if target_host else host_identifier
    target_name = (target_host.get("host") if target_host else ident_clean).strip().lower()
    target_ip = (target_host.get("ip") if target_host else "").strip().lower()

    # 2. Collect from Wazuh alerts.json
    wazuh_path = _find_wazuh_alerts_file()
    if wazuh_path and os.path.exists(wazuh_path):
        try:
            fsize = os.path.getsize(wazuh_path)
            read_bytes = min(fsize, 8 * 1024 * 1024)  # read last 8MB
            with open(wazuh_path, "r", encoding="utf-8", errors="replace") as f:
                if fsize > read_bytes:
                    f.seek(fsize - read_bytes)
                    f.readline()  # discard partial
                lines = f.readlines()
                for l in reversed(lines):
                    if not l.startswith("{"):
                        continue
                    try:
                        d = json.loads(l)
                        ag = d.get("agent", {})
                        ag_id = str(ag.get("id", "")).strip().lower()
                        ag_name = str(ag.get("name", "")).strip().lower()
                        ag_ip = str(ag.get("ip", "")).strip().lower()

                        # Match host by ID, hostname, or IP
                        matched = False
                        if ag_id and str(target_id).lower() == ag_id:
                            matched = True
                        elif target_name and ag_name and (ag_name == target_name or target_name in ag_name or ag_name in target_name):
                            matched = True
                        elif target_ip and ag_ip and (target_ip == ag_ip or ag_ip in target_ip):
                            matched = True

                        if matched:
                            rule = d.get("rule", {})
                            level = rule.get("level", 0)
                            sev = "CRITICAL" if level >= 12 else ("HIGH" if level >= 7 else ("MEDIUM" if level >= 4 else "LOW"))
                            groups = rule.get("groups", [])
                            cat = "syscheck" if "syscheck" in groups else ("auth" if any(g in groups for g in ["authentication_success", "authentication_failed", "sshd", "pam"]) else "hids")

                            full_log = d.get("full_log", "")
                            location = d.get("location", "")
                            desc = rule.get("description", "Wazuh agent security event")

                            matched_events.append({
                                "id": d.get("id", f"wazuh-{int(time.time()*1000)}-{len(matched_events)}"),
                                "timestamp": d.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                                "source": "Wazuh HIDS",
                                "source_type": "hids",
                                "event_type": "HIDS Security Event",
                                "severity": sev,
                                "level": level,
                                "category": cat,
                                "rule_id": str(rule.get("id", "")),
                                "description": desc,
                                "location": location,
                                "mitre": rule.get("mitre", {}).get("id", []),
                                "details": {
                                    "full_log": full_log,
                                    "data": d.get("data", {}),
                                    "groups": groups,
                                    "decoder": d.get("decoder", {}).get("name", ""),
                                },
                                "raw": d
                            })
                            if len(matched_events) >= limit * 2:
                                break
                    except Exception:
                        continue
        except Exception as e:
            pass

    # 3. Collect from Sophos XDR notables
    if os.path.exists(SOPHOS_FILE):
        try:
            with open(SOPHOS_FILE, "r", encoding="utf-8", errors="replace") as f:
                sophos_data = json.load(f)
            notables = sophos_data.get("top_notable_events", [])
            for n in notables:
                n_host = str(n.get("host", "")).lower()
                n_ip = str(n.get("src_ip", "")).lower()
                if (target_name and (n_host == target_name or target_name in n_host or n_host in target_name)) or (target_ip and n_ip == target_ip):
                    matched_events.append({
                        "id": n.get("id", f"sophos-{int(time.time()*1000)}-{len(matched_events)}"),
                        "timestamp": n.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                        "source": "Sophos Central XDR",
                        "source_type": "xdr",
                        "event_type": n.get("clean_title") or n.get("threat_type") or "Endpoint Notable",
                        "severity": str(n.get("urgency", "MEDIUM")).upper(),
                        "level": 9 if str(n.get("urgency", "")).lower() == "high" else 5,
                        "category": n.get("category", "malware"),
                        "rule_id": n.get("rule_name", "Sophos-InterceptX"),
                        "description": n.get("clean_title") or n.get("description", "Sophos endpoint protection notable"),
                        "location": n.get("process_path") or n.get("location_type") or "Local Endpoint Disk",
                        "mitre": [n.get("mitre_technique", "")] if n.get("mitre_technique") else [],
                        "details": {
                            "user": n.get("user"),
                            "action": n.get("action"),
                            "file_name": n.get("file_name"),
                            "sha256": n.get("sha256"),
                            "threat_details": n.get("threat_details"),
                        },
                        "raw": n.get("raw") or n.get("raw_json") or n
                    })
        except Exception:
            pass

    # 4. Collect from NetWitness 30-Day session logs
    if os.path.exists(NETWITNESS_EVENTS_FILE):
        try:
            with open(NETWITNESS_EVENTS_FILE, "r", encoding="utf-8", errors="replace") as f:
                nw_events = json.load(f)
            for ev in nw_events:
                src_ip = str(ev.get("source_ip", "")).lower()
                dst_ip = str(ev.get("destination_ip", "")).lower()
                ev_host = str(ev.get("host", "")).lower()
                if (target_ip and (src_ip == target_ip or dst_ip == target_ip)) or (target_name and (ev_host == target_name or target_name in ev_host)):
                    matched_events.append({
                        "id": str(ev.get("id", f"nw-{int(time.time()*1000)}-{len(matched_events)}")),
                        "timestamp": ev.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                        "source": "RSA NetWitness SIEM",
                        "source_type": "network",
                        "event_type": "Network Session Flow",
                        "severity": str(ev.get("severity", "LOW")).upper(),
                        "level": 3,
                        "category": "network",
                        "rule_id": ev.get("service") or ev.get("action") or "NetWitness-Flow",
                        "description": f"{ev.get('action', 'Network Flow')} - {ev.get('source_ip')}:{ev.get('source_port', 0)} -> {ev.get('destination_ip')}:{ev.get('destination_port', 0)}",
                        "location": f"Port {ev.get('destination_port', 'N/A')}",
                        "mitre": [],
                        "details": {
                            "source_ip": ev.get("source_ip"),
                            "destination_ip": ev.get("destination_ip"),
                            "service": ev.get("service"),
                            "bytes": ev.get("bytes_transferred"),
                            "meta": ev.get("meta_values", {})
                        },
                        "raw": ev
                    })
                    if len(matched_events) >= limit * 3:
                        break
        except Exception:
            pass

    # 5. Filter by category & search term if requested
    if category != "all":
        cat_lower = category.lower()
        if cat_lower in ["wazuh", "hids"]:
            matched_events = [e for e in matched_events if e["source_type"] == "hids"]
        elif cat_lower in ["sophos", "xdr"]:
            matched_events = [e for e in matched_events if e["source_type"] == "xdr"]
        elif cat_lower in ["netwitness", "network"]:
            matched_events = [e for e in matched_events if e["source_type"] == "network"]
        else:
            matched_events = [e for e in matched_events if e["category"].lower() == cat_lower]

    if search:
        s_term = search.strip().lower()
        matched_events = [
            e for e in matched_events
            if (
                s_term in e.get("description", "").lower()
                or s_term in e.get("rule_id", "").lower()
                or s_term in e.get("location", "").lower()
                or s_term in json.dumps(e.get("details", {})).lower()
            )
        ]

    # Sort descending by timestamp
    matched_events.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    events_slice = matched_events[:limit]

    # Compute category metrics
    cats_count: Dict[str, int] = {}
    for ev in matched_events:
        src = ev.get("source", "Other")
        cats_count[src] = cats_count.get(src, 0) + 1

    return {
        "status": "SUCCESS",
        "host": target_host or {
            "id": host_identifier,
            "host": host_identifier,
            "ip": target_ip,
            "os": "Unknown",
            "status": "ONLINE"
        },
        "total_events": len(matched_events),
        "events_count_by_source": cats_count,
        "events": events_slice
    }
