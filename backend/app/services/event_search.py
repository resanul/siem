"""
OpenSOC Forge - Event Search Service & Multi-Source Resilient Fallback Engine.
Provides unified query execution across Elasticsearch cluster indices, Suricata EVE streams,
Wazuh HIDS alerts, syslog telemetry, and offline threat intelligence IOC repositories.
"""

import base64
import fnmatch
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from backend.app.models.schemas import (
    EventItem,
    EventSearchRequest,
    EventSearchResponse,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONFIGS_DIR = os.path.join(REPO_ROOT, "configs")
PERSISTENT_ALERTS_FILE = os.path.join(CONFIGS_DIR, "persisted_alerts.json")

ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200").rstrip("/")
ES_USER = os.environ.get("ELASTIC_USER", "elastic")
ES_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "OpenSocForge2026!")

TOKEN_REGEX = re.compile(
    r'(?P<not_prefix>NOT\s+)?(?P<neg>-)?(?:(?P<key>[a-zA-Z0-9_.-]+):)?(?:"(?P<dqval>[^"]*)"|\'(?P<sqval>[^\']*)\'|(?P<rawval>\S+))'
)


def _tail_lines(file_path: str, max_lines: int = 200, chunk_size: int = 262144) -> List[str]:
    """Efficiently reads the last N lines of large telemetry logs without loading the full file."""
    if not os.path.exists(file_path):
        return []
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return []
        read_bytes = min(file_size, chunk_size)
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            if file_size > read_bytes:
                f.seek(file_size - read_bytes)
                f.readline()  # discard partial line
            lines = f.readlines()
            return lines[-max_lines:]
    except Exception:
        return []


def _find_suricata_eve_log() -> str:
    """Finds active eve.json log across standard Linux and local installation paths."""
    candidates = [
        os.environ.get("SURICATA_EVE_PATH"),
        "/var/log/suricata/eve.json",
        "/var/log/suricata/eve-alerts.json",
        "/opt/opensoc-forge/logs/eve.json",
        os.path.join(REPO_ROOT, "logs", "eve.json"),
        os.path.join(REPO_ROOT, "eve.json"),
        "/var/log/suricata.log",
    ]
    for c in candidates:
        if c and os.path.exists(c) and os.path.getsize(c) > 0:
            return c
    return os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")


def _parse_time_cutoff(time_range: str) -> Optional[datetime]:
    """Computes UTC cutoff datetime from time range token (e.g. 15m, 1h, 24h, 7d)."""
    try:
        tr = (time_range or "24h").strip().lower()
        if tr in ("all", "*"):
            return None

        m = re.match(r"^(\d+)([smhd])$", tr)
        if m:
            val, unit = int(m.group(1)), m.group(2)
            if unit == "s":
                delta = timedelta(seconds=val)
            elif unit == "m":
                delta = timedelta(minutes=val)
            elif unit == "h":
                delta = timedelta(hours=val)
            elif unit == "d":
                delta = timedelta(days=val)
            else:
                delta = timedelta(hours=24)
        else:
            delta = timedelta(hours=24)

        return datetime.now(timezone.utc) - delta
    except (OverflowError, ValueError):
        return None


def _matches_time_range(timestamp_str: str, time_range: str, is_demo: bool = False) -> bool:
    """Evaluates whether event timestamp falls within the requested time range."""
    tr = (time_range or "24h").strip().lower()
    if tr in ("all", "*"):
        return True

    # Allow demo fixtures during standard demonstration time frames (24h+)
    if is_demo and tr in ("24h", "7d", "30d", "all"):
        return True

    cutoff = _parse_time_cutoff(time_range)
    if cutoff is None:
        return True

    if not timestamp_str:
        return True

    try:
        clean_ts = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt >= cutoff
    except Exception:
        # Fallback parsing for alternative date string formats
        try:
            dt = datetime.strptime(timestamp_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt >= cutoff
        except Exception:
            return True


def _matches_indices(event_index: str, indices: Optional[List[str]]) -> bool:
    """Checks whether an event index matches the requested index patterns."""
    if not indices or "*" in indices or not event_index:
        return True

    ev_idx = event_index.lower()
    for pattern in indices:
        pat = pattern.strip().lower()
        if not pat or pat == "*":
            return True
        if fnmatch.fnmatch(ev_idx, pat):
            return True
        # Match common prefixes (e.g. pattern 'suricata-*' matches 'suricata-eve')
        clean_pat = pat.rstrip("*").rstrip("-")
        if clean_pat and (clean_pat in ev_idx or ev_idx in clean_pat):
            return True
        # Handle 'syslog-*' matching 'opensoc-syslog'
        if "syslog" in pat and "syslog" in ev_idx:
            return True
        if "wazuh" in pat and "wazuh" in ev_idx:
            return True
        if "suricata" in pat and "suricata" in ev_idx:
            return True
        if "threat" in pat and "threat" in ev_idx:
            return True

    return False


def _get_field_values_for_key(event: EventItem, key: str) -> List[str]:
    """Resolves potential values for a given query key against an EventItem."""
    k = key.lower()
    values: List[str] = []

    if k in ("host", "host.name", "hostname", "agent.name"):
        if event.host:
            values.append(event.host)
        if "host" in event.raw and isinstance(event.raw["host"], str):
            values.append(event.raw["host"])
        agent = event.raw.get("agent")
        if isinstance(agent, dict) and "name" in agent:
            values.append(str(agent["name"]))

    elif k in ("severity", "level", "log.level"):
        if event.severity:
            values.append(event.severity)
        if "severity" in event.raw:
            values.append(str(event.raw["severity"]))
        rule = event.raw.get("rule")
        if isinstance(rule, dict) and "level" in rule:
            values.append(str(rule["level"]))

    elif k in ("index", "source", "_index"):
        values.append(event.index)
        if "source" in event.raw:
            values.append(str(event.raw["source"]))

    elif k in ("source_type", "event.category", "category", "event_type", "type"):
        values.append(event.source_type)
        if "source" in event.raw:
            values.append(str(event.raw["source"]))
        if "event_type" in event.raw:
            values.append(str(event.raw["event_type"]))
        # Category aliases for multi-source correlation
        if "suricata" in event.source_type.lower() or "suricata" in event.index.lower():
            values.extend(["network", "nids", "suricata"])
        if "wazuh" in event.source_type.lower() or "wazuh" in event.index.lower():
            values.extend(["endpoint", "hids", "wazuh"])
        if "syslog" in event.source_type.lower() or "syslog" in event.index.lower():
            values.extend(["syslog", "network"])
        if "threat_intel" in event.source_type.lower():
            values.extend(["threat_intel", "ioc"])

    elif k in ("ip", "src_ip", "source.ip", "source_ip"):
        for field in ("src_ip", "source_ip", "client_ip", "ip"):
            if field in event.raw and event.raw[field]:
                values.append(str(event.raw[field]))

    elif k in ("dest_ip", "destination.ip", "destination_ip"):
        for field in ("dest_ip", "destination_ip"):
            if field in event.raw and event.raw[field]:
                values.append(str(event.raw[field]))

    elif k in ("id", "event.id", "_id"):
        values.append(event.id)
        if "id" in event.raw:
            values.append(str(event.raw["id"]))

    elif k in ("summary", "title", "message", "description"):
        values.append(event.summary)
        for field in ("title", "description", "message"):
            if field in event.raw and event.raw[field]:
                values.append(str(event.raw[field]))

    elif k in ("mitre_attack_id", "mitre", "mitre.id", "technique"):
        if "mitre_attack_id" in event.raw and event.raw["mitre_attack_id"]:
            values.append(str(event.raw["mitre_attack_id"]))
        rule = event.raw.get("rule")
        if isinstance(rule, dict):
            mitre = rule.get("mitre")
            if isinstance(mitre, dict) and "id" in mitre:
                values.append(str(mitre["id"]))

    else:
        # Check direct key in raw dict
        if key in event.raw:
            val = event.raw[key]
            if isinstance(val, (str, int, float, bool)):
                values.append(str(val))
            elif isinstance(val, list):
                values.extend([str(x) for x in val if isinstance(x, (str, int, float, bool))])
        # Check nested path
        parts = key.split(".")
        curr: Any = event.raw
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                curr = None
                break
        if curr is not None and isinstance(curr, (str, int, float, bool)):
            values.append(str(curr))

    return values


def _matches_conjunction(event: EventItem, clause: str) -> bool:
    """Evaluates an AND-conjunction clause against an EventItem."""
    clean_clause = clause.strip()
    if not clean_clause or clean_clause in ("*", "*:*"):
        return True

    matches = list(TOKEN_REGEX.finditer(clean_clause))
    if not matches:
        return True

    raw_json_str = None

    for m in matches:
        key = m.group("key")
        val = m.group("dqval") if m.group("dqval") is not None else (
            m.group("sqval") if m.group("sqval") is not None else m.group("rawval")
        )
        if val is None:
            continue

        # Filter out standalone boolean keyword 'AND'
        if not key and not m.group("not_prefix") and not m.group("neg") and val.upper() == "AND":
            continue

        is_neg = bool(m.group("not_prefix") or m.group("neg"))

        if key is not None:
            field_vals = _get_field_values_for_key(event, key)
            if val == "*":
                condition_met = len(field_vals) > 0 and any(bool(str(fv).strip()) for fv in field_vals)
            else:
                v_low = val.lower()
                condition_met = any(
                    fnmatch.fnmatch(str(fv).lower(), v_low) or v_low in str(fv).lower()
                    for fv in field_vals
                )
        else:
            # Free-text token / substring match across fields
            if val in ("", "*", "*:*"):
                condition_met = True
            else:
                v_low = val.lower()
                if raw_json_str is None:
                    raw_json_str = json.dumps(event.raw, default=str).lower()

                if "*" in val or "?" in val:
                    clean_v = v_low.rstrip("*").rstrip("-")
                    condition_met = (
                        fnmatch.fnmatch(event.summary.lower(), v_low)
                        or fnmatch.fnmatch(event.host.lower(), v_low)
                        or fnmatch.fnmatch(event.source_type.lower(), v_low)
                        or fnmatch.fnmatch(event.severity.lower(), v_low)
                        or fnmatch.fnmatch(event.index.lower(), v_low)
                        or fnmatch.fnmatch(event.id.lower(), v_low)
                        or fnmatch.fnmatch(raw_json_str, f"*{v_low}*")
                        or (bool(clean_v) and (
                            clean_v in event.index.lower()
                            or event.index.lower() in clean_v
                            or clean_v in event.source_type.lower()
                            or clean_v in event.summary.lower()
                            or clean_v in raw_json_str
                        ))
                    )
                else:
                    condition_met = (
                        v_low in event.summary.lower()
                        or v_low in event.host.lower()
                        or v_low in event.source_type.lower()
                        or v_low in event.severity.lower()
                        or v_low in event.index.lower()
                        or v_low in event.id.lower()
                        or v_low in raw_json_str
                    )

        if is_neg:
            condition_met = not condition_met

        if not condition_met:
            return False

    return True


def _matches_query(event: EventItem, query: str) -> bool:
    """Evaluates full query with OR clauses and AND conjunctions against an EventItem."""
    q = (query or "").strip()
    if not q or q in ("*", "*:*"):
        return True

    # Split top-level by whitespace-bounded 'OR'
    or_clauses = re.split(r"\s+OR\s+", q)
    return any(_matches_conjunction(event, clause) for clause in or_clauses if clause.strip())


class EventSearchService:
    """Unified service for querying security telemetry across Elasticsearch and resilient local stores."""

    def __init__(self) -> None:
        self.es_url = ES_URL
        self.es_user = ES_USER
        self.es_password = ES_PASSWORD

    def search(
        self,
        query: Optional[Union[str, EventSearchRequest]] = "*",
        indices: Optional[List[str]] = None,
        time_range: Optional[str] = "24h",
        limit: Optional[int] = 50,
    ) -> EventSearchResponse:
        """
        Executes event search with automatic Elasticsearch integration and resilient local fallback.
        Accepts either an EventSearchRequest object or individual query parameters.
        """
        start_time = time.time()

        if isinstance(query, EventSearchRequest):
            indices = query.indices
            time_range = query.time_range
            limit = query.limit
            query_str = query.query or "*"
        else:
            query_str = query or "*"

        norm_query = query_str.strip() or "*"
        norm_limit = max(1, min(int(limit or 50), 200))
        norm_time_range = (time_range or "24h").strip()
        norm_indices = indices if (indices and len(indices) > 0) else ["*"]

        # 1. Attempt Elasticsearch search
        es_events = None
        try:
            es_events = self._query_elasticsearch(
                query=norm_query,
                indices=norm_indices,
                time_range=norm_time_range,
                limit=norm_limit,
            )
            if es_events is not None and len(es_events) > 0:
                took_ms = max(1, int((time.time() - start_time) * 1000))
                return EventSearchResponse(
                    total_hits=len(es_events),
                    took_ms=took_ms,
                    indices_searched=norm_indices,
                    events=es_events[:norm_limit],
                )
        except Exception:
            es_events = None

        # 2. Resilient Fallback: Search across local heterogeneous data stores
        local_events = self._load_local_events()

        filtered_events: List[EventItem] = []
        for ev in local_events:
            if not _matches_indices(ev.index, norm_indices):
                continue
            is_demo = ev.raw.get("is_demo", False)
            if not _matches_time_range(ev.timestamp, norm_time_range, is_demo=is_demo):
                continue
            if not _matches_query(ev, norm_query):
                continue
            filtered_events.append(ev)

        # Sort newest first
        def _sort_key(ev: EventItem) -> float:
            try:
                clean = ev.timestamp.replace("Z", "+00:00")
                return datetime.fromisoformat(clean).timestamp()
            except Exception:
                try:
                    return datetime.strptime(ev.timestamp[:19], "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    return 0.0

        filtered_events.sort(key=_sort_key, reverse=True)

        total_hits = len(filtered_events)
        results = filtered_events[:norm_limit]
        took_ms = max(1, int((time.time() - start_time) * 1000))

        return EventSearchResponse(
            total_hits=total_hits,
            took_ms=took_ms,
            indices_searched=norm_indices,
            events=results,
        )

    def _query_elasticsearch(
        self,
        query: str,
        indices: List[str],
        time_range: str,
        limit: int,
    ) -> Optional[List[EventItem]]:
        """Queries Elasticsearch _search endpoint with Basic Auth, handling timeouts and offline states."""
        try:
            target_indices = ",".join(indices) if indices and "*" not in indices else "_all"
            url = f"{self.es_url}/{target_indices}/_search"

            if not query or query in ("*", "*:*"):
                must_clause: Dict[str, Any] = {"match_all": {}}
            else:
                must_clause = {
                    "query_string": {
                        "query": query,
                        "default_operator": "AND",
                        "analyze_wildcard": True,
                    }
                }

            filter_clauses = []
            if time_range and time_range.lower() not in ("all", "*"):
                filter_clauses.append({
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{time_range}"
                        }
                    }
                })

            es_payload = {
                "query": {
                    "bool": {
                        "must": [must_clause],
                        "filter": filter_clauses,
                    }
                },
                "size": min(limit, 200),
                "sort": [
                    {"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}
                ],
            }

            req = urllib.request.Request(
                url,
                data=json.dumps(es_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            auth_str = f"{self.es_user}:{self.es_password}"
            auth_header = "Basic " + base64.b64encode(auth_str.encode("ascii")).decode("ascii")
            req.add_header("Authorization", auth_header)

            with urllib.request.urlopen(req, timeout=3.0) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    return None

                data = json.loads(resp.read().decode("utf-8"))
                hits_wrapper = data.get("hits", {})
                hits = hits_wrapper.get("hits", [])
                if not hits:
                    return None

                events: List[EventItem] = []
                for h in hits:
                    src = h.get("_source", {})
                    doc_id = h.get("_id", f"es-{hashlib.md5(json.dumps(src).encode()).hexdigest()[:8]}")
                    ts = src.get("@timestamp") or src.get("timestamp") or datetime.now(timezone.utc).isoformat()
                    idx = h.get("_index", "events")
                    
                    src_type = (
                        src.get("source_type")
                        or src.get("event", {}).get("dataset")
                        or f"{idx}.event"
                    )
                    host = (
                        src.get("host", {}).get("name") if isinstance(src.get("host"), dict)
                        else src.get("host") or src.get("agent", {}).get("name") or "unknown"
                    )
                    sev = str(
                        src.get("severity")
                        or src.get("log", {}).get("level")
                        or "INFORMATIONAL"
                    ).upper()
                    summary = (
                        src.get("message")
                        or src.get("title")
                        or src.get("description")
                        or f"Event from {idx}"
                    )

                    events.append(EventItem(
                        id=doc_id,
                        timestamp=ts,
                        index=idx,
                        source_type=src_type,
                        host=host,
                        severity=sev,
                        summary=summary,
                        raw=src,
                    ))

                return events
        except Exception:
            return None

    def _load_local_events(self) -> List[EventItem]:
        """Loads and normalizes events across all local fallback stores."""
        events: List[EventItem] = []
        seen_ids = set()

        # 1. In-memory LIVE_SIMULATION_ALERTS from live_telemetry.py
        try:
            from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
            for a in LIVE_SIMULATION_ALERTS:
                if a.id in seen_ids:
                    continue
                seen_ids.add(a.id)
                events.append(self._alert_to_event(a))
        except Exception:
            pass

        # 2. Persisted alerts from configs/persisted_alerts.json
        try:
            from backend.app.services.retention_policy import load_persisted_alerts
            persisted = load_persisted_alerts()
            for pa in persisted:
                aid = pa.get("id")
                if not aid or aid in seen_ids:
                    continue
                seen_ids.add(aid)
                events.append(self._persisted_dict_to_event(pa))
        except Exception:
            # Direct disk file read fallback
            if os.path.exists(PERSISTENT_ALERTS_FILE):
                try:
                    with open(PERSISTENT_ALERTS_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for pa in data:
                                aid = pa.get("id")
                                if aid and aid not in seen_ids:
                                    seen_ids.add(aid)
                                    events.append(self._persisted_dict_to_event(pa))
                except Exception:
                    pass

        # 3. Curated in-memory DEMO_ALERTS from backend/app/api/v1/api.py
        try:
            from backend.app.api.v1.api import DEMO_ALERTS
            for a in DEMO_ALERTS:
                if a.id in seen_ids:
                    continue
                seen_ids.add(a.id)
                events.append(self._alert_to_event(a))
        except Exception:
            pass

        # 4. Suricata EVE logs (eve.json)
        eve_path = _find_suricata_eve_log()
        if os.path.exists(eve_path):
            try:
                lines = _tail_lines(eve_path, max_lines=250)
                for line in lines:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        ev = json.loads(line_str)
                    except Exception:
                        continue

                    etype = ev.get("event_type", "event")
                    flow_id = str(ev.get("flow_id", int(time.time() * 1000)))
                    evt_id = f"suri-{flow_id[-10:]}"
                    if evt_id in seen_ids:
                        continue
                    seen_ids.add(evt_id)

                    ts = ev.get("timestamp", datetime.now(timezone.utc).isoformat())
                    src_ip = ev.get("src_ip", "-")
                    dest_ip = ev.get("dest_ip", "-")
                    src_port = ev.get("src_port", "")
                    dest_port = ev.get("dest_port", "")
                    host = ev.get("in_iface") or "sensor-iface"

                    if etype == "alert":
                        alert_info = ev.get("alert", {})
                        sev_num = alert_info.get("severity", 3)
                        sev = "CRITICAL" if sev_num == 1 else ("HIGH" if sev_num == 2 else "MEDIUM")
                        summary = f"Suricata NIDS: {alert_info.get('signature', 'Intrusion Alert')}"
                    elif etype == "anomaly":
                        sev = "MEDIUM"
                        summary = f"Suricata Anomaly: {ev.get('anomaly', {}).get('event', 'protocol_anomaly')}"
                    elif etype == "ssh":
                        sev = "LOW"
                        client_ver = ev.get("ssh", {}).get("client", {}).get("software_version", "")
                        summary = f"Suricata SSH Connection ({client_ver})"
                    else:
                        sev = "INFORMATIONAL"
                        summary = f"Suricata {etype.upper()} ({src_ip}:{src_port} -> {dest_ip}:{dest_port})"

                    events.append(EventItem(
                        id=evt_id,
                        timestamp=ts,
                        index="suricata-eve",
                        source_type=f"suricata.eve.{etype}",
                        host=host,
                        severity=sev,
                        summary=summary,
                        raw=ev,
                    ))
            except Exception:
                pass

        # 5. Threat Intelligence Indicators from ioc_storage.py
        try:
            from backend.app.services.ioc_storage import query_offline_iocs
            iocs = query_offline_iocs(limit=100)
            for ioc in iocs:
                indicator = str(ioc.get("indicator", ""))
                if not indicator:
                    continue
                ioc_id = f"ioc-{hashlib.md5(indicator.encode('utf-8')).hexdigest()[:10]}"
                if ioc_id in seen_ids:
                    continue
                seen_ids.add(ioc_id)

                ts = ioc.get("updated_at") or ioc.get("last_seen") or datetime.now(timezone.utc).isoformat()
                confidence = int(ioc.get("confidence") or 0)
                rep = str(ioc.get("reputation", "")).upper()
                sev = "CRITICAL" if (confidence >= 90 or rep == "MALICIOUS") else "HIGH"
                src = str(ioc.get("source", "Talos")).lower().replace(" ", "_")
                malware = ioc.get("malware_family") or "Threat Indicator"
                desc = ioc.get("description") or ioc.get("threat_actor") or ""

                events.append(EventItem(
                    id=ioc_id,
                    timestamp=ts,
                    index="threat-intel",
                    source_type=f"threat_intel.{src}",
                    host="threat-intel-db",
                    severity=sev,
                    summary=f"Threat IOC: {indicator} ({malware}) - {desc}".strip(" -"),
                    raw=ioc,
                ))
        except Exception:
            pass

        # 6. Syslog files (/var/log/opensoc/syslog/syslog.log, etc.)
        syslog_candidates = [
            os.environ.get("SYSLOG_LOG_PATH"),
            "/var/log/opensoc/syslog/syslog.log",
            "/var/log/syslog",
            "/var/log/messages",
        ]
        for sp in syslog_candidates:
            if sp and os.path.exists(sp):
                try:
                    lines = _tail_lines(sp, max_lines=200)
                    for line in lines:
                        lstr = line.strip()
                        if not lstr:
                            continue
                        sid = f"sys-{hashlib.md5(lstr.encode('utf-8')).hexdigest()[:10]}"
                        if sid in seen_ids:
                            continue
                        seen_ids.add(sid)

                        try:
                            sdata = json.loads(lstr)
                            ts = sdata.get("timestamp") or sdata.get("@timestamp") or datetime.now(timezone.utc).isoformat()
                            host = sdata.get("host") or sdata.get("hostname") or "syslog-host"
                            if isinstance(host, dict):
                                host = host.get("name") or host.get("hostname") or "syslog-host"
                            msg = sdata.get("message") or lstr
                            sev = str(sdata.get("log", {}).get("syslog", {}).get("severity") or sdata.get("severity") or "INFORMATIONAL").upper()
                            raw_val = sdata
                        except Exception:
                            ts = datetime.now(timezone.utc).isoformat()
                            host = "syslog-host"
                            parts = lstr.split()
                            if len(parts) >= 4:
                                host = parts[3]
                            msg = lstr
                            sev = "INFORMATIONAL"
                            raw_val = {"raw": lstr}

                        events.append(EventItem(
                            id=sid,
                            timestamp=ts,
                            index="opensoc-syslog",
                            source_type="syslog.system",
                            host=host,
                            severity=sev,
                            summary=f"Syslog ({host}): {msg}" if not msg.startswith("Syslog") else msg,
                            raw=raw_val,
                        ))
                except Exception:
                    pass

        return events

    def _alert_to_event(self, alert: Any) -> EventItem:
        """Converts an AlertItem model instance into an EventItem."""
        src_val = alert.source.value if hasattr(alert.source, "value") else str(alert.source)
        sev_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        stat_val = alert.status.value if hasattr(alert.status, "value") else str(alert.status)

        if src_val == "suricata":
            index = "suricata-eve"
            src_type = "suricata.eve.alert"
        elif src_val == "wazuh":
            index = "wazuh-alerts"
            src_type = "wazuh.alert"
        elif src_val == "syslog":
            index = "opensoc-syslog"
            src_type = "syslog.system"
        else:
            index = f"{src_val}-alerts"
            src_type = f"{src_val}.alert"

        raw_dict = {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "host": alert.host,
            "src_ip": alert.src_ip,
            "dest_ip": alert.dest_ip,
            "mitre_attack_id": alert.mitre_attack_id,
            "mitre_tactic": alert.mitre_tactic,
            "status": stat_val,
            "source": src_val,
            "severity": sev_val,
            "payload": alert.raw_payload or {},
            "is_demo": getattr(alert, "is_demo", False),
        }
        if isinstance(alert.raw_payload, dict):
            for k, v in alert.raw_payload.items():
                if k not in raw_dict:
                    raw_dict[k] = v

        return EventItem(
            id=alert.id,
            timestamp=alert.timestamp,
            index=index,
            source_type=src_type,
            host=alert.host or "unknown",
            severity=sev_val,
            summary=alert.title,
            raw=raw_dict,
        )

    def _persisted_dict_to_event(self, pa: Dict[str, Any]) -> EventItem:
        """Converts a persisted alert dictionary into an EventItem."""
        src = str(pa.get("source", "alert")).lower()
        if src == "suricata":
            index = "suricata-eve"
            src_type = "suricata.eve.alert"
        elif src == "wazuh":
            index = "wazuh-alerts"
            src_type = "wazuh.alert"
        elif src == "syslog":
            index = "opensoc-syslog"
            src_type = "syslog.system"
        else:
            index = f"{src}-alerts"
            src_type = f"{src}.alert"

        return EventItem(
            id=str(pa.get("id", f"pa-{hashlib.md5(json.dumps(pa).encode()).hexdigest()[:8]}")),
            timestamp=str(pa.get("timestamp", datetime.now(timezone.utc).isoformat())),
            index=index,
            source_type=src_type,
            host=str(pa.get("host", "sensor")),
            severity=str(pa.get("severity", "HIGH")).upper(),
            summary=str(pa.get("title") or pa.get("description") or "Security Alert"),
            raw=pa,
        )


event_search_service = EventSearchService()
