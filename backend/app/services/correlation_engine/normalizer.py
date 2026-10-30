"""
Multi-source log normalizer for OpenSOC Forge Correlation Engine.
Translates heterogeneous raw events from 6 telemetry sources:
1. Wazuh HIDS
2. Suricata NIDS
3. Squid Web Gateway
4. Check Point Firewall
5. RSA NetWitness SIEM
6. Active Directory (Windows Security Events: 4624, 4625, 4672, 4720, 4728, 4768, 4769)
into canonical NormalizedEvent representations.
"""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional, Union
import uuid

from backend.app.services.correlation_engine.schema import (
    DnsEntity,
    EndpointEntity,
    EventCategory,
    FileEntity,
    HttpEntity,
    NormalizedEvent,
    NormalizedOutcome,
    NormalizedSeverity,
    ProcessEntity,
    UserEntity,
)


def _parse_iso_or_epoch(val: Any) -> datetime:
    """Parse various datetime representations into timezone-aware UTC datetime."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    if isinstance(val, (int, float)):
        # Epoch seconds or milliseconds
        ts = float(val)
        if ts > 1e11:  # milliseconds
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    if isinstance(val, str):
        val_str = val.strip()
        # Try epoch float as string
        try:
            ts = float(val_str)
            if ts > 1e11:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except ValueError:
            pass

        # Handle Wazuh "+0000" or ISO formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(val_str, fmt)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue

        # Try fromisoformat as fallback
        try:
            cleaned = val_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    return datetime.now(timezone.utc)


def _normalize_wazuh(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize Wazuh HIDS alert payload into NormalizedEvent."""
    event_id = str(raw.get("id") or f"wazuh-{uuid.uuid4().hex[:12]}")
    timestamp = _parse_iso_or_epoch(raw.get("timestamp"))

    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    syscheck = raw.get("syscheck", {})

    rule_id = str(rule.get("id", ""))
    rule_level = int(rule.get("level", 3))
    groups = rule.get("groups", [])
    if isinstance(groups, str):
        groups = [groups]
    description = rule.get("description", "Wazuh Alert")

    # Severity mapping
    if rule_level >= 13:
        severity = NormalizedSeverity.CRITICAL
    elif rule_level >= 10:
        severity = NormalizedSeverity.HIGH
    elif rule_level >= 7:
        severity = NormalizedSeverity.MEDIUM
    elif rule_level >= 4:
        severity = NormalizedSeverity.LOW
    else:
        severity = NormalizedSeverity.INFORMATIONAL

    # Host & Agent
    host_name = agent.get("name")
    host_ip = agent.get("ip")
    host = EndpointEntity(host=host_name, ip=host_ip)

    # User & Source
    user_raw = data.get("srcuser") or data.get("dstuser") or data.get("user")
    user_name = user_raw.strip().lower() if isinstance(user_raw, str) and user_raw != "-" else None
    user = UserEntity(name=user_name)

    src_ip = data.get("srcip")
    src_port = int(data.get("srcport")) if data.get("srcport") and str(data.get("srcport")).isdigit() else None
    dst_ip = data.get("dstip") or host_ip
    dst_port = int(data.get("dstport")) if data.get("dstport") and str(data.get("dstport")).isdigit() else None

    source = EndpointEntity(ip=src_ip, port=src_port)
    destination = EndpointEntity(ip=dst_ip, port=dst_port)

    # MITRE ATT&CK
    mitre = rule.get("mitre", {})
    mitre_tactics = mitre.get("tactic", [])
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics]
    mitre_techniques = mitre.get("id", [])
    if isinstance(mitre_techniques, str):
        mitre_techniques = [mitre_techniques]

    process: Optional[ProcessEntity] = None
    file_entity: Optional[FileEntity] = None

    # Detect category and action
    if syscheck:
        category = EventCategory.FILE
        file_action = syscheck.get("event", "modified")
        action = f"file_{file_action}"
        outcome = NormalizedOutcome.SUCCESS
        file_entity = FileEntity(
            path=syscheck.get("path"),
            hash_sha256=syscheck.get("sha256_after"),
            size_bytes=syscheck.get("size_after"),
            action=file_action,
        )
    elif rule_id in ("5710", "5503", "5716", "2501") or any(
        g in groups for g in ("authentication_failed", "authentication_failures", "sshd_failed")
    ) or "authentication failed" in description.lower() or "login failed" in description.lower():
        category = EventCategory.AUTHENTICATION
        action = "logon_failed"
        outcome = NormalizedOutcome.FAILURE
    elif rule_id == "5715" or any(g in groups for g in ("authentication_success", "sshd_success")) or "authentication succeeded" in description.lower():
        category = EventCategory.AUTHENTICATION
        action = "logon_success"
        outcome = NormalizedOutcome.SUCCESS
    elif rule_id in ("510", "516", "517", "7001") or "rootcheck" in groups or "rootcheck" in description.lower():
        category = EventCategory.THREAT
        action = "rootcheck_detected"
        outcome = NormalizedOutcome.UNKNOWN
    elif "process" in groups or "command" in data or "process" in raw or raw.get("full_log", "").startswith("command") or "powershell" in description.lower() or "mimikatz" in description.lower():
        category = EventCategory.PROCESS
        action = "process_started"
        outcome = NormalizedOutcome.SUCCESS
        proc_raw = raw.get("process", {}) if isinstance(raw.get("process"), dict) else {}
        cmd = proc_raw.get("command_line") or data.get("command") or raw.get("full_log") or description
        p_name = proc_raw.get("name") or data.get("process") or ("mimikatz.exe" if "mimikatz" in description.lower() else None)
        process = ProcessEntity(command_line=cmd, name=p_name, user=user_name)
    else:
        category = EventCategory.CONFIGURATION
        action = "wazuh_alert"
        outcome = NormalizedOutcome.UNKNOWN

    # If full_log contains process details
    if not process and ("powershell" in description.lower() or "cmd.exe" in description.lower() or "powershell" in raw.get("full_log", "").lower()):
        category = EventCategory.PROCESS
        action = "process_started"
        process = ProcessEntity(
            name="powershell.exe" if "powershell" in (description + raw.get("full_log", "")).lower() else "cmd.exe",
            command_line=raw.get("full_log") or description,
            user=user_name,
        )

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="wazuh",
        original_id=rule_id,
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        severity=severity,
        source=source,
        destination=destination,
        user=user,
        host=host,
        process=process,
        file=file_entity,
        signature=description,
        signature_id=rule_id,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw,
    )


def _normalize_suricata(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize Suricata EVE NIDS JSON event into NormalizedEvent."""
    flow_id = raw.get("flow_id")
    event_id = f"suricata-{flow_id}-{uuid.uuid4().hex[:8]}" if flow_id else f"suricata-{uuid.uuid4().hex[:12]}"
    timestamp = _parse_iso_or_epoch(raw.get("timestamp"))

    src_ip = raw.get("src_ip")
    src_port = raw.get("src_port")
    dest_ip = raw.get("dest_ip")
    dest_port = raw.get("dest_port")
    host_val = raw.get("host")

    source = EndpointEntity(ip=src_ip, port=src_port)
    destination = EndpointEntity(ip=dest_ip, port=dest_port)
    host = EndpointEntity(host=host_val, ip=dest_ip)

    event_type = raw.get("event_type", "alert")
    http_entity: Optional[HttpEntity] = None
    dns_entity: Optional[DnsEntity] = None
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

    # Check for HTTP payload inside EVE event
    http_data = raw.get("http")
    if isinstance(http_data, dict):
        http_entity = HttpEntity(
            method=http_data.get("http_method"),
            url=http_data.get("url"),
            status_code=http_data.get("status"),
            user_agent=http_data.get("http_user_agent"),
            host=http_data.get("hostname"),
            bytes_in=http_data.get("length"),
        )

    if event_type == "alert":
        alert = raw.get("alert", {})
        category = EventCategory.THREAT
        action = "nids_alert"
        suricata_action = alert.get("action", "allowed")
        outcome = NormalizedOutcome.BLOCKED if suricata_action in ("blocked", "drop") else NormalizedOutcome.SUCCESS

        suricata_sev = int(alert.get("severity", 3))
        if suricata_sev == 1:
            severity = NormalizedSeverity.CRITICAL
        elif suricata_sev == 2:
            severity = NormalizedSeverity.HIGH
        elif suricata_sev == 3:
            severity = NormalizedSeverity.MEDIUM
        else:
            severity = NormalizedSeverity.LOW

        signature = alert.get("signature")
        signature_id = str(alert.get("signature_id", ""))

        # MITRE heuristics from signature & classtype
        sig_lower = (signature or "").lower()
        classtype = (alert.get("category") or "").lower()
        if "exploit" in sig_lower or "web-application-attack" in classtype or "rce" in sig_lower:
            mitre_techniques.append("T1190")
            mitre_tactics.append("TA0001")
        if "cve-2021-44228" in sig_lower or "log4j" in sig_lower:
            mitre_techniques.append("T1190")
            mitre_tactics.append("TA0001")

    elif event_type == "dns":
        category = EventCategory.DNS
        action = "dns_query"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.INFORMATIONAL
        dns_data = raw.get("dns", {})
        dns_entity = DnsEntity(
            query_name=dns_data.get("rrname"),
            query_type=dns_data.get("rrtype"),
            response_code=str(dns_data.get("rcode", "NOERROR")),
        )
        signature = f"DNS query {dns_data.get('rrname')}"

    elif event_type == "http":
        category = EventCategory.HTTP
        action = "http_request"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.INFORMATIONAL
        if http_entity:
            signature = f"HTTP {http_entity.method} {http_entity.url}"

    elif event_type == "anomaly":
        category = EventCategory.NETWORK
        action = "flow_anomaly"
        outcome = NormalizedOutcome.UNKNOWN
        severity = NormalizedSeverity.MEDIUM
        anomaly = raw.get("anomaly", {})
        signature = anomaly.get("event", "Flow anomaly")

    else:
        category = EventCategory.NETWORK
        action = f"network_{event_type}"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.INFORMATIONAL

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="suricata",
        original_id=signature_id or str(flow_id),
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        severity=severity,
        source=source,
        destination=destination,
        host=host,
        http=http_entity,
        dns=dns_entity,
        signature=signature,
        signature_id=signature_id,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw,
    )


# Regex for Squid native CLF:
# 1761746401.120    145 192.168.10.150 TCP_MISS/200 4812 GET https://pypi.org/simple/requests/ - HIER_DIRECT/151.101.128.223 application/json
SQUID_CLF_PATTERN = re.compile(
    r"^(?P<epoch>\d+(?:\.\d+)?)\s+(?P<duration>\d+)\s+(?P<client_ip>\S+)\s+(?P<action>\S+)/(?P<status>\d+)\s+(?P<bytes>\d+)\s+(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<hierarchy>\S+)\s*(?P<mime>\S*)"
)


def _normalize_squid(raw: Union[Dict[str, Any], str]) -> NormalizedEvent:
    """Normalize Squid Web Gateway proxy access log into NormalizedEvent."""
    raw_dict: Dict[str, Any] = {}
    clf_string = ""

    if isinstance(raw, str):
        clf_string = raw.strip()
    elif isinstance(raw, dict):
        raw_dict = raw
        clf_string = str(raw.get("message") or raw.get("log") or raw.get("raw") or "").strip()

    epoch_ts: float = 0.0
    client_ip: Optional[str] = None
    status_code: Optional[int] = None
    bytes_out: Optional[int] = None
    method: str = "GET"
    url: str = ""
    user_name: Optional[str] = None
    squid_action: str = ""

    match = SQUID_CLF_PATTERN.match(clf_string) if clf_string else None
    if match:
        groups = match.groupdict()
        epoch_ts = float(groups["epoch"])
        client_ip = groups["client_ip"]
        squid_action = groups["action"]
        status_code = int(groups["status"])
        bytes_out = int(groups["bytes"])
        method = groups["method"].upper()
        url = groups["url"]
        user_val = groups["user"]
        if user_val != "-":
            user_name = user_val.strip().lower()
    else:
        # Try extracting from dict keys
        epoch_ts = float(raw_dict.get("timestamp") or raw_dict.get("epoch") or datetime.now(timezone.utc).timestamp())
        client_ip = raw_dict.get("client_ip") or raw_dict.get("src_ip") or raw_dict.get("srcip")
        status_code = int(raw_dict.get("status_code") or raw_dict.get("status") or 200)
        bytes_out = int(raw_dict.get("bytes_out") or raw_dict.get("bytes") or 0)
        method = str(raw_dict.get("method") or "GET").upper()
        url = str(raw_dict.get("url") or "")
        squid_action = str(raw_dict.get("action") or "")
        user_val = raw_dict.get("user") or raw_dict.get("username")
        if user_val and user_val != "-":
            user_name = str(user_val).strip().lower()

    timestamp = _parse_iso_or_epoch(epoch_ts if epoch_ts > 0 else datetime.now(timezone.utc))
    event_id = f"squid-{uuid.uuid4().hex[:12]}"

    # Action & Outcome
    is_blocked = (
        status_code in (403, 407)
        or "DENIED" in squid_action.upper()
        or "BLOCK" in squid_action.upper()
    )
    outcome = NormalizedOutcome.BLOCKED if is_blocked else NormalizedOutcome.SUCCESS

    if is_blocked:
        action = "http_denied"
    elif method == "CONNECT":
        action = "http_connect"
    else:
        action = "http_request"

    severity = NormalizedSeverity.MEDIUM if is_blocked else (
        NormalizedSeverity.HIGH if bytes_out and bytes_out >= 5000000 else NormalizedSeverity.INFORMATIONAL
    )

    # Extract target host from URL or CONNECT host:port
    dest_host: Optional[str] = None
    dest_port: Optional[int] = None
    if method == "CONNECT" and ":" in url:
        parts = url.split(":")
        dest_host = parts[0]
        if len(parts) > 1 and parts[1].isdigit():
            dest_port = int(parts[1])
    elif "://" in url:
        clean = url.split("://", 1)[1].split("/")[0]
        if ":" in clean:
            dest_host, p = clean.split(":", 1)
            if p.isdigit():
                dest_port = int(p)
        else:
            dest_host = clean
            dest_port = 443 if url.startswith("https") else 80

    source = EndpointEntity(ip=client_ip)
    destination = EndpointEntity(host=dest_host, port=dest_port, ip=dest_host if (dest_host and re.match(r"^\d+\.\d+\.\d+\.\d+$", dest_host)) else None)
    user = UserEntity(name=user_name)
    http_entity = HttpEntity(
        method=method,
        url=url,
        status_code=status_code,
        bytes_out=bytes_out,
        host=dest_host,
    )

    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    if bytes_out and bytes_out >= 5000000:
        mitre_tactics.append("TA0010")
        mitre_techniques.append("T1048")

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="squid",
        original_id=None,
        event_category=EventCategory.HTTP,
        event_action=action,
        event_outcome=outcome,
        severity=severity,
        source=source,
        destination=destination,
        user=user,
        host=EndpointEntity(ip=client_ip),
        http=http_entity,
        signature=f"Squid {method} {url[:60]}",
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw if isinstance(raw, dict) else {"message": raw},
    )


def _normalize_checkpoint(raw: Union[Dict[str, Any], str]) -> NormalizedEvent:
    """Normalize Check Point Firewall key-value syslog or dict into NormalizedEvent."""
    fields: Dict[str, str] = {}
    if isinstance(raw, str):
        # Support both pipe and space separated KV
        pairs = re.findall(r"(\w+)=([^|;\s]+(?: [^|;\s=]+(?!=))*|\"[^\"]*\")", raw)
        for k, v in pairs:
            fields[k.strip()] = v.strip().strip('"')
    elif isinstance(raw, dict):
        fields = {str(k): str(v) for k, v in raw.items()}

    event_id = f"cp-{uuid.uuid4().hex[:12]}"
    time_val = fields.get("time") or fields.get("timestamp") or datetime.now(timezone.utc)
    timestamp = _parse_iso_or_epoch(time_val)

    src_ip = fields.get("src") or fields.get("src_ip")
    src_port = int(fields["s_port"]) if fields.get("s_port", "").isdigit() else None
    dst_ip = fields.get("dst") or fields.get("dst_ip")
    dst_port = int(fields["service"]) if fields.get("service", "").isdigit() else None
    orig_host = fields.get("orig") or fields.get("logserver") or "firewall"

    action_raw = (fields.get("action") or "drop").lower()
    is_blocked = action_raw in ("drop", "reject", "block")
    action = "firewall_drop" if is_blocked else "firewall_accept"
    outcome = NormalizedOutcome.BLOCKED if is_blocked else NormalizedOutcome.SUCCESS
    severity = NormalizedSeverity.MEDIUM if is_blocked else NormalizedSeverity.INFORMATIONAL

    rule_name = fields.get("rule_name") or fields.get("rule")
    reason = fields.get("reason")
    signature = f"CheckPoint {action_raw}: rule {rule_name or 'default'}"
    if reason:
        signature += f" ({reason})"

    source = EndpointEntity(ip=src_ip, port=src_port)
    destination = EndpointEntity(ip=dst_ip, port=dst_port)
    host = EndpointEntity(host=orig_host)

    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    if is_blocked:
        mitre_tactics.append("TA0043")
        mitre_techniques.append("T1046")

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="checkpoint",
        original_id=rule_name,
        event_category=EventCategory.NETWORK,
        event_action=action,
        event_outcome=outcome,
        severity=severity,
        source=source,
        destination=destination,
        host=host,
        signature=signature,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw if isinstance(raw, dict) else {"message": raw},
    )


def _normalize_netwitness(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize RSA NetWitness SIEM session meta event into NormalizedEvent."""
    session_id = raw.get("sessionId")
    event_id = f"nw-{session_id}" if session_id else f"nw-{uuid.uuid4().hex[:12]}"
    time_val = raw.get("time") or datetime.now(timezone.utc)
    timestamp = _parse_iso_or_epoch(time_val)

    # Flatten metas list: [["key", "value"], ...]
    meta_dict: Dict[str, Any] = {}
    metas = raw.get("metas", [])
    if isinstance(metas, list):
        for item in metas:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                meta_dict[item[0]] = item[1]
            elif isinstance(item, dict):
                meta_dict.update(item)
    meta_dict.update({k: v for k, v in raw.items() if k not in ("metas", "time", "sessionId")})

    src_ip = meta_dict.get("ip.src") or meta_dict.get("ipv6.src") or meta_dict.get("src_ip")
    src_port = int(meta_dict["tcp.srcport"]) if str(meta_dict.get("tcp.srcport", "")).isdigit() else None
    dst_ip = meta_dict.get("ip.dst") or meta_dict.get("ipv6.dst") or meta_dict.get("dest_ip")
    dst_port = None
    for p_key in ("tcp.dstport", "udp.dstport", "ip.dstport", "dest_port"):
        if str(meta_dict.get(p_key, "")).isdigit():
            dst_port = int(meta_dict[p_key])
            break

    user_val = meta_dict.get("username") or meta_dict.get("user.src")
    user_name = str(user_val).strip().lower() if user_val and user_val != "-" else None

    host_name = meta_dict.get("device.host") or meta_dict.get("alias.host") or meta_dict.get("host")
    nw_action = meta_dict.get("action") or meta_dict.get("event.desc") or "session_closed"
    threat_desc = meta_dict.get("threat.desc") or meta_dict.get("alert")
    bytes_val = int(meta_dict["payload.bytes"]) if str(meta_dict.get("payload.bytes", "")).isdigit() else None

    is_threat = bool(threat_desc or "anomalous" in nw_action.lower())
    category = EventCategory.THREAT if is_threat else EventCategory.NETWORK
    severity = NormalizedSeverity.HIGH if is_threat else NormalizedSeverity.INFORMATIONAL
    outcome = NormalizedOutcome.SUCCESS

    http_entity: Optional[HttpEntity] = None
    if bytes_val:
        http_entity = HttpEntity(bytes_out=bytes_val)

    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []
    if bytes_val and bytes_val > 10000000:
        mitre_tactics.append("TA0010")
        mitre_techniques.append("T1041")

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="netwitness",
        original_id=str(session_id) if session_id else None,
        event_category=category,
        event_action=str(nw_action),
        event_outcome=outcome,
        severity=severity,
        source=EndpointEntity(ip=src_ip, port=src_port),
        destination=EndpointEntity(ip=dst_ip, port=dst_port),
        user=UserEntity(name=user_name),
        host=EndpointEntity(host=host_name, ip=src_ip),
        http=http_entity,
        signature=str(threat_desc or nw_action),
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw,
    )


def _normalize_active_directory(raw: Dict[str, Any]) -> NormalizedEvent:
    """
    Normalize Windows Active Directory security events (JSON/dict format).
    Covers Event IDs: 4624, 4625, 4672, 4720, 4728, 4768, 4769.
    """
    system = {}
    event_data = {}

    if "Event" in raw and isinstance(raw["Event"], dict):
        system = raw["Event"].get("System", {})
        event_data = raw["Event"].get("EventData", {})
    else:
        system = raw.get("System", {})
        event_data = raw.get("EventData", raw)

    event_id_num = system.get("EventID") or raw.get("EventID")
    try:
        event_id_int = int(event_id_num)
    except (ValueError, TypeError):
        event_id_int = 0

    time_created = (
        system.get("TimeCreated", {}).get("SystemTime")
        if isinstance(system.get("TimeCreated"), dict)
        else (raw.get("TimeCreated") or datetime.now(timezone.utc))
    )
    timestamp = _parse_iso_or_epoch(time_created)
    event_id = f"ad-{event_id_int}-{uuid.uuid4().hex[:8]}"

    computer = system.get("Computer") or raw.get("Computer")
    target_user_raw = (
        event_data.get("TargetUserName")
        or event_data.get("SubjectUserName")
        or raw.get("TargetUserName")
    )
    user_name = (
        target_user_raw.strip().lower()
        if isinstance(target_user_raw, str) and target_user_raw != "-"
        else None
    )

    domain = event_data.get("TargetDomainName") or event_data.get("SubjectDomainName")
    ip_raw = event_data.get("IpAddress") or raw.get("IpAddress")
    src_ip = None
    if ip_raw and ip_raw not in ("-", "::1") and not ip_raw.startswith("127."):
        src_ip = ip_raw
    elif ip_raw in ("127.0.0.1", "::1"):
        src_ip = ip_raw

    port_raw = event_data.get("IpPort") or raw.get("IpPort")
    src_port = int(port_raw) if port_raw and str(port_raw).isdigit() and int(port_raw) > 0 else None

    user = UserEntity(name=user_name, domain=domain)
    host = EndpointEntity(host=computer)
    source = EndpointEntity(ip=src_ip, port=src_port)
    destination = EndpointEntity(host=computer)

    mitre_tactics: List[str] = []
    mitre_techniques: List[str] = []

    if event_id_int == 4624:
        # Logon Success
        logon_type = str(event_data.get("LogonType", ""))
        user.logon_type = logon_type
        category = EventCategory.AUTHENTICATION
        action = "logon_success"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.INFORMATIONAL
        signature = f"Windows Logon Success (Type {logon_type})"
        if logon_type in ("3", "9"):
            mitre_tactics.append("TA0008")
            mitre_techniques.append("T1021")

    elif event_id_int == 4625:
        # Logon Failure
        category = EventCategory.AUTHENTICATION
        action = "logon_failed"
        outcome = NormalizedOutcome.FAILURE
        severity = NormalizedSeverity.MEDIUM
        sub_status = event_data.get("SubStatus") or event_data.get("Status") or "0xC000006A"
        signature = f"Windows Logon Failure (SubStatus: {sub_status})"
        mitre_tactics.append("TA0006")
        mitre_techniques.append("T1110")

    elif event_id_int == 4672:
        # Special Privileges Assigned
        category = EventCategory.PRIVILEGE
        action = "privilege_assigned"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.LOW
        privs = event_data.get("PrivilegeList", [])
        if isinstance(privs, str):
            privs = [p.strip() for p in privs.splitlines() if p.strip()]
        user.privileges = privs
        signature = f"Special Privileges Assigned ({len(privs)} privileges)"
        mitre_tactics.append("TA0004")
        mitre_techniques.append("T1078")

    elif event_id_int == 4720:
        # User Account Created
        category = EventCategory.CONFIGURATION
        action = "user_created"
        outcome = NormalizedOutcome.SUCCESS
        severity = NormalizedSeverity.LOW
        signature = f"User Account Created: {user_name}"
        mitre_tactics.append("TA0003")
        mitre_techniques.append("T1136")

    elif event_id_int == 4728:
        # Member Added to Security Group
        category = EventCategory.PRIVILEGE
        action = "group_member_added"
        outcome = NormalizedOutcome.SUCCESS
        target_group = event_data.get("TargetUserName", "")
        member_raw = str(event_data.get("MemberName") or "")
        if member_raw:
            m_match = re.search(r"CN=([^,]+)", member_raw, re.IGNORECASE)
            if m_match:
                user.name = m_match.group(1).strip().lower()
            else:
                user.name = member_raw.strip().lower()
        signature = f"Member Added to Security Group: {target_group}"
        if any(admin in target_group.lower() for admin in ("admin", "administrators", "domain admins", "enterprise admins")):
            severity = NormalizedSeverity.HIGH
            mitre_tactics.append("TA0004")
            mitre_techniques.append("T1098")
        else:
            severity = NormalizedSeverity.LOW

    elif event_id_int in (4768, 4769):
        # Kerberos TGT / TGS Request
        category = EventCategory.AUTHENTICATION
        action = "kerberos_ticket_request"
        outcome = NormalizedOutcome.SUCCESS
        service_name = event_data.get("ServiceName", "")
        enc_type = event_data.get("TicketEncryptionType", "")
        signature = f"Kerberos Ticket Request for {service_name} (Enc: {enc_type})"
        severity = NormalizedSeverity.INFORMATIONAL
        if enc_type in ("0x17", "23"):  # RC4-HMAC commonly used in Kerberoasting
            severity = NormalizedSeverity.MEDIUM
            mitre_tactics.append("TA0006")
            mitre_techniques.append("T1558.003")

    else:
        category = EventCategory.CONFIGURATION
        action = f"ad_event_{event_id_int}"
        outcome = NormalizedOutcome.UNKNOWN
        severity = NormalizedSeverity.INFORMATIONAL
        signature = f"Active Directory Event {event_id_int}"

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="active_directory",
        original_id=str(event_id_int),
        event_category=category,
        event_action=action,
        event_outcome=outcome,
        severity=severity,
        source=source,
        destination=destination,
        user=user,
        host=host,
        signature=signature,
        signature_id=str(event_id_int),
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        raw_payload=raw,
    )




def _normalize_sophos(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize Sophos Central XDR / MDR threat telemetry into NormalizedEvent."""
    event_id = str(raw.get("id") or f"sophos-{uuid.uuid4().hex[:12]}")
    timestamp = _parse_iso_or_epoch(raw.get("timestamp") or raw.get("when") or datetime.now(timezone.utc))
    severity_str = str(raw.get("severity") or "high").upper()
    sev = NormalizedSeverity.CRITICAL if severity_str in ("CRITICAL", "HIGH") else NormalizedSeverity.MEDIUM

    host = raw.get("endpoint") or raw.get("endpoint_id") or raw.get("hostname") or "workstation-xdr"
    user = raw.get("user") or raw.get("username")
    threat = raw.get("title") or raw.get("threat_name") or raw.get("name") or "Sophos XDR Behavioral Detection"

    proc = None
    if raw.get("process") or raw.get("path") or raw.get("command_line"):
        proc = ProcessEntity(
            name=raw.get("process") or raw.get("process_name"),
            path=raw.get("path"),
            command_line=raw.get("command_line") or raw.get("cmdline") or threat,
            user=user
        )

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="sophos_xdr",
        original_id=str(raw.get("id", "")),
        event_category=EventCategory.PROCESS if proc else EventCategory.THREAT,
        event_action="xdr_threat_detected",
        event_outcome=NormalizedOutcome.BLOCKED if raw.get("action") == "clean" else NormalizedOutcome.SUCCESS,
        severity=sev,
        source=EndpointEntity(ip=raw.get("src_ip")),
        destination=EndpointEntity(ip=raw.get("dest_ip")),
        user=UserEntity(name=str(user).strip().lower() if user else None),
        host=EndpointEntity(host=host),
        process=proc,
        signature=threat,
        mitre_tactics=["Execution", "Defense Evasion"],
        mitre_techniques=["T1059", "T1003"],
        raw_payload=raw,
    )


def _normalize_crowdstrike(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize CrowdStrike Falcon ITDR / EDR detection into NormalizedEvent."""
    event_id = str(raw.get("id") or raw.get("composite_id") or f"falcon-{uuid.uuid4().hex[:12]}")
    timestamp = _parse_iso_or_epoch(raw.get("timestamp") or raw.get("created_timestamp") or datetime.now(timezone.utc))
    severity_str = str(raw.get("severity") or raw.get("max_severity") or "high").upper()
    sev = NormalizedSeverity.CRITICAL if severity_str in ("CRITICAL", "HIGH") else NormalizedSeverity.MEDIUM

    host = raw.get("device") or raw.get("hostname") or "falcon-endpoint"
    user = raw.get("user_name") or raw.get("user")
    title = raw.get("name") or raw.get("title") or "CrowdStrike Falcon Identity Threat Detection"

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="crowdstrike_falcon",
        original_id=str(raw.get("id", "")),
        event_category=EventCategory.AUTHENTICATION,
        event_action="falcon_identity_alert",
        event_outcome=NormalizedOutcome.FAILURE if "fail" in title.lower() else NormalizedOutcome.SUCCESS,
        severity=sev,
        source=EndpointEntity(ip=raw.get("ip")),
        destination=EndpointEntity(host=host),
        user=UserEntity(name=str(user).strip().lower() if user else None),
        host=EndpointEntity(host=host),
        signature=title,
        mitre_tactics=["Credential Access", "Identity Threat"],
        mitre_techniques=["T1110", "T1078"],
        raw_payload=raw,
    )

def normalize_event(
    raw_event: Union[Dict[str, Any], str], source_hint: Optional[str] = None
) -> NormalizedEvent:
    """
    Main entry point for log normalization across all 6 telemetry sources.
    Performs robust format auto-detection with fallback and graceful error isolation.
    """
    try:
        # Check source_hint if provided
        hint = (source_hint or "").strip().lower()

        # If input is string, parse JSON if possible or treat as raw syslog / CLF
        parsed_dict: Optional[Dict[str, Any]] = None
        if isinstance(raw_event, str):
            trimmed = raw_event.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    parsed_dict = json.loads(trimmed)
                except Exception:
                    pass

        target = parsed_dict if parsed_dict is not None else raw_event

        # Route by explicit hint
        if hint in ("wazuh", "hids", "ossec"):
            if isinstance(target, dict):
                return _normalize_wazuh(target)
        elif hint in ("suricata", "nids", "eve"):
            if isinstance(target, dict):
                return _normalize_suricata(target)
        elif hint in ("squid", "proxy", "web_gateway"):
            return _normalize_squid(target)
        elif hint in ("checkpoint", "firewall", "fw"):
            return _normalize_checkpoint(target)
        elif hint in ("netwitness", "nw", "stomp"):
            if isinstance(target, dict):
                return _normalize_netwitness(target)
        elif hint in ("active_directory", "ad", "windows", "security_log"):
            if isinstance(target, dict):
                return _normalize_active_directory(target)
        elif hint in ("sophos", "xdr", "sophos_xdr", "central"):
            if isinstance(target, dict):
                return _normalize_sophos(target)
        elif hint in ("crowdstrike", "falcon", "itdr", "edr"):
            if isinstance(target, dict):
                return _normalize_crowdstrike(target)

        # Auto-detection heuristic if hint not provided or matched
        if isinstance(target, dict):
            # Active Directory check
            if (
                ("Event" in target and isinstance(target["Event"], dict) and "System" in target["Event"])
                or ("EventID" in target and ("TargetUserName" in target or "System" in target))
            ):
                return _normalize_active_directory(target)

            # Wazuh check
            if ("rule" in target and "agent" in target) or "syscheck" in target:
                return _normalize_wazuh(target)

            # Suricata check
            if ("flow_id" in target and ("alert" in target or "dns" in target or "http" in target or "event_type" in target)) or target.get("event_type") in ("alert", "dns", "http", "flow", "anomaly"):
                return _normalize_suricata(target)

            # NetWitness check
            if "sessionId" in target or "metas" in target:
                return _normalize_netwitness(target)

            # Check Point check
            if (
                target.get("product") == "FireWall-1"
                or ("action" in target and "src" in target and "dst" in target and "service" in target)
            ):
                return _normalize_checkpoint(target)

            # Squid check
            if "client_ip" in target and ("status_code" in target or "method" in target):
                return _normalize_squid(target)

        elif isinstance(target, str):
            # Check Point pipe-delimited format
            if "action=" in target and ("src=" in target or "product=FireWall-1" in target):
                return _normalize_checkpoint(target)

            # Squid CLF format
            if SQUID_CLF_PATTERN.match(target):
                return _normalize_squid(target)

        # Fallback if dictionary has enough generic fields
        if isinstance(target, dict):
            cat_str = str(target.get("category") or target.get("event_category") or ("process" if "process" in target else "configuration")).lower()
            try:
                cat = EventCategory(cat_str)
            except Exception:
                cat = EventCategory.CONFIGURATION

            out_str = str(target.get("outcome") or target.get("event_outcome") or "unknown").lower()
            try:
                outcome = NormalizedOutcome(out_str)
            except Exception:
                outcome = NormalizedOutcome.UNKNOWN

            proc_val = target.get("process")
            proc_entity = None
            if isinstance(proc_val, dict):
                proc_entity = ProcessEntity(
                    name=proc_val.get("name"),
                    command_line=proc_val.get("command_line"),
                    user=proc_val.get("user")
                )
            elif target.get("command_line") or target.get("process_name"):
                proc_entity = ProcessEntity(
                    name=target.get("process_name") or target.get("process"),
                    command_line=target.get("command_line"),
                    user=target.get("user")
                )

            http_val = target.get("http")
            http_entity = None
            if isinstance(http_val, dict):
                http_entity = HttpEntity(
                    url=http_val.get("url"),
                    method=http_val.get("method"),
                    status_code=http_val.get("status_code")
                )
            elif target.get("url"):
                http_entity = HttpEntity(
                    url=target.get("url"),
                    status_code=target.get("status_code")
                )

            user_obj = target.get("user")
            user_name = user_obj.get("name") if isinstance(user_obj, dict) else (user_obj or target.get("username", ""))

            return NormalizedEvent(
                event_id=f"generic-{uuid.uuid4().hex[:12]}",
                timestamp=_parse_iso_or_epoch(target.get("timestamp") or datetime.now(timezone.utc)),
                source_type=hint or target.get("source_type") or "generic",
                original_id=str(target.get("id", "")),
                event_category=cat,
                event_action=str(target.get("action") or target.get("event_action") or "unknown"),
                event_outcome=outcome,
                severity=NormalizedSeverity.LOW,
                source=EndpointEntity(ip=target.get("src_ip") or target.get("srcip")),
                destination=EndpointEntity(ip=target.get("dest_ip") or target.get("dstip")),
                user=UserEntity(name=str(user_name).strip().lower() if user_name else None),
                host=EndpointEntity(host=target.get("host")),
                process=proc_entity,
                http=http_entity,
                signature=str(target.get("signature") or target.get("summary") or target.get("title", "")),
                raw_payload=target,
            )

    except Exception as exc:
        # Robust error isolation - never raise out of normalizer
        pass

    # Safe ultra-fallback
    return NormalizedEvent(
        event_id=f"fallback-{uuid.uuid4().hex[:12]}",
        timestamp=datetime.now(timezone.utc),
        source_type=source_hint or "unknown",
        event_category=EventCategory.CONFIGURATION,
        event_action="unparsed_raw",
        event_outcome=NormalizedOutcome.UNKNOWN,
        severity=NormalizedSeverity.INFORMATIONAL,
        raw_payload=raw_event if isinstance(raw_event, dict) else {"message": str(raw_event)},
    )
