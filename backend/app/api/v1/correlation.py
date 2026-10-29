"""
OpenSOC Forge SIEM Correlation Engine - REST API Router.
Provides production-grade endpoints for engine status, lifecycle control,
rule management, incident drill-down, on-demand evaluation, attack simulation,
and the comprehensive SIEM Detection Capability Matrix.
"""

from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from backend.app.services.correlation_engine import get_correlation_engine
from backend.app.services.correlation_engine.datasets import generate_attack_dataset
from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
    EngineStatus,
    NormalizedSeverity,
)
from backend.app.services.correlation_engine.service import bridge_incident_to_alerts

logger = logging.getLogger("correlation_engine.api")

router = APIRouter()


# ==============================================================================
# Request & Response Models
# ==============================================================================

class EngineControlAction(str, Enum):
    START = "start"
    STOP = "stop"
    RESET = "reset"


class EngineControlRequest(BaseModel):
    action: EngineControlAction = Field(..., description="Action to perform: 'start', 'stop', or 'reset'")


class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = Field(None, description="Enable or disable the correlation rule")
    window_seconds: Optional[int] = Field(None, gt=0, description="Sliding time-window duration in seconds")
    threshold: Optional[int] = Field(None, gt=0, description="Event count trigger threshold")
    cooldown_seconds: Optional[int] = Field(None, ge=0, description="Deduplication cooldown suppression period")
    severity: Optional[NormalizedSeverity] = Field(None, description="Incident severity level")
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Composite entity risk score")


class EvaluateRequest(BaseModel):
    events: List[Union[Dict[str, Any], str]] = Field(default_factory=list, description="List of raw or normalized events")
    source_hint: Optional[str] = Field(None, description="Optional log source hint (wazuh, suricata, etc.)")


# ==============================================================================
# Endpoints
# ==============================================================================

@router.get("/status", response_model=EngineStatus, summary="Get Correlation Engine Status")
def get_status() -> EngineStatus:
    """Returns real-time operational status, event counters, and sliding window metrics."""
    engine = get_correlation_engine()
    st = engine.get_status()
    summary = st.get("entity_store_summary", {})
    active_entities = summary.get("total_tracked_entities", 0)

    return EngineStatus(
        running=st.get("running", True),
        events_processed=st.get("events_processed", 0),
        incidents_generated=st.get("incidents_generated", 0),
        active_windows_count=st.get("active_windows_count", 0),
        active_entities_count=active_entities,
        rules_count=st.get("rules_count", 0),
        active_rules_count=st.get("active_rules_count", 0),
        uptime_seconds=st.get("uptime_seconds", 0.0),
        last_processed_timestamp=engine.watermark,
    )


@router.post("/control", summary="Control Correlation Engine State")
def control_engine(payload: EngineControlRequest) -> Dict[str, Any]:
    """Starts, stops, or resets the Correlation Engine state."""
    engine = get_correlation_engine()
    action = payload.action

    if action == EngineControlAction.START:
        engine.start()
        msg = "Correlation engine resumed successfully."
    elif action == EngineControlAction.STOP:
        engine.stop()
        msg = "Correlation engine paused successfully."
    elif action == EngineControlAction.RESET:
        engine.reset_state()
        msg = "Correlation engine state, sliding windows, and entity caches reset successfully."
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported action: {action}")

    return {
        "status": "SUCCESS",
        "action": action.value,
        "engine_running": engine.is_running,
        "message": msg,
    }


# Convenience control endpoints
@router.post("/start", summary="Start Engine")
def start_engine() -> Dict[str, Any]:
    return control_engine(EngineControlRequest(action=EngineControlAction.START))


@router.post("/stop", summary="Stop Engine")
def stop_engine() -> Dict[str, Any]:
    return control_engine(EngineControlRequest(action=EngineControlAction.STOP))


@router.post("/reset", summary="Reset Engine State")
def reset_engine() -> Dict[str, Any]:
    return control_engine(EngineControlRequest(action=EngineControlAction.RESET))


@router.get("/rules", response_model=List[CorrelationRuleConfig], summary="List Correlation Rules")
def list_rules(
    enabled: Optional[bool] = Query(None, description="Filter rules by enabled state"),
    severity: Optional[str] = Query(None, description="Filter rules by severity"),
) -> List[CorrelationRuleConfig]:
    """Returns the library of detection rules with their sliding windows, thresholds, and MITRE mapping."""
    engine = get_correlation_engine()
    rules = engine.get_rules()

    if enabled is not None:
        rules = [r for r in rules if r.enabled == enabled]
    if severity:
        rules = [r for r in rules if r.severity.value.upper() == severity.upper()]

    return rules


@router.get("/rules/{rule_id}", response_model=CorrelationRuleConfig, summary="Get Rule Configuration")
def get_rule_detail(rule_id: str) -> CorrelationRuleConfig:
    """Returns detailed configuration for a specific correlation rule."""
    engine = get_correlation_engine()
    rule = engine.get_rule(rule_id)
    if not rule:
        # Check canonical format
        canonical_id = f"RULE-CORR-{rule_id.zfill(3)}" if rule_id.isdigit() else rule_id.upper()
        rule = engine.get_rule(canonical_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation rule '{rule_id}' not found.",
        )
    return rule


@router.put("/rules/{rule_id}", response_model=CorrelationRuleConfig, summary="Update Rule Configuration")
def update_rule(rule_id: str, updates: RuleUpdateRequest) -> CorrelationRuleConfig:
    """Updates sliding window length, trigger threshold, cooldown, or enabled state for a rule."""
    engine = get_correlation_engine()
    # Resolve canonical rule ID
    target_id = rule_id
    if not engine.get_rule(target_id):
        canonical_id = f"RULE-CORR-{rule_id.zfill(3)}" if rule_id.isdigit() else rule_id.upper()
        if engine.get_rule(canonical_id):
            target_id = canonical_id

    update_dict = updates.model_dump(exclude_unset=True)
    success = engine.update_rule(target_id, update_dict)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation rule '{rule_id}' not found.",
        )

    updated_rule = engine.get_rule(target_id)
    if not updated_rule:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve updated rule.")
    return updated_rule


@router.post("/rules/{rule_id}/toggle", summary="Toggle Rule Enabled State")
def toggle_rule(rule_id: str) -> Dict[str, Any]:
    """Toggles a correlation rule between enabled and disabled."""
    engine = get_correlation_engine()
    target_id = rule_id
    rule = engine.get_rule(target_id)
    if not rule:
        canonical_id = f"RULE-CORR-{rule_id.zfill(3)}" if rule_id.isdigit() else rule_id.upper()
        rule = engine.get_rule(canonical_id)
        if rule:
            target_id = canonical_id

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation rule '{rule_id}' not found.",
        )

    new_state = not rule.enabled
    if new_state:
        engine.enable_rule(target_id)
    else:
        engine.disable_rule(target_id)

    return {
        "status": "SUCCESS",
        "rule_id": target_id,
        "enabled": new_state,
        "message": f"Rule '{target_id}' is now {'enabled' if new_state else 'disabled'}.",
    }


@router.get("/incidents", response_model=List[CorrelatedIncident], summary="List Correlated Incidents")
def list_incidents(
    limit: int = Query(50, ge=1, le=200, description="Max incidents to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
) -> List[CorrelatedIncident]:
    """Retrieves synthesized correlation incidents with pagination and filtering."""
    engine = get_correlation_engine()
    # Fetch a wider batch to accommodate in-memory filtering
    raw_incidents = engine.get_incidents(limit=limit * 3, offset=offset)

    filtered = raw_incidents
    if severity:
        filtered = [i for i in filtered if i.severity.value.upper() == severity.upper()]
    if rule_id:
        r_clean = rule_id.upper()
        filtered = [i for i in filtered if i.rule_id.upper() == r_clean or r_clean in i.rule_id.upper()]

    return filtered[:limit]


@router.get("/incidents/{incident_id}", summary="Get Incident Detail with Timeline")
def get_incident_detail(incident_id: str) -> Dict[str, Any]:
    """Retrieves full incident dossier with root-cause events and chronological entity timeline."""
    engine = get_correlation_engine()
    inc = engine.get_incident(incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlated incident '{incident_id}' not found.",
        )

    timeline: List[Dict[str, Any]] = []
    for evt in inc.evidence_events:
        if isinstance(evt, dict):
            timeline.append({
                "timestamp": evt.get("timestamp"),
                "source": evt.get("source_type"),
                "category": evt.get("event_category"),
                "action": evt.get("event_action"),
                "host": evt.get("host", {}).get("host") if isinstance(evt.get("host"), dict) else str(evt.get("host")),
                "src_ip": evt.get("source", {}).get("ip") if isinstance(evt.get("source"), dict) else None,
                "dest_ip": evt.get("destination", {}).get("ip") if isinstance(evt.get("destination"), dict) else None,
                "user": evt.get("user", {}).get("name") if isinstance(evt.get("user"), dict) else None,
                "severity": evt.get("severity"),
                "summary": evt.get("signature") or evt.get("event_action"),
            })

    # Sort timeline chronologically
    timeline.sort(key=lambda x: str(x.get("timestamp") or ""))

    incident_data = inc.model_dump()
    incident_data["entity_timeline"] = timeline
    return incident_data


@router.post("/evaluate", summary="Evaluate Events Synchronously")
async def evaluate_events(request: Request) -> Dict[str, Any]:
    """
    Synchronously evaluates raw or normalized telemetry payloads against all enabled
    correlation rules, updating sliding-window buffers and returning triggered incidents.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload.")

    raw_events: List[Any] = []
    source_hint: Optional[str] = None

    if isinstance(body, list):
        raw_events = body
    elif isinstance(body, dict):
        if "events" in body and isinstance(body["events"], list):
            raw_events = body["events"]
            source_hint = body.get("source_hint")
        else:
            raw_events = [body]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a list of events or an object containing an 'events' list.",
        )

    engine = get_correlation_engine()
    triggered_incidents: List[CorrelatedIncident] = []

    for item in raw_events:
        incidents = engine.process_raw(item, source=source_hint)
        for inc in incidents:
            triggered_incidents.append(inc)
            # Ensure bridged into native SIEM alert stores
            bridge_incident_to_alerts(inc)

    return {
        "status": "SUCCESS",
        "evaluated_count": len(raw_events),
        "incidents_count": len(triggered_incidents),
        "incidents": [inc.model_dump() for inc in triggered_incidents],
    }


@router.post("/simulate/{rule_id}", summary="Simulate Multi-Source Attack Scenario")
def simulate_attack(rule_id: str) -> Dict[str, Any]:
    """
    Injects a synthetic multi-source attack log sequence from datasets.py for the specified rule,
    evaluating it against the Correlation Engine and returning the synthesized incident.
    """
    engine = get_correlation_engine()

    # Normalize rule_id
    target_rule_id = rule_id.upper()
    if target_rule_id.isdigit():
        target_rule_id = f"RULE-CORR-{target_rule_id.zfill(3)}"
    elif not target_rule_id.startswith("RULE-CORR-"):
        # e.g. "001" or "1"
        cleaned = "".join(filter(str.isdigit, target_rule_id))
        if cleaned:
            target_rule_id = f"RULE-CORR-{cleaned.zfill(3)}"

    rule = engine.get_rule(target_rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation rule '{rule_id}' not found in rule library.",
        )

    # Ensure rule is enabled for simulation
    if not rule.enabled:
        engine.enable_rule(target_rule_id)

    # Generate synthetic telemetry stream for this attack
    try:
        events = generate_attack_dataset(target_rule_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate simulation dataset for rule '{rule_id}': {exc}",
        )

    # Clear cooldown tracker for this rule so simulation deterministically triggers
    for key in list(engine.cooldown_tracker.keys()):
        if key[0] == target_rule_id:
            engine.cooldown_tracker.pop(key, None)

    # Process events in sequence
    triggered: List[CorrelatedIncident] = []
    for evt in events:
        incs = engine.process_raw(evt)
        for inc in incs:
            triggered.append(inc)
            bridge_incident_to_alerts(inc)

    # If deduplication held active incident, retrieve it
    if not triggered:
        for (r_id, _), inc in engine.active_incidents.items():
            if r_id == target_rule_id:
                triggered.append(inc)
                bridge_incident_to_alerts(inc)
                break

    primary_incident = triggered[0] if triggered else None

    return {
        "status": "SUCCESS",
        "rule_id": target_rule_id,
        "rule_name": rule.name,
        "events_injected": len(events),
        "incidents_triggered": len(triggered),
        "incident": primary_incident.model_dump() if primary_incident else None,
        "message": f"Multi-source attack sequence for rule '{target_rule_id}' executed successfully.",
    }


@router.get("/entities", summary="Get Entity Tracking Graph Summary")
def get_entity_summary() -> Dict[str, Any]:
    """Returns entity tracking store metrics, host-IP-user graph relations, and top risky entities."""
    engine = get_correlation_engine()
    return engine.get_entities()


@router.get("/matrix", summary="SIEM Detection Capability Matrix")
def get_capability_matrix() -> Dict[str, Any]:
    """
    Returns the comprehensive SIEM Detection Capability Matrix evaluating OpenSOC Forge
    against Microsoft Sentinel, Splunk ES, IBM QRadar, Elastic Security, and Wazuh SIEM.
    """
    return {
        "title": "OpenSOC Forge Enterprise SIEM Detection Capability Matrix",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platforms": [
            {
                "name": "OpenSOC Forge",
                "vendor": "OpenSOC Project",
                "architecture": "Modular Microservices (FastAPI / Linux Systemd / Docker / Podman)",
                "correlation_model": "Stateful In-Memory Sliding-Window Buffers & FSM Chains",
                "air_gapped_readiness": "100% Native Offline Capability",
            },
            {
                "name": "Microsoft Sentinel",
                "vendor": "Microsoft",
                "architecture": "Cloud SaaS (Azure Log Analytics / KQL Engine)",
                "correlation_model": "Scheduled KQL Analytics Rules & Fusion Graph AI",
                "air_gapped_readiness": "0% (Cloud Only)",
            },
            {
                "name": "Splunk Enterprise Security",
                "vendor": "Splunk / Cisco",
                "architecture": "Distributed Search Head / Indexer Cluster (SPL)",
                "correlation_model": "Scheduled SavedSearches & Asset/Identity Correlation",
                "air_gapped_readiness": "Supported (High Infrastructure Footprint)",
            },
            {
                "name": "IBM QRadar",
                "vendor": "IBM Security",
                "architecture": "Custom Event Processor (QFlow / AQL / Ariel DB)",
                "correlation_model": "Custom Rules Engine (CRE) Real-Time Stream Processing",
                "air_gapped_readiness": "Supported (On-Premises Appliance / VM)",
            },
            {
                "name": "Elastic Security",
                "vendor": "Elastic",
                "architecture": "Elasticsearch / Kibana (EQL / ES|QL / Lucene)",
                "correlation_model": "EQL Sequence Rules & Threshold Query Rules",
                "air_gapped_readiness": "Supported (Self-Managed Elasticsearch)",
            },
            {
                "name": "Wazuh SIEM",
                "vendor": "Wazuh",
                "architecture": "Wazuh Manager / Analysis Engine (OSSEC Decoder / Ruleset)",
                "correlation_model": "XML Rule Hierarchy with timeframe and frequency",
                "air_gapped_readiness": "Supported (Host & Syslog Driven)",
            },
        ],
        "telemetry_matrix": [
            {
                "source": "Wazuh HIDS",
                "telemetry_type": "Endpoint Detection, FIM, Rootcheck, SCA",
                "normalization": "Canonical ECS-Compatible EndpointEntity & ProcessEntity",
                "support": {
                    "OpenSOC Forge": "Native High-Performance JSON Decoder",
                    "Microsoft Sentinel": "AMA Agent via Syslog / CEF connector",
                    "Splunk ES": "Splunk Add-on for Wazuh",
                    "IBM QRadar": "Wazuh/OSSEC DSM",
                    "Elastic Security": "Wazuh-Elastic Integration",
                    "Wazuh SIEM": "Native Ingestion",
                },
            },
            {
                "source": "Suricata NIDS",
                "telemetry_type": "Network Intrusion Signatures, DNS, Flow, HTTP EVE JSON",
                "normalization": "Canonical ECS Network / Threat Model",
                "support": {
                    "OpenSOC Forge": "Direct Host AF_PACKET & EVE JSON Parser",
                    "Microsoft Sentinel": "Syslog Forwarder to Log Analytics",
                    "Splunk ES": "Splunk Add-on for Suricata",
                    "IBM QRadar": "Suricata DSM",
                    "Elastic Security": "Elastic Agent Suricata Integration",
                    "Wazuh SIEM": "Syslog to Wazuh Analysis Engine",
                },
            },
            {
                "source": "Squid Web Proxy",
                "telemetry_type": "CLF / Custom Access Logs, HTTP CONNECT/POST Egress",
                "normalization": "HttpEntity with Method, URL, Status Code, Bytes In/Out",
                "support": {
                    "OpenSOC Forge": "CLF Regex + JSON Dual Decoder",
                    "Microsoft Sentinel": "CEF via Logstash/AMA",
                    "Splunk ES": "Splunk Add-on for Squid",
                    "IBM QRadar": "Squid DSM",
                    "Elastic Security": "Filebeat Squid Module",
                    "Wazuh SIEM": "Syslog Decoders",
                },
            },
            {
                "source": "Check Point Firewall",
                "telemetry_type": "OPSEC LEA / Syslog Key-Value Connection Drops & Accepts",
                "normalization": "NormalizedCategory.NETWORK with Action & Port mapping",
                "support": {
                    "OpenSOC Forge": "RFC 5424 Key-Value & Pipe Parser",
                    "Microsoft Sentinel": "Data Connector for Check Point",
                    "Splunk ES": "Splunk Add-on for Check Point OPSEC",
                    "IBM QRadar": "Check Point DSM",
                    "Elastic Security": "Filebeat Check Point Module",
                    "Wazuh SIEM": "Check Point Syslog Decoders",
                },
            },
            {
                "source": "RSA NetWitness",
                "telemetry_type": "STOMP Meta Sessions, Deep Packet Metas, Network Sensor",
                "normalization": "Canonical Session Tuple Ingestion",
                "support": {
                    "OpenSOC Forge": "Native STOMP Meta Array Extractor",
                    "Microsoft Sentinel": "Custom REST API Poller",
                    "Splunk ES": "Modular Input / Add-on",
                    "IBM QRadar": "Universal DSM",
                    "Elastic Security": "Custom Logstash Pipeline",
                    "Wazuh SIEM": "External Syslog Forwarding",
                },
            },
            {
                "source": "Active Directory",
                "telemetry_type": "Windows Security Event IDs 4624, 4625, 4672, 4720, 4728, 4769",
                "normalization": "UserEntity with LogonType and Domain Privileges",
                "support": {
                    "OpenSOC Forge": "Windows XML/JSON Event Schema Decoders",
                    "Microsoft Sentinel": "Native Windows Security Events (AMA)",
                    "Splunk ES": "Splunk Add-on for Windows (WinEventLog)",
                    "IBM QRadar": "WinCollect / WEF DSM",
                    "Elastic Security": "Winlogbeat / Windows Integration",
                    "Wazuh SIEM": "Wazuh Agent for Windows",
                },
            },
        ],
        "attack_scenarios": [
            {
                "rule_id": "RULE-CORR-001",
                "name": "Multi-Source Brute Force & Credential Stuffing",
                "mitre_technique": "T1110.001",
                "mitre_tactic": "Credential Access",
                "sources": ["active_directory", "wazuh"],
                "window_seconds": 300,
                "threshold": 10,
                "opensoc_implementation": "Sliding window frequency threshold with successful logon escalation",
                "industry_equivalents": {
                    "Microsoft Sentinel": "KQL: SecurityEvent | where EventID == 4625 | summarize count() by IpAddress | join kind=inner (SecurityEvent | where EventID == 4624)",
                    "Splunk ES": "| tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.src, Authentication.user | where count > 10",
                    "IBM QRadar": "Rule: 'Multiple Login Failures from same IP followed by Login Success'",
                    "Elastic Security": "EQL sequence by source.ip with maxspan=5m [authentication where outcome == 'failure'] with runs=10 [authentication where outcome == 'success']",
                    "Wazuh SIEM": "Rule 5710 (sshd failed login) with frequency=10 and timeframe=300",
                },
            },
            {
                "rule_id": "RULE-CORR-002",
                "name": "Port Scan to Exploit Chain",
                "mitre_technique": "T1046 -> T1190",
                "mitre_tactic": "Discovery -> Initial Access",
                "sources": ["checkpoint", "suricata"],
                "window_seconds": 300,
                "threshold": 15,
                "opensoc_implementation": "Check Point port sweep cardinality >= 15 distinct ports followed by Suricata exploit signature",
                "industry_equivalents": {
                    "Microsoft Sentinel": "Multi-table join (CommonSecurityLog | where Action == 'Drop' | summarize dcount(DestinationPort)) -> SecurityAlert",
                    "Splunk ES": "Correlation search combining Network_Traffic datamodel and Intrusion_Detection datamodel",
                    "IBM QRadar": "CRE rule linking BB:PortScan to BB:ExploitAttempt within 5 minutes",
                    "Elastic Security": "EQL sequence with maxspan=5m [network where event.action == 'drop'] [threat where rule.category == 'exploit']",
                    "Wazuh SIEM": "Composite OSSEC rules linking firewall drop frequency to web attack alert",
                },
            },
            {
                "rule_id": "RULE-CORR-003",
                "name": "Lateral Movement via Pass-the-Hash / Remote Execution",
                "mitre_technique": "T1021.002",
                "mitre_tactic": "Lateral Movement",
                "sources": ["active_directory", "wazuh"],
                "window_seconds": 300,
                "threshold": 2,
                "opensoc_implementation": "AD 4624 LogonType 3/9 followed within 60s by Wazuh process execution (PowerShell/cmd)",
                "industry_equivalents": {
                    "Microsoft Sentinel": "KQL: SecurityEvent where LogonType in (3, 9) | join kind=inner (DeviceProcessEvents)",
                    "Splunk ES": "Correlation Search between Authentication datamodel and Endpoint.Processes datamodel",
                    "IBM QRadar": "CRE rule linking Windows logon event to Endpoint process spawn",
                    "Elastic Security": "EQL sequence by host.name with maxspan=1m [authentication where winlog.logon.type == 3] [process where process.name == 'powershell.exe']",
                    "Wazuh SIEM": "Child rule triggering on agent process event after remote authentication",
                },
            },
            {
                "rule_id": "RULE-CORR-004",
                "name": "Web Exploit to Data Exfiltration",
                "mitre_technique": "T1190 -> T1048",
                "mitre_tactic": "Initial Access -> Exfiltration",
                "sources": ["suricata", "squid"],
                "window_seconds": 300,
                "threshold": 2,
                "opensoc_implementation": "Suricata Web Application Attack followed by Squid HTTP POST egress transfer >= 5MB",
                "industry_equivalents": {
                    "Microsoft Sentinel": "KQL join between Suricata alerts and Web proxy logs",
                    "Splunk ES": "Correlation Search linking Intrusion datamodel to Web.bytes_out > 5000000",
                    "IBM QRadar": "CRE multi-event rule linking exploit signature to outbound high volume flow",
                    "Elastic Security": "EQL sequence [network where suricata.category == 'Web Application Attack'] [network where http.request.method == 'POST' and http.response.bytes > 5000000]",
                    "Wazuh SIEM": "Requires external log correlation script or custom active response",
                },
            },
            {
                "rule_id": "RULE-CORR-005",
                "name": "Privilege Escalation & Persistence",
                "mitre_technique": "T1078 -> T1068",
                "mitre_tactic": "Privilege Escalation -> Persistence",
                "sources": ["active_directory", "wazuh"],
                "window_seconds": 600,
                "threshold": 2,
                "opensoc_implementation": "AD Event 4728 (Domain Admins Group Modification) followed by Wazuh FIM modification of sensitive binaries (/etc/sudoers)",
                "industry_equivalents": {
                    "Microsoft Sentinel": "KQL join between EventID 4728 and File integrity modification tables",
                    "Splunk ES": "Correlation Search linking Change datamodel to Endpoint.Filesystem datamodel",
                    "IBM QRadar": "CRE rule combining Account Management change with File Integrity alert",
                    "Elastic Security": "EQL sequence [iam where event.code == 4728] [file where file.path == '/etc/sudoers']",
                    "Wazuh SIEM": "OSSEC rule matching syscheck modification following user addition",
                },
            },
            {
                "rule_id": "RULE-CORR-006",
                "name": "Multi-Stage APT Campaign",
                "mitre_technique": "T1046 / T1190 / T1071 / T1021 / T1041",
                "mitre_tactic": "Multi-Tactic Full Killchain",
                "sources": ["checkpoint", "suricata", "squid", "active_directory", "netwitness"],
                "window_seconds": 1800,
                "threshold": 4,
                "opensoc_implementation": "Multi-stage campaign across at least 4 distinct sources over an 1800s sliding window",
                "industry_equivalents": {
                    "Microsoft Sentinel": "Fusion ML Graph Analytics across multi-source security incidents",
                    "Splunk ES": "Risk-Based Alerting (RBA) risk score accumulation across MITRE ATT&CK tactics",
                    "IBM QRadar": "Offense chaining multiple offenses linked to single source IP/host",
                    "Elastic Security": "Detection Engine complex EQL sequence with multiple stages and 30m window",
                    "Wazuh SIEM": "Not supported natively across 5+ heterogeneous sensor types",
                },
            },
        ],
        "architectural_advantages": [
            "Microsecond in-memory sliding-window ring buffer per entity",
            "Watermarked late-arriving log resequencing (up to 120s tolerance)",
            "Dual-layer alert deduplication with configurable cooldown suppression",
            "Dynamic entity graph (IP <-> Host <-> User) with automatic composite risk scoring",
            "100% self-contained air-gapped execution without external cloud or license dependencies",
            "Explainable incident evidence dossiers linking root-cause raw telemetry events",
        ],
    }
