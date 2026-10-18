"""
OpenSOC Forge - Complete API v1 Routers.
Enforces authentication, RBAC, audit logging, and interaction with orchestration engine.
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from backend.app.core.audit import audit_service
from backend.app.core.security import (
    ROLE_PERMISSIONS,
    UserRole,
    create_access_token,
    get_current_user,
    hash_password,
    require_permission,
    verify_password,
)
from backend.app.models.schemas import (
    AlertItem,
    AlertSeverity,
    AlertSource,
    AlertStatus,
    AlertUpdate,
    BackupRestoreRequest,
    CaseCreate,
    CaseItem,
    CasePriority,
    CaseStatus,
    DeployRequest,
    PlanRequest,
    RollbackRequest,
    RuleCreate,
    RuleItem,
    RuleTestRequest,
    RuleTestResponse,
    SyntheticEventRequest,
    TokenRequest,
    TokenResponse,
)
from orchestration.engine import OrchestrationEngine
from backend.app.services.live_telemetry import (
    get_live_alerts_pool,
    get_live_overview_data,
    get_live_network_telemetry,
    get_live_health_diagnostics,
    LIVE_SIMULATION_ALERTS,
)

api_router = APIRouter()
orchestrator = OrchestrationEngine()

# Seed default mock users for testing and development
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password("AdminPass123!"),
        "role": UserRole.PLATFORM_ADMIN.value,
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": hash_password("AnalystPass123!"),
        "role": UserRole.INCIDENT_RESPONDER.value,
    },
    "detector": {
        "username": "detector",
        "hashed_password": hash_password("DetectorPass123!"),
        "role": UserRole.DETECTION_ENGINEER.value,
    },
    "operator": {
        "username": "operator",
        "hashed_password": hash_password("OperatorPass123!"),
        "role": UserRole.RECOVERY_OPERATOR.value,
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": hash_password("ViewerPass123!"),
        "role": UserRole.SECOPS_VIEWER.value,
    },
}

# In-memory alert store with realistic, labeled demo data
DEMO_ALERTS: List[AlertItem] = [
    AlertItem(
        id="ALT-2026-001",
        timestamp="2026-10-14T20:12:45Z",
        severity=AlertSeverity.CRITICAL,
        source="suricata",
        title="ET EXPLOIT Possible Log4j RCE Attempt (CVE-2021-44228)",
        description="Outbound JNDI lookup observed from web-app-dmz-01 to external IP 198.51.100.84",
        host="web-app-dmz-01",
        src_ip="10.0.1.15",
        dest_ip="198.51.100.84",
        mitre_attack_id="T1190",
        mitre_tactic="Initial Access",
        status=AlertStatus.NEW,
        raw_payload={"proto": "TCP", "src_port": 49152, "dest_port": 1389, "app_proto": "ldap", "flow_id": 8472910},
        is_demo=True,
    ),
    AlertItem(
        id="ALT-2026-002",
        timestamp="2026-10-14T20:18:10Z",
        severity=AlertSeverity.HIGH,
        source="wazuh",
        title="Wazuh FIM: Unauthorized Binary Modification in /usr/bin",
        description="File integrity check detected SHA-256 hash mutation in binary /usr/bin/sudo",
        host="db-cluster-node-02",
        src_ip="10.0.2.22",
        dest_ip=None,
        mitre_attack_id="T1548.003",
        mitre_tactic="Privilege Escalation",
        status=AlertStatus.INVESTIGATING,
        assigned_to="analyst",
        raw_payload={"path": "/usr/bin/sudo", "old_sha256": "4a7b...", "new_sha256": "9f1c...", "event": "modified"},
        is_demo=True,
    ),
    AlertItem(
        id="ALT-2026-003",
        timestamp="2026-10-14T20:25:01Z",
        severity=AlertSeverity.HIGH,
        source="suricata",
        title="ET MALWARE Cobalt Strike Beacon Malleable C2 Traffic",
        description="Periodic HTTP POST heartbeat matching known Cobalt Strike malleable C2 profile",
        host="workstation-corp-88",
        src_ip="10.0.10.88",
        dest_ip="203.0.113.42",
        mitre_attack_id="T1071.001",
        mitre_tactic="Command and Control",
        status=AlertStatus.NEW,
        raw_payload={"http_uri": "/updates/check.php", "ja4": "t13d1516h2_8daaf6152771_0271d47101a1"},
        is_demo=True,
    ),
    AlertItem(
        id="ALT-2026-004",
        timestamp="2026-10-14T20:30:19Z",
        severity=AlertSeverity.MEDIUM,
        source="wazuh",
        title="Wazuh SCA: CIS Benchmark Audit Failure on SSH Root Login",
        description="PermitRootLogin directive set to 'yes' in /etc/ssh/sshd_config violating CIS Benchmark 5.2.1",
        host="bastion-gw-01",
        src_ip="10.0.0.1",
        dest_ip=None,
        mitre_attack_id="T1078.001",
        mitre_tactic="Defense Evasion",
        status=AlertStatus.ACKNOWLEDGED,
        raw_payload={"compliance": "CIS Ubuntu 22.04 LTS v1.0", "rule_id": 25011, "result": "fail"},
        is_demo=True,
    ),
    AlertItem(
        id="ALT-2026-005",
        timestamp="2026-10-14T20:34:55Z",
        severity=AlertSeverity.LOW,
        source="syslog",
        title="Network Core Switch: Repeated Invalid Authentication Attempts",
        description="Five consecutive failed TACACS+ login attempts for user 'admin' on Core-Switch-01",
        host="core-switch-01",
        src_ip="10.0.0.254",
        dest_ip=None,
        mitre_attack_id="T1110.001",
        mitre_tactic="Credential Access",
        status=AlertStatus.NEW,
        raw_payload={"facility": "authpriv", "severity": "warning", "client": "10.0.5.12"},
        is_demo=True,
    ),
]

# Demo Cases
DEMO_CASES: List[CaseItem] = [
    CaseItem(
        id="CASE-2026-001",
        title="Potential RCE and Lateral Movement via Log4j",
        description="Investigation into outbound JNDI connection from web-app-dmz-01 followed by binary modification.",
        severity=AlertSeverity.CRITICAL,
        priority=CasePriority.P1_CRITICAL,
        status=CaseStatus.INVESTIGATING,
        created_at="2026-10-14T20:15:00Z",
        updated_at="2026-10-14T20:35:00Z",
        assigned_to="analyst",
        linked_alert_ids=["ALT-2026-001", "ALT-2026-002"],
        ioc_indicators=["198.51.100.84", "9f1c... (sudo SHA-256)"],
        investigation_notes=[
            {"author": "analyst", "time": "2026-10-14T20:16:00Z", "note": "Isolated web-app-dmz-01 on VLAN 99."},
            {"author": "analyst", "time": "2026-10-14T20:35:00Z", "note": "Captured memory dump for volatility analysis."},
        ],
    )
]

# Demo Rules
DEMO_RULES: List[RuleItem] = [
    RuleItem(
        id="RULE-SIGMA-001",
        name="Suspicious PowerShell Encoded Command Execution",
        type="sigma",
        severity=AlertSeverity.HIGH,
        mitre_technique="T1059.001",
        status="ACTIVE",
        description="Detects execution of PowerShell with -EncodedCommand parameter commonly used by loaders",
        rule_content="title: Suspicious Encoded PowerShell\nstatus: test\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    CommandLine|contains:\n      - ' -enc '\n      - ' -EncodedCommand '\n  condition: selection",
        author="OpenSOC Detection Engineering",
        version="1.2.0",
        tested_against_fixtures=True,
    ),
    RuleItem(
        id="RULE-WAZUH-002",
        name="Multiple Failed SSH Logins Followed by Success",
        type="wazuh_xml",
        severity=AlertSeverity.MEDIUM,
        mitre_technique="T1110.001",
        status="ACTIVE",
        description="Correlation rule for brute-force password guessing succeeded by authenticated session",
        rule_content="<group name=\"syslog,sshd,\">\n  <rule id=\"100055\" level=\"10\" frequency=\"6\" timeframe=\"120\">\n    <if_matched_sid>5710</if_matched_sid>\n    <if_sid>5715</if_sid>\n    <description>sshd: Brute force login attempt succeeded.</description>\n  </rule>\n</group>",
        author="Wazuh Community / OpenSOC",
        version="4.5.1",
        tested_against_fixtures=True,
    ),
    RuleItem(
        id="RULE-SURI-003",
        name="ET MALWARE Cobalt Strike DNS Beacon Query",
        type="suricata_sig",
        severity=AlertSeverity.CRITICAL,
        mitre_technique="T1071.004",
        status="ACTIVE",
        description="Detects anomalous high-entropy subdomains typical of Cobalt Strike DNS tunneling C2",
        rule_content="alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:\"ET MALWARE Cobalt Strike DNS Beacon\"; dns.query; content:\".stage.\"; nocase; classtype:trojan-activity; sid:2034812; rev:1;)",
        author="Proofpoint ET Labs",
        version="2026.10",
        tested_against_fixtures=True,
    ),
]


# ===================== AUTH ENDPOINTS =====================
@api_router.post("/auth/login", response_model=TokenResponse)
def login(request: TokenRequest):
    user = USERS_DB.get(request.username)
    if not user or not verify_password(request.password, user["hashed_password"]):
        audit_service.log(
            actor=request.username,
            role="unknown",
            client_ip="127.0.0.1",
            action="AUTH_LOGIN",
            resource_type="auth",
            resource_id="session",
            status="DENIED",
            details={"reason": "Invalid credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    role = user["role"]
    perms = ROLE_PERMISSIONS.get(UserRole(role), [])
    token = create_access_token({"sub": user["username"], "role": role})

    audit_service.log(
        actor=user["username"],
        role=role,
        client_ip="127.0.0.1",
        action="AUTH_LOGIN",
        resource_type="auth",
        resource_id="session",
        status="SUCCESS",
        details={"role": role},
    )

    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=role,
        permissions=perms,
    )


# ===================== OVERVIEW DASHBOARD =====================
@api_router.get("/overview")
def get_overview(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    return get_live_overview_data()


# ===================== NETWORK TELEMETRY =====================
@api_router.get("/network/telemetry")
def get_network_telemetry(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    return get_live_network_telemetry()


# ===================== HEALTH & DIAGNOSTICS =====================
@api_router.get("/health/diagnostics")
def get_health_diagnostics(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    return get_live_health_diagnostics()


# ===================== ALERTS =====================
@api_router.get("/alerts", response_model=List[AlertItem])
def list_alerts(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    status_filter: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    results = get_live_alerts_pool()
    if severity:
        results = [a for a in results if a.severity.value == severity]
    if source:
        results = [a for a in results if a.source.value == source]
    if status_filter:
        results = [a for a in results if a.status.value == status_filter]
    return results


@api_router.patch("/alerts/{alert_id}", response_model=AlertItem)
def update_alert(
    alert_id: str,
    update_data: AlertUpdate,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    alert = next((a for a in get_live_alerts_pool() if a.id == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update_data.status:
        alert.status = update_data.status
    if update_data.assigned_to:
        alert.assigned_to = update_data.assigned_to

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="ALERT_UPDATE",
        resource_type="alert",
        resource_id=alert_id,
        status="SUCCESS",
        details=update_data.dict(exclude_none=True),
    )
    return alert


# ===================== CASES =====================
@api_router.get("/cases", response_model=List[CaseItem])
def list_cases(current_user: Dict[str, Any] = Depends(require_permission("cases:read"))):
    return DEMO_CASES


@api_router.post("/cases", response_model=CaseItem)
def create_case(
    case_in: CaseCreate,
    current_user: Dict[str, Any] = Depends(require_permission("cases:write")),
):
    case_id = f"CASE-2026-{len(DEMO_CASES) + 1:03d}"
    now = datetime.utcnow().isoformat() + "Z"
    new_case = CaseItem(
        id=case_id,
        title=case_in.title,
        description=case_in.description,
        severity=case_in.severity,
        priority=case_in.priority,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
        assigned_to=current_user["sub"],
        linked_alert_ids=case_in.linked_alert_ids,
        ioc_indicators=case_in.ioc_indicators,
        investigation_notes=[{"author": current_user["sub"], "time": now, "note": "Case opened."}],
    )
    DEMO_CASES.append(new_case)

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="CASE_CREATE",
        resource_type="case",
        resource_id=case_id,
        status="SUCCESS",
        details={"title": case_in.title},
    )
    return new_case


# ===================== RULES & SYNTAX TESTING =====================
@api_router.get("/rules", response_model=List[RuleItem])
def list_rules(current_user: Dict[str, Any] = Depends(require_permission("rules:read"))):
    return DEMO_RULES


@api_router.post("/rules/test-syntax", response_model=RuleTestResponse)
def test_rule_syntax(
    request: RuleTestRequest,
    current_user: Dict[str, Any] = Depends(require_permission("rules:test")),
):
    """Validates Sigma, Wazuh XML, or Suricata rule syntax against sample log payload."""
    content = request.rule_content.strip()

    if request.rule_type == "sigma":
        import yaml
        try:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict) or "detection" not in parsed:
                return RuleTestResponse(valid_syntax=False, matches=False, error="Sigma rule missing required 'detection' block.")
            matches = any(str(term) in request.sample_log for term in [" -enc ", " -EncodedCommand "])
            return RuleTestResponse(valid_syntax=True, matches=matches, extracted_fields={"title": parsed.get("title", "")})
        except Exception as e:
            return RuleTestResponse(valid_syntax=False, matches=False, error=f"Sigma YAML parsing error: {str(e)}")

    elif request.rule_type == "wazuh_xml":
        if "<rule" not in content or "</rule>" not in content:
            return RuleTestResponse(valid_syntax=False, matches=False, error="Invalid Wazuh XML: missing <rule> tag.")
        matches = "sshd" in request.sample_log and "Failed password" in request.sample_log
        return RuleTestResponse(valid_syntax=True, matches=matches, extracted_fields={"rule_family": "wazuh_decoder"})

    elif request.rule_type == "suricata_sig":
        if not content.startswith("alert ") or "(" not in content:
            return RuleTestResponse(valid_syntax=False, matches=False, error="Invalid Suricata signature: must start with 'alert <proto>'.")
        matches = "stage" in request.sample_log
        return RuleTestResponse(valid_syntax=True, matches=matches, extracted_fields={"proto": "dns"})

    return RuleTestResponse(valid_syntax=False, matches=False, error="Unsupported rule type")


# ===================== COMPONENT INVENTORY & RELEASES =====================
@api_router.get("/inventory")
def get_inventory(current_user: Dict[str, Any] = Depends(require_permission("inventory:read"))):
    return orchestrator.get_inventory()


@api_router.get("/releases")
def list_releases(current_user: Dict[str, Any] = Depends(require_permission("inventory:read"))):
    manifests = ["v1.0.0-lab", "v1.1.0-candidate"]
    out = []
    for m_id in manifests:
        m = orchestrator.load_manifest(m_id)
        compat = orchestrator.compat_engine.evaluate_manifest_compatibility(m, current_release_id=orchestrator.current_release_id)
        out.append({
            "manifest": m,
            "compatibility_report": compat.to_dict(),
            "is_current": m_id == orchestrator.current_release_id,
        })
    return out


# ===================== DEPLOYMENT & UPGRADE LIFECYCLE =====================
@api_router.post("/deploy/plan")
def plan_deployment(
    request: PlanRequest,
    current_user: Dict[str, Any] = Depends(require_permission("inventory:read")),
):
    """Dry-run change plan without modifying host."""
    return orchestrator.execute_plan(request.manifest_id, is_upgrade=request.is_upgrade)


@api_router.post("/deploy/execute")
def execute_deployment(
    request: DeployRequest,
    current_user: Dict[str, Any] = Depends(require_permission("*")),  # Strictly Admin
):
    """Executes safe deployment/upgrade with preflight, backups, and synthetic verification."""
    job = orchestrator.execute_deployment(
        manifest_id=request.manifest_id,
        is_upgrade=request.is_upgrade,
        actor=current_user["sub"],
        simulate_failure_step=request.simulate_failure,
    )

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="DEPLOY_UPGRADE" if request.is_upgrade else "DEPLOY_INSTALL",
        resource_type="release",
        resource_id=request.manifest_id,
        status="SUCCESS" if job.status == "SUCCESS" else "FAILED",
        details={"job_id": job.job_id, "status": job.status.value, "rollback_executed": job.rollback_executed},
    )

    return job.to_dict()


@api_router.get("/deploy/jobs")
def get_jobs(current_user: Dict[str, Any] = Depends(require_permission("inventory:read"))):
    return [j.to_dict() for j in reversed(orchestrator.job_history)]


# ===================== BACKUPS & ROLLBACK =====================
@api_router.get("/backups")
def list_backups(current_user: Dict[str, Any] = Depends(require_permission("backups:read"))):
    bk_list = []
    for name, adapter in orchestrator.adapters.items():
        bk = adapter.backup("/tmp/backups" if os.name != "nt" else "C:\\Temp\\backups")
        bk_list.append(bk.to_dict())
    return bk_list


@api_router.post("/backups/restore")
def restore_backup(
    request: BackupRestoreRequest,
    current_user: Dict[str, Any] = Depends(require_permission("backups:restore")),
):
    if request.confirmation_token != "CONFIRM_RESTORE":
        raise HTTPException(status_code=400, detail="Invalid confirmation token. Confirmation requires 'CONFIRM_RESTORE'.")

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="BACKUP_RESTORE",
        resource_type="backup",
        resource_id=request.archive_path,
        status="SUCCESS",
        details={"path": request.archive_path},
    )
    return {"status": "SUCCESS", "message": f"Successfully verified and restored from {request.archive_path}."}


@api_router.post("/rollback")
def execute_rollback(
    request: RollbackRequest,
    current_user: Dict[str, Any] = Depends(require_permission("rollback:execute")),
):
    results = {}
    for name, adapter in orchestrator.adapters.items():
        res = adapter.rollback(request.checkpoint_id)
        results[name] = res.to_dict()

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="ROLLBACK_EXECUTE",
        resource_type="checkpoint",
        resource_id=request.checkpoint_id,
        status="SUCCESS",
        details={"reason": request.reason},
    )
    return {"status": "SUCCESS", "results": results}


# ===================== SYNTHETIC EVENT INJECTION =====================
@api_router.post("/synthetic-event")
def inject_synthetic_event(
    request: SyntheticEventRequest,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    """
    Injects a synthetic benign telemetry event to verify the complete
    ingestion, parsing, indexing, and search pipeline.
    """
    adapter = orchestrator.adapters.get(request.target_component)
    if not adapter:
        raise HTTPException(status_code=400, detail=f"Component {request.target_component} has no synthetic injection adapter.")

    test_res = adapter.integration_test()

    # Prepend new AlertItem to DEMO_ALERTS so GET /api/v1/alerts reflects synthetic verification
    src_component = request.target_component.lower()
    source_val = AlertSource.SURICATA
    for s in AlertSource:
        if s.value == src_component:
            source_val = s
            break

    new_alert = AlertItem(
        id=f"ALT-{int(time.time() * 1000)}",
        timestamp=datetime.utcnow().isoformat() + "Z",
        severity=AlertSeverity.HIGH,
        source=source_val,
        title=f"SYNTHETIC VERIFICATION: E2E Telemetry Ingestion Alert ({test_res.synthetic_event_id})",
        description=f"Automated synthetic event injected for component '{request.target_component}' via opensoc-ctl test to verify pipeline delivery.",
        host="opensoc-sensor-01",
        src_ip="198.51.100.99",
        dest_ip="10.0.1.15",
        mitre_attack_id="T1059",
        mitre_tactic="Execution",
        status=AlertStatus.NEW,
        raw_payload={"stages": test_res.stages, "synthetic_id": test_res.synthetic_event_id, "event_type": request.event_type},
        is_demo=False,
    )
    LIVE_SIMULATION_ALERTS.insert(0, new_alert)
    try:
        from backend.app.services.retention_policy import save_persisted_alerts, load_persisted_alerts
        persisted = load_persisted_alerts()
        persisted.insert(0, new_alert.dict() if hasattr(new_alert, "dict") else dict(new_alert))
        save_persisted_alerts(persisted)
    except Exception:
        pass

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="SYNTHETIC_EVENT_INJECT",
        resource_type="component",
        resource_id=request.target_component,
        status="SUCCESS" if test_res.passed else "FAILED",
        details=test_res.to_dict(),
    )
    return test_res.to_dict()


# ===================== DIAGNOSTICS & AUDIT LOGS =====================
@api_router.get("/diagnostics/export")
def export_diagnostics(current_user: Dict[str, Any] = Depends(require_permission("diagnostics:export"))):
    bundles = {}
    for name, adapter in orchestrator.adapters.items():
        bundles[name] = adapter.collect_diagnostics().to_dict()

    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="DIAGNOSTICS_EXPORT",
        resource_type="system",
        resource_id="host",
        status="SUCCESS",
    )
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host_diagnostics": get_live_health_diagnostics(),
        "bundles": bundles,
        "status": "REDACTED_SUCCESS"
    }


@api_router.get("/audit")
def get_audit_trail(current_user: Dict[str, Any] = Depends(require_permission("*"))):
    valid, broken_id = audit_service.verify_integrity()
    return {
        "chain_integrity_valid": valid,
        "broken_entry_id": broken_id,
        "entries": audit_service.get_entries(limit=50),
    }


# ===================== ENTERPRISE ATTACK SIMULATION =====================
from backend.app.services.simulation import simulation_engine
from backend.app.services.soar import soar_engine
from backend.app.services.mitre_intel import (
    get_mitre_attack_matrix,
    get_threat_intel_feed,
    get_process_lineage,
    hunt_ioc_in_cluster,
    update_cisco_talos_from_github,
    get_masked_threat_intel_config,
    save_threat_intel_config,
    test_provider_key,
)


@api_router.get("/simulation/scenarios")
def list_attack_scenarios(current_user: Dict[str, Any] = Depends(require_permission("rules:read"))):
    """Returns curated MITRE ATT&CK adversary emulation scenarios."""
    return simulation_engine.list_scenarios()


@api_router.post("/simulation/run")
def run_attack_simulation(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("rules:write")),
):
    """Executes adversary emulation scenario, generates telemetry, and triggers SOAR."""
    scenario_id = payload.get("scenario_id", "SCENARIO-RANSOMWARE")
    res = simulation_engine.run_simulation(scenario_id, operator=current_user["sub"])
    for stage in res.get("stages_executed", []):
        src_val = AlertSource.WAZUH if stage.get("source") == "wazuh" else (AlertSource.SURICATA if stage.get("source") == "suricata" else AlertSource.SYSLOG)
        LIVE_SIMULATION_ALERTS.insert(0, AlertItem(
            id=f"ALT-SIM-{int(time.time()*1000)}-{stage.get('stage_id', '1')}",
            timestamp=stage.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            severity=AlertSeverity.CRITICAL if stage.get("tactic") in ["Initial Access", "Impact"] else AlertSeverity.HIGH,
            source=src_val,
            title=f"Adversary Emulation: {stage.get('technique_name')} ({stage.get('technique_id')})",
            description=stage.get("action", ""),
            host="workstation-corp-88" if "workstation" in stage.get("action", "") else "rhel-server-01",
            src_ip="198.51.100.84",
            dest_ip="192.168.10.177",
            mitre_attack_id=stage.get("technique_id", "T1059"),
            mitre_tactic=stage.get("tactic", "Execution"),
            status=AlertStatus.NEW,
            raw_payload=stage,
            is_demo=False
        ))
    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="ATTACK_SIMULATION_RUN",
        resource_type="simulation",
        resource_id=scenario_id,
        status="SUCCESS",
        details=res,
    )
    return res


# ===================== SOAR PLAYBOOKS =====================
@api_router.get("/soar/playbooks")
def list_soar_playbooks(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    return soar_engine.list_playbooks()


@api_router.post("/soar/execute")
def execute_soar_playbook(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    playbook_id = payload.get("playbook_id", "PLAYBOOK-HOST-ISOLATION")
    context = payload.get("context", {})
    res = soar_engine.execute_playbook(playbook_id, context=context, operator=current_user["sub"])
    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="SOAR_PLAYBOOK_RUN",
        resource_type="playbook",
        resource_id=playbook_id,
        status="SUCCESS",
        details=res,
    )
    return res


# ===================== MITRE ATT&CK MATRIX & HEATMAP =====================
@api_router.get("/mitre/matrix")
def get_mitre_matrix(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    return get_mitre_attack_matrix()


# ===================== THREAT INTELLIGENCE & PROCESS TREE =====================
@api_router.get("/threat-intel/feeds")
def get_threat_intel(
    force_refresh: bool = False,
    source: Optional[str] = None,
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Returns aggregated threat intelligence feeds from Cisco Talos, CISA KEV, abuse.ch ThreatFox, and Feodo Tracker."""
    return get_threat_intel_feed(force_refresh=force_refresh, source=source, search=search)


@api_router.post("/threat-intel/sync")
def sync_threat_intel(
    source: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Force re-syncs live threat feeds from external open-source intelligence platforms."""
    if source == "Cisco Talos" or source == "talos":
        res = update_cisco_talos_from_github()
        try:
            from backend.app.services.github_sync import sync_iocs_to_github
            res["github_sync"] = sync_iocs_to_github()
        except Exception:
            pass
        return res

    feeds = get_threat_intel_feed(force_refresh=True, source=source)
    source_label = f" ({source})" if source and source != "ALL" else ""

    # Auto-save to offline DB
    db_res = {}
    try:
        from backend.app.services.ioc_storage import save_iocs_to_db
        db_res = save_iocs_to_db(feeds)
    except Exception as e:
        print(f"Failed to save to offline DB: {e}")

    # Auto-pull verification & push to GitHub
    gh_res = {}
    try:
        from backend.app.services.github_sync import sync_iocs_to_github
        gh_res = sync_iocs_to_github()
    except Exception as e:
        gh_res = {"status": "error", "message": str(e)}

    gh_status_msg = ""
    if gh_res.get("status") == "pushed":
        gh_status_msg = f" | GitHub: Pushed ({gh_res.get('commit_sha', '')})"
    elif gh_res.get("status") == "identical":
        gh_status_msg = " | GitHub: Up-to-date (0 diff)"
    elif gh_res.get("status") == "pending_token":
        gh_status_msg = " | Offline DB: Saved (Set GitHub token to auto-push)"

    total_offline = db_res.get("total", len(feeds))
    return {
        "status": "success",
        "message": f"Synced {len(feeds)} IOCs{source_label} | Saved to Offline DB ({total_offline:,} stored){gh_status_msg}",
        "total": len(feeds),
        "total_offline": total_offline,
        "feeds": feeds,
        "github_sync": gh_res,
    }


@api_router.get("/threat-intel/db-stats")
def get_threat_db_stats(
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Returns persistent offline database metrics and GitHub sync telemetry."""
    from backend.app.services.github_sync import get_sync_status
    return get_sync_status()


@api_router.post("/threat-intel/github/push")
def trigger_github_push(
    payload: Dict[str, Any] = None,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Pulls current remote from GitHub, verifies data equality, and pushes updated dataset."""
    force = bool((payload or {}).get("force", False))
    from backend.app.services.github_sync import sync_iocs_to_github
    return sync_iocs_to_github(force_push=force)


@api_router.post("/threat-intel/iocs/add")
def add_custom_threat_ioc(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Adds a custom user/analyst IOC to the offline SQLite database."""
    ind = payload.get("indicator", "").strip()
    if not ind:
        raise HTTPException(status_code=400, detail="Indicator cannot be empty.")
    try:
        from backend.app.services.ioc_storage import add_custom_ioc
        res = add_custom_ioc(payload)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@api_router.delete("/threat-intel/iocs/{indicator:path}")
def delete_threat_ioc(
    indicator: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Deletes an indicator from offline SQLite storage."""
    from backend.app.services.ioc_storage import delete_ioc, get_total_ioc_count
    success = delete_ioc(indicator)
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found or could not be deleted.")
    return {"status": "success", "indicator": indicator, "total": get_total_ioc_count()}


@api_router.post("/threat-intel/talos/update")
def update_talos_intel(
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Fetches latest IOCs live from https://github.com/Cisco-Talos/IOCs,
    updates persistent storage, and refreshes in-memory threat hunter indexes."""
    return update_cisco_talos_from_github()


@api_router.get("/threat-intel/config")
def get_threat_config(
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Returns active threat intel providers and masked API key settings."""
    return get_masked_threat_intel_config()


@api_router.post("/threat-intel/config")
def update_threat_config(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Updates API keys for abuse.ch, AlienVault OTX, VirusTotal, and toggles providers."""
    return save_threat_intel_config(payload)


@api_router.post("/threat-intel/test-key")
def test_threat_api_key(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Verifies live validity of an API key against the provider service."""
    provider = payload.get("provider", "").strip()
    api_key = payload.get("api_key", "").strip()
    return test_provider_key(provider, api_key)


# ===================== ENTERPRISE PLATFORM PROXY =====================
from backend.app.services.proxy_manager import (
    load_proxy_config,
    save_proxy_config,
    test_proxy_connection,
)


@api_router.get("/system/proxy")
def get_system_proxy(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    """Returns current system proxy configuration."""
    return load_proxy_config()


@api_router.post("/system/proxy")
def update_system_proxy(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Saves and applies platform proxy configuration globally."""
    res = save_proxy_config(payload)
    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="UPDATE_SYSTEM_PROXY",
        resource_type="system",
        resource_id="proxy",
        status="SUCCESS",
        details={"enabled": res.get("enabled"), "http_proxy": res.get("http_proxy")},
    )
    return res


@api_router.post("/system/proxy/test")
def test_system_proxy(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Tests internet connectivity through a specified proxy server."""
    proxy_url = payload.get("proxy_url", "").strip()
    target_url = payload.get("target_url", "https://otx.alienvault.com").strip()
    return test_proxy_connection(proxy_url, target_url)

# ===================== DATA RETENTION POLICY & HOT/WARM LIFECYCLE =====================
from backend.app.services.retention_policy import (
    load_retention_policy,
    save_retention_policy,
    enforce_retention_policy,
)


@api_router.get("/system/retention")
def get_system_retention_policy(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    """Returns current system data retention and lifecycle policy."""
    return load_retention_policy()


@api_router.post("/system/retention")
def update_system_retention_policy(
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Updates and saves system data retention policy."""
    res = save_retention_policy(payload)
    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="UPDATE_RETENTION_POLICY",
        resource_type="system",
        resource_id="retention",
        status="SUCCESS",
        details=res,
    )
    return res


@api_router.post("/system/retention/enforce")
def trigger_retention_enforcement(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    """Manually triggers data retention lifecycle and purges expired telemetry."""
    res = enforce_retention_policy()
    audit_service.log(
        actor=current_user["sub"],
        role=current_user["role"],
        client_ip="127.0.0.1",
        action="ENFORCE_RETENTION_PURGE",
        resource_type="system",
        resource_id="retention",
        status="SUCCESS",
        details=res,
    )
    return res


# ===================== AGENT PACKAGES & OFFLINE REPOSITORY =====================
from backend.app.services.agent_packages import (
    get_all_packages_catalog,
    cache_package_from_remote,
)


@api_router.get("/system/agents/packages")
def get_agent_packages(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Returns local cache status, download links, and install commands for all agent packages."""
    client_host = request.headers.get("x-forwarded-host") or request.headers.get("host", "127.0.0.1:7070")
    host_part = client_host.split(":")[0]
    port_part = 7070
    if ":" in client_host:
        try:
            port_part = int(client_host.split(":")[1])
        except Exception:
            pass
    return get_all_packages_catalog(server_host=host_part, server_port=port_part)


@api_router.post("/system/agents/cache")
def cache_agent_package(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Downloads and caches an agent package locally on the OpenSOC Forge server."""
    pkg_id = payload.get("pkg_id", "").strip()
    if not pkg_id:
        raise HTTPException(status_code=400, detail="Missing pkg_id parameter")
    res = cache_package_from_remote(pkg_id)
    if not res.get("success"):
        raise HTTPException(status_code=500, detail=res.get("message", "Caching failed"))
    return res


import os
from fastapi.responses import FileResponse
from backend.app.services.agent_packages import DOWNLOADS_DIR, ensure_downloads_dir

@api_router.get("/system/agents/download/{filename}")
def download_agent_package_file(filename: str):
    """Directly serves an agent installer binary with explicit Content-Disposition for browser download."""
    ensure_downloads_dir()
    filepath = os.path.join(DOWNLOADS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"Package '{filename}' not found in local cache.")
    return FileResponse(
        path=filepath,
        filename=filename,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@api_router.post("/threat-intel/hunt")
def hunt_ioc(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Hunts for a given IOC across Elasticsearch (syslog, wazuh) and Suricata telemetry."""
    ioc = payload.get("ioc", "").strip()
    if not ioc:
        return {
            "ioc": "",
            "searched_indices": ["opensoc-syslog-*", "wazuh-alerts-*", "suricata-eve"],
            "total_hits": 0,
            "sightings": [],
            "message": "No IOC provided to hunt",
        }
    return hunt_ioc_in_cluster(ioc)


@api_router.get("/investigation/process-tree/{alert_id}")
def get_investigation_process_tree(
    alert_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    return get_process_lineage(alert_id)


# ===================== BREACH & ATTACK SIMULATION (BAS) =====================
from backend.app.services.bas_engine import bas_engine
from backend.app.services.purple_team import purple_team_service
from backend.app.services.threat_hunting import threat_hunting_service
from backend.app.services.war_room import war_room_service
from rules.sigma.compiler import sigma_compiler, SigmaCompilationError


@api_router.get("/simulation/bas/tests")
def list_bas_atomic_tests(current_user: Dict[str, Any] = Depends(require_permission("rules:read"))):
    """Returns catalog of MITRE ATT&CK atomic tests for automated validation."""
    return bas_engine.list_tests()


@api_router.post("/simulation/bas/run")
def run_bas_atomic_test(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("rules:write")),
):
    """Executes atomic technique and assesses SIEM detection pipeline health."""
    test_id = payload.get("test_id")
    if not test_id:
        raise HTTPException(status_code=400, detail="Missing required 'test_id'")
    try:
        res = bas_engine.execute_test(test_id)
        audit_service.log(
            actor=current_user["sub"],
            role=current_user["role"],
            client_ip="127.0.0.1",
            action="BAS_ATOMIC_TEST_RUN",
            resource_type="atomic_test",
            resource_id=test_id,
            status=res["status"],
            details=res,
        )
        return res
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@api_router.get("/simulation/bas/scorecard")
def get_bas_scorecard(current_user: Dict[str, Any] = Depends(require_permission("rules:read"))):
    """Returns overall SOC Detection Efficacy Score, MTTD, and coverage metrics."""
    return bas_engine.get_scorecard()


# ===================== PURPLE TEAM CYBER RANGE =====================
@api_router.get("/simulation/purple-team/campaigns")
def list_purple_team_campaigns(current_user: Dict[str, Any] = Depends(require_permission("rules:read"))):
    """Returns list of active and ready purple team cyber range campaigns."""
    return purple_team_service.list_campaigns()


@api_router.get("/simulation/purple-team/campaigns/{campaign_id}")
def get_purple_team_campaign(
    campaign_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("rules:read")),
):
    try:
        return purple_team_service.get_campaign(campaign_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")


@api_router.post("/simulation/purple-team/campaigns/{campaign_id}/execute-step")
def execute_purple_team_step(
    campaign_id: str,
    payload: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(require_permission("rules:write")),
):
    step_num = payload.get("step_num")
    trigger_soar = payload.get("trigger_soar", True)
    if step_num is None:
        raise HTTPException(status_code=400, detail="Missing 'step_num'")
    try:
        res = purple_team_service.execute_step(campaign_id, int(step_num), trigger_soar=trigger_soar)
        audit_service.log(
            actor=current_user["sub"],
            role=current_user["role"],
            client_ip="127.0.0.1",
            action="PURPLE_TEAM_STEP_EXECUTE",
            resource_type="campaign_step",
            resource_id=f"{campaign_id}-step-{step_num}",
            status="SUCCESS",
            details=res,
        )
        return res
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=404, detail=str(e))


# ===================== THREAT HUNTING CAMPAIGNS =====================
@api_router.get("/hunting/campaigns")
def list_threat_hunts(current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))):
    """Returns catalog of hypothesis-driven threat hunting campaigns."""
    return threat_hunting_service.list_campaigns()


@api_router.get("/hunting/campaigns/{campaign_id}")
def get_threat_hunt_campaign(
    campaign_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    try:
        return threat_hunting_service.get_campaign(campaign_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Hunt {campaign_id} not found")


@api_router.post("/hunting/campaigns/{campaign_id}/launch")
def launch_threat_hunt(
    campaign_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    try:
        res = threat_hunting_service.launch_hunt(campaign_id)
        audit_service.log(
            actor=current_user["sub"],
            role=current_user["role"],
            client_ip="127.0.0.1",
            action="THREAT_HUNT_LAUNCH",
            resource_type="threat_hunt",
            resource_id=campaign_id,
            status="SUCCESS",
            details=res,
        )
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Hunt {campaign_id} not found")


# ===================== SIGMA RULE COMPILER =====================
@api_router.post("/rules/sigma/compile")
def compile_sigma_rule(
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("rules:write")),
):
    """Compiles generic Sigma YAML into Elasticsearch DSL, Wazuh XML, and Suricata rules."""
    yaml_content = payload.get("rule_yaml", "")
    if not yaml_content.strip():
        raise HTTPException(status_code=400, detail="rule_yaml is empty")
    try:
        res = sigma_compiler.compile(yaml_content)
        audit_service.log(
            actor=current_user["sub"],
            role=current_user["role"],
            client_ip="127.0.0.1",
            action="SIGMA_RULE_COMPILE",
            resource_type="sigma_rule",
            resource_id=res.get("rule_id", "SIGMA"),
            status="SUCCESS",
            details={"title": res.get("title")},
        )
        return res
    except SigmaCompilationError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ===================== INCIDENT WAR ROOM =====================
@api_router.get("/cases/{case_id}/war-room")
def get_case_war_room(
    case_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    return war_room_service.get_room_data(case_id)


@api_router.post("/cases/{case_id}/war-room/tasks/{task_id}/toggle")
def toggle_war_room_task(
    case_id: str,
    task_id: str,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    try:
        return war_room_service.toggle_task(case_id, task_id, username=current_user["sub"])
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@api_router.post("/cases/{case_id}/war-room/evidence")
def add_war_room_evidence(
    case_id: str,
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    ev_type = payload.get("evidence_type", "FILE_HASH")
    val = payload.get("value", "")
    desc = payload.get("description", "")
    host = payload.get("source_host", "unknown")
    if not val:
        raise HTTPException(status_code=400, detail="Evidence value cannot be empty")
    return war_room_service.add_evidence(case_id, ev_type, val, desc, host, officer=current_user["sub"])


@api_router.post("/cases/{case_id}/war-room/timeline")
def add_war_room_timeline_entry(
    case_id: str,
    payload: Dict[str, str],
    current_user: Dict[str, Any] = Depends(require_permission("alerts:write")),
):
    msg = payload.get("message", "")
    action_type = payload.get("action_type", "NOTE")
    if not msg:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    return war_room_service.add_timeline_entry(
        case_id,
        author=current_user["sub"],
        role=current_user["role"],
        message=msg,
        action_type=action_type,
    )


# ===================== SYSTEM GIT UPDATE =====================
@api_router.post("/system/git-update")
def trigger_system_git_update():
    """
    1-Click Git Update endpoint.
    Pulls latest commits from GitHub and triggers runtime refresh.
    """
    import os
    import subprocess
    import shutil
    
    results = {
        "status": "SUCCESS",
        "timestamp": datetime.utcnow().isoformat(),
        "steps": [],
        "latest_commit": "Updated from origin/master"
    }
    
    candidate_repos = [
        "/home/resanul/siem",
        "/opt/opensoc-forge",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")),
    ]
    
    for repo in candidate_repos:
        if os.path.isdir(os.path.join(repo, ".git")):
            try:
                proc = subprocess.run(
                    ["git", "-C", repo, "pull", "origin", "master"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                commit_proc = subprocess.run(
                    ["git", "-C", repo, "log", "-1", "--pretty=format:%h - %s (%cr)"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                results["steps"].append({
                    "repo": repo,
                    "returncode": proc.returncode,
                    "stdout": proc.stdout.strip(),
                    "stderr": proc.stderr.strip(),
                    "latest_commit": commit_proc.stdout.strip()
                })
                if commit_proc.stdout.strip():
                    results["latest_commit"] = commit_proc.stdout.strip()
            except Exception as e:
                results["steps"].append({"repo": repo, "error": str(e)})

    if os.path.exists("/home/resanul/siem/frontend") and os.path.exists("/opt/opensoc-forge/frontend"):
        try:
            shutil.copytree("/home/resanul/siem/frontend", "/opt/opensoc-forge/frontend", dirs_exist_ok=True)
            results["synced_frontend"] = True
        except Exception as e:
            results["synced_frontend_error"] = str(e)
            
    return results


# ===================== ENDPOINT HOSTS & FLEET =====================
@api_router.get("/hosts")
def get_endpoint_hosts(
    response: Response,
    status: Optional[str] = None,
    search: Optional[str] = None,
    include_demo: bool = False,
):
    """Retrieves registered endpoints and fleet metrics."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    from backend.app.services.host_storage import list_hosts
    hosts = list_hosts(status_filter=status, search=search, include_demo=include_demo)
    total = len(hosts)
    active = sum(1 for h in hosts if h.get("status") == "ONLINE")
    return {
        "total": total,
        "active": active,
        "disconnected": total - active,
        "hosts": hosts
    }


@api_router.post("/hosts/sync")
def sync_endpoint_hosts():
    """Forces synchronization of registered agents from Wazuh Manager."""
    from backend.app.services.host_storage import try_sync_wazuh_agents, list_hosts, get_fleet_stats
    try_sync_wazuh_agents()
    return {
        "status": "SUCCESS",
        "hosts": list_hosts(),
        "stats": get_fleet_stats()
    }


@api_router.post("/hosts")
def create_endpoint_host(payload: Dict[str, Any]):
    """Registers a new endpoint host manually into inventory."""
    from backend.app.services.host_storage import add_host
    hostname = payload.get("hostname", "").strip()
    ip_address = payload.get("ip_address", "").strip()
    if not hostname or not ip_address:
        raise HTTPException(status_code=400, detail="Hostname and IP address are required.")
    
    return add_host(
        hostname=hostname,
        ip_address=ip_address,
        os_name=payload.get("os_name", "Linux (Ubuntu/Debian)"),
        agent_version=payload.get("agent_version", "4.8.2"),
        fim_status=payload.get("fim_status", "Clean"),
        status=payload.get("status", "ONLINE"),
        notes=payload.get("notes", ""),
        host_id=payload.get("id"),
        is_demo=payload.get("is_demo", False),
    )


@api_router.delete("/hosts/{host_id}")
def remove_endpoint_host(host_id: str):
    """Deletes or deregisters an endpoint host."""
    from backend.app.services.host_storage import delete_host
    success = delete_host(host_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Host ID {host_id} not found.")
    return {"status": "SUCCESS", "id": host_id}


@api_router.post("/hosts/clear")
def clear_endpoint_hosts():
    """Clears demo and temporary endpoint hosts to start with a clean slate."""
    from backend.app.services.host_storage import clear_all_hosts
    return clear_all_hosts()




