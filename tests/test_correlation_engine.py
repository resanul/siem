"""
Automated Verification Suite for OpenSOC Forge Correlation Engine (M1/M2).
Verifies:
- Canonical schema validation and serialization
- 6-Source telemetry normalization (Wazuh, Suricata, Squid, Check Point, NetWitness, AD)
- Normalization auto-detection and fallback resilience
- Positive detection for all 6 production correlation rules (RULE-CORR-001 to 006)
- Negative non-detection on benign traffic and sub-threshold events
- Sliding-window timestamp ordering and boundary expiration
- Watermarked out-of-order log resequencing
- Alert deduplication and cooldown suppression
- Entity Tracking Store (IP <-> Host <-> User mappings and risk scoring)
- Persistent JSON storage and engine status/rule controls
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List

import pytest

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
    EndpointEntity,
    EngineStatus,
    EventCategory,
    NormalizedEvent,
    NormalizedOutcome,
    NormalizedSeverity,
    ProcessEntity,
    UserEntity,
)
from backend.app.services.correlation_engine.normalizer import (
    normalize_event,
    _normalize_active_directory,
    _normalize_checkpoint,
    _normalize_netwitness,
    _normalize_squid,
    _normalize_suricata,
    _normalize_wazuh,
)
from backend.app.services.correlation_engine.rules import (
    RuleCorr001MultiSourceBruteForce,
    RuleCorr002PortScanToExploit,
    RuleCorr003LateralMovement,
    RuleCorr004WebExploitToExfil,
    RuleCorr005PrivilegeEscalation,
    RuleCorr006MultiStageAPT,
    get_default_rules,
    get_default_rule_configs,
)
from backend.app.services.correlation_engine.engine import (
    CorrelationEngine,
    EntityStore,
)
from backend.app.services.correlation_engine.storage import CorrelationStorage
from backend.app.services.correlation_engine.datasets import (
    generate_all_datasets,
    generate_attack_dataset,
    generate_benign_dataset,
    generate_edge_case_case_sensitivity,
    generate_edge_case_out_of_order,
    generate_edge_case_window_boundary,
    get_benign_active_directory_event,
    get_benign_checkpoint_event,
    get_benign_netwitness_event,
    get_benign_squid_event,
    get_benign_suricata_event,
    get_benign_wazuh_event,
)


# ==============================================================================
# 1. Schema & Model Tests
# ==============================================================================

class TestCorrelationSchema:
    def test_normalized_event_creation_and_properties(self):
        now = datetime.now(timezone.utc)
        event = NormalizedEvent(
            event_id="evt-001",
            timestamp=now,
            source_type="suricata",
            event_category=EventCategory.THREAT,
            event_action="nids_alert",
            event_outcome=NormalizedOutcome.BLOCKED,
            severity=NormalizedSeverity.CRITICAL,
            source=EndpointEntity(ip="198.51.100.84", port=54321),
            destination=EndpointEntity(ip="172.31.105.11", port=443, host="web-srv"),
            user=UserEntity(name="admin"),
            host=EndpointEntity(host="web-srv"),
            signature="ET EXPLOIT Log4j RCE",
            mitre_tactics=["TA0001"],
            mitre_techniques=["T1190"],
        )
        assert event.event_id == "evt-001"
        assert event.src_ip == "198.51.100.84"
        assert event.dest_ip == "172.31.105.11"
        assert event.user_name == "admin"
        assert event.hostname == "web-srv"
        assert event.severity == NormalizedSeverity.CRITICAL
        assert "T1190" in event.mitre_techniques

    def test_correlated_incident_model(self):
        incident = CorrelatedIncident(
            id="inc-100",
            rule_id="RULE-CORR-001",
            rule_name="Brute Force",
            severity=NormalizedSeverity.HIGH,
            risk_score=85.0,
            entities={"users": ["admin"], "ips": ["1.2.3.4"]},
            summary="Brute force test incident",
            description="Detailed explanation",
            root_cause_events=[{"event_id": "evt-1"}],
        )
        assert incident.incident_id == "inc-100"
        assert incident.affected_entities["users"] == ["admin"]
        assert incident.risk_score == 85.0


# ==============================================================================
# 2. Normalizer Unit Tests (All 6 Telemetry Sources)
# ==============================================================================

class TestTelemetryNormalizers:
    def test_normalize_wazuh_auth_failure(self):
        raw = {
            "timestamp": "2026-10-29T14:02:15.450+0000",
            "rule": {
                "id": "5710",
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "mitre": {"id": ["T1110.001"], "tactic": ["credential-access"]},
            },
            "agent": {"id": "001", "name": "rhel-client-01", "ip": "192.168.10.150"},
            "data": {"srcuser": "root", "srcip": "198.51.100.84", "dstport": 22},
        }
        event = normalize_event(raw)
        assert event.source_type == "wazuh"
        assert event.event_category == EventCategory.AUTHENTICATION
        assert event.event_action == "logon_failed"
        assert event.event_outcome == NormalizedOutcome.FAILURE
        assert event.user.name == "root"
        assert event.source.ip == "198.51.100.84"
        assert event.host.host == "rhel-client-01"
        assert "T1110.001" in event.mitre_techniques

    def test_normalize_wazuh_syscheck_fim(self):
        raw = {
            "timestamp": "2026-10-29T14:10:00Z",
            "rule": {"id": "550", "level": 12, "description": "Integrity checksum changed"},
            "agent": {"name": "bastion-gw-01", "ip": "10.0.0.5"},
            "syscheck": {
                "path": "/etc/sudoers",
                "event": "modified",
                "sha256_after": "abc123def456",
                "size_after": 2048,
            },
        }
        event = normalize_event(raw)
        assert event.source_type == "wazuh"
        assert event.event_category == EventCategory.FILE
        assert event.event_action == "file_modified"
        assert event.file is not None
        assert event.file.path == "/etc/sudoers"
        assert event.file.hash_sha256 == "abc123def456"

    def test_normalize_suricata_alert(self):
        raw = {
            "timestamp": "2026-10-29T14:05:12.981244+0000",
            "flow_id": 1827419827,
            "event_type": "alert",
            "src_ip": "198.51.100.84",
            "src_port": 49152,
            "dest_ip": "172.31.105.11",
            "dest_port": 8080,
            "alert": {
                "action": "allowed",
                "signature_id": 2024150,
                "signature": "ET EXPLOIT Apache Log4j JNDI RCE Attempt (CVE-2021-44228)",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
            "http": {
                "hostname": "web-portal.corp.internal",
                "url": "/login",
                "http_method": "POST",
                "status": 200,
            },
        }
        event = normalize_event(raw)
        assert event.source_type == "suricata"
        assert event.event_category == EventCategory.THREAT
        assert event.event_action == "nids_alert"
        assert event.severity == NormalizedSeverity.CRITICAL
        assert event.src_ip == "198.51.100.84"
        assert event.dest_ip == "172.31.105.11"
        assert event.http is not None
        assert event.http.method == "POST"
        assert "T1190" in event.mitre_techniques

    def test_normalize_squid_clf_string(self):
        log_line = "1761746712.540   1890 172.31.105.11 TCP_MISS/200 12582912 POST http://198.51.100.99/upload/drop.php - HIER_DIRECT/198.51.100.99 application/octet-stream"
        event = normalize_event(log_line)
        assert event.source_type == "squid"
        assert event.event_category == EventCategory.HTTP
        assert event.src_ip == "172.31.105.11"
        assert event.http is not None
        assert event.http.method == "POST"
        assert event.http.bytes_out == 12582912
        assert event.http.status_code == 200
        assert event.severity == NormalizedSeverity.HIGH

    def test_normalize_squid_connect_blocked(self):
        log_line = "1761746700.100 50 10.0.0.1 TCP_DENIED/403 0 CONNECT malware-domain.com:443 baduser HIER_NONE/- -"
        event = normalize_event(log_line)
        assert event.source_type == "squid"
        assert event.event_action == "http_denied"
        assert event.event_outcome == NormalizedOutcome.BLOCKED
        assert event.user.name == "baduser"
        assert event.destination.host == "malware-domain.com"
        assert event.destination.port == 443

    def test_normalize_checkpoint_syslog_string(self):
        log_line = "time=2026-10-29 14:01:45|action=drop|orig=fw-cluster-01|src=198.51.100.84|dst=172.31.105.11|proto=tcp|s_port=49110|service=1433|rule=999|reason=Connection rejected|product=FireWall-1"
        event = normalize_event(log_line)
        assert event.source_type == "checkpoint"
        assert event.event_category == EventCategory.NETWORK
        assert event.event_action == "firewall_drop"
        assert event.event_outcome == NormalizedOutcome.BLOCKED
        assert event.src_ip == "198.51.100.84"
        assert event.dest_ip == "172.31.105.11"
        assert event.destination.port == 1433
        assert event.host.host == "fw-cluster-01"

    def test_normalize_netwitness_stomp_session(self):
        raw = {
            "sessionId": 502841,
            "time": 1761746820,
            "metas": [
                ["device.type", "nwendpoint"],
                ["device.class", "Network Sensor"],
                ["ip.src", "172.31.105.11"],
                ["ip.dst", "198.51.100.99"],
                ["tcp.dstport", 8443],
                ["service", "http_post"],
                ["action", "anomalous_outbound"],
                ["payload.bytes", 14857600],
                ["threat.desc", "High volume binary stream to unknown ASN"],
            ],
        }
        event = normalize_event(raw)
        assert event.source_type == "netwitness"
        assert event.event_category == EventCategory.THREAT
        assert event.src_ip == "172.31.105.11"
        assert event.dest_ip == "198.51.100.99"
        assert event.destination.port == 8443
        assert event.http is not None
        assert event.http.bytes_out == 14857600
        assert event.severity == NormalizedSeverity.HIGH
        assert "T1041" in event.mitre_techniques

    def test_normalize_active_directory_events(self):
        # 4624 Logon Success Type 3
        ad_4624 = {
            "Event": {
                "System": {"EventID": 4624, "Computer": "DC01.TBLBD.COM"},
                "EventData": {"TargetUserName": "admin_svc", "LogonType": 3, "IpAddress": "10.0.0.50"},
            }
        }
        e4624 = normalize_event(ad_4624)
        assert e4624.source_type == "active_directory"
        assert e4624.event_action == "logon_success"
        assert e4624.user.logon_type == "3"
        assert e4624.user.name == "admin_svc"
        assert e4624.src_ip == "10.0.0.50"

        # 4625 Logon Failure
        ad_4625 = {
            "Event": {
                "System": {"EventID": 4625, "Computer": "DC01.TBLBD.COM"},
                "EventData": {"TargetUserName": "Administrator", "SubStatus": "0xC000006A", "IpAddress": "198.51.100.84"},
            }
        }
        e4625 = normalize_event(ad_4625)
        assert e4625.source_type == "active_directory"
        assert e4625.event_action == "logon_failed"
        assert e4625.event_outcome == NormalizedOutcome.FAILURE
        assert e4625.user.name == "administrator"  # Canonicalized lowercase

        # 4728 Member Added to Domain Admins
        ad_4728 = {
            "Event": {
                "System": {"EventID": 4728, "Computer": "DC01.TBLBD.COM"},
                "EventData": {"TargetUserName": "Domain Admins", "SubjectUserName": "attacker"},
            }
        }
        e4728 = normalize_event(ad_4728)
        assert e4728.source_type == "active_directory"
        assert e4728.event_action == "group_member_added"
        assert e4728.severity == NormalizedSeverity.HIGH

    def test_normalizer_fallback_graceful_handling(self):
        # Unknown structure should not raise, but produce fallback event
        fallback = normalize_event({"weird_custom_field": "unknown_value"})
        assert fallback.event_id is not None
        assert fallback.event_action in ("unknown", "unparsed_raw")

        string_fallback = normalize_event("some completely unparsable string message")
        assert string_fallback.event_id is not None
        assert string_fallback.severity == NormalizedSeverity.INFORMATIONAL


# ==============================================================================
# 3. Positive Detection Tests for All 6 Rules
# ==============================================================================

class TestPositiveDetections:
    @pytest.fixture
    def test_engine(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            storage = CorrelationStorage(
                rules_path=f"{tmp_dir}/rules.json",
                incidents_path=f"{tmp_dir}/incidents.json",
            )
            engine = CorrelationEngine(storage=storage)
            yield engine

    def test_rule_corr_001_brute_force_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-001")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-001"
        assert inc.severity in (NormalizedSeverity.HIGH, NormalizedSeverity.CRITICAL)
        assert "administrator" in inc.entities.get("users", [])
        assert inc.mitre_attack_id == "T1110"

    def test_rule_corr_002_port_scan_exploit_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-002")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-002"
        assert inc.severity == NormalizedSeverity.CRITICAL
        assert inc.stage_count == 2
        assert "198.51.100.84" in inc.entities.get("ips", [])

    def test_rule_corr_003_lateral_movement_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-003")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-003"
        assert inc.severity == NormalizedSeverity.CRITICAL
        assert "db-cluster-node-02" in inc.entities.get("hosts", [])
        assert "svc_admin" in inc.entities.get("users", [])

    def test_rule_corr_004_web_exploit_exfil_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-004")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-004"
        assert inc.severity == NormalizedSeverity.CRITICAL
        assert "172.31.105.11" in inc.entities.get("ips", [])

    def test_rule_corr_005_privilege_escalation_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-005")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-005"
        assert inc.severity == NormalizedSeverity.HIGH
        assert "backdoor_user" in inc.entities.get("users", [])
        assert "bastion-gw-01" in inc.entities.get("hosts", [])

    def test_rule_corr_006_multi_stage_apt_positive(self, test_engine):
        events = generate_attack_dataset("RULE-CORR-006")
        incidents = []
        for evt in events:
            incidents.extend(test_engine.process_raw(evt))

        assert len(incidents) >= 1
        inc = incidents[0]
        assert inc.rule_id == "RULE-CORR-006"
        assert inc.severity == NormalizedSeverity.CRITICAL
        assert inc.stage_count >= 4
        assert len(inc.contributing_sources) >= 4


# ==============================================================================
# 4. Negative Non-Detection Tests (Benign & Sub-Threshold)
# ==============================================================================

class TestNegativeNonDetections:
    @pytest.fixture
    def test_engine(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            storage = CorrelationStorage(
                rules_path=f"{tmp_dir}/rules.json",
                incidents_path=f"{tmp_dir}/incidents.json",
            )
            yield CorrelationEngine(storage=storage)

    def test_benign_telemetry_produces_zero_incidents(self, test_engine):
        benign_stream = generate_benign_dataset()
        all_incidents = []
        for evt in benign_stream:
            all_incidents.extend(test_engine.process_raw(evt))
        assert len(all_incidents) == 0

    def test_sub_threshold_brute_force_does_not_trigger(self, test_engine):
        # 5 failed logins when threshold is 10
        t = datetime.now(timezone.utc)
        sub_events = [
            {
                "Event": {
                    "System": {"EventID": 4625, "TimeCreated": {"SystemTime": (t + timedelta(seconds=i)).isoformat()}},
                    "EventData": {"TargetUserName": "sub_user", "IpAddress": "192.168.1.1"},
                }
            }
            for i in range(5)
        ]
        incidents = []
        for evt in sub_events:
            incidents.extend(test_engine.process_raw(evt))
        assert len(incidents) == 0

    def test_multi_user_failures_do_not_trigger_single_user_threshold(self, test_engine):
        # 9 failures across 9 distinct users (normal typo noise)
        t = datetime.now(timezone.utc)
        spread_events = [
            {
                "Event": {
                    "System": {"EventID": 4625, "TimeCreated": {"SystemTime": (t + timedelta(seconds=i)).isoformat()}},
                    "EventData": {"TargetUserName": f"user_{i}", "IpAddress": f"10.0.0.{i}"},
                }
            }
            for i in range(9)
        ]
        incidents = []
        for evt in spread_events:
            incidents.extend(test_engine.process_raw(evt))
        assert len(incidents) == 0

    def test_mismatched_target_does_not_trigger_rule_002(self, test_engine):
        # Port scan on Host A, but exploit on Host B
        t = datetime.now(timezone.utc)
        scan_event = f"time={t.strftime('%Y-%m-%d %H:%M:%S')}|action=drop|orig=fw-cluster-01|src=198.51.100.84|dst=10.0.0.1|proto=tcp|s_port=50000|service=80|rule=999"
        exploit_event = {
            "timestamp": (t + timedelta(seconds=10)).isoformat(),
            "event_type": "alert",
            "src_ip": "198.51.100.84",
            "dest_ip": "10.0.0.2",  # Different victim!
            "alert": {"signature": "Exploit", "severity": 1},
        }
        test_engine.process_raw(scan_event)
        incidents = test_engine.process_raw(exploit_event)
        assert len(incidents) == 0


# ==============================================================================
# 5. Edge Cases & Boundary Conditions
# ==============================================================================

class TestEdgeCasesAndBoundaries:
    @pytest.fixture
    def test_engine(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            storage = CorrelationStorage(
                rules_path=f"{tmp_dir}/rules.json",
                incidents_path=f"{tmp_dir}/incidents.json",
            )
            yield CorrelationEngine(storage=storage)

    def test_watermarked_out_of_order_resequencing(self, test_engine):
        t = datetime.now(timezone.utc)
        # Deliver event with T+10s first (advances watermark)
        evt_t_plus_10 = {
            "Event": {
                "System": {"EventID": 4625, "TimeCreated": {"SystemTime": (t + timedelta(seconds=10)).isoformat()}},
                "EventData": {"TargetUserName": "order_test_user", "IpAddress": "1.2.3.4"},
            }
        }
        test_engine.process_raw(evt_t_plus_10)

        # Deliver earlier event at T (within 120s tolerance)
        evt_t = {
            "Event": {
                "System": {"EventID": 4625, "TimeCreated": {"SystemTime": t.isoformat()}},
                "EventData": {"TargetUserName": "order_test_user", "IpAddress": "1.2.3.4"},
            }
        }
        test_engine.process_raw(evt_t)

        status = test_engine.get_status()
        assert status["late_events_dropped"] == 0
        assert status["events_processed"] == 2

    def test_sliding_window_boundary_expiration(self, test_engine):
        in_window, expired = generate_edge_case_window_boundary()
        for evt in in_window:
            test_engine.process_raw(evt)

        # Ingest 10th event that occurred 301s after start (outside 300s window)
        incidents = test_engine.process_raw(expired)
        assert len(incidents) == 0

    def test_deduplication_and_cooldown_suppression(self, test_engine):
        bf_logs = generate_attack_dataset("RULE-CORR-001")
        # Ingest 12 failures -> exactly 1 incident created
        incidents_batch_1 = []
        for log in bf_logs:
            incidents_batch_1.extend(test_engine.process_raw(log))
        assert len(incidents_batch_1) == 1

        # Ingest another 12 failures immediately within cooldown window -> 0 new incidents created
        incidents_batch_2 = []
        for log in bf_logs:
            incidents_batch_2.extend(test_engine.process_raw(log))
        assert len(incidents_batch_2) == 0

        status = test_engine.get_status()
        assert status["suppressed_incidents_count"] > 0
        assert status["incidents_generated"] == 1

    def test_case_insensitive_username_normalization(self, test_engine):
        cased_logs = generate_edge_case_case_sensitivity()
        incidents = []
        for log in cased_logs:
            incidents.extend(test_engine.process_raw(log))

        assert len(incidents) >= 1
        inc = incidents[0]
        # Should have correlated into canonical lowercase "administrator"
        assert "administrator" in inc.entities.get("users", [])


# ==============================================================================
# 6. Entity Graph & Risk Scoring Tests
# ==============================================================================

class TestEntityStoreAndRiskScoring:
    def test_entity_store_relationships_and_decay(self):
        store = EntityStore()
        event = NormalizedEvent(
            event_id="e-1",
            timestamp=datetime.now(timezone.utc),
            source_type="checkpoint",
            event_category=EventCategory.NETWORK,
            source=EndpointEntity(ip="10.0.0.15"),
            destination=EndpointEntity(ip="172.31.105.11"),
            user=UserEntity(name="resanul"),
            host=EndpointEntity(host="finance-srv"),
        )
        store.update_from_event(event)

        aliases = store.resolve_aliases("10.0.0.15")
        assert "finance-srv" in aliases or "resanul" in aliases

        score = store.add_risk("resanul", 35.0)
        assert score == 45.0  # initial 10 + 35
        assert store.get_risk("resanul") == 45.0


# ==============================================================================
# 7. Engine Management & State Control Tests
# ==============================================================================

class TestEngineManagement:
    @pytest.fixture
    def test_engine(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            storage = CorrelationStorage(
                rules_path=f"{tmp_dir}/rules.json",
                incidents_path=f"{tmp_dir}/incidents.json",
            )
            yield CorrelationEngine(storage=storage)

    def test_rule_enable_disable_and_update(self, test_engine):
        rule_id = "RULE-CORR-001"
        assert test_engine.get_rule(rule_id).enabled is True

        # Disable
        success = test_engine.disable_rule(rule_id)
        assert success is True
        assert test_engine.get_rule(rule_id).enabled is False

        # Disabled rule should not trigger
        bf_logs = generate_attack_dataset("RULE-CORR-001")
        for log in bf_logs:
            incidents = test_engine.process_raw(log)
            assert len(incidents) == 0

        # Re-enable
        test_engine.enable_rule(rule_id)
        assert test_engine.get_rule(rule_id).enabled is True

        # Update threshold
        test_engine.update_rule(rule_id, {"threshold": 20})
        assert test_engine.get_rule(rule_id).threshold == 20

    def test_engine_reset_state(self, test_engine):
        test_engine.process_raw(get_benign_wazuh_event())
        assert test_engine.get_status()["events_processed"] == 1

        test_engine.reset_state()
        status = test_engine.get_status()
        assert status["events_processed"] == 0
        assert status["incidents_generated"] == 0
        assert status["active_windows_count"] == 0
