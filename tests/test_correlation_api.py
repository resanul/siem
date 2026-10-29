"""
Comprehensive Automated Test Suite for OpenSOC Forge Correlation Engine REST API.
Verifies all endpoints mounted under /api/v1/correlation:
- Status and health metrics
- Lifecycle controls (start, stop, reset)
- Rule catalog, individual rule retrieval, updates, and toggle
- Attack simulation for all 6 correlation rules
- Incident querying, filtering, and timeline drill-down
- Synchronous telemetry evaluation
- Detection Capability Matrix
- Alert bridging to native SIEM stores (LIVE_SIMULATION_ALERTS and persisted_alerts.json)
- Proper HTTP error handling (404, 400, 422)
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.schemas import AlertSource
from backend.app.services.correlation_engine import get_correlation_engine
from backend.app.services.correlation_engine.datasets import (
    generate_rule_001_brute_force_attack,
    get_benign_wazuh_event,
)
from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
from backend.app.services.retention_policy import load_persisted_alerts


@pytest.fixture(autouse=True)
def clean_engine_state():
    """Ensure clean engine state before each test."""
    engine = get_correlation_engine()
    engine.start()
    engine.reset_state()
    yield
    engine.reset_state()


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. Status & Control Tests
# ==============================================================================

def test_get_correlation_status(client):
    """GET /api/v1/correlation/status returns valid EngineStatus schema."""
    resp = client.get("/api/v1/correlation/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "running" in data
    assert "events_processed" in data
    assert "incidents_generated" in data
    assert "active_windows_count" in data
    assert "active_entities_count" in data
    assert "rules_count" in data
    assert data["rules_count"] >= 6
    assert data["active_rules_count"] >= 6
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))


def test_engine_control_lifecycle(client):
    """POST /api/v1/correlation/control executes start, stop, and reset actions."""
    # Stop engine
    resp = client.post("/api/v1/correlation/control", json={"action": "stop"})
    assert resp.status_code == 200
    assert resp.json()["engine_running"] is False

    # Start engine
    resp = client.post("/api/v1/correlation/control", json={"action": "start"})
    assert resp.status_code == 200
    assert resp.json()["engine_running"] is True

    # Reset engine
    resp = client.post("/api/v1/correlation/control", json={"action": "reset"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCESS"

    # Convenience endpoints
    assert client.post("/api/v1/correlation/stop").status_code == 200
    assert client.post("/api/v1/correlation/start").status_code == 200
    assert client.post("/api/v1/correlation/reset").status_code == 200


def test_engine_control_invalid_action(client):
    """POST /api/v1/correlation/control with invalid action returns 422 Unprocessable Entity."""
    resp = client.post("/api/v1/correlation/control", json={"action": "invalid_action"})
    assert resp.status_code == 422


# ==============================================================================
# 2. Rule Management Tests
# ==============================================================================

def test_list_rules(client):
    """GET /api/v1/correlation/rules returns all configured rules."""
    resp = client.get("/api/v1/correlation/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 6
    rule_ids = [r["rule_id"] for r in rules]
    assert "RULE-CORR-001" in rule_ids
    assert "RULE-CORR-002" in rule_ids
    assert "RULE-CORR-003" in rule_ids
    assert "RULE-CORR-004" in rule_ids
    assert "RULE-CORR-005" in rule_ids
    assert "RULE-CORR-006" in rule_ids


def test_list_rules_with_filters(client):
    """GET /api/v1/correlation/rules supports enabled and severity query filters."""
    resp = client.get("/api/v1/correlation/rules?enabled=true")
    assert resp.status_code == 200
    assert all(r["enabled"] is True for r in resp.json())

    resp_sev = client.get("/api/v1/correlation/rules?severity=HIGH")
    assert resp_sev.status_code == 200
    for r in resp_sev.json():
        assert r["severity"].upper() == "HIGH"


def test_get_rule_by_id(client):
    """GET /api/v1/correlation/rules/{rule_id} returns rule configuration."""
    # Full canonical ID
    resp = client.get("/api/v1/correlation/rules/RULE-CORR-001")
    assert resp.status_code == 200
    rule = resp.json()
    assert rule["rule_id"] == "RULE-CORR-001"
    assert rule["mitre_attack_id"] == "T1110"

    # Numeric short ID
    resp_short = client.get("/api/v1/correlation/rules/001")
    assert resp_short.status_code == 200
    assert resp_short.json()["rule_id"] == "RULE-CORR-001"


def test_get_rule_not_found(client):
    """GET /api/v1/correlation/rules/NONEXISTENT returns 404."""
    resp = client.get("/api/v1/correlation/rules/RULE-NONEXISTENT-999")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_update_rule_configuration(client):
    """PUT /api/v1/correlation/rules/{rule_id} modifies window and threshold."""
    payload = {
        "window_seconds": 450,
        "threshold": 12,
        "cooldown_seconds": 900,
        "severity": "CRITICAL",
    }
    resp = client.put("/api/v1/correlation/rules/RULE-CORR-001", json=payload)
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["window_seconds"] == 450
    assert updated["threshold"] == 12
    assert updated["cooldown_seconds"] == 900
    assert updated["severity"] == "CRITICAL"

    # Restore default
    client.put(
        "/api/v1/correlation/rules/RULE-CORR-001",
        json={"window_seconds": 300, "threshold": 10, "cooldown_seconds": 600, "severity": "HIGH"},
    )


def test_update_rule_invalid_payload(client):
    """PUT /api/v1/correlation/rules/{rule_id} rejects invalid parameters."""
    # Negative threshold
    resp = client.put("/api/v1/correlation/rules/RULE-CORR-001", json={"threshold": -5})
    assert resp.status_code == 422


def test_update_rule_not_found(client):
    """PUT /api/v1/correlation/rules/NONEXISTENT returns 404."""
    resp = client.put("/api/v1/correlation/rules/NONEXISTENT", json={"threshold": 5})
    assert resp.status_code == 404


def test_toggle_rule_enabled(client):
    """POST /api/v1/correlation/rules/{rule_id}/toggle inverts enabled state."""
    # First toggle: should disable
    resp1 = client.post("/api/v1/correlation/rules/RULE-CORR-001/toggle")
    assert resp1.status_code == 200
    assert resp1.json()["enabled"] is False

    # Second toggle: should enable
    resp2 = client.post("/api/v1/correlation/rules/RULE-CORR-001/toggle")
    assert resp2.status_code == 200
    assert resp2.json()["enabled"] is True


def test_toggle_rule_not_found(client):
    """POST /api/v1/correlation/rules/NONEXISTENT/toggle returns 404."""
    resp = client.post("/api/v1/correlation/rules/NONEXISTENT/toggle")
    assert resp.status_code == 404


# ==============================================================================
# 3. Attack Simulation Tests
# ==============================================================================

@pytest.mark.parametrize(
    "rule_id",
    [
        "RULE-CORR-001",
        "RULE-CORR-002",
        "RULE-CORR-003",
        "RULE-CORR-004",
        "RULE-CORR-005",
        "RULE-CORR-006",
    ],
)
def test_simulate_attack_all_rules(client, rule_id):
    """POST /api/v1/correlation/simulate/{rule_id} successfully triggers incident for each rule."""
    resp = client.post(f"/api/v1/correlation/simulate/{rule_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["rule_id"] == rule_id
    assert data["events_injected"] > 0
    assert data["incidents_triggered"] >= 1
    assert data["incident"] is not None
    assert data["incident"]["rule_id"] == rule_id
    assert "entities" in data["incident"]


def test_simulate_attack_short_id(client):
    """POST /api/v1/correlation/simulate/001 resolves short rule ID."""
    resp = client.post("/api/v1/correlation/simulate/001")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == "RULE-CORR-001"


def test_simulate_attack_unknown_rule(client):
    """POST /api/v1/correlation/simulate/RULE-CORR-999 returns 404."""
    resp = client.post("/api/v1/correlation/simulate/RULE-CORR-999")
    assert resp.status_code == 404


# ==============================================================================
# 4. Incident Querying & Drill-Down Tests
# ==============================================================================

def test_list_and_get_incident_detail(client):
    """Test incident listing and full detail retrieval including entity timeline."""
    # First simulate an attack to ensure at least one incident exists
    sim_resp = client.post("/api/v1/correlation/simulate/RULE-CORR-001")
    assert sim_resp.status_code == 200
    incident_id = sim_resp.json()["incident"]["id"]

    # List incidents
    list_resp = client.get("/api/v1/correlation/incidents?limit=10")
    assert list_resp.status_code == 200
    incidents = list_resp.json()
    assert len(incidents) >= 1
    assert any(i["id"] == incident_id for i in incidents)

    # Filter incidents by rule_id
    filter_resp = client.get("/api/v1/correlation/incidents?rule_id=RULE-CORR-001")
    assert filter_resp.status_code == 200
    for inc in filter_resp.json():
        assert "RULE-CORR-001" in inc["rule_id"]

    # Get incident detail
    detail_resp = client.get(f"/api/v1/correlation/incidents/{incident_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == incident_id
    assert "entity_timeline" in detail
    assert isinstance(detail["entity_timeline"], list)
    assert len(detail["entity_timeline"]) >= 1
    # Check timeline fields
    timeline_item = detail["entity_timeline"][0]
    assert "timestamp" in timeline_item
    assert "source" in timeline_item
    assert "action" in timeline_item


def test_get_incident_not_found(client):
    """GET /api/v1/correlation/incidents/NONEXISTENT returns 404."""
    resp = client.get("/api/v1/correlation/incidents/INC-NONEXISTENT-999")
    assert resp.status_code == 404


# ==============================================================================
# 5. Synchronous Event Evaluation Tests
# ==============================================================================

def test_evaluate_benign_events(client):
    """POST /api/v1/correlation/evaluate on benign telemetry generates zero incidents."""
    benign_evt = get_benign_wazuh_event()
    resp = client.post("/api/v1/correlation/evaluate", json={"events": [benign_evt]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["evaluated_count"] == 1
    assert data["incidents_count"] == 0


def test_evaluate_attack_sequence(client):
    """POST /api/v1/correlation/evaluate on full attack sequence generates incident."""
    attack_events = generate_rule_001_brute_force_attack()
    resp = client.post("/api/v1/correlation/evaluate", json={"events": attack_events})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["evaluated_count"] == len(attack_events)
    assert data["incidents_count"] >= 1
    assert data["incidents"][0]["rule_id"] == "RULE-CORR-001"


def test_evaluate_invalid_json(client):
    """POST /api/v1/correlation/evaluate with non-JSON payload returns 400."""
    resp = client.post(
        "/api/v1/correlation/evaluate",
        content="non-json-string",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# ==============================================================================
# 6. Detection Capability Matrix & Entity Graph Tests
# ==============================================================================

def test_get_capability_matrix(client):
    """GET /api/v1/correlation/matrix returns comprehensive SIEM matrix across all 6 platforms."""
    resp = client.get("/api/v1/correlation/matrix")
    assert resp.status_code == 200
    matrix = resp.json()

    assert "platforms" in matrix
    platform_names = [p["name"] for p in matrix["platforms"]]
    assert "OpenSOC Forge" in platform_names
    assert "Microsoft Sentinel" in platform_names
    assert "Splunk Enterprise Security" in platform_names
    assert "IBM QRadar" in platform_names
    assert "Elastic Security" in platform_names
    assert "Wazuh SIEM" in platform_names

    assert "telemetry_matrix" in matrix
    sources = [t["source"] for t in matrix["telemetry_matrix"]]
    assert "Wazuh HIDS" in sources
    assert "Suricata NIDS" in sources
    assert "Squid Web Proxy" in sources
    assert "Check Point Firewall" in sources
    assert "RSA NetWitness" in sources
    assert "Active Directory" in sources

    assert "attack_scenarios" in matrix
    assert len(matrix["attack_scenarios"]) == 6
    assert "architectural_advantages" in matrix


def test_get_entities_summary(client):
    """GET /api/v1/correlation/entities returns entity tracking metrics."""
    resp = client.get("/api/v1/correlation/entities")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_tracked_entities" in data
    assert "ip_count" in data
    assert "host_count" in data
    assert "user_count" in data


# ==============================================================================
# 7. Alert Bridging Integration Tests
# ==============================================================================

def test_alert_bridging_into_live_and_persisted_alerts(client):
    """
    Verifies that when a correlation incident is generated:
    1. An AlertItem with source=AlertSource.CORRELATION is placed into LIVE_SIMULATION_ALERTS.
    2. The alert is saved to configs/persisted_alerts.json.
    3. The alert surfaces via GET /api/v1/alerts without breaking existing screens.
    """
    sim_resp = client.post("/api/v1/correlation/simulate/RULE-CORR-001")
    assert sim_resp.status_code == 200
    incident_id = sim_resp.json()["incident"]["id"]

    # Check LIVE_SIMULATION_ALERTS
    correlated_live = [
        a for a in LIVE_SIMULATION_ALERTS
        if a.source == AlertSource.CORRELATION and incident_id in a.id
    ]
    assert len(correlated_live) >= 1, "Bridged alert missing from LIVE_SIMULATION_ALERTS"
    alert = correlated_live[0]
    assert alert.source == AlertSource.CORRELATION
    assert "RULE-CORR-001" in alert.title
    assert alert.mitre_attack_id == "T1110"

    # Check persisted alerts file
    persisted = load_persisted_alerts()
    correlated_persisted = [
        p for p in persisted
        if p.get("source") == "correlation" and incident_id in p.get("id", "")
    ]
    assert len(correlated_persisted) >= 1, "Bridged alert missing from persisted_alerts.json"

    # Check GET /api/v1/alerts endpoint
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    all_alerts = alerts_resp.json()
    found_in_api = any(
        a.get("source") == "correlation" and incident_id in a.get("id", "")
        for a in all_alerts
    )
    assert found_in_api, "Bridged correlation alert not returned by /api/v1/alerts"
