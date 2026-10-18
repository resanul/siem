"""
OpenSOC Forge - Event Search Verification Test Suite (M3 / R3).
Verifies POST & GET /api/v1/events/search endpoints, schema compliance,
query parsing and multi-field filtering, live Elasticsearch integration,
resilient local fallback across heterogeneous data sources, boundary values,
and RBAC enforcement.
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import urllib.error

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.schemas import (
    AlertItem,
    AlertSeverity,
    AlertSource,
    AlertStatus,
    EventItem,
    EventSearchRequest,
    EventSearchResponse,
)
from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
from backend.app.api.v1.api import DEMO_ALERTS

client = TestClient(app)


# =============================================================================
# FIXTURES & HELPERS
# =============================================================================

@pytest.fixture(autouse=True)
def preserve_simulation_alerts():
    """Ensure in-memory alerts pool is clean and isolated before/after each test."""
    original = list(LIVE_SIMULATION_ALERTS)
    yield
    LIVE_SIMULATION_ALERTS.clear()
    LIVE_SIMULATION_ALERTS.extend(original)


def get_token_for_user(username: str, password: str) -> str:
    """Helper to authenticate a mock user and return JWT bearer token."""
    res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]


# =============================================================================
# TIER 1: SCHEMA & ENDPOINT PARITY
# =============================================================================

class TestTier1SchemaAndEndpointParity:
    """Verifies POST and GET /api/v1/events/search schema contracts and authentication parity."""

    def test_post_search_status_200_and_top_level_schema(self):
        """POST /api/v1/events/search returns HTTP 200 and schema keys: total_hits, took_ms, indices_searched, events."""
        payload = {"query": "*", "indices": ["*"], "time_range": "24h", "limit": 10}
        res = client.post("/api/v1/events/search", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "total_hits" in data
        assert isinstance(data["total_hits"], int)
        assert data["total_hits"] >= 0
        assert "took_ms" in data
        assert isinstance(data["took_ms"], (int, float))
        assert data["took_ms"] >= 0
        assert "indices_searched" in data
        assert isinstance(data["indices_searched"], list)
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_get_search_endpoint_parity(self):
        """GET /api/v1/events/search returns HTTP 200 with matching schema structure."""
        res = client.get("/api/v1/events/search?query=*&time_range=24h&limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "total_hits" in data
        assert isinstance(data["total_hits"], int)
        assert "took_ms" in data
        assert "indices_searched" in data
        assert isinstance(data["indices_searched"], list)
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_event_item_schema_structure(self):
        """Validate EventItem structure: id, timestamp, index, source_type, host, severity, summary, raw."""
        test_id = f"evt-schema-check-{int(time.time() * 1000)}"
        now_iso = datetime.now(timezone.utc).isoformat()
        LIVE_SIMULATION_ALERTS.append(
            AlertItem(
                id=test_id,
                timestamp=now_iso,
                severity=AlertSeverity.CRITICAL,
                source=AlertSource.SURICATA,
                title="Schema Structure Verification Alert",
                description="Verifies EventItem fields conformance",
                host="web-app-dmz-01",
                raw_payload={"proto": "TCP", "src_port": 54321, "dest_port": 80},
                is_demo=False,
            )
        )

        res = client.post("/api/v1/events/search", json={"query": test_id, "limit": 5})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        ev = next(e for e in data["events"] if e["id"] == test_id)

        assert isinstance(ev["id"], str) and ev["id"] == test_id
        assert isinstance(ev["timestamp"], str)
        assert isinstance(ev["index"], str)
        assert isinstance(ev["source_type"], str)
        assert isinstance(ev["host"], str) and ev["host"] == "web-app-dmz-01"
        assert ev["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        assert isinstance(ev["summary"], str)
        assert isinstance(ev["raw"], dict)
        assert ev["raw"].get("proto") == "TCP"

    def test_default_auth_dev_fallback(self):
        """Unauthenticated request in dev fallback defaults to Platform Admin permissions."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 2})
        assert res.status_code == 200
        data = res.json()
        assert "events" in data

    def test_jwt_bearer_token_auth(self):
        """Authenticated request with valid JWT token for analyst succeeds with HTTP 200."""
        token = get_token_for_user("analyst", "AnalystPass123!")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 2}, headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert "events" in data

    def test_empty_body_defaults_to_wildcard(self):
        """Empty POST body {} defaults to query='*' and limit=50 without validation error."""
        res = client.post("/api/v1/events/search", json={})
        assert res.status_code == 200
        data = res.json()
        assert "events" in data
        assert "total_hits" in data
        assert data["indices_searched"] == ["*"]


# =============================================================================
# TIER 2: WILDCARD & DEFAULT QUERY EXECUTION
# =============================================================================

class TestTier2WildcardAndDefaultQueries:
    """Verifies wildcard and default query behaviors, index expansion, and filtering."""

    def test_wildcard_asterisk_returns_recent_events(self):
        """Query '*' returns list of recent telemetry events."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 20})
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data["events"], list)
        assert data["total_hits"] >= 0

    def test_empty_string_query_returns_recent_events(self):
        """Empty string query '' is normalized to wildcard '*' and returns recent events."""
        res = client.post("/api/v1/events/search", json={"query": "", "limit": 20})
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data["events"], list)
        assert data["total_hits"] >= 0

    def test_custom_indices_parameter_filtering(self):
        """Restricting indices to ['suricata-*'] returns only Suricata events."""
        res = client.post("/api/v1/events/search", json={"query": "*", "indices": ["suricata-*"]})
        assert res.status_code == 200
        data = res.json()
        assert data["indices_searched"] == ["suricata-*"]
        for ev in data["events"]:
            assert "suricata" in ev["index"].lower() or "suricata" in ev["source_type"].lower()

    def test_indices_wildcard_expansion(self):
        """Specifying indices=['*'] correctly searches all indices."""
        res = client.post("/api/v1/events/search", json={"query": "*", "indices": ["*"]})
        assert res.status_code == 200
        data = res.json()
        assert data["indices_searched"] == ["*"]
        assert isinstance(data["events"], list)

    def test_get_endpoint_comma_separated_indices(self):
        """GET endpoint normalizes comma-separated indices into separate pattern filters."""
        res = client.get("/api/v1/events/search?query=*&indices=suricata-*,wazuh-alerts-*&limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "suricata-*" in data["indices_searched"]
        assert "wazuh-alerts-*" in data["indices_searched"]


# =============================================================================
# TIER 3: QUERY PARSING & FILTERING
# =============================================================================

class TestTier3QueryParsingAndFiltering:
    """Verifies KQL/Lucene-style field parsing, keyword matching, and conjunctions."""

    def test_field_filter_by_host(self):
        """Query host:web-app-dmz-01 filters returned events to that specific host."""
        res = client.post("/api/v1/events/search", json={"query": "host:web-app-dmz-01"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert all(ev["host"] == "web-app-dmz-01" for ev in data["events"])

    def test_field_filter_by_host_name_alias(self):
        """Query host.name:web-app-dmz-01 resolves to host attribute."""
        res = client.post("/api/v1/events/search", json={"query": "host.name:web-app-dmz-01"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert all(ev["host"] == "web-app-dmz-01" for ev in data["events"])

    def test_field_filter_by_severity(self):
        """Query severity:CRITICAL returns only CRITICAL severity events."""
        res = client.post("/api/v1/events/search", json={"query": "severity:CRITICAL"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert all(ev["severity"] == "CRITICAL" for ev in data["events"])

    def test_field_filter_by_source_type_or_category(self):
        """Query source_type:suricata* or event.category:network filters to matching category."""
        res = client.post("/api/v1/events/search", json={"query": "source:suricata"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        for ev in data["events"]:
            assert "suricata" in ev["source_type"].lower() or "suricata" in ev["index"].lower()

    def test_free_text_keyword_search(self):
        """Free-text keyword search for 'Log4j' matches in summary or raw payload."""
        res = client.post("/api/v1/events/search", json={"query": "Log4j"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert any("log4j" in ev["summary"].lower() or "log4j" in json.dumps(ev["raw"]).lower() for ev in data["events"])

    def test_conjunction_and_query(self):
        """Conjunction query 'host:web-app-dmz-01 AND severity:CRITICAL' returns events matching both."""
        res = client.post("/api/v1/events/search", json={"query": "host:web-app-dmz-01 AND severity:CRITICAL"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        for ev in data["events"]:
            assert ev["host"] == "web-app-dmz-01"
            assert ev["severity"] == "CRITICAL"

    def test_non_matching_query_returns_zero_hits(self):
        """Non-matching query returns total_hits == 0 and empty events list without error."""
        res = client.post("/api/v1/events/search", json={"query": "non_existent_token_xyz_987654321"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] == 0
        assert data["events"] == []


# =============================================================================
# TIER 4: ELASTICSEARCH INTEGRATION & RESILIENT FALLBACK
# =============================================================================

class TestTier4ElasticsearchAndResilientFallback:
    """Verifies Elasticsearch online normalization and offline multi-source fallback."""

    def test_elasticsearch_online_normalization(self):
        """Mock Elasticsearch online response normalizes hits into EventItem schema."""
        mock_es_payload = {
            "took": 12,
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_id": "mock-es-doc-999",
                        "_index": "suricata-eve-2026.10.18",
                        "_source": {
                            "timestamp": "2026-10-18T14:30:00Z",
                            "source_type": "suricata.eve.alert",
                            "host": "sensor-core-01",
                            "severity": "CRITICAL",
                            "message": "ET EXPLOIT Mock Online Cluster Exploit",
                            "src_ip": "10.0.1.25",
                            "dest_ip": "198.51.100.84",
                        },
                    }
                ],
            },
        }

        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.read.return_value = json.dumps(mock_es_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = client.post("/api/v1/events/search", json={"query": "Mock Online Cluster Exploit"})
            assert res.status_code == 200
            data = res.json()
            assert data["total_hits"] == 1
            assert len(data["events"]) == 1
            ev = data["events"][0]
            assert ev["id"] == "mock-es-doc-999"
            assert ev["host"] == "sensor-core-01"
            assert ev["severity"] == "CRITICAL"
            assert "Mock Online Cluster Exploit" in ev["summary"]

    def test_elasticsearch_offline_graceful_fallback(self):
        """When Elasticsearch is unreachable (URLError), endpoint falls back gracefully to local sources."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": "*"})
            assert res.status_code == 200
            data = res.json()
            assert "events" in data
            assert data["total_hits"] >= 1
            assert isinstance(data["events"], list)

    def test_fallback_queries_in_memory_simulation_alerts(self):
        """Fallback correctly queries and finds in-memory LIVE_SIMULATION_ALERTS."""
        synth_id = f"synth-sim-test-{int(time.time() * 1000)}"
        LIVE_SIMULATION_ALERTS.append(
            AlertItem(
                id=synth_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=AlertSeverity.HIGH,
                source=AlertSource.ENDPOINT,
                title="Simulation Alert In Memory",
                description="Testing simulation alert fallback",
                host="sim-host-verified",
                raw_payload={"tag": "sim_test"},
                is_demo=False,
            )
        )

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": synth_id})
            assert res.status_code == 200
            data = res.json()
            assert data["total_hits"] >= 1
            assert any(ev["id"] == synth_id for ev in data["events"])

    def test_fallback_queries_persisted_alerts(self):
        """Fallback loads and returns alerts from configs/persisted_alerts.json."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 50})
            assert res.status_code == 200
            data = res.json()
            assert isinstance(data["events"], list)
            assert data["total_hits"] >= 1

    def test_fallback_queries_demo_alerts(self):
        """Fallback loads and searches curated DEMO_ALERTS (e.g. Log4j alert ALT-2026-001)."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": "ALT-2026-001"})
            assert res.status_code == 200
            data = res.json()
            assert data["total_hits"] >= 1
            assert any(ev["id"] == "ALT-2026-001" for ev in data["events"])

    def test_fallback_suricata_eve_log_parsing(self, monkeypatch):
        """Fallback parses Suricata EVE json log records and normalizes them into EventItem."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp_eve:
            sample_records = [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "alert",
                    "src_ip": "10.0.1.50",
                    "dest_ip": "198.51.100.22",
                    "in_iface": "eth0",
                    "flow_id": 9988776655,
                    "alert": {"signature": "ET MALWARE Custom Eve Signature Trigger", "severity": 1},
                }
            ]
            for r in sample_records:
                tmp_eve.write(json.dumps(r) + "\n")
            tmp_eve.flush()
            eve_path = tmp_eve.name

        try:
            monkeypatch.setenv("SURICATA_EVE_PATH", eve_path)
            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
                res = client.post("/api/v1/events/search", json={"query": "Custom Eve Signature Trigger"})
                assert res.status_code == 200
                data = res.json()
                assert data["total_hits"] >= 1
                ev = next(e for e in data["events"] if "Custom Eve Signature Trigger" in e["summary"])
                assert ev["index"] == "suricata-eve"
                assert ev["source_type"] == "suricata.eve.alert"
                assert ev["severity"] == "CRITICAL"
        finally:
            if os.path.exists(eve_path):
                os.unlink(eve_path)


# =============================================================================
# TIER 5: BOUNDARY VALUES & ERROR HANDLING
# =============================================================================

class TestTier5BoundaryValuesAndErrorHandling:
    """Verifies limit bounding, error handling, time range filters, RBAC, and robustness."""

    def test_limit_exact_bounding(self):
        """Parameter limit=3 returns at most 3 events."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 3})
        assert res.status_code == 200
        data = res.json()
        assert len(data["events"]) <= 3

    def test_limit_over_maximum_rejection(self):
        """Limit > 200 is rejected with HTTP 422 Unprocessable Entity."""
        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 500})
        assert res_post.status_code == 422

        res_get = client.get("/api/v1/events/search?query=*&limit=500")
        assert res_get.status_code == 422

    def test_limit_zero_rejection(self):
        """Limit = 0 is rejected with HTTP 422 Unprocessable Entity on both GET and POST."""
        res_get = client.get("/api/v1/events/search?query=*&limit=0")
        assert res_get.status_code == 422

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 0})
        assert res_post.status_code == 422

    def test_limit_negative_rejection(self):
        """Negative limit is rejected with HTTP 422 on both GET and POST."""
        res_get = client.get("/api/v1/events/search?query=*&limit=-5")
        assert res_get.status_code == 422

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": -5})
        assert res_post.status_code == 422

    def test_limit_invalid_string_rejection(self):
        """Non-integer limit value is rejected with HTTP 422."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": "invalid_number"})
        assert res.status_code == 422

    @pytest.mark.parametrize("invalid_limit", [
        "invalid_number",
        "abc",
        [10],
        {"limit": 10},
        3.14,
        True,
    ])
    def test_limit_non_integer_type_rejection(self, invalid_limit):
        """Non-integer and non-scalar limit values are rejected with HTTP 422 (never HTTP 500)."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": invalid_limit})
        assert res.status_code == 422

    @pytest.mark.parametrize("extreme_tr", [
        "100000000d",
        "9999999999999999999999999999999999999999999999999999d",
        "100000000h",
    ])
    def test_extreme_time_range_overflow_resilience(self, extreme_tr):
        """Extreme time_range values do not crash server with HTTP 500, falling back safely."""
        res_post = client.post("/api/v1/events/search", json={"query": "*", "time_range": extreme_tr})
        assert res_post.status_code == 200
        assert "events" in res_post.json()

        res_get = client.get(f"/api/v1/events/search?query=*&time_range={extreme_tr}")
        assert res_get.status_code == 200
        assert "events" in res_get.json()

    def test_time_range_window_filtering(self):
        """Time range filtering excludes events outside the specified window."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        recent_time = datetime.now(timezone.utc).isoformat()

        LIVE_SIMULATION_ALERTS.append(
            AlertItem(
                id="evt-old-test-record",
                timestamp=old_time,
                severity=AlertSeverity.LOW,
                source=AlertSource.SYSLOG,
                title="Historical Syslog Entry",
                description="Older than 24h",
                host="time-test-host",
                is_demo=False,
            )
        )
        LIVE_SIMULATION_ALERTS.append(
            AlertItem(
                id="evt-recent-test-record",
                timestamp=recent_time,
                severity=AlertSeverity.LOW,
                source=AlertSource.SYSLOG,
                title="Recent Syslog Entry",
                description="Within 15m",
                host="time-test-host",
                is_demo=False,
            )
        )

        # 15m window should include recent but exclude old
        res_15m = client.post("/api/v1/events/search", json={"query": "host:time-test-host", "time_range": "15m"})
        assert res_15m.status_code == 200
        ids_15m = [e["id"] for e in res_15m.json()["events"]]
        assert "evt-recent-test-record" in ids_15m
        assert "evt-old-test-record" not in ids_15m

        # 'all' time range should include both
        res_all = client.post("/api/v1/events/search", json={"query": "host:time-test-host", "time_range": "all"})
        assert res_all.status_code == 200
        ids_all = [e["id"] for e in res_all.json()["events"]]
        assert "evt-recent-test-record" in ids_all
        assert "evt-old-test-record" in ids_all

    def test_rbac_rejection_for_user_without_permission(self):
        """User with role lacking 'alerts:read' (e.g. operator / Recovery Operator) receives HTTP 403."""
        operator_token = get_token_for_user("operator", "OperatorPass123!")
        headers = {"Authorization": f"Bearer {operator_token}"}

        res_post = client.post("/api/v1/events/search", json={"query": "*"}, headers=headers)
        assert res_post.status_code == 403
        assert "alerts:read" in res_post.json()["detail"]

        res_get = client.get("/api/v1/events/search?query=*", headers=headers)
        assert res_get.status_code == 403

    def test_case_insensitive_matching(self):
        """Token filtering and keyword matching are case-insensitive."""
        res_lower_sev = client.post("/api/v1/events/search", json={"query": "severity:critical"})
        res_upper_sev = client.post("/api/v1/events/search", json={"query": "severity:CRITICAL"})
        assert res_lower_sev.status_code == 200
        assert res_upper_sev.status_code == 200
        assert res_lower_sev.json()["total_hits"] == res_upper_sev.json()["total_hits"]

        res_lower_kw = client.post("/api/v1/events/search", json={"query": "log4j"})
        res_upper_kw = client.post("/api/v1/events/search", json={"query": "LOG4J"})
        assert res_lower_kw.status_code == 200
        assert res_upper_kw.status_code == 200
        assert res_lower_kw.json()["total_hits"] == res_upper_kw.json()["total_hits"]

    def test_malformed_syntax_resilience(self):
        """Endpoint handles malformed query syntax safely without throwing 500 error."""
        malformed_queries = [
            'host:"unclosed_quote',
            'severity:::CRITICAL',
            'AND OR NOT && ||',
            '()[]{}*?^~:\\"\\\\',
            '   ',
        ]
        for q in malformed_queries:
            res = client.post("/api/v1/events/search", json={"query": q})
            assert res.status_code in [200, 400, 422], f"Query '{q}' raised unexpected status {res.status_code}"
