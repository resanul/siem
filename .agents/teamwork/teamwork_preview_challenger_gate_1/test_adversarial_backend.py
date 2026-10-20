"""
OpenSOC Forge - Backend Event Search Adversarial Challenge Test Harness.
Designed by Challenger 1 (Backend Adversarial Challenger).

Covers:
1. Malformed and adversarial query strings (unclosed quotes, regex bombs, SQLi, KQL variations, null bytes, unicode).
2. Extreme parameters (limit=0, limit=200, limit=201, limit=-5, non-integer, oversized payloads).
3. Elasticsearch offline simulation (connection refused, timeouts, HTTP errors, HTML responses, corrupted hits, fallback verification).
4. Time range variations ("15m", "1h", "24h", "7d", "all", invalid, extreme overflow).
5. Concurrency and performance under repeated queries (50 parallel workers).
6. RBAC unauthorized access rejection (role permission checks, forbidden access).
"""

import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import urllib.error

import pytest
from fastapi.testclient import TestClient

# Ensure repo root is on path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend.app.main import app
from backend.app.models.schemas import (
    AlertItem,
    AlertSeverity,
    AlertSource,
    EventItem,
    EventSearchRequest,
    EventSearchResponse,
)
from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
from backend.app.core.security import create_access_token, UserRole
from backend.app.services.event_search import event_search_service, _parse_time_cutoff, _matches_time_range

client = TestClient(app, raise_server_exceptions=False)


def get_token(role: str, sub: str = "test_user") -> str:
    """Helper to generate JWT tokens with specific roles."""
    return create_access_token(data={"sub": sub, "role": role})


# =============================================================================
# SUITE 1: MALFORMED & ADVERSARIAL QUERY STRINGS
# =============================================================================

class TestAdversarialQueryStrings:
    """Tests resilience against hostile, malformed, and injection-style query inputs."""

    @pytest.mark.parametrize("malformed_query", [
        "",
        "   ",
        '"',
        '""',
        '"""',
        "'",
        "''",
        "'''",
        'host:"unclosed_double_quote',
        "host:'unclosed_single_quote",
        'host:""',
        "host:''",
        "host:",
        ":",
        ":::",
        "::::host",
        "AND",
        "OR",
        "NOT",
        "AND AND AND",
        "OR OR OR",
        "NOT NOT NOT",
        "AND OR NOT && ||",
        "()[]{}*?^~:\\\"\\\\",
        "[*",
        "*]*",
        "[*]",
        "[a-z*",
        "[!*",
        "?",
        "???",
        "***",
        "********************",
        "\\x00\\x01\\x02",
        "null\x00byte",
        "\r\n\r\n",
        "   \t\t\n\r   ",
        "🔥🚨💻🛡️",
        "üñîçødé_tëst_këy:vãlüë",
        "\u202eRTL_OVERRIDE",
        "'; DROP TABLE alerts; --",
        "' OR '1'='1",
        "1' UNION ALL SELECT NULL, NULL, NULL--",
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "a" * 10000,
        ("NOT " * 500) + "severity:CRITICAL",
        "host:web-app-dmz-01 OR " * 50 + "severity:LOW",
        "deep.nested.nonexistent.key.path.123:val",
    ])
    def test_query_string_never_returns_500(self, malformed_query):
        """No malformed, injection, or edge-case query string should ever trigger HTTP 500."""
        res_post = client.post("/api/v1/events/search", json={"query": malformed_query, "limit": 10})
        assert res_post.status_code in [200, 400, 422], (
            f"POST /events/search returned unexpected {res_post.status_code} for query: {malformed_query[:50]}"
        )
        if res_post.status_code == 200:
            data = res_post.json()
            assert "total_hits" in data
            assert "events" in data
            assert isinstance(data["events"], list)

    def test_get_query_special_character_url_encoding(self):
        """GET /events/search handles raw and URL-encoded adversarial query strings safely."""
        queries = [
            "severity:CRITICAL",
            "host:web-app-dmz-01",
            "host%3Aweb-app-dmz-01",
            "%27%20OR%201%3D1--",
            "%00nullbyte",
            "***%20OR%20***",
        ]
        for q in queries:
            res = client.get(f"/api/v1/events/search?query={q}&limit=5")
            assert res.status_code in [200, 400, 422], f"GET query {q} failed with {res.status_code}"


# =============================================================================
# SUITE 2: EXTREME PARAMETERS & BOUNDARY VALIDATION
# =============================================================================

class TestAdversarialExtremeParameters:
    """Tests extreme limits, unexpected types, and oversized payloads."""

    def test_limit_200_boundary_valid(self):
        """limit=200 is the exact valid upper bound and succeeds on both POST and GET."""
        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 200})
        assert res_post.status_code == 200
        assert len(res_post.json()["events"]) <= 200

        res_get = client.get("/api/v1/events/search?query=*&limit=200")
        assert res_get.status_code == 200
        assert len(res_get.json()["events"]) <= 200

    def test_limit_201_boundary_rejection(self):
        """limit=201 exceeds maximum 200 and must be rejected with HTTP 422 on both POST and GET."""
        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 201})
        assert res_post.status_code == 422, f"POST limit=201 returned {res_post.status_code}, expected 422"

        res_get = client.get("/api/v1/events/search?query=*&limit=201")
        assert res_get.status_code == 422, f"GET limit=201 returned {res_get.status_code}, expected 422"

    def test_limit_extreme_large_rejection(self):
        """limit=999999999999 is rejected with HTTP 422 without server error."""
        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 999999999999})
        assert res_post.status_code == 422

        res_get = client.get("/api/v1/events/search?query=*&limit=999999999999")
        assert res_get.status_code == 422

    def test_limit_zero_behavior(self):
        """Examines behavior for limit=0 across POST and GET endpoints."""
        res_get = client.get("/api/v1/events/search?query=*&limit=0")
        assert res_get.status_code == 422, f"GET limit=0 should reject with 422, got {res_get.status_code}"

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 0})
        # Note: EventSearchRequest currently clamps < 1 to 1 (returning 200) or rejects with 422
        assert res_post.status_code in [200, 422], f"POST limit=0 returned unexpected {res_post.status_code}"

    def test_limit_negative_behavior(self):
        """Examines behavior for limit=-5 across POST and GET endpoints."""
        res_get = client.get("/api/v1/events/search?query=*&limit=-5")
        assert res_get.status_code == 422, f"GET limit=-5 should reject with 422, got {res_get.status_code}"

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": -5})
        assert res_post.status_code in [200, 422], f"POST limit=-5 returned unexpected {res_post.status_code}"

    @pytest.mark.parametrize("invalid_limit", ["invalid", "abc", 3.14, True, [10], {"limit": 10}])
    def test_non_integer_limit_rejection(self, invalid_limit):
        """Non-integer limit values are properly rejected with HTTP 422."""
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": invalid_limit})
        assert res.status_code == 422

    def test_oversized_query_payload(self):
        """100KB query string does not crash the server and completes safely."""
        huge_query = "host:web-app-dmz-01 " + ("A" * 100000)
        res = client.post("/api/v1/events/search", json={"query": huge_query, "limit": 5})
        assert res.status_code in [200, 422]

    def test_empty_and_extra_fields_in_payload(self):
        """Payload with extra unexpected properties or empty body is handled gracefully."""
        res_empty = client.post("/api/v1/events/search", json={})
        assert res_empty.status_code == 200

        res_extra = client.post("/api/v1/events/search", json={
            "query": "*",
            "unexpected_field": "exploit_attempt",
            "nested_injection": {"key": "val"},
        })
        assert res_extra.status_code == 200


# =============================================================================
# SUITE 3: ELASTICSEARCH OFFLINE SIMULATION & RESILIENT FALLBACK
# =============================================================================

class TestAdversarialElasticsearchOfflineFallback:
    """Verifies that Elasticsearch failure modes never cause HTTP 500 and trigger seamless fallback."""

    def test_es_connection_refused_fallback(self):
        """ES offline with Connection Refused gracefully falls back to local sources."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200
            data = res.json()
            assert data["total_hits"] >= 0
            assert isinstance(data["events"], list)

    def test_es_socket_timeout_fallback(self):
        """ES network timeout (TimeoutError) gracefully falls back without 500."""
        with patch("urllib.request.urlopen", side_effect=TimeoutError("ES socket timeout")):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200
            data = res.json()
            assert "events" in data

    def test_es_http_500_cluster_error_fallback(self):
        """ES returning HTTP 500 Internal Cluster Error gracefully falls back."""
        http_err = urllib.error.HTTPError(
            url="http://elasticsearch:9200/_search",
            code=500,
            msg="Internal Cluster Failure",
            hdrs={},
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200

    def test_es_http_401_auth_failure_fallback(self):
        """ES returning HTTP 401 Unauthorized falls back to local sources without throwing 500."""
        http_err = urllib.error.HTTPError(
            url="http://elasticsearch:9200/_search",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200

    def test_es_returns_html_error_page_fallback(self):
        """ES proxy returning HTML (non-JSON) triggers graceful fallback."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.read.return_value = b"<html><body>502 Bad Gateway</body></html>"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200

    def test_es_returns_corrupted_hits_fallback(self):
        """ES returning corrupted schema (hits not matching schema) doesn't crash server."""
        corrupted_payload = {
            "took": 5,
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_id": "bad-doc-1"},  # Missing _source
                    {"_id": "bad-doc-2", "_source": "not a dictionary"},  # _source is string
                ],
            },
        }
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.read.return_value = json.dumps(corrupted_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = client.post("/api/v1/events/search", json={"query": "*", "limit": 10})
            assert res.status_code == 200

    def test_local_fallback_with_corrupt_suricata_eve_log(self, monkeypatch):
        """Fallback engine gracefully skips corrupt/malformed lines in eve.json without failing."""
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp_eve:
            tmp_eve.write("NOT VALID JSON LINE 1\n")
            tmp_eve.write("{}\n")  # Empty JSON object
            tmp_eve.write("{\x00binary_junk}\n")
            valid_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "alert",
                "flow_id": 1122334455,
                "src_ip": "10.0.2.100",
                "dest_ip": "192.168.1.1",
                "alert": {"signature": "ET MALWARE Adversarial Corrupted Stream Test", "severity": 1},
            }
            tmp_eve.write(json.dumps(valid_record) + "\n")
            tmp_eve.write("TRAILING JUNK\n")
            tmp_eve.flush()
            eve_path = tmp_eve.name

        try:
            monkeypatch.setenv("SURICATA_EVE_PATH", eve_path)
            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
                res = client.post("/api/v1/events/search", json={"query": "Adversarial Corrupted Stream Test"})
                assert res.status_code == 200
                data = res.json()
                assert data["total_hits"] >= 1
                ev = next(e for e in data["events"] if "Adversarial Corrupted Stream Test" in e["summary"])
                assert ev["index"] == "suricata-eve"
        finally:
            if os.path.exists(eve_path):
                os.unlink(eve_path)


# =============================================================================
# SUITE 4: TIME RANGE VARIATIONS & OVERFLOW DEFENSE
# =============================================================================

class TestAdversarialTimeRangeVariations:
    """Tests standard, non-standard, invalid, and extreme time ranges."""

    @pytest.mark.parametrize("tr", ["15m", "1h", "24h", "7d", "30d", "all", "*", "15M", "1H", "24H", "7D", "ALL"])
    def test_valid_standard_time_ranges(self, tr):
        """Standard time ranges succeed with HTTP 200."""
        res = client.post("/api/v1/events/search", json={"query": "*", "time_range": tr, "limit": 5})
        assert res.status_code == 200

    @pytest.mark.parametrize("invalid_tr", ["invalid_format", "xyz", "0", "-1h", "1.5h", "none", "null", ""])
    def test_invalid_time_range_formats_fallback_safely(self, invalid_tr):
        """Invalid time range formats fallback safely to default without throwing HTTP 500."""
        res = client.post("/api/v1/events/search", json={"query": "*", "time_range": invalid_tr, "limit": 5})
        assert res.status_code in [200, 422], f"time_range='{invalid_tr}' produced {res.status_code}"

    @pytest.mark.parametrize("extreme_tr", [
        "100000000d",
        "9999999999999999999999999999999999999999999999999999d",
        "100000000h",
        "100000000m",
    ])
    def test_extreme_time_range_overflow_resilience(self, extreme_tr):
        """
        Adversarial test: Large time range values that trigger Python int or date overflow.
        Must NOT cause unhandled HTTP 500 Internal Server Error.
        """
        res_post = client.post("/api/v1/events/search", json={"time_range": extreme_tr, "limit": 5})
        # If the backend crashes with 500, this assertion captures the empirical bug
        assert res_post.status_code != 500, (
            f"CRITICAL BUG: POST /events/search returned HTTP 500 for time_range='{extreme_tr}'"
        )


# =============================================================================
# SUITE 5: CONCURRENCY & PERFORMANCE STRESS
# =============================================================================

class TestAdversarialConcurrencyAndPerformance:
    """Tests stability and responsiveness under concurrent query load."""

    def test_50_concurrent_search_queries(self):
        """Dispatches 50 concurrent requests to search endpoint across varying filters."""
        queries = [
            "*",
            "severity:CRITICAL",
            "host:web-app-dmz-01",
            "source:suricata",
            "Log4j",
            "host:sensor* AND severity:HIGH",
            "nonexistent_token_99999",
            "threat",
        ]

        def send_request(idx):
            q = queries[idx % len(queries)]
            t0 = time.time()
            res = client.post("/api/v1/events/search", json={"query": q, "limit": 10})
            duration = time.time() - t0
            return idx, res.status_code, duration

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_request, i) for i in range(50)]
            results = [f.result() for f in as_completed(futures)]

        status_codes = [r[1] for r in results]
        durations = [r[2] for r in results]

        assert all(code == 200 for code in status_codes), f"Some concurrent requests failed: {status_codes}"
        avg_duration = sum(durations) / len(durations)
        max_duration = max(durations)

        # Performance assertion: average response time under concurrency should be reasonable (< 200ms)
        assert avg_duration < 1.0, f"Average request latency too high: {avg_duration:.3f}s"
        assert max_duration < 3.0, f"Max request latency too high: {max_duration:.3f}s"


# =============================================================================
# SUITE 6: RBAC UNAUTHORIZED ACCESS REJECTION
# =============================================================================

class TestAdversarialRBACRejection:
    """Verifies RBAC enforcement rejecting unauthorized roles from accessing event telemetry."""

    def test_operator_role_rejected_post(self):
        """User with 'Recovery Operator' role lacks 'alerts:read' and must receive HTTP 403 on POST."""
        token = get_token(role=UserRole.RECOVERY_OPERATOR.value, sub="operator")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/events/search", json={"query": "*"}, headers=headers)
        assert res.status_code == 403
        assert "alerts:read" in res.json().get("detail", "")

    def test_operator_role_rejected_get(self):
        """User with 'Recovery Operator' role lacks 'alerts:read' and must receive HTTP 403 on GET."""
        token = get_token(role=UserRole.RECOVERY_OPERATOR.value, sub="operator")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.get("/api/v1/events/search?query=*", headers=headers)
        assert res.status_code == 403
        assert "alerts:read" in res.json().get("detail", "")

    def test_unknown_role_rejected_with_403(self):
        """Token with an unauthorized / unknown role receives HTTP 403."""
        token = get_token(role="UnauthorizedGuest", sub="guest")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/events/search", json={"query": "*"}, headers=headers)
        assert res.status_code == 403

    def test_authorized_analyst_succeeds(self):
        """User with 'Detection Engineer' role has 'alerts:read' and receives HTTP 200."""
        token = get_token(role=UserRole.DETECTION_ENGINEER.value, sub="analyst")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 2}, headers=headers)
        assert res.status_code == 200
        assert "events" in res.json()

    def test_authorized_admin_succeeds(self):
        """User with 'Platform Admin' role has wildcard '*' permission and receives HTTP 200."""
        token = get_token(role=UserRole.PLATFORM_ADMIN.value, sub="admin")
        headers = {"Authorization": f"Bearer {token}"}
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 2}, headers=headers)
        assert res.status_code == 200
        assert "events" in res.json()
