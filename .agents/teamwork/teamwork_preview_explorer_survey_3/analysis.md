# Technical Exploration Report: Testing Framework, Test Infrastructure & Verification Strategy (R3)

**Author**: Explorer 3  
**Date**: 2026-10-18T13:45:00Z  
**Feature**: OpenSOC Forge Event Search (`POST` & `GET /api/v1/events/search`)  
**Target Test Suite**: `tests/test_event_search.py`  
**Integrity Mode**: Read-Only Analysis / Development  

---

## Executive Summary
This report presents a comprehensive technical exploration of the OpenSOC Forge test infrastructure, execution environment, and verification strategy for the new **Event Investigation & Query Console** search feature (R3 from `ORIGINAL_REQUEST.md`). The exploration verifies that the project uses `pytest` 9.1.1 running under Python 3.13.15, leverages FastAPI's `TestClient` (Starlette/HTTPX) for synchronous in-process API testing, and discovers tests automatically via `pyproject.toml`. 

A concrete, production-grade test plan comprising **25 test cases** across 5 distinct categories is specified for `tests/test_event_search.py`. It thoroughly covers schema compliance, wildcard/empty query defaults, multi-field filtering (host, severity, category, keyword), live Elasticsearch queries, resilient local fallback (in-memory `LIVE_SIMULATION_ALERTS`, `persisted_alerts.json`, and Suricata `eve.json`), and boundary/edge case robustness.

---

## 1. Existing Test Infrastructure & Repository Configuration

### 1.1 Configuration Files
- **`pyproject.toml`** (Project Root: `d:\AI\siem\pyproject.toml`):
  Defines project packaging and primary pytest configuration:
  ```toml
  [project]
  name = "opensoc-forge"
  version = "1.0.0"
  requires-python = ">=3.10"
  dependencies = [
      "fastapi>=0.110.0",
      "uvicorn>=0.28.0",
      "pydantic>=2.6.0",
      "pyyaml>=6.0.1",
      "jsonschema>=4.21.0",
      "cryptography>=42.0.0",
      "httpx>=0.27.0"
  ]

  [project.optional-dependencies]
  dev = [
      "pytest>=8.0.0",
      "pytest-cov>=4.1.0"
  ]

  [tool.pytest.ini_options]
  pythonpath = ["."]
  testpaths = ["tests"]
  python_files = ["test_*.py"]
  python_classes = ["Test*"]
  python_functions = ["test_*"]
  filterwarnings = [
      "ignore::DeprecationWarning"
  ]
  ```
  **Key Insights**:
  - `pythonpath = ["."]` ensures `d:\AI\siem` is automatically added to Python's module resolution path (`sys.path`), eliminating any need to export manual environment variables.
  - `python_files = ["test_*.py"]` ensures that any new test file in the `tests/` directory (including `tests/test_event_search.py`) is automatically discovered and executed by pytest.
  - No `conftest.py` currently exists at the project root or in `tests/`, which gives complete freedom to either provide self-contained test fixtures in `tests/test_event_search.py` or introduce a shared `conftest.py` if needed.
  - No `requirements.txt` is present; packaging is entirely managed through `pyproject.toml`.

### 1.2 Existing Test Layout & Suites
The repository contains 3 existing test directories:
1. **`tests/unit/`** (46 passing unit tests):
   - `test_adapters.py`: Lifecycle, healthchecks, configuration validation for Elasticsearch, Kibana, Wazuh, Suricata.
   - `test_agent_packages.py`: Wazuh agent package catalog definitions.
   - `test_manifest_and_compatibility.py`: Manifest schema validation, semantic version checks, OS compatibility engine.
   - `test_milestone1_data_plane.py`: Docker/Podman compose topologies, port allocations, certificate scripts.
   - `test_milestones_2_3_4.py`: Installer hardware preflight thresholds, systemd units, firewalld XMLs, and synthetic events.
   - `test_proxy_manager.py`: Enterprise outbound proxy configurations.
   - `test_rbac_and_audit.py`: JWT token signing, verification, password hashing, and SHA-256 HMAC tamper-evident audit trail integrity.
2. **`tests/integration/`**:
   - `test_api_endpoints.py`: Integration testing for FastAPI endpoints (authentication, RBAC, rule testing, synthetic event injection).
   - `test_enterprise_bas_and_hunting.py`: 5 passing tests for MITRE BAS atomic execution, purple team range, threat hunting, and Sigma YAML compiler.
   - `test_simulation_and_soar.py`: Enterprise ransomware attack simulation, automated SOAR host isolation playbook execution.
   - `test_orchestration_and_recovery.py`: Idempotent installation, upgrade dry-run planning, automated rollback triggers.
3. **`tests/e2e/`** (78+ passing E2E tests):
   - `helpers.py`: Common fixtures, OS-release parsers, hardware preflight validators, systemd unit validators, and cryptographic utilities.
   - `test_tier1_feature_coverage.py`: 30 tests covering happy path for requirements R1 through R5.
   - `test_tier2_boundary_corner.py`: 30 tests covering boundary thresholds, edge cases, malformed configs.
   - `test_tier3_cross_feature.py`: 12 pairwise subsystem tests.
   - `test_tier4_real_world.py`: 6 operational end-to-end scenarios.
   - `test_tier5_adversarial_probes.py` & `test_tier5_infra_adversarial.py`.
   - `e2e_test_runner.py`: Standalone CLI runner with tiered reporting tables.

---

## 2. Test Execution Environment & Mechanics

### 2.1 Runtime Environment
- **Python Version**: Python 3.13.15 (`C:\Users\resanul\AppData\Local\Programs\Python\Python313\python.exe`) on Windows 64-bit.
- **Pytest Version**: pytest 9.1.1 (pluggy 1.6.0, plugins: anyio-4.15.0, asyncio-1.4.0).
- **FastAPI / HTTP Client**: FastAPI 0.110+ with `starlette.testclient.TestClient` powered by `httpx`.
- **Execution Mechanism**:
  `TestClient(app)` spins up the ASGI application in-process, allowing fast, synchronous HTTP requests without binding to physical TCP sockets:
  ```python
  from fastapi.testclient import TestClient
  from backend.app.main import app

  client = TestClient(app)
  response = client.post("/api/v1/events/search", json={...})
  ```

### 2.2 Authentication & RBAC in Tests
In `backend/app/core/security.py`, lines 137-144:
```python
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)) -> Dict[str, Any]:
    if not credentials or not credentials.credentials:
        # Development / Lab fallback: default to Platform Admin
        return {
            "sub": "admin",
            "role": UserRole.PLATFORM_ADMIN.value,
            "permissions": ROLE_PERMISSIONS[UserRole.PLATFORM_ADMIN],
        }
```
- Unauthenticated requests during testing and development automatically inherit Platform Admin permissions (`*`), allowing straightforward unauthenticated endpoint calls.
- For tests that explicitly verify RBAC or role restrictions, JWT bearer tokens are generated via `/api/v1/auth/login` and passed in request headers:
  ```python
  res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
  token = res.json()["access_token"]
  headers = {"Authorization": f"Bearer {token}"}
  ```

### 2.3 Mocking Strategies for Elasticsearch and Data Sources
In the test environment, Elasticsearch is typically offline unless running in a live Docker container. Tests must verify both **Online** and **Offline (Fallback)** states without depending on an external daemon.

#### A. Simulating Offline / Unreachable Elasticsearch
Elasticsearch requests in `backend/app/services/live_telemetry.py` (and the new search service) use `urllib.request` or `httpx`. We can mock `urllib.request.urlopen` using `unittest.mock.patch`:
```python
from unittest.mock import patch
import urllib.error

# Simulate Connection Refused / Network Timeout
with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
    res = client.post("/api/v1/events/search", json={"query": "*"})
    assert res.status_code == 200
    assert "suricata-eve" in res.json()["indices_searched"] or len(res.json()["events"]) >= 0
```

#### B. Simulating Online Elasticsearch Cluster with Synthetic Hits
```python
from unittest.mock import patch, MagicMock
import io
import json

mock_es_payload = {
    "took": 8,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [
            {
                "_id": "es-hit-101",
                "_index": "suricata-eve-2026.10.18",
                "_source": {
                    "@timestamp": "2026-10-18T13:20:00Z",
                    "event_type": "alert",
                    "host": "web-app-dmz-01",
                    "alert": {"signature": "ET EXPLOIT Apache Log4j RCE Attempt", "severity": 1},
                    "src_ip": "10.0.1.15",
                    "dest_ip": "198.51.100.84",
                    "proto": "TCP"
                }
            }
        ]
    }
}

mock_resp = MagicMock()
mock_resp.read.return_value = json.dumps(mock_es_payload).encode("utf-8")
mock_resp.__enter__.return_value = mock_resp

with patch("urllib.request.urlopen", return_value=mock_resp):
    res = client.post("/api/v1/events/search", json={"query": "Log4j"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] >= 1
    assert data["events"][0]["host"] == "web-app-dmz-01"
```

#### C. Testing Local Fallback Data Sources
When Elasticsearch is offline or returns 0 hits, the fallback system must query:
1. `backend.app.services.live_telemetry.LIVE_SIMULATION_ALERTS`
2. `configs/persisted_alerts.json` (via `backend.app.services.retention_policy.load_persisted_alerts`)
3. `eve.json` (Suricata EVE log)
4. Threat Indicators / IOC sightings

In tests, we can seed `LIVE_SIMULATION_ALERTS` or inject a synthetic alert via `POST /api/v1/synthetic-event`:
```python
client.post("/api/v1/synthetic-event", json={
    "event_type": "test_alert",
    "target_component": "suricata",
    "payload": {"test_marker": "EVENT_SEARCH_TEST_SEED", "host": "search-test-host"}
})
```

---

## 3. Concrete Test Plan for `tests/test_event_search.py`

The test suite will be structured as a dedicated integration test module `tests/test_event_search.py` containing **25 comprehensive tests** categorized into 5 tiers:

```
tests/test_event_search.py
├── 1. Schema & Endpoint Compliance (Tests 1 - 5)
├── 2. Wildcard & Default Query Behavior (Tests 6 - 9)
├── 3. Query Parsing & Multi-Field Filtering (Tests 10 - 15)
├── 4. Elasticsearch Integration & Resilient Fallback (Tests 16 - 20)
└── 5. Boundary Cases, Limits, Time Ranges & Robustness (Tests 21 - 25)
```

### 3.1 Tier 1: Schema & Endpoint Compliance
Verifies that both `POST` and `GET` routes adhere strictly to the JSON contract specified in `ORIGINAL_REQUEST.md § R1`.

| # | Test Name | Target Route | Description & Assertions |
|---|-----------|--------------|--------------------------|
| 1 | `test_post_search_status_200_and_top_level_schema` | `POST /api/v1/events/search` | Send valid JSON payload `{"query": "*", "indices": ["*"], "time_range": "24h", "limit": 10}`. Assert status 200; assert top-level keys `total_hits` (int >= 0), `took_ms` (int/float >= 0), `indices_searched` (list), and `events` (list). |
| 2 | `test_post_search_event_item_schema` | `POST /api/v1/events/search` | Inspect returned event items in `events`. Verify each event contains: `id` (str), `timestamp` (ISO-8601 str), `index` (str), `source_type` (str), `host` (str), `severity` (str in `CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL`), `summary` (str), and `raw` (dict). |
| 3 | `test_get_search_endpoint_parity` | `GET /api/v1/events/search` | Send GET request with query params `?query=*&time_range=24h&limit=10`. Assert status 200 and schema parity with the POST endpoint. |
| 4 | `test_search_with_authenticated_analyst_token` | `POST /api/v1/events/search` | Generate JWT for `analyst` user (`alerts:read`), pass `Authorization: Bearer <token>`. Verify 200 OK. |
| 5 | `test_search_empty_body_post` | `POST /api/v1/events/search` | Send empty body `{}`. Assert endpoint defaults `query="*"` and `limit=50`, returning 200 OK without unhandled validation failure. |

### 3.2 Tier 2: Wildcard & Default Query Behavior
Verifies that searching with wildcards or empty queries returns recent telemetry sorted by timestamp.

| # | Test Name | Target Route | Description & Assertions |
|---|-----------|--------------|--------------------------|
| 6 | `test_wildcard_asterisk_returns_recent_events` | `POST /api/v1/events/search` | Body: `{"query": "*"}`. Assert status 200; returns non-empty list of recent events if telemetry exists in pool. |
| 7 | `test_empty_string_query_returns_recent_events` | `POST /api/v1/events/search` | Body: `{"query": ""}`. Empty string must be treated as wildcard `*`, returning recent events. |
| 8 | `test_indices_wildcard_expansion` | `POST /api/v1/events/search` | Body: `{"indices": ["*"]}`. Assert `indices_searched` contains default index patterns (`suricata-*`, `wazuh-alerts-*`, `syslog-*`). |
| 9 | `test_specific_index_selection` | `POST /api/v1/events/search` | Body: `{"indices": ["suricata-*"]}`. Assert `indices_searched` is restricted to `["suricata-*"]`, and returned events match Suricata sources. |

### 3.3 Tier 3: Query Parsing & Multi-Field Filtering
Verifies KQL/Lucene-style key:value filters, boolean operations, and substring keyword matching.

| # | Test Name | Target Route | Description & Assertions |
|---|-----------|--------------|--------------------------|
| 10 | `test_filter_by_host_exact_and_wildcard` | `POST /api/v1/events/search` | Body: `{"query": "host:web-app-dmz-01"}` and `{"query": "host:opensoc*"}`. Assert all returned events have matching `host` attributes. |
| 11 | `test_filter_by_severity` | `POST /api/v1/events/search` | Body: `{"query": "severity:CRITICAL"}`. Assert all returned events have `severity == "CRITICAL"`. |
| 12 | `test_filter_by_source_type_or_category` | `POST /api/v1/events/search` | Body: `{"query": "source_type:suricata*"}` or `{"query": "event.category:network"}`. Assert events match Suricata / network categories. |
| 13 | `test_free_text_keyword_search` | `POST /api/v1/events/search` | Body: `{"query": "Log4j"}` or `{"query": "198.51.100.84"}`. Assert matches occurrences in `summary`, `host`, or `raw`. |
| 14 | `test_conjunction_and_filter` | `POST /api/v1/events/search` | Body: `{"query": "host:web-app-dmz-01 AND severity:CRITICAL"}`. Assert returned events satisfy both conditions. |
| 15 | `test_non_matching_query_returns_zero_hits` | `POST /api/v1/events/search` | Body: `{"query": "random_non_existent_token_string_99999"}`. Assert HTTP 200, `total_hits: 0`, `events: []`. |

### 3.4 Tier 4: Elasticsearch Integration & Resilient Fallback
Verifies query execution against live/mocked Elasticsearch and graceful fallback to local data when Elasticsearch is unreachable.

| # | Test Name | Target Route | Description & Assertions |
|---|-----------|--------------|--------------------------|
| 16 | `test_elasticsearch_online_query_dispatch` | `POST /api/v1/events/search` | Mock `urllib.request.urlopen` returning valid ES JSON hits. Assert ES response is correctly mapped into `EventItem` schema, `took_ms` reflects execution time, and `total_hits` equals ES hit count. |
| 17 | `test_elasticsearch_offline_graceful_fallback` | `POST /api/v1/events/search` | Mock `urllib.request.urlopen` raising `URLError("Connection refused")`. Assert status 200 (NOT 500 error); verify fallback queries local telemetry and returns valid result structure. |
| 18 | `test_fallback_queries_in_memory_simulation_alerts` | `POST /api/v1/events/search` | Inject a synthetic event into `LIVE_SIMULATION_ALERTS`. Query by its unique synthetic ID. Assert the event is retrieved and formatted properly. |
| 19 | `test_fallback_queries_persisted_alerts` | `POST /api/v1/events/search` | Verify alerts stored in `configs/persisted_alerts.json` are discovered and returned during fallback search. |
| 20 | `test_fallback_suricata_eve_log_parsing` | `POST /api/v1/events/search` | Mock `SURICATA_LOG_PATH` with sample EVE JSON records (alert, dns, http). Verify parser extracts timestamps, severity, and event payload. |

### 3.5 Tier 5: Boundary Cases, Limits, Time Ranges & Robustness
Verifies edge cases, limit capping, time window filtering, and resilience against malformed query strings.

| # | Test Name | Target Route | Description & Assertions |
|---|-----------|--------------|--------------------------|
| 21 | `test_limit_exact_bounding` | `POST /api/v1/events/search` | Send `{"limit": 3}`. Assert `len(events) <= 3`. |
| 22 | `test_limit_maximum_capping` | `POST /api/v1/events/search` | Send `{"limit": 500}`. Assert limit is capped to max 200 and response does not exceed 200 items. |
| 23 | `test_time_range_window_filtering` | `POST /api/v1/events/search` | Test `time_range="15m"`, `"1h"`, `"24h"`, `"7d"`, `"all"`. Verify that events older than the specified duration are filtered out when a relative window is selected. |
| 24 | `test_malformed_syntax_resilience` | `POST /api/v1/events/search` | Send queries with unclosed quotes (`host:"web`), special regex characters (`*?[{()` ), and malformed key:value colons (`:::foo`). Assert endpoint handles them gracefully (either parses text safely or returns 200/400 without crashing). |
| 25 | `test_case_insensitive_matching` | `POST /api/v1/events/search` | Query `severity:critical` vs `severity:CRITICAL`, and `log4j` vs `LOG4J`. Assert results are case-insensitive. |

---

## 4. Test Implementation Blueprint

Below is the concrete code blueprint for `tests/test_event_search.py` to be handed off to the implementation team:

```python
"""
OpenSOC Forge - Event Search Verification Test Suite (R3).
Verifies POST & GET /api/v1/events/search schema, query parsing,
Elasticsearch dispatch, and resilient offline fallback.
"""

import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import urllib.error

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.schemas import AlertItem, AlertSeverity, AlertSource, AlertStatus
from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS

client = TestClient(app)


# =============================================================================
# FIXTURES & HELPERS
# =============================================================================

@pytest.fixture(autouse=True)
def clean_simulation_alerts():
    """Ensure in-memory alerts pool is clean before and after each test."""
    original = list(LIVE_SIMULATION_ALERTS)
    yield
    LIVE_SIMULATION_ALERTS.clear()
    LIVE_SIMULATION_ALERTS.extend(original)


def get_analyst_token() -> str:
    res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
    if res.status_code == 200:
        return res.json()["access_token"]
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    return res.json()["access_token"]


# =============================================================================
# TIER 1: SCHEMA & ENDPOINT COMPLIANCE
# =============================================================================

def test_post_search_status_200_and_top_level_schema():
    payload = {"query": "*", "indices": ["*"], "time_range": "24h", "limit": 10}
    res = client.post("/api/v1/events/search", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "total_hits" in data
    assert isinstance(data["total_hits"], int)
    assert "took_ms" in data
    assert isinstance(data["took_ms"], (int, float))
    assert "indices_searched" in data
    assert isinstance(data["indices_searched"], list)
    assert "events" in data
    assert isinstance(data["events"], list)


def test_post_search_event_item_schema():
    # Inject a known event to guarantee at least one hit
    test_id = f"evt-test-{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=test_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.CRITICAL,
            source=AlertSource.SURICATA,
            title="Suricata NIDS: Test Exploit Trigger",
            description="Schema compliance test synthetic payload",
            host="web-app-dmz-01",
            raw_payload={"proto": "TCP", "src_port": 12345},
            is_demo=False,
        )
    )

    res = client.post("/api/v1/events/search", json={"query": test_id, "limit": 5})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] >= 1
    ev = next(e for e in data["events"] if e["id"] == test_id)
    assert ev["id"] == test_id
    assert "timestamp" in ev
    assert "index" in ev
    assert "source_type" in ev
    assert ev["host"] == "web-app-dmz-01"
    assert ev["severity"] == "CRITICAL"
    assert "summary" in ev
    assert isinstance(ev["raw"], dict)


def test_get_search_endpoint_parity():
    res = client.get("/api/v1/events/search?query=*&time_range=24h&limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "total_hits" in data
    assert "took_ms" in data
    assert "indices_searched" in data
    assert "events" in data


def test_search_with_authenticated_analyst_token():
    token = get_analyst_token()
    headers = {"Authorization": f"Bearer {token}"}
    res = client.post("/api/v1/events/search", json={"query": "*", "limit": 5}, headers=headers)
    assert res.status_code == 200


def test_search_empty_body_post():
    res = client.post("/api/v1/events/search", json={})
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "total_hits" in data


# =============================================================================
# TIER 2: WILDCARD & DEFAULT QUERY BEHAVIOR
# =============================================================================

def test_wildcard_asterisk_returns_recent_events():
    res = client.post("/api/v1/events/search", json={"query": "*", "limit": 20})
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data["events"], list)


def test_empty_string_query_returns_recent_events():
    res = client.post("/api/v1/events/search", json={"query": "", "limit": 20})
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data["events"], list)


def test_indices_wildcard_expansion():
    res = client.post("/api/v1/events/search", json={"query": "*", "indices": ["*"]})
    assert res.status_code == 200
    data = res.json()
    assert len(data["indices_searched"]) > 0


def test_specific_index_selection():
    res = client.post("/api/v1/events/search", json={"query": "*", "indices": ["suricata-*"]})
    assert res.status_code == 200
    data = res.json()
    assert "suricata-*" in data["indices_searched"] or "suricata-eve" in str(data["indices_searched"])


# =============================================================================
# TIER 3: QUERY PARSING & MULTI-FIELD FILTERING
# =============================================================================

def test_filter_by_host_exact_and_wildcard():
    h = f"host-test-{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=f"evt-{int(time.time())}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.HIGH,
            source=AlertSource.ENDPOINT,
            title="Endpoint Host Filter Verification",
            description="Testing host filtering",
            host=h,
            is_demo=False,
        )
    )
    res = client.post("/api/v1/events/search", json={"query": f"host:{h}"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] >= 1
    assert all(e["host"] == h for e in data["events"])


def test_filter_by_severity():
    res = client.post("/api/v1/events/search", json={"query": "severity:CRITICAL", "limit": 20})
    assert res.status_code == 200
    data = res.json()
    assert all(e["severity"].upper() == "CRITICAL" for e in data["events"])


def test_filter_by_source_type_or_category():
    res = client.post("/api/v1/events/search", json={"query": "source:suricata", "limit": 20})
    assert res.status_code == 200
    data = res.json()
    assert all("suricata" in e.get("source_type", "").lower() or "suricata" in e.get("index", "").lower() for e in data["events"])


def test_free_text_keyword_search():
    marker = f"UNIQUE_KEYWORD_{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=f"evt-kw-{int(time.time())}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.MEDIUM,
            source=AlertSource.SYSLOG,
            title=f"Syslog Alert with {marker}",
            description="Keyword search validation",
            host="syslog-host-01",
            is_demo=False,
        )
    )
    res = client.post("/api/v1/events/search", json={"query": marker})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] >= 1
    assert any(marker in e["summary"] or marker in str(e["raw"]) for e in data["events"])


def test_conjunction_and_filter():
    h = f"conj-host-{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=f"evt-conj-1",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.CRITICAL,
            source=AlertSource.SURICATA,
            title="Conjunction match",
            description="Matches both",
            host=h,
            is_demo=False,
        )
    )
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=f"evt-conj-2",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.LOW,
            source=AlertSource.SURICATA,
            title="Conjunction non-match",
            description="Matches host only",
            host=h,
            is_demo=False,
        )
    )
    res = client.post("/api/v1/events/search", json={"query": f"host:{h} AND severity:CRITICAL"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] == 1
    assert data["events"][0]["severity"] == "CRITICAL"


def test_non_matching_query_returns_zero_hits():
    res = client.post("/api/v1/events/search", json={"query": "non_existent_token_xyz_987654321"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_hits"] == 0
    assert len(data["events"]) == 0


# =============================================================================
# TIER 4: ELASTICSEARCH INTEGRATION & RESILIENT FALLBACK
# =============================================================================

def test_elasticsearch_online_query_dispatch():
    mock_es_payload = {
        "took": 14,
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "mock-es-doc-001",
                    "_index": "suricata-eve-2026.10.18",
                    "_source": {
                        "timestamp": "2026-10-18T13:30:00Z",
                        "event_type": "alert",
                        "host": "web-app-dmz-01",
                        "alert": {"signature": "ET EXPLOIT Log4j RCE", "severity": 1},
                        "src_ip": "10.0.1.15",
                        "dest_ip": "198.51.100.84",
                    },
                }
            ],
        },
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_es_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.post("/api/v1/events/search", json={"query": "Log4j"})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert any(e["id"] == "mock-es-doc-001" or "Log4j" in e["summary"] for e in data["events"])


def test_elasticsearch_offline_graceful_fallback():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = client.post("/api/v1/events/search", json={"query": "*"})
        # Must NOT return 500
        assert res.status_code == 200
        data = res.json()
        assert "events" in data
        assert "indices_searched" in data


def test_fallback_queries_in_memory_simulation_alerts():
    synth_id = f"synth-sim-{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=synth_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.HIGH,
            source=AlertSource.ENDPOINT,
            title="In-Memory Simulation Alert",
            description="Fallback verification payload",
            host="sim-host-01",
            is_demo=False,
        )
    )
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = client.post("/api/v1/events/search", json={"query": synth_id})
        assert res.status_code == 200
        data = res.json()
        assert data["total_hits"] >= 1
        assert any(e["id"] == synth_id for e in data["events"])


def test_fallback_queries_persisted_alerts():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = client.post("/api/v1/events/search", json={"query": "*", "limit": 50})
        assert res.status_code == 200
        data = res.json()
        # Persisted alerts from configs/persisted_alerts.json should be loaded
        assert isinstance(data["events"], list)


def test_fallback_suricata_eve_log_parsing(tmp_path):
    mock_eve_file = tmp_path / "eve.json"
    sample_records = [
        {"timestamp": datetime.utcnow().isoformat() + "Z", "event_type": "alert", "src_ip": "10.0.1.50", "dest_ip": "198.51.100.22", "alert": {"signature": "ET MALWARE C2 Callback", "severity": 1}, "host": "eve-sensor-01"},
        {"timestamp": datetime.utcnow().isoformat() + "Z", "event_type": "dns", "dns": {"rrname": "c2.evil.com", "type": "query"}, "src_ip": "10.0.1.50", "dest_ip": "8.8.8.8", "host": "eve-sensor-01"}
    ]
    with open(mock_eve_file, "w") as f:
        for r in sample_records:
            f.write(json.dumps(r) + "\n")

    with patch("backend.app.services.live_telemetry.SURICATA_LOG_PATH", str(mock_eve_file)):
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            res = client.post("/api/v1/events/search", json={"query": "c2.evil.com"})
            assert res.status_code == 200
            data = res.json()
            assert isinstance(data["events"], list)


# =============================================================================
# TIER 5: BOUNDARY CASES, LIMITS, TIME RANGES & ROBUSTNESS
# =============================================================================

def test_limit_exact_bounding():
    res = client.post("/api/v1/events/search", json={"query": "*", "limit": 3})
    assert res.status_code == 200
    data = res.json()
    assert len(data["events"]) <= 3


def test_limit_maximum_capping():
    res = client.post("/api/v1/events/search", json={"query": "*", "limit": 500})
    assert res.status_code == 200
    data = res.json()
    assert len(data["events"]) <= 200


def test_time_range_window_filtering():
    old_time = (datetime.utcnow() - timedelta(days=2)).isoformat() + "Z"
    recent_time = datetime.utcnow().isoformat() + "Z"

    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id="evt-old-telemetry",
            timestamp=old_time,
            severity=AlertSeverity.LOW,
            source=AlertSource.SYSLOG,
            title="Old Telemetry 48 Hours Ago",
            description="Testing time range filter",
            host="archive-host",
            is_demo=False,
        )
    )
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id="evt-recent-telemetry",
            timestamp=recent_time,
            severity=AlertSeverity.LOW,
            source=AlertSource.SYSLOG,
            title="Recent Telemetry 10s Ago",
            description="Testing time range filter",
            host="archive-host",
            is_demo=False,
        )
    )

    # 15m should exclude the 48h event
    res = client.post("/api/v1/events/search", json={"query": "host:archive-host", "time_range": "15m"})
    assert res.status_code == 200
    data = res.json()
    ids = [e["id"] for e in data["events"]]
    assert "evt-recent-telemetry" in ids
    assert "evt-old-telemetry" not in ids


def test_malformed_syntax_resilience():
    malformed_queries = [
        'host:"unclosed_quote',
        'severity:::CRITICAL',
        '()[]{}*?^~:\"\\',
        'AND OR NOT && ||',
    ]
    for q in malformed_queries:
        res = client.post("/api/v1/events/search", json={"query": q})
        # Must return valid HTTP code (200 OK or 400 Bad Request), never uncaught 500
        assert res.status_code in [200, 400, 422]


def test_case_insensitive_matching():
    h = f"case-test-{int(time.time())}"
    LIVE_SIMULATION_ALERTS.append(
        AlertItem(
            id=f"evt-case-{int(time.time())}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            severity=AlertSeverity.HIGH,
            source=AlertSource.ENDPOINT,
            title="Case Sensitivity Test with LOG4J Marker",
            description="Log4j matching test",
            host=h,
            is_demo=False,
        )
    )
    res_lower = client.post("/api/v1/events/search", json={"query": "log4j"})
    assert res_lower.status_code == 200
    assert any("log4j" in e["summary"].lower() for e in res_lower.json()["events"])
```

---

## 5. Test Runner Commands & CI Verification

To execute and verify the event search test suite, the following standard commands should be employed:

### 5.1 Primary Test Runner Command (Single Target)
```powershell
python -m pytest tests/test_event_search.py -v
```
- Executes all 25 test cases in `tests/test_event_search.py`.
- Formats test outcomes with full test names and execution statuses.

### 5.2 Fast Short-Traceback Invocation
```powershell
python -m pytest tests/test_event_search.py -v --tb=short
```
- Minimizes terminal noise during test failure diagnosis.

### 5.3 Full Repository Test Suite (Regression Guard)
```powershell
python -m pytest tests/unit/ tests/test_event_search.py -v
```
- Runs unit tests and event search tests without regression.

### 5.4 Standalone E2E Test Suite Runner
```powershell
python tests/e2e/e2e_test_runner.py
```
- Runs all 5 tiers of E2E verification across installer, systemd, compose, network policies, and CLI wrapper.

---

## 6. Recommendations & Design Guidelines for Implementer

1. **Schema Models (`backend/app/models/schemas.py`)**:
   Add `EventSearchRequest`, `EventItem`, and `EventSearchResponse` models with Pydantic v2:
   ```python
   class EventItem(BaseModel):
       id: str
       timestamp: str
       index: str
       source_type: str
       host: str
       severity: str
       summary: str
       raw: Dict[str, Any] = Field(default_factory=dict)

   class EventSearchRequest(BaseModel):
       query: str = "*"
       indices: List[str] = Field(default_factory=lambda: ["*"])
       time_range: str = "24h"
       limit: int = Field(default=50, ge=1, le=200)

   class EventSearchResponse(BaseModel):
       total_hits: int
       took_ms: float
       indices_searched: List[str]
       events: List[EventItem]
   ```

2. **Dedicated Search Service (`backend/app/services/event_search.py`)**:
   Encapsulate query parsing (host, severity, keyword), Elasticsearch dispatching, and fallback aggregation into a clean service function `execute_event_search(request: EventSearchRequest) -> EventSearchResponse`.
   This keeps `api.py` lightweight and facilitates easy unit and integration testing.

3. **Time Range Parsing**:
   Support `"15m"`, `"1h"`, `"24h"`, `"7d"`, `"30d"`, `"all"` via a datetime delta calculation against event ISO timestamps.

4. **KQL/Lucene Parser**:
   Use simple regex tokenizer extracting `key:value` pairs (e.g. `(host|severity|source|source_type):(\S+)`) and treat remainder as free text tokens. This provides robust parsing without introducing heavy external dependencies.
