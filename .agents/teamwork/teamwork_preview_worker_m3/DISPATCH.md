## 2026-10-18T13:59:55Z
You are the Test Writer for Milestone M3 (Automated Test Verification).
Your working directory is: d:\AI\siem\.agents\teamwork\teamwork_preview_worker_m3
Project root is: d:\AI\siem

MANDATORY: Read the original user request at:
d:\AI\siem\.agents\teamwork\ORIGINAL_REQUEST.md (specifically under section ## 2026-10-18T13:37:03Z)

Also review the Testing Explorer analysis report at:
d:\AI\siem\.agents\teamwork\teamwork_preview_explorer_survey_3\analysis.md
and the project scope document at:
d:\AI\siem\.agents\teamwork\orchestrator_2\SCOPE.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Write Ownership & Exclusive File Boundaries:
You EXCLUSIVELY own and may create/edit:
- `tests/test_event_search.py`
Do NOT modify any implementation code in `backend/` or `frontend/`.

Requirements:
Create `tests/test_event_search.py` with comprehensive unit and integration tests using `pytest` and `fastapi.testclient.TestClient(app)` from `backend.app.main import app`.
Implement tests across the 5 tiers identified in the testing survey:
1. Tier 1: Schema & Endpoint Parity
   - `POST /api/v1/events/search` returns HTTP 200 with schema keys: `total_hits`, `took_ms`, `indices_searched`, `events`.
   - `GET /api/v1/events/search` returns HTTP 200 with matching schema.
   - Validate `EventItem` schema structure (`id`, `timestamp`, `index`, `source_type`, `host`, `severity`, `summary`, `raw`).
   - Test default auth (dev fallback) and JWT bearer token auth.
   - Test empty body `{}` defaults to query `'*'`.
2. Tier 2: Wildcard & Default Query Execution
   - Wildcard query `'*'` returns recent events.
   - Empty query `""` returns recent events.
   - Custom index parameter filtering (e.g. `indices=["suricata-*"]`).
3. Tier 3: Query Parsing & Filtering
   - Field filtering by host (e.g. `host:web-app-dmz-01` or `host.name:web-app-dmz-01`).
   - Field filtering by severity (e.g. `severity:CRITICAL`).
   - Field filtering by source type (e.g. `source_type:suricata`).
   - Free text keyword search (e.g. `Log4j` or `SQLi`).
   - Conjunction query with `AND`.
   - Non-matching query returns `total_hits == 0` and empty `events` list without error.
4. Tier 4: Elasticsearch Integration & Resilient Fallback
   - Mock Elasticsearch online scenario (verifying ES response normalization).
   - Mock Elasticsearch unreachable / offline scenario (e.g. connection error, HTTP error) -> verify seamless fallback to local sources with status 200 and positive hits.
   - Fallback searches across `LIVE_SIMULATION_ALERTS`, `persisted_alerts.json`, `DEMO_ALERTS`, and `eve.json`.
5. Tier 5: Boundary Values & Error Handling
   - `limit=3` returns at most 3 events.
   - `limit=500` or `limit > 200` rejected with HTTP 422 Unprocessable Entity or capped.
   - `limit=0` rejected with HTTP 422.
   - Time range filtering (`15m`, `1h`, `24h`, `7d`, `all`).
   - RBAC rejection: user with role lacking `alerts:read` gets HTTP 403.
   - Case-insensitivity in search tokens.

Verification:
Run the tests:
`python -m pytest tests/test_event_search.py -v`
Ensure all tests in `tests/test_event_search.py` and existing tests in `tests/unit/` pass.

Output:
Write your handoff report to `d:\AI\siem\.agents\teamwork\teamwork_preview_worker_m3\handoff.md`.
Update `progress.md` with your liveness timestamp and checklist.
Send a message back to orchestrator_2 when complete.
