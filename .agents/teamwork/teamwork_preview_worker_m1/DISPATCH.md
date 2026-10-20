## 2026-10-18T13:48:02Z
You are the Worker for Milestone M1 (Backend Event Search API & Resilient Fallback Engine).
Your working directory is: d:\AI\siem\.agents\teamwork\teamwork_preview_worker_m1
Project root is: d:\AI\siem

MANDATORY: Read the original user request at:
d:\AI\siem\.agents\teamwork\ORIGINAL_REQUEST.md (specifically under section ## 2026-10-18T13:37:03Z)

Also review the Explorer analysis report at:
d:\AI\siem\.agents\teamwork\teamwork_preview_explorer_survey_1\analysis.md
and the project scope document at:
d:\AI\siem\.agents\teamwork\orchestrator_2\SCOPE.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Write Ownership & Exclusive File Boundaries:
You EXCLUSIVELY own and may edit:
- `backend/app/models/schemas.py`
- `backend/app/services/event_search.py` (create new service)
- `backend/app/api/v1/api.py`
Do NOT modify any files outside these paths.

Requirements:
1. In `backend/app/models/schemas.py`:
   - Add `EventSearchRequest` with fields: `query: Optional[str] = "*"`, `indices: Optional[List[str]] = None`, `time_range: Optional[str] = "24h"`, `limit: Optional[int] = 50`. Validate `limit` <= 200.
   - Add `EventItem` with fields: `id: str`, `timestamp: str`, `index: str`, `source_type: str`, `host: str`, `severity: str`, `summary: str`, `raw: Dict[str, Any]`.
   - Add `EventSearchResponse` with fields: `total_hits: int`, `took_ms: int`, `indices_searched: List[str]`, `events: List[EventItem]`.
2. In `backend/app/services/event_search.py`:
   - Implement `EventSearchService` with methods for search execution.
   - Elasticsearch integration: Check reachability of `ELASTICSEARCH_URL` (default `http://elasticsearch:9200`), query Elasticsearch `_search` with HTTP Basic Auth (`elastic` / `OpenSocForge2026!`), handle timeouts and connection errors gracefully.
   - Resilient Fallback: When Elasticsearch is unreachable, offline, or returns 0 hits, fallback to searching across local sources:
     - In-memory `LIVE_SIMULATION_ALERTS` from `backend/app/services/live_telemetry.py`
     - Persisted alerts from `configs/persisted_alerts.json`
     - In-memory `DEMO_ALERTS` from `backend/app/api/v1/api.py`
     - Suricata EVE logs `eve.json` (using `find_suricata_eve_log()` / tailing)
     - Threat indicators from `backend/app/services/ioc_storage.py`
   - Query parser & filter:
     - Support key:value filters (e.g. `host:web-app-dmz-01`, `severity:CRITICAL`, `source_type:suricata`, `event.category:network`)
     - Support Lucene/KQL style tokens and case-insensitive substring search across summary, host, source_type, and raw JSON fields
     - Time range filtering: "15m", "1h", "24h", "7d", "all"
     - Limit bounding: default 50, max 200
     - Format and return `EventSearchResponse`
3. In `backend/app/api/v1/api.py`:
   - Expose `POST /api/v1/events/search` accepting `EventSearchRequest` payload
   - Expose `GET /api/v1/events/search` accepting query params `query`, `indices`, `time_range`, `limit`
   - Secure both with `current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))`
4. Verification:
   - Run existing unit tests: `python -m pytest tests/unit/`
   - Verify syntax and import cleanly: `python -c "from backend.app.services.event_search import event_search_service; print(event_search_service)"`
   - Document verification commands and output in your handoff report.

Output:
Write your handoff report to `d:\AI\siem\.agents\teamwork\teamwork_preview_worker_m1\handoff.md`.
Update `progress.md` with your liveness timestamp and checklist.
Send a message back to orchestrator_2 when complete.
