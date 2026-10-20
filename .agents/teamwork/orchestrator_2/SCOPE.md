# Scope: OpenSOC Forge Event Investigation & Query Console

## Architecture
- **Backend Service Layer**:
  - `backend/app/models/schemas.py`: `EventSearchRequest`, `EventItem`, `EventSearchResponse` schemas with strict validation.
  - `backend/app/services/event_search.py`: `EventSearchService` handles query execution. When Elasticsearch is online (`ELASTICSEARCH_URL`), executes query via Elasticsearch REST API with basic auth. When Elasticsearch is offline or returns no hits, parses query into field filters / text terms and searches across local sources (`LIVE_SIMULATION_ALERTS`, `configs/persisted_alerts.json`, `DEMO_ALERTS`, Suricata `eve.json`, and offline IOCs).
  - `backend/app/api/v1/api.py`: Registers `POST /api/v1/events/search` and `GET /api/v1/events/search` with RBAC `require_permission("alerts:read")`.
- **Frontend Console UI**:
  - `frontend/index.html`: Standalone React 18 UMD application using `React.createElement`.
  - Replaced static mockup in `currentScreen === "search"` with interactive state-driven console:
    - Input query state with Enter key & button trigger
    - Responsive hit counter & execution time display (`Query Results: X hits in Yms`)
    - Time range selector dropdown ("15m", "1h", "24h", "7d", "all")
    - Quick filter preset chips (`suricata-*`, `wazuh-alerts-*`, `event.category:network`, etc.)
    - Dynamic event card rendering with timestamp, host, color-coded source badge, and summary
    - Event detail modal showing syntax-formatted JSON with one-click copy button
    - Empty state with actionable suggestions and reset button
    - Auto-load of recent events when navigating to the search screen
- **Automated Verification**:
  - `tests/test_event_search.py`: Comprehensive test suite verifying schema compliance, wildcard queries, field filters, Elasticsearch integration, offline fallback resilience, limits, and time ranges.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Event Search Schemas | Define `EventSearchRequest`, `EventItem`, and `EventSearchResponse` | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Resilient Search Service | `EventSearchService` with ES querying and multi-source local fallback | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Query Parsing Engine | Lucene/KQL/key:value regex parser for field filters and substring search | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Search API Endpoints | `POST /api/v1/events/search` and `GET /api/v1/events/search` in `api.py` | M1 | ORIGINAL_REQUEST §R1 |
| 5 | Reactive Search Input | State-bound input box triggered by "Execute Query" button or Enter key | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Execution Stats & Timer | Real query execution time and hit counter display (`Query Results: X hits in Yms`) | M2 | ORIGINAL_REQUEST §R2 |
| 7 | Quick Filter Chips | Preset chips for common indices/syntax (`suricata-*`, `wazuh-alerts-*`, etc.) | M2 | ORIGINAL_REQUEST §R2 |
| 8 | Dynamic Event Rendering | Color-coded source badge, timestamp, host name, and summary card list | M2 | ORIGINAL_REQUEST §R2 |
| 9 | Formatted JSON Detail Modal | Detail modal displaying formatted raw JSON with one-click copy button | M2 | ORIGINAL_REQUEST §R2 |
| 10 | Actionable Empty State | Friendly empty state with query suggestions when no events match | M2 | ORIGINAL_REQUEST §R2 |
| 11 | Screen Auto-Load | Automatic event retrieval on screen entry / component mount | M2 | ORIGINAL_REQUEST §R2 |
| 12 | Automated Test Verification | 42 pytest tests in `tests/test_event_search.py` | M3 | ORIGINAL_REQUEST §R3 |
| 13 | E2E Dual-Track Audit | Independent Reviewers, Challengers, and Forensic Integrity Auditor | M4 | System Directives |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Backend Search API & Fallback | `backend/app/models/schemas.py`, `backend/app/services/event_search.py`, `backend/app/api/v1/api.py` | None | DONE |
| M2 | Interactive Frontend Console | `frontend/index.html` (Event Investigation screen) | M1 | DONE |
| M3 | Automated Test Suite | `tests/test_event_search.py` | M1 | DONE |
| M4 | Review, Challenge & Forensic Audit | Verification, Challenger tests, Reviewers, Forensic Auditor | M1, M2, M3 | DONE |

## Interface Contracts
### Frontend UI ↔ Backend Search API
- Endpoint: `POST /api/v1/events/search` (or `GET /api/v1/events/search?query=...&indices=...&time_range=...&limit=...`)
- Headers: `Content-Type: application/json`, `Authorization: Bearer <token>`
- Request Body:
  ```json
  {
    "query": "string (default: '*')",
    "indices": ["string"],
    "time_range": "15m | 1h | 24h | 7d | all",
    "limit": 50
  }
  ```
- Response Body (HTTP 200):
  ```json
  {
    "total_hits": 12,
    "took_ms": 14,
    "indices_searched": ["suricata-*", "wazuh-alerts-*", "syslog-*"],
    "events": [
      {
        "id": "evt-...",
        "timestamp": "2026-10-18T19:20:00Z",
        "index": "suricata-eve",
        "source_type": "suricata.eve.alert",
        "host": "web-app-dmz-01",
        "severity": "CRITICAL",
        "summary": "...",
        "raw": { ... }
      }
    ]
  }
  ```

## Code Layout
```
d:\AI\siem\
├── backend/app/
│   ├── api/v1/api.py                   # Search endpoint registration (M1)
│   ├── models/schemas.py               # EventSearchRequest, EventItem, EventSearchResponse (M1)
│   └── services/event_search.py        # EventSearchService & local fallback engine (M1)
├── frontend/
│   └── index.html                      # Interactive Event Investigation Console (M2)
├── tests/
│   └── test_event_search.py            # Comprehensive pytest test suite (M3)
└── .agents/teamwork/
    └── orchestrator_2/                 # Orchestrator metadata & gate status
```
