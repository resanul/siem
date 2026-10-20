# Deep Technical Exploration: Backend Architecture for Event Search (R1)

## Executive Summary
This report provides a comprehensive technical exploration of OpenSOC Forge's backend architecture to implement the end-to-end event querying and search functionality (`POST /api/v1/events/search` and `GET /api/v1/events/search`). The investigation analyzes existing API routers, Pydantic data schemas, authentication & RBAC mechanisms, data sources (in-memory simulation alerts, persisted disk alerts, offline threat intelligence IOCs, Suricata EVE JSON streams, Wazuh HIDS alerts, and syslog), Elasticsearch integration, query parsing strategies (Lucene / KQL / key:value / substring text), and a resilient multi-tier fallback mechanism.

---

## 1. API Architecture, Routers, Schemas, & Security Layer

### 1.1 Router Hierarchy and Endpoint Registration
- **Application Entry Point**: `backend/app/main.py` instantiates FastAPI (`app = FastAPI(...)`) and mounts `api_router` from `backend/app/api/v1/api.py` under the prefix `settings.API_V1_STR` (`/api/v1`):
  ```python
  # backend/app/main.py (lines 43-44)
  app.include_router(api_router, prefix=settings.API_V1_STR)
  ```
- **Router Definition**: `backend/app/api/v1/api.py` initializes `api_router = APIRouter()`.
  - Adding `@api_router.post("/events/search")` and `@api_router.get("/events/search")` binds the endpoints directly to `/api/v1/events/search`.

### 1.2 Authentication & Dependency Injection
- **Security Provider**: `backend/app/core/security.py` implements JWT token creation/decoding and RBAC verification.
- **Dependency Flow**:
  - `get_current_user`: Extracts Bearer token from `HTTPAuthorizationCredentials`.
    - **Lab/Dev Resiliency**: If no Authorization header is present or if token decoding fails, `get_current_user` defaults to `Platform Admin` (`sub="admin"`, `role="Platform Admin"`, `permissions=["*"]`). This guarantees that both local browser sessions and automated lab tests work seamlessly out-of-the-box.
  - `require_permission(permission: str)`: A FastAPI dependency closure verifying that the user's role contains the required permission (or wildcard `*`).
- **Permission for Event Search**:
  - Permission `"alerts:read"` is granted to:
    - `UserRole.SECOPS_VIEWER`
    - `UserRole.INCIDENT_RESPONDER`
    - `UserRole.DETECTION_ENGINEER`
    - `UserRole.PLATFORM_ADMIN` (via `*`)
  - Endpoint dependency definition:
    ```python
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read"))
    ```

### 1.3 Pydantic Schemas to Add in `backend/app/models/schemas.py`
The schemas must strictly conform to the user requirements and response contract:
```python
class EventSearchRequest(BaseModel):
    query: Optional[str] = Field(default="", description="Lucene, KQL, key:value, or substring search query")
    indices: Optional[List[str]] = Field(default_factory=lambda: ["*"], description="Target index patterns, e.g. ['suricata-*', 'wazuh-alerts-*', 'syslog-*']")
    time_range: Optional[str] = Field(default="24h", description="Time range: 15m, 1h, 24h, 7d, all")
    limit: Optional[int] = Field(default=50, ge=1, le=200, description="Maximum number of events to return (1-200)")


class EventItem(BaseModel):
    id: str
    timestamp: str
    index: str
    source_type: str
    host: str
    severity: str
    summary: str
    raw: Dict[str, Any] = Field(default_factory=dict)


class EventSearchResponse(BaseModel):
    total_hits: int
    took_ms: int
    indices_searched: List[str]
    events: List[EventItem]
```

---

## 2. Existing Event & Alert Structures in the Codebase

OpenSOC Forge maintains heterogeneous data sources across live memory, configuration stores, SQLite databases, and disk logs:

### 2.1 In-Memory Simulation & Synthetic Alerts (`LIVE_SIMULATION_ALERTS`)
- **Location**: `backend/app/services/live_telemetry.py` (line 67):
  ```python
  LIVE_SIMULATION_ALERTS: List[AlertItem] = []
  ```
- **Lifecycle & Ingestion**:
  - Injected via `POST /api/v1/synthetic-event` (`api.py` lines 580, 667) and `POST /api/v1/simulation/run`.
  - In-memory alerts represent real-time synthetic attack activity (e.g. `ET EXPLOIT Possible Log4j RCE Attempt`, `Wazuh FIM: Unauthorized Binary Modification`, `Cobalt Strike Beacon`).
  - Structure: Pydantic `AlertItem` instances with fields `id`, `timestamp`, `severity`, `source`, `title`, `description`, `host`, `src_ip`, `dest_ip`, `mitre_attack_id`, `mitre_tactic`, `status`, and `raw_payload`.

### 2.2 Persisted Alerts (`configs/persisted_alerts.json`)
- **Location**: Managed by `backend/app/services/retention_policy.py`:
  ```python
  CONFIG_DIR = "configs"
  PERSISTENT_ALERTS_FILE = os.path.join(CONFIG_DIR, "persisted_alerts.json")
  ```
- **Access Functions**: `load_persisted_alerts() -> List[Dict[str, Any]]` and `save_persisted_alerts(alerts: List[Dict[str, Any]])`.
- **Purpose**: Persists up to 500 high-priority security alerts across service restarts and browser reloads.

### 2.3 Curated Baseline Demo Alerts (`DEMO_ALERTS`)
- **Location**: `backend/app/api/v1/api.py` (lines 85-167).
- **Contents**: 5 realistic production-grade alerts covering Suricata NIDS (Log4j JNDI, Cobalt Strike), Wazuh HIDS (FIM `/usr/bin/sudo`, CIS benchmark root login), and network syslog (TACACS+ brute-force failures).

### 2.4 Threat Intelligence Indicators (Offline SQLite DB)
- **Location**: `backend/app/services/ioc_storage.py` and `backend/app/data/threat_intel_iocs.db` (seeded from `backend/app/data/cisco_talos_iocs.json` with 17,214 Cisco Talos IOCs).
- **Access Function**:
  ```python
  query_offline_iocs(source: Optional[str] = None, search: Optional[str] = None, limit: int = 250, offset: int = 0) -> List[Dict[str, Any]]
  ```
- **Fields**: `indicator` (IP, domain, hash, CVE), `type`, `reputation`, `confidence`, `threat_actor`, `malware_family`, `source`, `first_seen`, `last_seen`, `description`, `cvss_score`, `status`, `updated_at`.

### 2.5 Suricata EVE JSON Logs (`eve.json`)
- **Path Resolution**: `find_suricata_eve_log()` in `live_telemetry.py` inspects:
  1. `os.environ.get("SURICATA_EVE_PATH")`
  2. `/var/log/suricata/eve.json`
  3. `/var/log/suricata/eve-alerts.json`
  4. `/opt/opensoc-forge/logs/eve.json`
  5. Local repository paths: `logs/eve.json`
- **Format**: Newline-delimited JSON (JSONL).
- **Key Fields**: `timestamp`, `flow_id`, `in_iface`, `event_type` (`alert`, `dns`, `http`, `flow`, `ssh`, `anomaly`), `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `alert` (`signature`, `category`, `severity`).
- **High-Performance Tail**: `_tail_lines(file_path, max_lines=500, chunk_size=262144)` seeks from EOF to stream only recent lines without loading multi-gigabyte log files into memory.

### 2.6 Wazuh HIDS Alerts (`alerts.json`)
- **Paths**: `/var/ossec/logs/alerts/alerts.json` on Wazuh Manager hosts, or normalized alerts from ES index `wazuh-alerts-*`.
- **Key Fields**: `timestamp` / `@timestamp`, `rule` (`id`, `level`, `description`, `mitre`), `agent` (`id`, `name`, `ip`), `full_log`, `decoder`.

### 2.7 Syslog
- **Paths**: `/var/log/opensoc/syslog/syslog.log`, `/var/log/syslog`, or ES index `opensoc-syslog-*` / `syslog-*`.
- **Key Fields**: `timestamp`, `host` / `hostname`, `message` (RFC 5424/3164 or CEF), `facility`, `severity`.

---

## 3. Elasticsearch Integration & Health Handling

### 3.1 Configuration & Client Library
- **Environment Variables**:
  ```python
  ES_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
  ES_USER = os.environ.get("ELASTIC_USER", "elastic")
  ES_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "OpenSocForge2026!")
  ```
- **Client Mechanism**: In `pyproject.toml`, standard dependencies include `httpx>=0.27.0` and Python's built-in `urllib.request`. The project does NOT use the heavy `elasticsearch-py` client; instead, it issues direct HTTP REST queries against Elasticsearch port 9200 with HTTP Basic Authorization (`elastic:OpenSocForge2026!`).
- **Existing Helpers**:
  - `backend/app/services/live_telemetry.py` implements `_es_request(path: str, timeout: int = 4)` and `fetch_syslog_alerts()`, `fetch_wazuh_alerts()`.
  - `backend/app/services/mitre_intel.py` implements `hunt_ioc_in_cluster(ioc: str)`.

### 3.2 Index Patterns
The platform indexes security telemetry across the following patterns:
- `suricata-*` / `suricata-eve`
- `wazuh-alerts-*`
- `opensoc-syslog-*` / `syslog-*`
- `opensoc-synthetic-test`

### 3.3 Query Execution & Resilience
- **Query DSL Construction**:
  When dispatching to Elasticsearch `{ES_URL}/{indices_str}/_search`:
  ```json
  {
    "query": {
      "bool": {
        "must": [
          {
            "query_string": {
              "query": es_query,
              "default_operator": "AND",
              "analyze_wildcard": true
            }
          }
        ],
        "filter": [
          {
            "range": {
              "@timestamp": {
                "gte": "now-24h"
              }
            }
          }
        ]
      }
    },
    "size": 50,
    "sort": [
      { "@timestamp": { "order": "desc", "unmapped_type": "boolean" } }
    ]
  }
  ```
- **Error Handling & Fallback Trigger**:
  - Elasticsearch network errors (`urllib.error.URLError`, `httpx.RequestError`, `TimeoutError`, HTTP 4xx/5xx) are caught safely.
  - As explicitly required in `ORIGINAL_REQUEST.md`: **"When Elasticsearch is offline or returns no hits, parse and search across local Suricata EVE logs (eve.json), Wazuh alerts, syslog, in-memory LIVE_SIMULATION_ALERTS, persisted alerts, and threat indicators matching the query terms."**
  - Therefore, if ES is unreachable OR returns 0 hits, the query seamlessly executes against local fallback data.

---

## 4. Technical Strategy for `POST` & `GET /api/v1/events/search`

### 4.1 Modular Architecture: New Service `backend/app/services/event_search.py`
To avoid bloating `api.py` and maintain testability, create a dedicated `EventSearchService` in `backend/app/services/event_search.py` with singleton instance `event_search_service`.

### 4.2 Endpoint Definitions in `backend/app/api/v1/api.py`
Both endpoints delegate to `event_search_service.search(...)`:

```python
@api_router.post("/events/search", response_model=EventSearchResponse)
def search_events_post(
    request: EventSearchRequest,
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """Executes Lucene/KQL search against Elasticsearch or local fallback data."""
    return event_search_service.search(
        query=request.query or "",
        indices=request.indices or ["*"],
        time_range=request.time_range or "24h",
        limit=request.limit or 50,
    )


@api_router.get("/events/search", response_model=EventSearchResponse)
def search_events_get(
    query: Optional[str] = Query(default=""),
    indices: Optional[List[str]] = Query(default=None),
    time_range: str = Query(default="24h"),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(require_permission("alerts:read")),
):
    """GET query endpoint with parameter normalization (handles comma-separated and repeated indices)."""
    norm_indices = []
    if indices:
        for idx in indices:
            for part in idx.split(","):
                clean = part.strip()
                if clean:
                    norm_indices.append(clean)
    if not norm_indices:
        norm_indices = ["*"]

    return event_search_service.search(
        query=query or "",
        indices=norm_indices,
        time_range=time_range,
        limit=limit,
    )
```

### 4.3 Query Parser & Matcher Engine (`_matches_query`)
The local query evaluator must handle:
1. **Wildcards & Empty Queries**:
   - `""`, `"*"`, `"*:*"`: Match all events.
2. **KQL / Lucene Field Queries (`key:value`, `key:"quoted value"`):**
   - Regular expression extraction: `r'(?:([a-zA-Z0-9_.]+):(?:"([^"]*)"|\'([^\']*)\'|(\S+)))'`
   - Field Aliases:
     - `host`, `host.name`, `hostname` -> inspects `event.host`, `raw.host`, `raw.agent.name`
     - `event.category`, `category`, `source_type` -> inspects `event.source_type`, `raw.event_type`, `raw.rule.groups`
     - `source`, `index` -> inspects `event.index`, `event.source_type`
     - `severity`, `level` -> inspects `event.severity` (case-insensitive)
     - `src_ip`, `source.ip`, `ip` -> inspects `raw.src_ip`, `raw.source_ip`, `event.summary`
     - `dest_ip`, `destination.ip` -> inspects `raw.dest_ip`, `raw.destination_ip`
     - `id`, `event.id` -> inspects `event.id`
     - Generic nested paths: `k.sub` -> traverses nested dictionaries in `raw`.
   - Wildcard Matching in Values: uses `fnmatch.fnmatch(val.lower(), pattern.lower())` (e.g. `web-app-*` matches `web-app-dmz-01`).
3. **Free Text & Substring Search**:
   - Matches if query token appears in `summary`, `host`, `id`, `source_type`, or serialized `raw`.
4. **Boolean Logic (`AND`, `OR`, `NOT`)**:
   - `OR`: Splitting on top-level ` OR ` — matching any branch succeeds.
   - `AND`: Splitting on ` AND ` or whitespace — all conditions must succeed.
   - `NOT` / `-`: Negated conditions invert match.

### 4.4 Time Range Filter (`_matches_time_range`)
- Options: `"15m"`, `"1h"`, `"24h"`, `"7d"`, `"30d"`, `"all"`.
- Calculation:
  - If `"all"`, always returns `True`.
  - Otherwise, computes `cutoff = datetime.utcnow() - delta`.
  - Parses ISO-8601 timestamps (`2026-10-18T19:20:00Z`, `2026-10-14 20:12:45`).
  - If timestamp cannot be parsed or if event is a baseline demo fixture within reasonable operational range, it remains available.

### 4.5 Index Pattern Filtering (`_matches_indices`)
- Normalizes indices requested, e.g. `["suricata-*", "wazuh-alerts-*"]`.
- Matches each event's `index` against requested patterns using `fnmatch.fnmatch`.
- If `["*"]` is specified, matches all indices.

### 4.6 Fallback Event Normalization Mapping Table
Every local record is converted into an `EventItem`:

| Source | Index | `source_type` | `host` | `severity` | `summary` |
|---|---|---|---|---|---|
| Suricata EVE log | `suricata-eve` | `suricata.eve.alert` (or `.flow`, `.dns`, `.http`) | `in_iface` or sensor name | Based on `alert.severity` (`1`=CRITICAL, `2`=HIGH, `3`=MEDIUM) | `alert.signature` or flow summary |
| Wazuh Alert | `wazuh-alerts` | `wazuh.alert` (or `.syscheck`, `.sca`) | `agent.name` or host | Based on `rule.level` (>=10 CRITICAL, >=7 HIGH, >=4 MEDIUM) | `rule.description` or full log |
| Syslog | `opensoc-syslog` | `syslog.system` or `syslog.auth` | `host` | Warning/Error/CEF severity | Message content |
| `AlertItem` (Simulation / Memory) | `suricata-eve` / `wazuh-alerts` / `opensoc-syslog` | `{source}.alert` | `host` | `alert.severity.value` | `alert.title` |
| Threat Intel IOC | `threat-intel` | `threat_intel.{source}` | `threat-intel-db` | CRITICAL if confidence >=90 else HIGH | `Threat IOC: {indicator} ({malware_family}) - {description}` |

---

## 5. Automated Testing Strategy (`tests/test_event_search.py`)

Create `tests/test_event_search.py` using `fastapi.testclient.TestClient(app)` verifying:
1. **Schema Compliance**:
   - `POST /api/v1/events/search` returns HTTP 200 with keys `total_hits`, `took_ms`, `indices_searched`, and `events`.
   - Each event contains `id`, `timestamp`, `index`, `source_type`, `host`, `severity`, `summary`, `raw`.
2. **Wildcard & Empty Search**:
   - Query `""` or `"*"` returns recent events.
3. **Field Filtering**:
   - `host.name:"web-app-dmz-01"` returns Log4j event.
   - `event.category:"network"` or `source:suricata` returns network security events.
4. **Boolean Query Logic**:
   - `host.name:"web-app-dmz-01" AND event.category:"network"` correctly filters results.
5. **GET Method Support**:
   - `GET /api/v1/events/search?query=Log4j&limit=10` returns HTTP 200 with matching schema.
6. **Resilient Elasticsearch Fallback**:
   - Even when Elasticsearch is unreachable or mocked to raise connection errors, search operates smoothly without raising HTTP 500 errors.
7. **RBAC Authorization**:
   - Role with `"alerts:read"` (or admin) successfully queries events; unauthenticated requests in lab mode default cleanly.
