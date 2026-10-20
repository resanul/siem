# Challenger 1 Handoff Report: Backend Event Search Adversarial Stress-Test

## 1. Observation

Adversarial stress-testing of `POST /api/v1/events/search`, `GET /api/v1/events/search`, and `EventSearchService` was executed using a dedicated 104-test adversarial harness (`test_adversarial_backend.py`) and parameter fuzzer (`fuzz_search.py`).

Execution command:
```bash
python -m pytest .agents/teamwork/teamwork_preview_challenger_gate_1/test_adversarial_backend.py -v
```

Execution results:
- **Total Tests**: 104
- **Passed**: 97
- **Failed**: 7

### Observation A: Unhandled `TypeError` causing HTTP 500 when `limit` is a List or Object
- **File**: `backend/app/models/schemas.py`, lines 179-193:
  ```python
  @field_validator("limit", mode="before")
  @classmethod
  def validate_limit(cls, v: Any) -> int:
      if v is None:
          return 50
      try:
          val = int(v)
          if val < 1:
              return 1
          if val > 200:
              raise ValueError("limit must not exceed 200")
          return val
      except ValueError:
          raise
  ```
- **Reproduction**:
  ```bash
  python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c = TestClient(app, raise_server_exceptions=False); print(c.post('/api/v1/events/search', json={'limit': [10]}).status_code)"
  ```
- **Verbatim Error & Status**:
  `500 Internal Server Error`
  ```
  TypeError: int() argument must be a string, a bytes-like object or a real number, not 'list'
  ```
  Because `validate_limit` only catches `ValueError`, passing `[10]` or `{"limit": 10}` raises unhandled `TypeError`, which bypasses Pydantic's 422 validation handler and crashes Starlette/FastAPI with HTTP 500.

### Observation B: Unhandled `OverflowError` causing HTTP 500 on large `time_range` values
- **File**: `backend/app/services/event_search.py`, lines 74-96:
  ```python
  def _parse_time_cutoff(time_range: str) -> Optional[datetime]:
      tr = (time_range or "24h").strip().lower()
      if tr in ("all", "*"):
          return None

      m = re.match(r"^(\d+)([smhd])$", tr)
      if m:
          val, unit = int(m.group(1)), m.group(2)
          if unit == "s":
              delta = timedelta(seconds=val)
          elif unit == "m":
              delta = timedelta(minutes=val)
          elif unit == "h":
              delta = timedelta(hours=val)
          elif unit == "d":
              delta = timedelta(days=val)
          else:
              delta = timedelta(hours=24)
      else:
          delta = timedelta(hours=24)

      return datetime.now(timezone.utc) - delta
  ```
- **Reproduction**:
  ```bash
  python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c = TestClient(app, raise_server_exceptions=False); print('POST:', c.post('/api/v1/events/search', json={'time_range': '100000000d'}).status_code); print('GET:', c.get('/api/v1/events/search?time_range=100000000d').status_code)"
  ```
- **Verbatim Error & Status**:
  `POST: 500 Internal Server Error`
  `GET: 500 Internal Server Error`
  Stack trace:
  ```
  File "D:\AI\siem\backend\app\services\event_search.py", line 96, in _parse_time_cutoff
    return datetime.now(timezone.utc) - delta
  OverflowError: date value out of range
  ```
  And for integers exceeding C int bounds (`9999999999999999999999999999999999999999999999999999d`):
  ```
  File "D:\AI\siem\backend\app\services\event_search.py", line 90, in _parse_time_cutoff
    delta = timedelta(days=val)
  OverflowError: Python int too large to convert to C int
  ```
  Both `_parse_time_cutoff` and the caller in `search()` lack try/except for `(OverflowError, ValueError)`.

### Observation C: Endpoint Contract Asymmetry between POST and GET on `limit <= 0`
- **GET Endpoint**: `backend/app/api/v1/api.py`, line 319:
  ```python
  limit: Optional[int] = Query(default=50, ge=1, le=200)
  ```
  `GET /api/v1/events/search?limit=0` -> Returns `HTTP 422 Unprocessable Entity` (FastAPI `ge=1` check).
  `GET /api/v1/events/search?limit=-5` -> Returns `HTTP 422 Unprocessable Entity`.
- **POST Endpoint**: `backend/app/models/schemas.py`, line 186:
  ```python
  if val < 1:
      return 1
  ```
  `POST /api/v1/events/search` with `{"limit": 0}` -> Coerces `0` to `1` and returns `HTTP 200 OK` with 1 event.
  `POST /api/v1/events/search` with `{"limit": -5}` -> Coerces `-5` to `1` and returns `HTTP 200 OK` with 1 event.
- **Contract Mismatch**: When a client requests `limit=0`, POST returns 1 event under HTTP 200, whereas GET returns HTTP 422.

### Observation D: Successful Adversarial Behaviors
1. **Hostile Query Strings**: 40+ variations of malformed queries (unclosed quotes, wildcards, regex bombs, SQLi, XSS, command injection, null bytes, unicode emojis) completed without crashing or returning HTTP 500.
2. **Elasticsearch Failure Modes**: Connection refused, socket timeout, HTTP 500 cluster failure, HTTP 401 unauthorized, non-JSON HTML proxy errors, and corrupted Elasticsearch hit objects were safely caught and transitioned smoothly to local fallback.
3. **Local Fallback Multi-Source Integrity**: Confirmed loading across `LIVE_SIMULATION_ALERTS`, `persisted_alerts.json`, `DEMO_ALERTS`, Suricata `eve.json`, and Threat Intel IOCs (120 total local events).
4. **Concurrency**: 50 concurrent requests executed across 10 threads completed with 100% HTTP 200 success, average latency ~0.15s, and zero race conditions.
5. **RBAC Rejection**: User with role `Recovery Operator` (`operator`) lacking `alerts:read` was strictly rejected with `HTTP 403 Forbidden` on both POST and GET.

---

## 2. Logic Chain

1. **Step 1 (Observation A)**: `validate_limit` runs `int(v)` in a `try...except ValueError` block. In Python, passing a list (`[10]`) or dictionary (`{"limit": 10}`) to `int()` raises a `TypeError`, not a `ValueError`.
2. **Step 2**: Because `TypeError` is unhandled, it escapes FastAPI's standard request validation lifecycle and bubbles up to Starlette's `ServerErrorMiddleware`, returning `HTTP 500 Internal Server Error`. A robust REST API must return `HTTP 422 Unprocessable Entity` for unparseable input structures, never HTTP 500.
3. **Step 3 (Observation B)**: `_parse_time_cutoff` matches regex `^(\d+)([smhd])$` and converts the group to an arbitrary-precision Python int. For values like `100000000d` or `3650000d`, `datetime.now(timezone.utc) - delta` exceeds `datetime.MAXYEAR` (year 9999), raising `OverflowError: date value out of range`. For values like `9999999999999999999999999999999999999999999999999999d`, `timedelta(days=val)` exceeds C int bounds, raising `OverflowError: Python int too large to convert to C int`.
4. **Step 4**: Neither `_parse_time_cutoff`, `_matches_time_range`, nor `search()` catches `OverflowError`. Consequently, any user query with a large time window (e.g. searching historical archives or typing a typo) immediately crashes the backend with HTTP 500.
5. **Step 5 (Observation C)**: The API documentation and OpenAPI schema specify `limit` with `ge=1, le=200`. In GET, passing `limit=0` or `limit=-5` fails validation with HTTP 422. In POST, `validate_limit` silently overrides user input `val < 1` to `1`, returning HTTP 200 and returning 1 event when the user asked for 0. This creates an asymmetric API contract.

---

## 3. Caveats

- In development mode, `get_current_user` in `backend/app/core/security.py` intentionally falls back to `Platform Admin` if an invalid or unauthenticated bearer token is passed. Tests verifying 403 Forbidden properly use valid JWT signatures with non-admin roles (e.g. `Recovery Operator`).
- Elasticsearch was tested in simulated offline / error mode using `unittest.mock.patch` since no live external Elasticsearch cluster was running on port 9200 during local execution.

---

## 4. Conclusion

**Explicit Verdict: REQUEST_CHANGES**

The backend implementation for Event Search is well-architected in its query parsing, multi-source local fallback, and RBAC enforcement. However, it fails production adversarial robustness in two critical areas:
1. **Critical Bug 1**: HTTP 500 crash on non-scalar `limit` parameters (`TypeError` unhandled in `schemas.py:184`).
2. **Critical Bug 2**: HTTP 500 crash on large `time_range` strings (`OverflowError` unhandled in `event_search.py:90,96`).
3. **Medium Bug 3**: Parity asymmetry between GET (422) and POST (200 with limit=1) for `limit <= 0`.

### Required Remediations
1. In `backend/app/models/schemas.py` (`validate_limit`):
   Catch `(ValueError, TypeError)` and raise `ValueError("limit must be an integer between 1 and 200")`.
   Enforce `val < 1` raising `ValueError("limit must be at least 1")` to match GET validation (or standardize both to return 422).
2. In `backend/app/services/event_search.py` (`_parse_time_cutoff`):
   Wrap `delta = ...` and `return datetime.now(timezone.utc) - delta` in `try...except (OverflowError, ValueError): return None` (or return default 24h cutoff).

---

## 5. Verification Method

To independently verify the bugs and validate fixes:

1. **Run the Adversarial Test Suite**:
   ```bash
   python -m pytest .agents/teamwork/teamwork_preview_challenger_gate_1/test_adversarial_backend.py -v
   ```
2. **Direct Reproduction Commands**:
   - Verify Bug 1 (Unhandled TypeError on list limit):
     ```bash
     python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c = TestClient(app, raise_server_exceptions=False); r = c.post('/api/v1/events/search', json={'limit': [10]}); print('Status:', r.status_code); assert r.status_code == 422"
     ```
   - Verify Bug 2 (Unhandled OverflowError on large time_range):
     ```bash
     python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c = TestClient(app, raise_server_exceptions=False); r = c.post('/api/v1/events/search', json={'time_range': '100000000d'}); print('Status:', r.status_code); assert r.status_code != 500"
     ```
   - Verify Bug 3 (Parity on limit=0):
     ```bash
     python -c "from fastapi.testclient import TestClient; from backend.app.main import app; c = TestClient(app, raise_server_exceptions=False); r_get = c.get('/api/v1/events/search?limit=0'); r_post = c.post('/api/v1/events/search', json={'limit': 0}); print('GET:', r_get.status_code, 'POST:', r_post.status_code); assert r_get.status_code == r_post.status_code"
     ```
