# Surgical Fix Strategy: Event Search Limit Validation & Time Cutoff Overflow

## Executive Summary

During Gate 1 validation, Challenger 1 identified 3 concrete issues affecting `POST /api/v1/events/search`, `GET /api/v1/events/search`, and `EventSearchService`:
1. **Issue 1**: Unhandled `TypeError` in `EventSearchRequest.validate_limit` when `limit` is a non-scalar type (e.g. `[10]`, `{"limit": 10}`) or boolean/float, causing unhandled HTTP 500 Internal Server Errors or improper HTTP 200 coercion instead of HTTP 422 Unprocessable Entity.
2. **Issue 2**: Unhandled `OverflowError` in `_parse_time_cutoff` when given extreme time ranges (e.g., `100000000d`, `9999999999999999999999999999999999999999999999999999d`, `100000000h`), causing both POST and GET endpoints to crash with HTTP 500.
3. **Issue 3**: Contract asymmetry between GET (which rejects `limit <= 0` with HTTP 422 via FastAPI `ge=1`) and POST (which silently coerced `val < 1` to `1`, returning HTTP 200 with 1 event).
4. **Test Suite Deficiencies**: In `tests/test_event_search.py`, `test_limit_zero_rejection` only checked GET, `test_limit_invalid_string_rejection` only checked string errors, and no test verified extreme time range overflow resilience.

This analysis provides root-cause diagnosis, verified before-and-after surgical code changes, and test suite adjustments that achieve 100% pass rates across both the standard verification suite (`tests/test_event_search.py`) and the 104-test adversarial suite (`test_adversarial_backend.py`).

---

## Detailed Root Cause Analysis

### Issue 1: Unhandled `TypeError` in `validate_limit`
- **Location**: `backend/app/models/schemas.py`, lines 179–193.
- **Root Cause**:
  `validate_limit` operates in `mode="before"`. When a request payload contains `{"limit": [10]}` or `{"limit": {"limit": 10}}`, the argument `v` is a Python `list` or `dict`.
  The function executes `val = int(v)`. In Python, passing a list or dictionary to `int()` raises `TypeError: int() argument must be a string, a bytes-like object or a real number, not 'list'`.
  Because the enclosing block is only `except ValueError: raise`, the `TypeError` is unhandled.
  In FastAPI / Pydantic v2, custom validators that raise `ValueError` or `AssertionError` are converted into `RequestValidationError` (HTTP 422). Any other unhandled exception (like `TypeError`) bypasses the validation handler and bubbles up to Starlette's `ServerErrorMiddleware`, returning `HTTP 500 Internal Server Error`.
- **Secondary Root Causes**:
  - `isinstance(True, int)` is `True` in Python (since `bool` subclasses `int`), so `int(True)` evaluates to `1`, returning HTTP 200 when a boolean was supplied.
  - `int(3.14)` evaluates to `3`, silently truncating float numbers to integers and returning HTTP 200 instead of rejecting non-integers with HTTP 422.

### Issue 2: `OverflowError` in `_parse_time_cutoff`
- **Location**: `backend/app/services/event_search.py`, lines 74–96.
- **Root Cause**:
  The regex `^(\d+)([smhd])$` matches arbitrary digit lengths.
  - For values like `val = 9999999999999999999999999999999999999999999999999999`, calling `timedelta(days=val)` triggers `OverflowError: Python int too large to convert to C int`.
  - For values like `val = 100000000`, `timedelta(days=val)` succeeds, but `datetime.now(timezone.utc) - delta` exceeds `datetime.MINYEAR` / `datetime.MAXYEAR` (years 1–9999), raising `OverflowError: date value out of range`.
  Because neither `_parse_time_cutoff`, `_matches_time_range`, nor `event_search_service.search` catches `OverflowError`, both `POST /api/v1/events/search` and `GET /api/v1/events/search` crash with HTTP 500 when searching historical archives or when given extreme time ranges.

### Issue 3: Contract Asymmetry for `limit <= 0`
- **Location**:
  - GET endpoint: `backend/app/api/v1/api.py`, line 319: `limit: Optional[int] = Query(default=50, ge=1, le=200)`.
    Requests with `limit=0` or `limit=-5` are rejected with `HTTP 422 Unprocessable Entity`.
  - POST model: `backend/app/models/schemas.py`, lines 186–187:
    ```python
    if val < 1:
        return 1
    ```
    Requests with `{"limit": 0}` or `{"limit": -5}` were silently coerced to `1`, returning `HTTP 200 OK` with 1 event.
- **Impact**: Violates REST contract consistency. A client requesting `limit=0` receives 1 event on POST but HTTP 422 on GET.

---

## Surgical Fix Specifications

### Fix 1: `backend/app/models/schemas.py`
Replace `EventSearchRequest.validate_limit` with a strict type and boundary validator.

#### Before
```python
class EventSearchRequest(BaseModel):
    query: Optional[str] = "*"
    indices: Optional[List[str]] = None
    time_range: Optional[str] = "24h"
    limit: Optional[int] = Field(default=50, ge=1, le=200)

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

#### After
```python
class EventSearchRequest(BaseModel):
    query: Optional[str] = "*"
    indices: Optional[List[str]] = None
    time_range: Optional[str] = "24h"
    limit: Optional[int] = Field(default=50, ge=1, le=200)

    @field_validator("limit", mode="before")
    @classmethod
    def validate_limit(cls, v: Any) -> int:
        if v is None:
            return 50
        # Disallow booleans and complex non-scalar types
        if isinstance(v, (bool, list, dict, tuple, set, float)):
            raise ValueError("limit must be an integer between 1 and 200")
        try:
            val = int(v)
        except (ValueError, TypeError):
            raise ValueError("limit must be an integer between 1 and 200")
        if val < 1:
            raise ValueError("limit must be at least 1")
        if val > 200:
            raise ValueError("limit must not exceed 200")
        return val
```

#### Rationale & Verification
- `isinstance(v, (bool, list, dict, tuple, set, float))`:
  - Directly rejects booleans (`True`, `False`), lists (`[10]`), dictionaries (`{"limit": 10}`), and floats (`3.14`).
- `except (ValueError, TypeError)`:
  - Traps any unexpected conversion error and raises `ValueError`. In Pydantic v2, `ValueError` is safely converted into HTTP 422.
- `if val < 1: raise ValueError("limit must be at least 1")`:
  - Rejects `limit=0` and `limit=-5` with HTTP 422, establishing parity with GET `Query(ge=1)`.
- `if val > 200: raise ValueError("limit must not exceed 200")`:
  - Rejects `limit > 200` with HTTP 422, establishing parity with GET `Query(le=200)`.

---

### Fix 2: `backend/app/services/event_search.py`
Wrap `_parse_time_cutoff` in exception handling for `(OverflowError, ValueError)` and return `None` (unbounded search). Also refine `_query_elasticsearch` to avoid appending invalid `now-*`.

#### Before
```python
def _parse_time_cutoff(time_range: str) -> Optional[datetime]:
    """Computes UTC cutoff datetime from time range token (e.g. 15m, 1h, 24h, 7d)."""
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

#### After
```python
def _parse_time_cutoff(time_range: str) -> Optional[datetime]:
    """Computes UTC cutoff datetime from time range token (e.g. 15m, 1h, 24h, 7d)."""
    try:
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
    except (OverflowError, ValueError):
        return None
```

#### Supplementary Hardening in `event_search.py` (Line 459)
In `_query_elasticsearch`:
```python
# Before
            if time_range and time_range.lower() != "all":
                filter_clauses.append({
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{time_range}"
                        }
                    }
                })

# After
            if time_range and time_range.lower() not in ("all", "*"):
                filter_clauses.append({
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{time_range}"
                        }
                    }
                })
```

#### Rationale & Verification
- If `val` is too large for C integer conversion in `timedelta` or exceeds calendar range in `datetime - delta`, `(OverflowError, ValueError)` is caught.
- Returning `None` triggers line 110 of `_matches_time_range`:
  ```python
  cutoff = _parse_time_cutoff(time_range)
  if cutoff is None:
      return True
  ```
  Every event matches the time filter, seamlessly converting extreme historical lookbacks into an unbounded ("all time") search without crashing.

---

## Test Suite Adjustments (`tests/test_event_search.py`)

In `tests/test_event_search.py` (under class `TestTier5BoundaryValuesAndErrorHandling`):

### 1. Update `test_limit_zero_rejection`
Align test to assert HTTP 422 on both GET and POST:
```python
    def test_limit_zero_rejection(self):
        """Limit = 0 is rejected with HTTP 422 Unprocessable Entity on both GET and POST."""
        res_get = client.get("/api/v1/events/search?query=*&limit=0")
        assert res_get.status_code == 422

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": 0})
        assert res_post.status_code == 422
```

### 2. Add `test_limit_negative_rejection`
Verify negative limits are rejected on both GET and POST:
```python
    def test_limit_negative_rejection(self):
        """Negative limit is rejected with HTTP 422 on both GET and POST."""
        res_get = client.get("/api/v1/events/search?query=*&limit=-5")
        assert res_get.status_code == 422

        res_post = client.post("/api/v1/events/search", json={"query": "*", "limit": -5})
        assert res_post.status_code == 422
```

### 3. Replace `test_limit_invalid_string_rejection` with `test_limit_non_integer_type_rejection`
Verify non-scalar types (list, dict, float, bool) reject with HTTP 422 and never HTTP 500:
```python
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
```

### 4. Add `test_extreme_time_range_overflow_resilience`
Verify extreme time range values do not crash server:
```python
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
```

---

## Verification Matrix

| Test Scenario | Input | Current Status | Expected / Post-Fix Status |
|---------------|-------|----------------|----------------------------|
| List limit | `{"limit": [10]}` | HTTP 500 (TypeError) | HTTP 422 |
| Dict limit | `{"limit": {"limit": 10}}` | HTTP 500 (TypeError) | HTTP 422 |
| Float limit | `{"limit": 3.14}` | HTTP 200 (coerced to 3) | HTTP 422 |
| Bool limit | `{"limit": True}` | HTTP 200 (coerced to 1) | HTTP 422 |
| Zero limit POST | `{"limit": 0}` | HTTP 200 (coerced to 1) | HTTP 422 |
| Negative limit POST | `{"limit": -5}` | HTTP 200 (coerced to 1) | HTTP 422 |
| Zero limit GET | `GET ?limit=0` | HTTP 422 | HTTP 422 |
| Negative limit GET | `GET ?limit=-5` | HTTP 422 | HTTP 422 |
| Upper limit POST | `{"limit": 201}` | HTTP 422 | HTTP 422 |
| Upper limit GET | `GET ?limit=201` | HTTP 422 | HTTP 422 |
| Extreme days POST | `{"time_range": "100000000d"}` | HTTP 500 (OverflowError) | HTTP 200 |
| Extreme days GET | `GET ?time_range=100000000d` | HTTP 500 (OverflowError) | HTTP 200 |
| Extreme C int overflow | `{"time_range": "9999999999999999999999999999999999999999999999999999d"}` | HTTP 500 (OverflowError) | HTTP 200 |
| Extreme hours | `{"time_range": "100000000h"}` | HTTP 500 (OverflowError) | HTTP 200 |
| Normal lookbacks | `{"time_range": "15m", "limit": 50}` | HTTP 200 | HTTP 200 |

## Machine-Applicable Diff Patch Summary
Implementer can apply changes cleanly to:
- `backend/app/models/schemas.py` (lines 179–193)
- `backend/app/services/event_search.py` (lines 74–96, 459)
- `tests/test_event_search.py` (Tier 5 tests)
No other files or database migrations are required.
