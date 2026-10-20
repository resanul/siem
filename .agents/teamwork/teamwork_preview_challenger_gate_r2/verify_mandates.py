"""
Verification script for specific Objective 2 mandates.
Outputs exact status codes and details for empirical handoff report.
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token, UserRole

client = TestClient(app, raise_server_exceptions=False)
token = create_access_token({"sub": "challenger_r2", "role": UserRole.PLATFORM_ADMIN.value})
headers = {"Authorization": f"Bearer {token}"}

print("=== CHECK 1: NON-SCALAR LIMIT VALUES (POST) ===")
non_scalar_tests = [
    ("[10]", {"limit": [10]}),
    ('{"limit": 10}', {"limit": {"limit": 10}}),
    ("3.14", {"limit": 3.14}),
    ("True", {"limit": True}),
    ('"abc"', {"limit": "abc"}),
]

for label, payload in non_scalar_tests:
    res = client.post("/api/v1/events/search", json=payload, headers=headers)
    print(f"POST limit={label:<15} -> HTTP {res.status_code} (detail: {res.json().get('detail')})")
    assert res.status_code == 422, f"Expected 422 for {label}, got {res.status_code}"

print("\n=== CHECK 2: LARGE/EXTREME TIME_RANGE VALUES (POST & GET) ===")
extreme_time_ranges = [
    "100000000d",
    "9999999999999999999999999999999999999999999999999999d",
    "100000000h",
]

for tr in extreme_time_ranges:
    res_post = client.post("/api/v1/events/search", json={"time_range": tr}, headers=headers)
    print(f"POST time_range={tr[:20]+('...' if len(tr)>20 else ''):<25} -> HTTP {res_post.status_code} (events: {len(res_post.json().get('events', []))}, hits: {res_post.json().get('total_hits')})")
    assert res_post.status_code == 200, f"Expected 200 for POST {tr}, got {res_post.status_code}"

    res_get = client.get(f"/api/v1/events/search?time_range={tr}", headers=headers)
    print(f"GET  time_range={tr[:20]+('...' if len(tr)>20 else ''):<25} -> HTTP {res_get.status_code} (events: {len(res_get.json().get('events', []))}, hits: {res_get.json().get('total_hits')})")
    assert res_get.status_code == 200, f"Expected 200 for GET {tr}, got {res_get.status_code}"

print("\n=== CHECK 3: GET VS POST CONTRACT PARITY ON LIMIT <= 0 ===")
parity_tests = [
    ("limit=0", 0),
    ("limit=-5", -5),
    ("limit=201", 201),
]

for label, val in parity_tests:
    res_get = client.get(f"/api/v1/events/search?limit={val}", headers=headers)
    res_post = client.post("/api/v1/events/search", json={"limit": val}, headers=headers)
    print(f"{label:<12} -> GET: HTTP {res_get.status_code} | POST: HTTP {res_post.status_code} | Parity: {'MATCH' if res_get.status_code == res_post.status_code else 'MISMATCH'}")
    assert res_get.status_code == 422, f"GET {label} expected 422, got {res_get.status_code}"
    assert res_post.status_code == 422, f"POST {label} expected 422, got {res_post.status_code}"
    assert res_get.status_code == res_post.status_code, f"Parity mismatch for {label}"

print("\nALL MANDATORY CHECKS PASSED EMPIRICALLY!")
