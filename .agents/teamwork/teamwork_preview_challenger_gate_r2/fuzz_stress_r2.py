"""
Adversarial stress and fuzz harness for Iteration 2 gate verification.
Tests concurrency, extreme edge payloads, Unicode/injection fuzzing, and RBAC rejection.
"""

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token, UserRole

client = TestClient(app, raise_server_exceptions=False)
admin_token = create_access_token({"sub": "admin_stress", "role": UserRole.PLATFORM_ADMIN.value})
operator_token = create_access_token({"sub": "unauth_op", "role": UserRole.RECOVERY_OPERATOR.value})
admin_headers = {"Authorization": f"Bearer {admin_token}"}
op_headers = {"Authorization": f"Bearer {operator_token}"}

print("=== 1. STRESS: MASSIVE QUERY PAYLOADS ===")
huge_query = "event.severity:CRITICAL AND host.name:" + ("a" * 10000)
res = client.post("/api/v1/events/search", json={"query": huge_query}, headers=admin_headers)
print(f"10KB query string -> HTTP {res.status_code}")
assert res.status_code == 200

print("\n=== 2. STRESS: SPECIAL CHARACTERS & INJECTION FUZZING ===")
fuzz_queries = [
    r'\x00\x01\x02\x03\xff',
    '"><script>alert(1)</script>',
    "'; DROP TABLE alerts; --",
    "${jndi:ldap://127.0.0.1:1389/a}",
    "(((nested:(((broken AND",
    "timestamp:[2026-01-01 TO 2026-12-31] AND severity:HIGH",
    "host.name:(web* OR db*) AND NOT (status:closed)",
    "🔥💻🚨🛡️🔍⚡",
    "a" * 50000,
]

for q in fuzz_queries:
    res = client.post("/api/v1/events/search", json={"query": q}, headers=admin_headers)
    assert res.status_code == 200, f"Query {q[:30]!r} returned {res.status_code}"
print(f"All {len(fuzz_queries)} hostile queries completed safely with HTTP 200!")

print("\n=== 3. STRESS: RBAC SECURITY ENFORCEMENT ===")
# Recovery Operator role has NO alerts:read permission
res_post_unauth = client.post("/api/v1/events/search", json={"query": "*"}, headers=op_headers)
res_get_unauth = client.get("/api/v1/events/search?query=*", headers=op_headers)
print(f"Unauthorized Operator POST -> HTTP {res_post_unauth.status_code}")
print(f"Unauthorized Operator GET  -> HTTP {res_get_unauth.status_code}")
assert res_post_unauth.status_code == 403
assert res_get_unauth.status_code == 403

print("\n=== 4. STRESS: 100 CONCURRENT MULTI-ENDPOINT REQUESTS ===")
def send_random_request(i):
    if i % 3 == 0:
        return client.post("/api/v1/events/search", json={"query": "*", "limit": 10 + (i % 50)}, headers=admin_headers)
    elif i % 3 == 1:
        return client.get(f"/api/v1/events/search?query=*&limit={10 + (i % 50)}", headers=admin_headers)
    else:
        # Invalid limit should consistently return 422
        return client.post("/api/v1/events/search", json={"limit": [i]}, headers=admin_headers)

success_count = 0
rejection_count = 0
error_count = 0

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(send_random_request, i) for i in range(100)]
    for f in as_completed(futures):
        r = f.result()
        if r.status_code == 200:
            success_count += 1
        elif r.status_code == 422:
            rejection_count += 1
        else:
            error_count += 1
            print(f"Unexpected status: {r.status_code}")

print(f"100 Concurrent Requests -> HTTP 200: {success_count}, HTTP 422: {rejection_count}, Errors: {error_count}")
assert error_count == 0, f"Encountered {error_count} unexpected server errors under concurrency"

print("\nALL STRESS & CONCURRENCY TESTS COMPLETED WITH 100% SUCCESS!")
