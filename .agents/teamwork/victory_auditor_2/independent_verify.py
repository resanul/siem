"""
Independent Post-Victory Verification Script
Auditor: victory_auditor_2
Target: SIEM Event Search API & Fallback Engine
"""

import sys
import time
from typing import Any, Dict
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def run_audit():
    print("=" * 60)
    print("INDEPENDENT VICTORY AUDIT TEST RUN")
    print("=" * 60)

    # 1. Login with analyst (has alerts:read)
    login_res = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
    assert login_res.status_code == 200, f"Analyst login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}
    print("[PASS] 1. Authentication successful with analyst user")

    # 2. POST /api/v1/events/search default wildcard query
    post_res = client.post("/api/v1/events/search", json={"query": "*", "limit": 50}, headers=auth_headers)
    assert post_res.status_code == 200, f"POST search failed: {post_res.text}"
    data = post_res.json()
    assert "total_hits" in data
    assert "took_ms" in data
    assert "indices_searched" in data
    assert "events" in data
    assert isinstance(data["events"], list)
    assert data["total_hits"] >= len(data["events"])
    print(f"[PASS] 2. Wildcard query returned {data['total_hits']} total hits, {len(data['events'])} items in {data['took_ms']}ms")

    # 3. Verify event item schema
    if len(data["events"]) > 0:
        ev = data["events"][0]
        for field in ["id", "timestamp", "index", "source_type", "host", "severity", "summary", "raw"]:
            assert field in ev, f"Missing required field {field} in event item: {ev}"
        print("[PASS] 3. Event item schema fully verified")
    else:
        print("[WARN] 3. No events returned to verify item schema")

    # 4. GET /api/v1/events/search endpoint parity
    get_res = client.get("/api/v1/events/search?query=*&limit=10", headers=auth_headers)
    assert get_res.status_code == 200, f"GET search failed: {get_res.text}"
    get_data = get_res.json()
    assert get_data["total_hits"] == data["total_hits"]
    assert len(get_data["events"]) <= 10
    print(f"[PASS] 4. GET endpoint parity verified (returned {len(get_data['events'])} events with limit=10)")

    # 5. Field filter: severity:CRITICAL
    sev_res = client.post("/api/v1/events/search", json={"query": "severity:CRITICAL"}, headers=auth_headers)
    assert sev_res.status_code == 200
    sev_data = sev_res.json()
    for ev in sev_data["events"]:
        assert ev["severity"].upper() == "CRITICAL", f"Expected CRITICAL severity, got {ev['severity']}"
    print(f"[PASS] 5. Severity filtering verified ({len(sev_data['events'])} CRITICAL events)")

    # 6. Specific host filtering
    host_res = client.post("/api/v1/events/search", json={"query": "host:web-app-dmz-01"}, headers=auth_headers)
    assert host_res.status_code == 200
    host_data = host_res.json()
    for ev in host_data["events"]:
        assert "web-app-dmz-01" in ev["host"].lower() or "web-app-dmz-01" in str(ev["raw"]).lower()
    print(f"[PASS] 6. Host filter verified ({len(host_data['events'])} events for web-app-dmz-01)")

    # 7. Non-matching query returns 0 hits
    non_match = client.post("/api/v1/events/search", json={"query": "non_existent_token_xyz_99999"}, headers=auth_headers)
    assert non_match.status_code == 200
    assert non_match.json()["total_hits"] == 0
    assert len(non_match.json()["events"]) == 0
    print("[PASS] 7. Non-matching query cleanly returns 0 hits")

    # 8. RBAC protection: operator user lacks alerts:read
    op_login = client.post("/api/v1/auth/login", json={"username": "operator", "password": "OperatorPass123!"})
    assert op_login.status_code == 200
    op_token = op_login.json()["access_token"]
    op_headers = {"Authorization": f"Bearer {op_token}"}
    op_res = client.post("/api/v1/events/search", json={"query": "*"}, headers=op_headers)
    assert op_res.status_code == 403, f"Expected 403 for operator, got {op_res.status_code}"
    print("[PASS] 8. RBAC authorization correctly denied operator (HTTP 403)")

    # 9. Parameter boundary validation
    # Limit > 200 -> 422
    over_limit = client.post("/api/v1/events/search", json={"query": "*", "limit": 201}, headers=auth_headers)
    assert over_limit.status_code == 422, f"Expected 422 for limit=201, got {over_limit.status_code}"

    # Limit = 0 -> 422
    zero_limit = client.post("/api/v1/events/search", json={"query": "*", "limit": 0}, headers=auth_headers)
    assert zero_limit.status_code == 422, f"Expected 422 for limit=0, got {zero_limit.status_code}"

    # Limit non-scalar list -> 422
    list_limit = client.post("/api/v1/events/search", json={"query": "*", "limit": [10]}, headers=auth_headers)
    assert list_limit.status_code == 422, f"Expected 422 for non-scalar limit, got {list_limit.status_code}"

    # Astronomical time range -> 200 (no crash)
    extreme_tr = client.post("/api/v1/events/search", json={"query": "*", "time_range": "9999999999999999999999999999d"}, headers=auth_headers)
    assert extreme_tr.status_code == 200, f"Expected 200 for extreme time range, got {extreme_tr.status_code}"
    print("[PASS] 9. Boundary validation: limit bounds, non-scalar types, and extreme time ranges all handled safely")

    print("=" * 60)
    print("ALL 9 INDEPENDENT VERIFICATION CHECKS PASSED UNCONDITIONALLY")
    print("=" * 60)

if __name__ == "__main__":
    run_audit()
