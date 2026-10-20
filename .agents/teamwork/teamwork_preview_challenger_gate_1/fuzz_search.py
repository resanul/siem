import sys, os
sys.path.insert(0, os.path.abspath("."))
from fastapi.testclient import TestClient
from backend.app.main import app

c = TestClient(app, raise_server_exceptions=False)

fuzz_tests = [
    # query variations
    {"query": None},
    {"query": ""},
    {"query": "a" * 50000},
    {"query": '"""'},
    {"query": '"\\"'},
    {"query": "NOT " * 100},
    {"query": "OR " * 100},
    {"query": "AND " * 100},
    # indices variations
    {"indices": []},
    {"indices": [""]},
    {"indices": ["*"]},
    {"indices": ["a" * 500]},
    {"indices": ["suricata-*", "wazuh-*"]},
    # time_range variations
    {"time_range": "0s"},
    {"time_range": "0m"},
    {"time_range": "0h"},
    {"time_range": "0d"},
    {"time_range": "-1d"},
    {"time_range": "none"},
    {"time_range": "all"},
    {"time_range": "*"},
    {"time_range": "99999d"},
    {"time_range": "365000d"},
    {"time_range": "3650000d"},
    {"time_range": "100000000d"},
    {"time_range": "9999999999999999999999999999999999999999999999999999d"},
    # limit variations
    {"limit": 1},
    {"limit": 50},
    {"limit": 200},
    {"limit": 201},
    {"limit": -1},
    {"limit": 0},
    {"limit": [10]},
    {"limit": {"a": 1}},
    {"limit": None},
]

crashes = []
for payload in fuzz_tests:
    r = c.post("/api/v1/events/search", json=payload)
    if r.status_code == 500:
        crashes.append(("POST", payload, r.status_code))

for payload in fuzz_tests:
    params = {}
    if "query" in payload and payload["query"] is not None:
        params["query"] = payload["query"]
    if "time_range" in payload:
        params["time_range"] = payload["time_range"]
    if "limit" in payload:
        params["limit"] = payload["limit"]
    r = c.get("/api/v1/events/search", params=params)
    if r.status_code == 500:
        crashes.append(("GET", params, r.status_code))

print(f"Total crashes (HTTP 500): {len(crashes)}")
for method, p, status in crashes:
    print(f"  {method} {p} -> {status}")
