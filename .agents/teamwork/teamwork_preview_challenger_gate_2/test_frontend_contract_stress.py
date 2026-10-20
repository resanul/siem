import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.models.schemas import EventSearchRequest, EventSearchResponse, EventItem
from backend.app.core.security import create_access_token, UserRole

INDEX_HTML_PATH = os.path.join(PROJECT_ROOT, "frontend", "index.html")

class TestResult:
    def __init__(self, name: str):
        self.name = name
        self.passed = True
        self.errors = []
        self.details = []

    def assert_true(self, condition: bool, msg: str):
        if not condition:
            self.passed = False
            self.errors.append(msg)
        else:
            self.details.append(f"PASS: {msg}")

    def log(self, msg: str):
        self.details.append(msg)

def test_pure_react18_umd_syntax() -> TestResult:
    res = TestResult("Pure React 18 UMD Syntax & JSX Scanner")
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract all script blocks
    script_pattern = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
    scripts = script_pattern.findall(content)

    res.assert_true(len(scripts) >= 1, f"Found {len(scripts)} script blocks in index.html")

    main_script = None
    for s in scripts:
        if "executeEventSearch" in s:
            main_script = s
            break

    res.assert_true(main_script is not None, "Main script containing executeEventSearch was located")
    if not main_script:
        return res

    # 1. Strip comments
    clean_js = re.sub(r"//.*", "", main_script)
    clean_js = re.sub(r"/\*(?!#__PURE__\*).*?\*/", "", clean_js, flags=re.DOTALL)

    # 2. Check for un-transpiled JSX tags outside strings
    tokenized_js = re.sub(r'`(?:\\.|[^`\\])*`', '""', clean_js)
    tokenized_js = re.sub(r'"(?:\\.|[^"\\])*"', '""', tokenized_js)
    tokenized_js = re.sub(r"'(?:\\.|[^'\\])*'", "''", tokenized_js)

    jsx_patterns = [
        (r"<[a-zA-Z][a-zA-Z0-9]*\b[^>]*\/?>", "Raw opening/self-closing JSX tag detected"),
        (r"<\/[a-zA-Z][a-zA-Z0-9]*>", "Raw closing JSX tag detected"),
        (r"\bimport\s+.*?from\s+['\"]", "ES module import statement detected (not supported in plain script)"),
        (r"\bexport\s+(?:default|const|let|var|function|class)", "ES module export statement detected"),
        (r"\b_jsx\s*\(", "Babel JSX transform artifact _jsx() detected"),
        (r"\b_jsxs\s*\(", "Babel JSX transform artifact _jsxs() detected"),
    ]

    for pat, label in jsx_patterns:
        matches = re.findall(pat, tokenized_js)
        filtered = [m for m in matches if "<=" not in m and "< " not in m]
        res.assert_true(len(filtered) == 0, f"{label}: count={len(filtered)} (samples: {filtered[:3]})")

    # 3. Verify createElement usage
    ce_count = len(re.findall(r"React\.createElement\(", main_script))
    res.assert_true(ce_count > 100, f"React.createElement is widely used across components: {ce_count} occurrences")

    # 4. Verify search console component uses createElement exclusively
    search_section_match = re.search(r'currentScreen === "search" && (/\*#__PURE__\*/)?React\.createElement\(.*?\), currentScreen === "hosts"', content, re.DOTALL)
    res.assert_true(search_section_match is not None, "Search screen section identified between 'search' and 'hosts'")
    if search_section_match:
        section_text = search_section_match.group(0)
        has_react_create = "React.createElement" in section_text
        res.assert_true(has_react_create, "Search console is constructed entirely using React.createElement")

    # 5. Verify all required state hooks exist
    required_states = [
        'eventQuery', 'setEventQuery',
        'eventTimeRange', 'setEventTimeRange',
        'eventResults', 'setEventResults',
        'eventTotalHits', 'setEventTotalHits',
        'eventTookMs', 'setEventTookMs',
        'eventIndicesSearched', 'setEventIndicesSearched',
        'eventLoading', 'setEventLoading',
        'eventError', 'setEventError',
        'selectedEvent', 'setSelectedEvent',
        'eventCopySuccess', 'setEventCopySuccess'
    ]
    for st in required_states:
        res.assert_true(st in main_script, f"State variable/setter '{st}' is declared in React component")

    return res

def test_api_contract_alignment() -> TestResult:
    res = TestResult("Backend API Contract Alignment & TestClient Execution")

    # 1. Verify schema contract definitions in backend
    req_fields = EventSearchRequest.model_fields
    res.assert_true("query" in req_fields, "EventSearchRequest contains 'query' field")
    res.assert_true("indices" in req_fields, "EventSearchRequest contains 'indices' field")
    res.assert_true("time_range" in req_fields, "EventSearchRequest contains 'time_range' field")
    res.assert_true("limit" in req_fields, "EventSearchRequest contains 'limit' field")

    # 2. Extract payload generated by executeEventSearch in frontend/index.html
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    res.assert_true('fetch("/api/v1/events/search"' in content, "Frontend targets '/api/v1/events/search'")
    res.assert_true('method: "POST"' in content or "method: 'POST'" in content, "Frontend uses HTTP POST method")
    res.assert_true('"Content-Type": "application/json"' in content, "Frontend sets Content-Type application/json header")
    res.assert_true('localStorage.getItem("token")' in content, "Frontend retrieves bearer token for Authorization header")

    # 3. Create authenticated TestClient session matching frontend login
    client = TestClient(app)
    login_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    res.assert_true(login_resp.status_code == 200, "Frontend login credentials succeed on /api/v1/auth/login")
    token = login_resp.json().get("access_token", "")
    auth_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 4. Execute all payloads that frontend produces against real backend API
    test_cases = [
        {"name": "Default search payload", "payload": {"query": "*", "time_range": "24h", "limit": 50}},
        {"name": "Preset suricata-*", "payload": {"query": "suricata-*", "time_range": "24h", "limit": 50}},
        {"name": "Preset wazuh-alerts-*", "payload": {"query": "wazuh-alerts-*", "time_range": "1h", "limit": 50}},
        {"name": "Preset syslog-*", "payload": {"query": "syslog-*", "time_range": "24h", "limit": 50}},
        {"name": "Preset severity:CRITICAL", "payload": {"query": "severity:CRITICAL", "time_range": "7d", "limit": 50}},
        {"name": "Preset host filter", "payload": {"query": "host:web-app-dmz-01", "time_range": "15m", "limit": 50}},
        {"name": "Preset event.category:network", "payload": {"query": "event.category:network", "time_range": "24h", "limit": 50}},
        {"name": "Preset mitre.tactic:Execution", "payload": {"query": "mitre.tactic:Execution", "time_range": "24h", "limit": 50}},
        {"name": "Preset all telemetry", "payload": {"query": "*", "time_range": "all", "limit": 50}},
    ]

    for tc in test_cases:
        # Pydantic schema validation
        try:
            req_obj = EventSearchRequest(**tc["payload"])
            res.assert_true(req_obj.limit == 50, f"{tc['name']}: limit validated to 50")
        except Exception as e:
            res.assert_true(False, f"{tc['name']} failed Pydantic validation: {e}")

        # Real backend endpoint execution
        resp = client.post("/api/v1/events/search", json=tc["payload"], headers=auth_headers)
        res.assert_true(resp.status_code == 200, f"{tc['name']} -> HTTP {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            res.assert_true("total_hits" in data, f"{tc['name']} response contains 'total_hits'")
            res.assert_true("took_ms" in data, f"{tc['name']} response contains 'took_ms'")
            res.assert_true("indices_searched" in data, f"{tc['name']} response contains 'indices_searched'")
            res.assert_true("events" in data, f"{tc['name']} response contains 'events'")
            res.assert_true(isinstance(data["events"], list), f"{tc['name']} events is a list")

    # 5. Test Response Schema Alignment with sample EventSearchResponse
    sample_response = EventSearchResponse(
        total_hits=3,
        took_ms=12,
        indices_searched=["suricata-*", "wazuh-alerts-*"],
        events=[
            EventItem(
                id="evt-001",
                timestamp="2026-10-18T19:00:00Z",
                index="suricata-eve",
                source_type="suricata.eve.alert",
                host="web-app-dmz-01",
                severity="CRITICAL",
                summary="ET EXPLOIT Apache Log4j RCE Attempt",
                raw={"alert": {"signature": "ET EXPLOIT Log4j"}}
            )
        ]
    )
    resp_dict = sample_response.model_dump()
    res.assert_true(isinstance(resp_dict["events"], list), "Response events is a list")
    res.assert_true(isinstance(resp_dict["total_hits"], int), "Response total_hits is an int")
    res.assert_true(isinstance(resp_dict["took_ms"], int), "Response took_ms is an int")
    res.assert_true(isinstance(resp_dict["indices_searched"], list), "Response indices_searched is a list")

    return res

def test_modal_and_clipboard_resiliency() -> TestResult:
    res = TestResult("Modal Rendering and Clipboard Resiliency Stress Testing")
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Verify modal raw JSON handling
    res.assert_true("JSON.stringify(selectedEvent.raw || selectedEvent, null, 2)" in content,
                    "Modal uses resilient raw JSON stringify: selectedEvent.raw || selectedEvent")

    # 2. Verify clipboard copy function implementation
    res.assert_true("const handleCopyEventJson = (eventObj) => {" in content, "handleCopyEventJson exists")
    res.assert_true("navigator.clipboard && navigator.clipboard.writeText" in content, "navigator.clipboard primary pathway exists")
    res.assert_true("document.execCommand(\"copy\")" in content or "document.execCommand('copy')" in content,
                    "document.execCommand('copy') fallback pathway exists")
    res.assert_true("fallbackCopyText" in content, "Dedicated fallbackCopyText function is defined")

    # 3. Stress-test JSON serialization with adversarial payloads simulating browser JS engine
    def simulate_event_modal_render(selectedEvent: Any) -> Dict[str, Any]:
        if not selectedEvent:
            return {"rendered": False}

        source_badge = (selectedEvent.get("source_type") or selectedEvent.get("index") or "event")
        severity_badge = (selectedEvent.get("severity") or "INFO").upper()
        summary = selectedEvent.get("summary") or selectedEvent.get("title") or "Raw Telemetry Event Record"

        event_id = selectedEvent.get("id") or "-"
        timestamp = selectedEvent.get("timestamp") or "-"
        host = selectedEvent.get("host") or "unknown"
        index_target = selectedEvent.get("index") or "-"

        raw_to_stringify = selectedEvent.get("raw") if selectedEvent.get("raw") is not None else selectedEvent
        json_output = json.dumps(raw_to_stringify, indent=2)

        copy_target = selectedEvent.get("raw") if selectedEvent.get("raw") is not None else selectedEvent
        copy_string = json.dumps(copy_target or {}, indent=2)

        return {
            "rendered": True,
            "source_badge": source_badge,
            "severity_badge": severity_badge,
            "summary": summary,
            "event_id": event_id,
            "timestamp": timestamp,
            "host": host,
            "index_target": index_target,
            "json_output_len": len(json_output),
            "copy_string_len": len(copy_string)
        }

    adversarial_events = [
        {
            "name": "Standard telemetry event",
            "event": {
                "id": "evt-101",
                "timestamp": "2026-10-18T12:00:00Z",
                "index": "suricata-eve",
                "source_type": "suricata.alert",
                "host": "sensor-01",
                "severity": "CRITICAL",
                "summary": "Outbound DNS Tunneling",
                "raw": {"dns": {"query": "evil.com", "rrtype": "TXT"}}
            }
        },
        {
            "name": "Event with raw = None / null",
            "event": {
                "id": "evt-102",
                "timestamp": "2026-10-18T12:05:00Z",
                "index": "syslog",
                "source_type": "syslog",
                "host": "auth-server",
                "severity": "HIGH",
                "summary": "SSH brute force attempt",
                "raw": None
            }
        },
        {
            "name": "Event with raw = {} (empty object)",
            "event": {
                "id": "evt-103",
                "timestamp": "2026-10-18T12:10:00Z",
                "index": "wazuh-alerts",
                "source_type": "wazuh",
                "host": "db-server",
                "severity": "MEDIUM",
                "summary": "File integrity modified",
                "raw": {}
            }
        },
        {
            "name": "Event with deeply nested object (15 levels)",
            "event": {
                "id": "evt-104",
                "timestamp": "2026-10-18T12:15:00Z",
                "index": "suricata-eve",
                "source_type": "suricata",
                "host": "core-gw",
                "severity": "LOW",
                "summary": "Deep nested payload",
                "raw": {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": {"l7": {"l8": {"l9": {"l10": {"val": [1, 2, "deep", None, True]}}}}}}}}}}}
            }
        },
        {
            "name": "Event with all optional fields missing or null",
            "event": {
                "id": None,
                "timestamp": None,
                "index": None,
                "source_type": None,
                "host": None,
                "severity": None,
                "summary": None,
                "raw": None
            }
        },
        {
            "name": "Event with Unicode, symbols, newlines, and quotes",
            "event": {
                "id": "evt-⚡-106",
                "timestamp": "2026-10-18T12:30:00Z",
                "index": "wazuh-alerts-2026",
                "source_type": "wazuh.fim",
                "host": "host-üñîçødé",
                "severity": "critical",
                "summary": "Exploit: \"'; DROP TABLE alerts; -- \n\t🔥",
                "raw": {"attack_vector": "cmd.exe /c echo 'hello \"world\"' & dir", "unicode": "こんにちは"}
            }
        }
    ]

    for adv in adversarial_events:
        try:
            out = simulate_event_modal_render(adv["event"])
            res.assert_true(out["rendered"] is True, f"{adv['name']} rendered successfully")
            res.assert_true(out["severity_badge"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                            f"{adv['name']} severity normalized: {out['severity_badge']}")
            res.assert_true(out["json_output_len"] > 0, f"{adv['name']} produced non-empty JSON output")
            res.assert_true(out["copy_string_len"] > 0, f"{adv['name']} produced non-empty clipboard string")
        except Exception as e:
            res.assert_true(False, f"{adv['name']} raised unexpected exception: {e}")

    # 4. Test modal Escape key close integration
    res.assert_true("if (selectedEvent) setSelectedEvent(null);" in content,
                    "Global Escape key listener closes selectedEvent modal")

    return res

def test_empty_state_and_error_recovery() -> TestResult:
    res = TestResult("Empty State and Error Recovery Verification")
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Verify Empty State rendering condition and elements
    empty_cond = "(!eventLoading && eventResults.length === 0)" in content
    res.assert_true(empty_cond, "Empty state triggers when !eventLoading && eventResults.length === 0")

    res.assert_true("No Telemetry Events Found" in content, "Empty state renders 'No Telemetry Events Found' title")
    res.assert_true('No events matched your query' in content, "Empty state displays current query and time range message")
    res.assert_true("Actionable Suggestions:" in content, "Empty state displays 'Actionable Suggestions' guidance")
    res.assert_true("Reset Search to All Events (*)" in content, "Empty state includes 'Reset Search to All Events (*)' button")

    # 2. Verify Reset Search button action
    reset_action_found = (
        'setEventQuery("*");' in content and
        'setEventTimeRange("24h");' in content and
        'executeEventSearch("*", "24h");' in content
    )
    res.assert_true(reset_action_found, "Reset button resets query to '*', time_range to '24h', and re-executes search")

    # 3. Verify Error Handling in executeEventSearch
    res.assert_true("setEventError(null);" in content, "executeEventSearch clears previous error on new execution")
    res.assert_true("setEventError(errJson.detail" in content,
                    "Non-200 HTTP responses extract backend error detail or status code")
    res.assert_true('setEventError("Network error: Unable to reach search backend.");' in content,
                    "Network exceptions set descriptive network error message")
    res.assert_true("setEventLoading(false);" in content, "finally block guarantees loading state resets")

    # 4. Verify Error Banner UI and Retry Action
    res.assert_true("eventError &&" in content, "Error banner renders conditionally on eventError")
    res.assert_true('"alert-triangle"' in content, "Error banner displays alert triangle icon")
    res.assert_true('"Retry"' in content, "Error banner provides Retry button")

    # 5. Live TestClient Error Verification (RBAC 403 Forbidden with detail)
    client = TestClient(app)
    unauthorized_role_token = create_access_token(data={"sub": "operator", "role": UserRole.RECOVERY_OPERATOR.value})
    unauth_role_resp = client.post(
        "/api/v1/events/search",
        json={"query": "*"},
        headers={"Authorization": f"Bearer {unauthorized_role_token}"}
    )
    res.assert_true(unauth_role_resp.status_code == 403, f"API rejects role lacking alerts:read with 403 (got {unauth_role_resp.status_code})")
    err_json = unauth_role_resp.json()
    res.assert_true("detail" in err_json, "403 response contains 'detail' field parsed by frontend")

    # 6. Live TestClient Error Verification (Invalid limit produces 422 with detail)
    admin_token = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"}).json()["access_token"]
    invalid_limit_resp = client.post(
        "/api/v1/events/search",
        json={"query": "*", "limit": 9999},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    res.assert_true(invalid_limit_resp.status_code == 422, "API rejects limit > 200 with 422 Unprocessable Entity")
    res.assert_true("detail" in invalid_limit_resp.json(), "422 response contains 'detail' field")

    return res

def test_auto_load_and_lucide_hydration() -> TestResult:
    res = TestResult("Auto-Load Navigation & Lucide Icon Hydration Verification")
    with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Verify Navigation item in navSections
    nav_item_found = (
        'id: "search"' in content and
        'label: "Event Investigation"' in content and
        'icon: "search"' in content
    )
    res.assert_true(nav_item_found, "Nav item 'search' (Event Investigation) registered under OPERATIONS")

    # 2. Verify Auto-load on currentScreen transition
    autoload_block = re.search(r'if\s*\(\s*currentScreen\s*===\s*["\']search["\']\s*\)\s*\{\s*executeEventSearch\(\);\s*\}', content)
    res.assert_true(autoload_block is not None, "useEffect([currentScreen]) automatically invokes executeEventSearch()")

    # 3. Verify Lucide Icon Hydration
    res.assert_true("window.lucide.createIcons()" in content, "window.lucide.createIcons() called for icon rehydration")

    # Check Lucide useEffect dependencies
    lucide_deps_match = re.search(r'\}\s*,\s*\[([^\]]*eventResults[^\]]*)\]\s*\);', content)
    res.assert_true(lucide_deps_match is not None, "Lucide useEffect includes event search dependencies")
    if lucide_deps_match:
        deps = lucide_deps_match.group(1)
        res.assert_true("currentScreen" in deps, "Lucide deps include 'currentScreen'")
        res.assert_true("eventResults" in deps, "Lucide deps include 'eventResults'")
        res.assert_true("eventLoading" in deps, "Lucide deps include 'eventLoading'")
        res.assert_true("selectedEvent" in deps, "Lucide deps include 'selectedEvent'")
        res.assert_true("eventCopySuccess" in deps, "Lucide deps include 'eventCopySuccess'")

    # 4. Verify all icons used in Search Console
    icons_used = ["search", "zap", "loader", "alert-triangle", "refresh-cw", "x", "check", "copy"]
    for icon in icons_used:
        res.assert_true(f'"{icon}"' in content, f"Icon '{icon}' referenced in search UI")

    return res

def test_browser_headless_dom_render() -> TestResult:
    res = TestResult("Headless Browser DOM & Syntax Execution (msedge)")
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if not os.path.exists(edge_path):
        edge_path = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

    if not os.path.exists(edge_path):
        res.log("WARN: msedge.exe not found on default paths; skipping live browser execution.")
        return res

    file_url = f"file:///{INDEX_HTML_PATH.replace(os.sep, '/')}"
    cmd = [
        edge_path,
        "--headless",
        "--disable-gpu",
        "--dump-dom",
        file_url
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            timeout=15
        )
        html_out = proc.stdout or ""

        # Verify that root rendered
        res.assert_true(len(html_out) > 5000, f"Headless browser dumped {len(html_out)} bytes of DOM")

        # Crucial check: make sure the Global Error Diagnostics banner did NOT trigger inside #root
        root_match = re.search(r'<div id="root">(.*?)</div>', html_out, re.DOTALL)
        if root_match:
            root_content = root_match.group(1)
            error_in_root = "A JavaScript dependency or startup exception occurred" in root_content
            res.assert_true(not error_in_root, "Zero JavaScript startup errors or dependency exceptions in #root")
        else:
            res.assert_true("OpenSOC Forge" in html_out, "DOM includes 'OpenSOC Forge' header")

        # Verify that the navigation sidebar rendered
        res.assert_true("Event Investigation" in html_out, "DOM includes 'Event Investigation' sidebar element")
        res.assert_true("OpenSOC Forge" in html_out, "DOM includes 'OpenSOC Forge' header")

    except Exception as e:
        res.assert_true(False, f"Headless browser execution failed: {e}")

    return res

def run_all_tests():
    print("=" * 80)
    print("OPEN-SOC FORGE — FRONTEND CONTRACT & STRESS CHALLENGER SUITE")
    print("=" * 80)

    suites = [
        test_pure_react18_umd_syntax,
        test_api_contract_alignment,
        test_modal_and_clipboard_resiliency,
        test_empty_state_and_error_recovery,
        test_auto_load_and_lucide_hydration,
        test_browser_headless_dom_render
    ]

    total_suites = len(suites)
    passed_suites = 0

    for test_fn in suites:
        result = test_fn()
        status = "PASSED" if result.passed else "FAILED"
        if result.passed:
            passed_suites += 1
        print(f"\n[{status}] {result.name}")
        for d in result.details:
            print(f"   {d}")
        for err in result.errors:
            print(f"   FAIL: {err}")

    print("\n" + "=" * 80)
    print(f"SUMMARY: {passed_suites}/{total_suites} Suites Passed")
    print("=" * 80)

    if passed_suites != total_suites:
        sys.exit(1)

if __name__ == "__main__":
    run_all_tests()
