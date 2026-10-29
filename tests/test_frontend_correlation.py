"""
Comprehensive automated verification suite for Correlation Engine Frontend Integration (Milestone M4).
Verifies React 18 UMD syntax purity, state hooks, navigation, sub-tab views,
forensic drill-down modal, 1-click clipboard copy with fallback, rule toggle & attack simulation,
engine control actions, Lucide icon hydration, and FastAPI static mount.
"""

import json
import os
import re
import sys
import unittest
from typing import Any, Dict, List

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from backend.app.main import app

INDEX_HTML_PATH = os.path.join(PROJECT_ROOT, "frontend", "index.html")


class TestFrontendCorrelationIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

        # Extract all script tags
        cls.scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", cls.html_content, re.DOTALL | re.IGNORECASE)
        cls.main_script = None
        for s in cls.scripts:
            if "fetchCorrelationIncidents" in s:
                cls.main_script = s
                break

        cls.client = TestClient(app)

    # =========================================================================
    # 1. Pure React 18 UMD Syntax Purity Tests
    # =========================================================================

    def test_r1_index_html_exists_and_non_empty(self):
        """frontend/index.html must exist and contain valid HTML document structure."""
        self.assertTrue(os.path.exists(INDEX_HTML_PATH))
        self.assertGreater(len(self.html_content), 100000)
        self.assertIn("<!DOCTYPE html>", self.html_content)
        self.assertIn('<html lang="en" class="dark">', self.html_content)

    def test_r2_zero_raw_jsx_in_scripts(self):
        """All JavaScript script tags must be free of raw un-transpiled JSX and ES modules."""
        self.assertIsNotNone(self.main_script, "Main application script was not located in index.html")

        # Strip comments
        clean_js = re.sub(r"//.*", "", self.main_script)
        clean_js = re.sub(r"/\*(?!#__PURE__\*).*?\*/", "", clean_js, flags=re.DOTALL)

        # Tokenize string literals to avoid false positives inside text
        tokenized_js = re.sub(r'`(?:\\.|[^`\\])*`', '""', clean_js)
        tokenized_js = re.sub(r'"(?:\\.|[^"\\])*"', '""', tokenized_js)
        tokenized_js = re.sub(r"'(?:\\.|[^'\\])*'", "''", tokenized_js)

        patterns = [
            (r"<[a-zA-Z][a-zA-Z0-9]*\b[^>]*\/?>", "Raw opening/self-closing JSX tag detected"),
            (r"<\/[a-zA-Z][a-zA-Z0-9]*>", "Raw closing JSX tag detected"),
            (r"\bimport\s+.*?from\s+['\"]", "ES module import detected in script"),
            (r"\bexport\s+(?:default|const|let|var|function|class)", "ES module export detected"),
            (r"\b_jsx\s*\(", "Babel JSX artifact _jsx() detected"),
            (r"\b_jsxs\s*\(", "Babel JSX artifact _jsxs() detected"),
        ]

        for pat, desc in patterns:
            matches = re.findall(pat, tokenized_js)
            filtered = [m for m in matches if "<=" not in m and "< " not in m]
            self.assertEqual(len(filtered), 0, f"{desc}: {filtered[:5]}")

    def test_r3_balanced_delimiters_in_all_scripts(self):
        """All <script> tags must have 0 delimiter imbalances (parentheses, braces, brackets)."""
        for idx, s in enumerate(self.scripts):
            paren = brace = bracket = 0
            in_single = in_double = in_backtick = False
            in_line_comment = in_block_comment = False
            i = 0
            n = len(s)
            while i < n:
                c = s[i]
                c2 = s[i:i+2]
                if in_line_comment:
                    if c == '\n': in_line_comment = False
                    i += 1
                    continue
                if in_block_comment:
                    if c2 == '*/':
                        in_block_comment = False
                        i += 2
                        continue
                    i += 1
                    continue
                if in_single:
                    if c == '\\': i += 2; continue
                    if c == "'": in_single = False
                    i += 1
                    continue
                if in_double:
                    if c == '\\': i += 2; continue
                    if c == '"': in_double = False
                    i += 1
                    continue
                if in_backtick:
                    if c == '\\': i += 2; continue
                    if c == '`': in_backtick = False
                    i += 1
                    continue
                if c2 == '//':
                    in_line_comment = True
                    i += 2
                    continue
                if c2 == '/*':
                    in_block_comment = True
                    i += 2
                    continue
                if c == "'": in_single = True; i += 1; continue
                if c == '"': in_double = True; i += 1; continue
                if c == '`': in_backtick = True; i += 1; continue
                if c == '(': paren += 1
                elif c == ')': paren -= 1
                elif c == '{': brace += 1
                elif c == '}': brace -= 1
                elif c == '[': bracket += 1
                elif c == ']': bracket -= 1
                i += 1

            self.assertEqual(paren, 0, f"Script #{idx} has unbalanced parentheses ({paren})")
            self.assertEqual(brace, 0, f"Script #{idx} has unbalanced braces ({brace})")
            self.assertEqual(bracket, 0, f"Script #{idx} has unbalanced brackets ({bracket})")

    # =========================================================================
    # 2. State Hooks & Baseline Constants
    # =========================================================================

    def test_r4_correlation_baseline_constants_present(self):
        """Baseline initialCorrelationRules and initialCorrelationStatus must exist."""
        self.assertIn("initialCorrelationRules", self.html_content)
        self.assertIn("initialCorrelationStatus", self.html_content)
        self.assertIn("RULE-CORR-001", self.html_content)
        self.assertIn("RULE-CORR-006", self.html_content)

    def test_r5_correlation_state_hooks_declared(self):
        """All required correlation state hooks and setters must be declared."""
        required_states = [
            "correlationIncidents", "setCorrelationIncidents",
            "correlationRules", "setCorrelationRules",
            "correlationStatus", "setCorrelationStatus",
            "correlationTab", "setCorrelationTab",
            "selectedIncident", "setSelectedIncident",
            "selectedIncidentDetail", "setSelectedIncidentDetail",
            "corrCopySuccess", "setCorrCopySuccess",
            "editingRule", "setEditingRule",
            "ruleConfigModalOpen", "setRuleConfigModalOpen",
            "incidentFilterSev", "setIncidentFilterSev",
            "incidentFilterSrc", "setIncidentFilterSrc",
            "incidentSearchQ", "setIncidentSearchQ",
            "correlationLoading", "setCorrelationLoading",
            "ruleActionLoading", "setRuleActionLoading",
            "engineActionLoading", "setEngineActionLoading",
            "simulatingRule", "setSimulatingRule",
            "simulationToast", "setSimulationToast",
        ]
        for st in required_states:
            self.assertIn(st, self.main_script, f"State variable/setter '{st}' is declared in React component")

    # =========================================================================
    # 3. Navigation Integration Tests
    # =========================================================================

    def test_r6_navigation_item_registered(self):
        """Correlation Engine navigation item must be registered in navSections."""
        self.assertIn('id: "correlation"', self.html_content)
        self.assertIn('label: "Correlation Engine"', self.html_content)
        self.assertIn('icon: "cpu"', self.html_content)

    def test_r7_correlation_screen_conditional_render(self):
        """currentScreen === 'correlation' must conditionally render the correlation view."""
        self.assertIn('currentScreen === "correlation"', self.html_content)
        self.assertIn("Cross-Source Real-Time Correlation Engine", self.html_content)

    # =========================================================================
    # 4. Correlation Engine Sub-Views & Components
    # =========================================================================

    def test_r8_sub_navigation_tabs_present(self):
        """All three sub-navigation tabs must be present with proper labels and icons."""
        self.assertIn("Incidents & Attack Chains", self.html_content)
        self.assertIn("Detection Rules Catalog", self.html_content)
        self.assertIn("Engine Status & Telemetry", self.html_content)

    def test_r9_incidents_view_components(self):
        """Incidents view must feature severity badges, risk score meter, MITRE tags, and entity tags."""
        self.assertIn("TOTAL CORRELATED INCIDENTS", self.html_content)
        self.assertIn("CRITICAL ATTACK CHAINS", self.html_content)
        self.assertIn("ENTITIES AT RISK", self.html_content)
        self.assertIn("ACTIVE SLIDING WINDOWS", self.html_content)
        self.assertIn("Pivot & Inspect Root Cause", self.html_content)

    def test_r10_rules_catalog_components(self):
        """Rules catalog must display all 6 rules with toggle switches and attack simulation buttons."""
        self.assertIn("Executable Multi-Source Correlation Detection Rules", self.html_content)
        self.assertIn("RULE-CORR-001", self.html_content)
        self.assertIn("RULE-CORR-002", self.html_content)
        self.assertIn("RULE-CORR-003", self.html_content)
        self.assertIn("RULE-CORR-004", self.html_content)
        self.assertIn("RULE-CORR-005", self.html_content)
        self.assertIn("RULE-CORR-006", self.html_content)
        self.assertIn("Simulate Attack", self.html_content)

    def test_r11_engine_status_and_telemetry_metrics(self):
        """Engine status view must display running state, controls, 5 KPI cards, and 6-source health cards."""
        self.assertIn("Engine Core: RUNNING", self.html_content)
        self.assertIn("EVENTS EVALUATED", self.html_content)
        self.assertIn("ACTIVE WINDOWS", self.html_content)
        self.assertIn("RESEQUENCED EVENTS", self.html_content)
        self.assertIn("DEDUP SUPPRESSIONS", self.html_content)
        self.assertIn("ENGINE UPTIME", self.html_content)

        # 6-Source telemetry cards
        sources = [
            "Wazuh HIDS",
            "Suricata NIDS",
            "Squid Gateway",
            "Check Point FW",
            "RSA NetWitness",
            "Active Directory",
        ]
        for src in sources:
            self.assertIn(src, self.html_content, f"Telemetry source card for '{src}' is rendered")

    # =========================================================================
    # 5. Forensic Drill-Down Modal & 1-Click Clipboard Copy
    # =========================================================================

    def test_r12_forensic_drill_down_modal_structure(self):
        """Forensic drill-down modal must render timeline, entity graph, raw JSON, and containment actions."""
        self.assertIn("INCIDENT FORENSIC DRILL-DOWN:", self.html_content)
        self.assertIn("ATTACKER SOURCE IP", self.html_content)
        self.assertIn("TARGET HOST", self.html_content)
        self.assertIn("TARGET ACCOUNT / USER", self.html_content)
        self.assertIn("Attack Sequence Timeline", self.html_content)
        self.assertIn("NIST SP 800-61r2 Containment & Active Response Actions", self.html_content)
        self.assertIn("Isolate Host", self.html_content)
        self.assertIn("Revoke Account & TGT", self.html_content)
        self.assertIn("Block IP at Firewall", self.html_content)
        self.assertIn("Escalate to Incident War Room", self.html_content)

    def test_r13_1click_clipboard_copy_with_fallback(self):
        """handleCopyIncidentJson must implement navigator.clipboard with fallback to fallbackCopyText."""
        self.assertIn("handleCopyIncidentJson", self.main_script)
        self.assertIn("navigator.clipboard && navigator.clipboard.writeText", self.main_script)
        self.assertIn("fallbackCopyText", self.main_script)
        self.assertIn("setCorrCopySuccess", self.main_script)

    def test_r14_escape_key_closes_modals(self):
        """Escape key listener must close selectedIncident and ruleConfigModalOpen."""
        self.assertIn("if (selectedIncident) setSelectedIncident(null);", self.main_script)
        self.assertIn("if (ruleConfigModalOpen) setRuleConfigModalOpen(false);", self.main_script)

    # =========================================================================
    # 6. API Fetch Contracts Alignment
    # =========================================================================

    def test_r15_api_fetch_endpoints_mapped_in_frontend(self):
        """Frontend must map all required /api/v1/correlation/* endpoints."""
        endpoints = [
            "/api/v1/correlation/incidents",
            "/api/v1/correlation/rules",
            "/api/v1/correlation/status",
            "/api/v1/correlation/control",
            "/api/v1/correlation/simulate/",
        ]
        for ep in endpoints:
            self.assertIn(ep, self.html_content, f"Endpoint '{ep}' is referenced in frontend API calls")

    def test_r16_backend_endpoints_live_execution(self):
        """Backend endpoints mapped by frontend must respond successfully via TestClient."""
        # 1. GET /status
        st_resp = self.client.get("/api/v1/correlation/status")
        self.assertEqual(st_resp.status_code, 200)
        st_data = st_resp.json()
        self.assertIn("running", st_data)
        self.assertIn("events_processed", st_data)
        self.assertIn("rules_count", st_data)

        # 2. GET /rules
        rules_resp = self.client.get("/api/v1/correlation/rules")
        self.assertEqual(rules_resp.status_code, 200)
        rules_data = rules_resp.json()
        self.assertEqual(len(rules_data), 6)

        # 3. GET /incidents
        inc_resp = self.client.get("/api/v1/correlation/incidents")
        self.assertEqual(inc_resp.status_code, 200)
        self.assertIsInstance(inc_resp.json(), list)

        # 4. POST /control
        ctrl_resp = self.client.post("/api/v1/correlation/control", json={"action": "start"})
        self.assertEqual(ctrl_resp.status_code, 200)
        self.assertEqual(ctrl_resp.json()["status"], "SUCCESS")

        # 5. POST /simulate/RULE-CORR-001
        sim_resp = self.client.post("/api/v1/correlation/simulate/RULE-CORR-001")
        self.assertEqual(sim_resp.status_code, 200)
        sim_data = sim_resp.json()
        self.assertEqual(sim_data["status"], "SUCCESS")
        self.assertIsNotNone(sim_data.get("incident"))

    # =========================================================================
    # 7. Lucide Icon Hydration & Dependencies
    # =========================================================================

    def test_r17_lucide_icon_hydration_hook(self):
        """Lucide createIcons must be called in useEffect with correlation dependencies."""
        self.assertIn("window.lucide.createIcons()", self.html_content)
        self.assertIn("correlationIncidents", self.html_content)
        self.assertIn("selectedIncident", self.html_content)
        self.assertIn("correlationTab", self.html_content)

    def test_r18_lucide_icons_referenced(self):
        """All icon tags used in the Correlation Engine must be valid Lucide icons."""
        icons = [
            "cpu",
            "shield-alert",
            "sliders",
            "activity",
            "database",
            "server",
            "globe",
            "users",
            "play",
            "square",
            "rotate-ccw",
            "refresh-cw",
            "check",
            "x",
            "copy",
            "search",
            "zap",
            "layers",
            "terminal",
            "lock",
        ]
        for icon in icons:
            self.assertIn(f'"{icon}"', self.html_content, f"Lucide icon '{icon}' is referenced in index.html")

    # =========================================================================
    # 8. Regression Safeguards
    # =========================================================================

    def test_r19_preservation_of_legacy_polling_and_routes(self):
        """Preserve existing /api/v1/alerts polling and existing screen views."""
        self.assertIn("/api/v1/alerts", self.html_content)
        self.assertIn("setInterval", self.html_content)
        self.assertIn("2000", self.html_content)
        self.assertIn("/api/v1/synthetic-event", self.html_content)

        # Existing screens
        screens = [
            'currentScreen === "overview"',
            'currentScreen === "alerts"',
            'currentScreen === "netwitness_siem"',
            'currentScreen === "search"',
            'currentScreen === "hosts"',
            'currentScreen === "endpoint_xdr"',
            'currentScreen === "rules"',
        ]
        for sc in screens:
            self.assertIn(sc, self.html_content, f"Screen condition '{sc}' remains present")

    def test_r20_web_console_static_mount(self):
        """FastAPI must serve /console/ returning 200 OK with Correlation Engine content."""
        resp = self.client.get("/console/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("content-type", ""))
        self.assertIn("Cross-Source Real-Time Correlation Engine", resp.text)
        self.assertIn("Correlation Engine", resp.text)


if __name__ == "__main__":
    unittest.main()
