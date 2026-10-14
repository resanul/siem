"""
Integration tests for OpenSOC Forge Management API Endpoints.
Verifies authentication, RBAC, endpoints, synthetic events, and audit logs.
"""

import unittest
from fastapi.testclient import TestClient
from backend.app.main import app


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_root_endpoint(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["platform"], "OpenSOC Forge")
        self.assertEqual(data["status"], "ONLINE")

    def test_auth_login_success(self):
        res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "Platform Admin")

    def test_auth_login_failure(self):
        res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "WrongPassword"})
        self.assertEqual(res.status_code, 401)

    def test_overview_requires_auth(self):
        res = self.client.get("/api/v1/overview")
        self.assertEqual(res.status_code, 401)

    def test_authenticated_overview_metrics(self):
        # 1. Login
        login_res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get overview
        res = self.client.get("/api/v1/overview", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "OPERATIONAL")
        self.assertTrue(data["demo_mode"])
        self.assertGreater(data["metrics"]["total_alerts"], 0)

    def test_alerts_listing_and_filtering(self):
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res = self.client.get("/api/v1/alerts?severity=CRITICAL", headers=headers)
        self.assertEqual(res.status_code, 200)
        alerts = res.json()
        for a in alerts:
            self.assertEqual(a["severity"], "CRITICAL")

    def test_rule_syntax_testing_endpoint(self):
        login_res = self.client.post("/api/v1/auth/login", json={"username": "detector", "password": "DetectorPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "rule_content": "alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:\"ET MALWARE C2\"; content:\".stage.\"; sid:100;)",
            "rule_type": "suricata_sig",
            "sample_log": "dns query .stage.c2.example.com",
        }
        res = self.client.post("/api/v1/rules/test-syntax", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["valid_syntax"])
        self.assertTrue(data["matches"])

    def test_synthetic_event_injection_endpoint(self):
        login_res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"event_type": "test_alert", "target_component": "suricata"}
        res = self.client.post("/api/v1/synthetic-event", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["passed"])
        self.assertTrue(data["synthetic_event_id"].startswith("synth-"))

    def test_audit_trail_endpoint(self):
        login_res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res = self.client.get("/api/v1/audit", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["chain_integrity_valid"])


if __name__ == "__main__":
    unittest.main()
