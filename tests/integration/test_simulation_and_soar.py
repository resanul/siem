"""
Integration tests for Enterprise Attack Simulation, SOAR Playbooks, MITRE Matrix, and Threat Intel.
"""

import unittest
from fastapi.testclient import TestClient
from backend.app.main import app


class TestEnterpriseSimulationAndSOAR(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        # Login as Admin
        res = self.client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
        token = res.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {token}"}

    def test_list_simulation_scenarios(self):
        res = self.client.get("/api/v1/simulation/scenarios", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        scenarios = res.json()
        self.assertGreaterEqual(len(scenarios), 3)
        ids = [s["scenario_id"] for s in scenarios]
        self.assertIn("SCENARIO-RANSOMWARE", ids)
        self.assertIn("SCENARIO-APT29", ids)
        self.assertIn("SCENARIO-LOG4J", ids)

    def test_execute_ransomware_simulation(self):
        payload = {"scenario_id": "SCENARIO-RANSOMWARE"}
        res = self.client.post("/api/v1/simulation/run", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scenario_id"], "SCENARIO-RANSOMWARE")
        self.assertTrue(data["all_detected"])
        self.assertGreaterEqual(len(data["stages_executed"]), 4)
        self.assertEqual(data["triggered_soar_playbook"], "PLAYBOOK-HOST-ISOLATION")

    def test_list_and_execute_soar_playbook(self):
        # 1. List playbooks
        res = self.client.get("/api/v1/soar/playbooks", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        playbooks = res.json()
        self.assertGreaterEqual(len(playbooks), 3)

        # 2. Execute Host Isolation Playbook
        exec_payload = {
            "playbook_id": "PLAYBOOK-HOST-ISOLATION",
            "context": {"host": "workstation-corp-88", "alert_id": "ALT-2026-002"},
        }
        exec_res = self.client.post("/api/v1/soar/execute", json=exec_payload, headers=self.headers)
        self.assertEqual(exec_res.status_code, 200)
        exec_data = exec_res.json()
        self.assertEqual(exec_data["status"], "SUCCESS")
        self.assertEqual(len(exec_data["steps"]), 5)

    def test_mitre_attack_matrix_and_coverage(self):
        res = self.client.get("/api/v1/mitre/matrix", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        matrix = res.json()
        self.assertEqual(matrix["total_tactics"], 12)
        self.assertGreater(matrix["coverage_percentage"], 70.0)
        self.assertEqual(len(matrix["tactics"]), 12)

    def test_threat_intel_and_ioc_hunting(self):
        # 1. Threat Intel Feed
        res = self.client.get("/api/v1/threat-intel/feeds", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        feed = res.json()
        self.assertGreaterEqual(len(feed), 4)

        # 2. IOC Hunt across SIEM
        hunt_res = self.client.post("/api/v1/threat-intel/hunt", json={"ioc": "198.51.100.84"}, headers=self.headers)
        self.assertEqual(hunt_res.status_code, 200)
        hunt_data = hunt_res.json()
        self.assertEqual(hunt_data["ioc"], "198.51.100.84")
        self.assertGreater(hunt_data["total_hits"], 0)

    def test_investigation_process_tree(self):
        res = self.client.get("/api/v1/investigation/process-tree/ALT-2026-001", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        tree = res.json()
        self.assertIn("root_process", tree)
        self.assertEqual(tree["root_process"]["name"], "winword.exe")
        self.assertGreater(len(tree["root_process"]["children"]), 0)


if __name__ == "__main__":
    unittest.main()
