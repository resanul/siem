import os
import unittest
from backend.app.services.agent_packages import (
    AGENT_CATALOG,
    get_package_file_info,
    get_all_packages_catalog,
    ensure_downloads_dir
)

class TestAgentPackages(unittest.TestCase):
    def test_catalog_definitions(self):
        self.assertIn("linux-deb", AGENT_CATALOG)
        self.assertIn("linux-rpm", AGENT_CATALOG)
        self.assertIn("windows", AGENT_CATALOG)
        self.assertEqual(AGENT_CATALOG["linux-deb"]["version"], "4.9.2-1")

    def test_get_all_packages_catalog(self):
        catalog = get_all_packages_catalog(server_host="192.168.1.50", server_port=7070)
        self.assertGreaterEqual(len(catalog), 3)

        deb_entry = next((item for item in catalog if item["id"] == "linux-deb"), None)
        self.assertIsNotNone(deb_entry)
        self.assertIn("192.168.1.50", deb_entry["offline_1liner"])
        self.assertIn("/downloads/agents/wazuh-agent.deb", deb_entry["local_url"])
        self.assertIn("packages.wazuh.com", deb_entry["remote_url"])

    def test_ensure_downloads_dir(self):
        d = ensure_downloads_dir()
        self.assertTrue(os.path.exists(d))
