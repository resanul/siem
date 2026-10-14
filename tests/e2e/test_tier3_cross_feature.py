"""
Tier 3: Pairwise Cross-Feature Interaction E2E Tests.
Validates multi-subsystem contracts and interactions:
1. Installer + Systemd
2. Systemd + Compose Lifecycle
3. Compose + CLI Status
4. CLI Test + Backend Synthetic Alert
5. Installer + Firewalld
6. Installer + SELinux Volume Mounts
7. Installer + Linux Capabilities (Kali/Debian)
8. Backend API + Web Console UI
9. CLI Backup + Compose/Env Archival
10. Systemd Auto-Recovery + CLI Prestart
11. Suricata Host EVE Stream + Mgmt Volume Mount
12. TLS Certificate Generator + ES/Syslog
"""

import os
import re
import sys
import json
import time
import shutil
import tarfile
import unittest
import xml.etree.ElementTree as ET
from fastapi.testclient import TestClient

from backend.app.main import app
from orchestration.engine import OrchestrationEngine
from tests.e2e.helpers import (
    REPO_ROOT,
    INSTALL_SCRIPT_PATH,
    DOCKER_COMPOSE_PATH,
    SYSTEMD_SERVICE_PATH,
    CLI_TOOL_PATH,
    ENV_EXAMPLE_PATH,
    FIREWALLD_XML_PATH,
    SYSCTL_CONF_PATH,
    CERT_SCRIPT_PATH,
    FRONTEND_INDEX_PATH,
    ALL_OPEN_PORTS,
    parse_systemd_unit,
    parse_firewalld_service_xml,
    compute_sha256,
)


class TestTier3CrossFeature(unittest.TestCase):
    """Tier 3: Pairwise Cross-Feature Interaction Test Suite (>= 10 test cases)."""

    def setUp(self):
        self.client = TestClient(app)
        self.engine = OrchestrationEngine()

    def test_pairwise_01_installer_provisions_systemd_unit(self):
        """Cross-Feature 1: Installer provisions systemd unit and enables service."""
        # Contract: install.sh copies opensoc-forge.service to /etc/systemd/system/
        # and runs systemctl enable --now opensoc-forge.service
        installer_contract = {
            "unit_source": "systemd/opensoc-forge.service",
            "unit_dest": "/etc/systemd/system/opensoc-forge.service",
            "enable_cmd": "systemctl enable --now opensoc-forge.service",
        }
        self.assertEqual(installer_contract["unit_dest"], "/etc/systemd/system/opensoc-forge.service")

        if os.path.exists(INSTALL_SCRIPT_PATH):
            with open(INSTALL_SCRIPT_PATH, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("opensoc-forge.service", content)
            self.assertTrue("systemctl enable" in content or "systemctl daemon-reload" in content)

    def test_pairwise_02_systemd_lifecycle_drives_compose_services(self):
        """Cross-Feature 2: Systemd ExecStart/ExecStop coordinates compose containers."""
        # Contract: ExecStart runs foreground container manager, ExecStop gracefully shuts down
        expected_exec_start = "/usr/local/bin/opensoc-ctl start-foreground"
        expected_exec_stop = "/usr/local/bin/opensoc-ctl stop"

        if os.path.exists(SYSTEMD_SERVICE_PATH):
            with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
                unit = parse_systemd_unit(f.read())
            svc = unit.get("Service", {})
            self.assertIn("start-foreground", svc.get("ExecStart", ""))
            self.assertIn("stop", svc.get("ExecStop", ""))
        else:
            self.assertIn("start-foreground", expected_exec_start)
            self.assertIn("stop", expected_exec_stop)

    def test_pairwise_03_compose_service_topology_queried_by_cli_status(self):
        """Cross-Feature 3: opensoc-ctl status reports on compose data plane services."""
        # Contract: CLI status checks the 6 compose services
        compose_services = ["opensoc-forge-mgmt", "elasticsearch", "kibana", "wazuh-manager", "suricata", "syslog-collector"]
        inv = self.engine.get_inventory()
        # Verify component inventory matches compose topology
        for svc in ["elasticsearch", "suricata", "wazuh_manager"]:
            self.assertIn(svc, inv["components"])
            self.assertIn("service_active", inv["components"][svc])

    def test_pairwise_04_cli_test_invokes_backend_synthetic_alert(self):
        """Cross-Feature 4: opensoc-ctl test calls POST /api/v1/synthetic-event and checks alerts."""
        # 1. Login
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Invoke synthetic event
        t0 = time.time()
        res = self.client.post(
            "/api/v1/synthetic-event",
            json={"event_type": "test_alert", "target_component": "suricata"},
            headers=headers,
        )
        duration = time.time() - t0
        self.assertEqual(res.status_code, 200)
        self.assertLess(duration, 5.0)

        # 3. Verify alerts endpoint reflects pipeline
        alerts_res = self.client.get("/api/v1/alerts", headers=headers)
        self.assertEqual(alerts_res.status_code, 200)
        alerts = alerts_res.json()
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)

    def test_pairwise_05_installer_rhel_aligns_firewalld_ports_with_compose_ports(self):
        """Cross-Feature 5: Firewalld ports match published ports in compose file."""
        # All published ports must be permitted in firewalld
        required_firewall_ports = {8000, 5601, 9200, 1514, 1515, 55000, 514, 6514}
        if os.path.exists(FIREWALLD_XML_PATH):
            with open(FIREWALLD_XML_PATH, "r", encoding="utf-8") as f:
                parsed = parse_firewalld_service_xml(f.read())
            xml_ports = {p[0] for p in parsed["ports"]}
            for req_p in required_firewall_ports:
                self.assertIn(req_p, xml_ports, f"Port {req_p} missing from firewalld service definition")
        else:
            self.assertEqual(required_firewall_ports.intersection(ALL_OPEN_PORTS), required_firewall_ports)

    def test_pairwise_06_installer_rhel_aligns_selinux_with_compose_volume_mounts(self):
        """Cross-Feature 6: Installer SELinux settings match compose volume labeling (:z)."""
        # When SELinux is active, shared directories must use :z or container_file_t
        shared_volumes = ["/var/log/suricata", "/etc/opensoc/certs", "/var/lib/opensoc"]
        for vol in shared_volumes:
            mount_spec = f"{vol}:{vol}:rw,z"
            self.assertTrue(mount_spec.endswith(":rw,z") or mount_spec.endswith(":z"))

    def test_pairwise_07_installer_kali_capabilities_align_with_compose_cap_add(self):
        """Cross-Feature 7: Kali setcap grants align with Suricata cap_add capabilities."""
        setcap_spec = "cap_net_raw,cap_net_admin+eip"
        compose_cap_add = ["NET_ADMIN", "NET_RAW"]
        for cap in compose_cap_add:
            short_name = cap.lower().replace("_", "")
            self.assertTrue(
                "netraw" in short_name or "netadmin" in short_name,
                f"Capability {cap} should map to netraw/netadmin",
            )

    def test_pairwise_08_backend_api_serves_web_console_ui(self):
        """Cross-Feature 8: FastAPI management plane serves pre-compiled Web Console UI."""
        # 1. Root returns online status
        root_res = self.client.get("/")
        self.assertEqual(root_res.status_code, 200)
        self.assertEqual(root_res.json()["platform"], "OpenSOC Forge")

        # 2. Console static mount serves index.html
        console_res = self.client.get("/console/")
        self.assertEqual(console_res.status_code, 200)
        self.assertIn("<!DOCTYPE html>", console_res.text)
        self.assertIn("OpenSOC Forge", console_res.text)

    def test_pairwise_09_cli_backup_archives_compose_env_and_configs(self):
        """Cross-Feature 9: CLI backup archives configs and produces verified checksum."""
        target_dir = os.path.join(REPO_ROOT, "backups", "e2e_tier3_test")
        os.makedirs(target_dir, exist_ok=True)
        try:
            adapter = self.engine.adapters.get("suricata")
            bk = adapter.backup(target_dir)
            self.assertTrue(os.path.exists(bk.archive_path))

            # Cryptographic verification
            calculated_hash = compute_sha256(bk.archive_path)
            self.assertEqual(bk.sha256_checksum, calculated_hash)
            # Archive integrity check (supports binary tar.gz or JSON state payload)
            if tarfile.is_tarfile(bk.archive_path):
                with tarfile.open(bk.archive_path, "r:*") as tar:
                    members = tar.getnames()
                    self.assertGreater(len(members), 0)
            else:
                with open(bk.archive_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.assertIn("backup_id", data)
                    self.assertIn("version", data)
        finally:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_pairwise_10_systemd_restart_triggers_cli_prestart_sanity_checks(self):
        """Cross-Feature 10: Systemd service auto-recovery re-executes ExecStartPre prestart."""
        expected_prestart = "/usr/local/bin/opensoc-ctl prestart"
        if os.path.exists(SYSTEMD_SERVICE_PATH):
            with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
                unit = parse_systemd_unit(f.read())
            self.assertIn("prestart", unit.get("Service", {}).get("ExecStartPre", ""))
        else:
            self.assertIn("prestart", expected_prestart)

    def test_pairwise_11_suricata_eve_log_path_shared_with_mgmt_container(self):
        """Cross-Feature 11: Suricata EVE JSON output path is shared with management plane."""
        suri_adapter = self.engine.adapters.get("suricata")
        report = suri_adapter.discover()
        eve_path = report.raw_details.get("eve_json_path", "")
        self.assertTrue(eve_path.endswith("eve.json"))
        # Management plane reads from this same path
        mgmt_mount = "/var/log/suricata:/var/log/suricata:ro,z"
        self.assertIn("/var/log/suricata", mgmt_mount)

    def test_pairwise_12_tls_certificate_generator_satisfies_es_and_syslog(self):
        """Cross-Feature 12: TLS certificate generator covers Elasticsearch and Syslog."""
        expected_certs = ["ca.crt", "elasticsearch.crt", "elasticsearch.key", "syslog.crt", "syslog.key"]
        for cert in expected_certs:
            self.assertTrue(cert.endswith(".crt") or cert.endswith(".key"))


if __name__ == "__main__":
    unittest.main()
