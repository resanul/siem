"""
Unit tests for Milestones 2, 3, and 4:
- Milestone 2: Universal 1-Click Installer (install.sh) (Requirement R1)
- Milestone 3: Native Systemd Service & Policy Alignment (Requirements R3 & R4)
- Milestone 4: Self-Contained CLI Wrapper Tool (bin/opensoc-ctl) & Pipeline Integration (Requirement R5)
"""

import os
import re
import sys
import json
import time
import unittest
import xml.etree.ElementTree as ET
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api.v1.api import DEMO_ALERTS
from backend.app.models.schemas import AlertItem, AlertSeverity, AlertSource, AlertStatus
from tests.e2e.helpers import (
    REPO_ROOT,
    INSTALL_SCRIPT_PATH,
    SYSTEMD_SERVICE_PATH,
    CLI_TOOL_PATH,
    FIREWALLD_XML_PATH,
    SYSCTL_CONF_PATH,
    FRONTEND_INDEX_PATH,
    ALL_OPEN_PORTS,
    parse_systemd_unit,
    validate_systemd_unit_specification,
    parse_firewalld_service_xml,
    compute_sha256,
)


class TestMilestone2Installer(unittest.TestCase):
    """Unit tests for Milestone 2: Universal 1-Click Installer (install.sh)."""

    def setUp(self):
        self.install_script = INSTALL_SCRIPT_PATH
        self.assertTrue(os.path.exists(self.install_script), "install.sh must exist in repository root")
        with open(self.install_script, "r", encoding="utf-8") as f:
            self.content = f.read()

    def test_install_script_shebang_and_strict_mode(self):
        """install.sh must use bash shebang and set -euo pipefail."""
        lines = self.content.splitlines()
        self.assertEqual(lines[0].strip(), "#!/usr/bin/env bash")
        self.assertTrue(any("set -euo pipefail" in l for l in lines[:10]))

    def test_os_family_detection_logic(self):
        """install.sh must inspect /etc/os-release and support Debian/Kali and RHEL/Rocky families."""
        self.assertIn("/etc/os-release", self.content)
        # Debian family check
        self.assertTrue("kali" in self.content.lower() and "debian" in self.content.lower())
        self.assertIn("apt-get", self.content)
        self.assertIn("DEBIAN_FRONTEND=noninteractive", self.content)
        # RHEL family check
        self.assertTrue("rhel" in self.content.lower() and "rocky" in self.content.lower())
        self.assertIn("dnf", self.content)

    def test_hardware_preflight_thresholds(self):
        """install.sh must check RAM (7600MB threshold), CPU (>=4), Disk (>=30GB), and network state."""
        # 7600 MB VM threshold in KB (7782400)
        self.assertIn("7782400", self.content)
        self.assertIn("--skip-preflight", self.content)
        # CPU cores check
        self.assertTrue("nproc" in self.content or "cpuinfo" in self.content)
        # Disk free check (30GB in KB = 31457280)
        self.assertIn("31457280", self.content)
        # Network interface check
        self.assertIn("operstate", self.content)

    def test_kernel_parameter_sysctl_configuration(self):
        """install.sh must apply and persist sysctl vm.max_map_count=262144."""
        self.assertIn("vm.max_map_count=262144", self.content)
        self.assertIn("fs.file-max=65536", self.content)
        self.assertIn("/etc/sysctl.d/99-opensoc-forge.conf", self.content)

    def test_container_engine_provisioning(self):
        """install.sh must provision or verify container engine (Docker Compose or Podman Compose)."""
        self.assertTrue("docker" in self.content.lower())
        self.assertTrue("podman" in self.content.lower())
        self.assertIn("docker-compose-plugin", self.content)
        self.assertIn("podman-compose", self.content)

    def test_non_interactive_deployment_to_opt(self):
        """install.sh must stage files to /opt/opensoc-forge idempotently and enable systemd."""
        self.assertIn("/opt/opensoc-forge", self.content)
        self.assertIn("mkdir -p", self.content)
        self.assertIn("generate_certs.sh", self.content)
        self.assertIn("opensoc-forge.service", self.content)
        self.assertIn("systemctl enable", self.content)
        self.assertIn("/usr/local/bin/opensoc-ctl", self.content)


class TestMilestone3SystemdAndPolicies(unittest.TestCase):
    """Unit tests for Milestone 3: Native Systemd Service & Policy Alignment."""

    def setUp(self):
        self.service_path = SYSTEMD_SERVICE_PATH
        self.firewalld_path = FIREWALLD_XML_PATH
        self.sysctl_path = SYSCTL_CONF_PATH
        self.policy_script_path = os.path.join(REPO_ROOT, "scripts", "configure_security_policies.sh")

    def test_systemd_unit_file_structure_and_contracts(self):
        """opensoc-forge.service must conform to Type=simple, Restart=on-failure, TimeoutStartSec>=300."""
        self.assertTrue(os.path.exists(self.service_path), "systemd/opensoc-forge.service must exist")
        with open(self.service_path, "r", encoding="utf-8") as f:
            unit_content = f.read()

        unit = parse_systemd_unit(unit_content)
        valid, errors = validate_systemd_unit_specification(unit)
        self.assertTrue(valid, f"Systemd unit validation failed: {errors}")

        svc = unit.get("Service", {})
        self.assertEqual(svc.get("Type"), "simple")
        self.assertEqual(svc.get("Restart"), "on-failure")
        self.assertEqual(svc.get("RestartSec"), "10s")
        self.assertEqual(svc.get("TimeoutStartSec"), "300")
        self.assertEqual(svc.get("LimitNOFILE"), "65536")
        self.assertIn("start-foreground", svc.get("ExecStart", ""))
        self.assertIn("stop", svc.get("ExecStop", ""))
        self.assertIn("restart", svc.get("ExecReload", ""))
        self.assertIn("prestart", svc.get("ExecStartPre", ""))

        install = unit.get("Install", {})
        self.assertEqual(install.get("WantedBy"), "multi-user.target")

    def test_firewalld_xml_service_definition(self):
        """configs/firewalld/opensoc-forge.xml must define all required platform ports."""
        self.assertTrue(os.path.exists(self.firewalld_path), "firewalld XML must exist")
        with open(self.firewalld_path, "r", encoding="utf-8") as f:
            parsed = parse_firewalld_service_xml(f.read())

        self.assertEqual(parsed["short"], "OpenSOC Forge")
        xml_ports = [p[0] for p in parsed["ports"]]
        for required_port in ALL_OPEN_PORTS:
            self.assertIn(required_port, xml_ports, f"Port {required_port} missing from firewalld service XML")

    def test_sysctl_persistent_configuration(self):
        """configs/sysctl/99-opensoc-forge.conf must define vm.max_map_count, fs.file-max, and somaxconn."""
        self.assertTrue(os.path.exists(self.sysctl_path), "sysctl config must exist")
        with open(self.sysctl_path, "r", encoding="utf-8") as f:
            content = f.read().replace(" ", "")

        self.assertIn("vm.max_map_count=262144", content)
        self.assertIn("fs.file-max=65536", content)
        self.assertIn("net.core.somaxconn=1024", content)

    def test_configure_security_policies_script(self):
        """scripts/configure_security_policies.sh must handle SELinux, Firewalld, UFW, and setcap."""
        self.assertTrue(os.path.exists(self.policy_script_path), "configure_security_policies.sh must exist")
        with open(self.policy_script_path, "r", encoding="utf-8") as f:
            script = f.read()

        self.assertEqual(script.splitlines()[0].strip(), "#!/usr/bin/env bash")
        self.assertIn("container_manage_cgroup", script)
        self.assertIn("container_use_devices", script)
        self.assertIn("firewall-cmd", script)
        self.assertIn("setcap", script)
        self.assertIn("cap_net_raw,cap_net_admin+eip", script)
        self.assertIn("ufw", script)
        self.assertIn("promisc on", script)


class TestMilestone4CliAndPipelineIntegration(unittest.TestCase):
    """Unit tests for Milestone 4: CLI Wrapper Tool (bin/opensoc-ctl) & Pipeline Integration."""

    def setUp(self):
        self.client = TestClient(app)
        self.cli_path = CLI_TOOL_PATH
        self.assertTrue(os.path.exists(self.cli_path), "bin/opensoc-ctl must exist")
        with open(self.cli_path, "r", encoding="utf-8") as f:
            self.cli_content = f.read()

    def test_cli_wrapper_subcommands_implemented(self):
        """bin/opensoc-ctl must implement status, logs, backup, test, and lifecycle hooks."""
        self.assertEqual(self.cli_content.splitlines()[0].strip(), "#!/usr/bin/env bash")
        self.assertIn("set -euo pipefail", self.cli_content)

        # User commands
        for cmd in ["status", "logs", "backup", "test"]:
            self.assertIn(f"cmd_{cmd}", self.cli_content)

        # Lifecycle hooks
        for hook in ["start_foreground", "start", "stop", "restart", "prestart"]:
            self.assertIn(f"cmd_{hook}", self.cli_content)

    def test_backend_synthetic_event_injection_prepends_to_alerts(self):
        """POST /api/v1/synthetic-event must insert a new AlertItem into DEMO_ALERTS."""
        # 1. Login to obtain JWT
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Record initial alert count
        initial_alerts_res = self.client.get("/api/v1/alerts", headers=headers)
        self.assertEqual(initial_alerts_res.status_code, 200)
        initial_count = len(initial_alerts_res.json())

        # 3. Inject synthetic event
        t0 = time.time()
        synth_res = self.client.post(
            "/api/v1/synthetic-event",
            json={"event_type": "unit_test_synthetic", "target_component": "suricata"},
            headers=headers,
        )
        latency = time.time() - t0
        self.assertEqual(synth_res.status_code, 200)
        synth_data = synth_res.json()
        self.assertTrue(synth_data.get("passed"))
        synthetic_id = synth_data.get("synthetic_event_id")
        self.assertIsNotNone(synthetic_id)
        self.assertLess(latency, 5.0, "Injection latency must be strictly < 5.0s")

        # 4. Verify new alert appears in GET /api/v1/alerts
        updated_alerts_res = self.client.get("/api/v1/alerts", headers=headers)
        self.assertEqual(updated_alerts_res.status_code, 200)
        updated_alerts = updated_alerts_res.json()
        self.assertEqual(len(updated_alerts), initial_count + 1)

        # Check newly prepended alert properties
        top_alert = updated_alerts[0]
        self.assertIn(synthetic_id, top_alert["title"])
        self.assertEqual(top_alert["severity"], "HIGH")
        self.assertEqual(top_alert["source"], "suricata")
        self.assertEqual(top_alert["status"], "NEW")
        self.assertEqual(top_alert["host"], "opensoc-sensor-01")
        self.assertEqual(top_alert["mitre_attack_id"], "T1059")

    def test_frontend_index_html_contains_live_polling_and_api_integration(self):
        """frontend/index.html must poll /api/v1/alerts every 2000ms."""
        self.assertTrue(os.path.exists(FRONTEND_INDEX_PATH), "frontend/index.html must exist")
        with open(FRONTEND_INDEX_PATH, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for polling effect
        self.assertIn("/api/v1/alerts", html)
        self.assertIn("setInterval", html)
        self.assertIn("2000", html)
        # Check synthetic event post call
        self.assertIn("/api/v1/synthetic-event", html)


if __name__ == "__main__":
    unittest.main()
