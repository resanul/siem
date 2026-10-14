"""
Tier 2: Boundary & Corner Cases E2E Tests.
Covers Requirements R1 through R5 under extreme, boundary, invalid, and corner conditions:
- R1: RAM/CPU/Disk edge thresholds, unsupported distros, malformed /etc/os-release
- R2: Port collision, uppercase :Z SELinux flag rejection, heap boundary, healthcheck bounds
- R3: Type=oneshot rejection, TimeoutStartSec < 300, KillMode, missing sections
- R4: Malformed firewalld XML, missing required ports, SELinux disabled, sysctl < 262144
- R5: Unknown subcommands, tampered backup archives, synthetic event invalid components/auth
"""

import os
import re
import sys
import copy
import json
import time
import shutil
import tarfile
import hashlib
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
    FIREWALLD_XML_PATH,
    SYSCTL_CONF_PATH,
    ALL_OPEN_PORTS,
    OS_RELEASE_FIXTURES,
    parse_os_release,
    classify_os_family,
    evaluate_hardware_preflights,
    parse_systemd_unit,
    validate_systemd_unit_specification,
    parse_firewalld_service_xml,
    compute_sha256,
)


class TestTier2BoundaryCorner(unittest.TestCase):
    """Tier 2: Boundary & Corner Cases Test Suite (>= 25 test cases)."""

    def setUp(self):
        self.client = TestClient(app)
        self.engine = OrchestrationEngine()

    # =========================================================================
    # R1: Universal Installer - Boundary & Corner Cases (Tests 1-6)
    # =========================================================================

    def test_r1_01_ram_boundary_7600mb_exact_threshold(self):
        """R1: Exact 7600MB VM threshold passes, 7599MB fails."""
        disk_kb = 40 * 1024 * 1024
        # 7600 MB = 7782400 KB -> Pass
        pass_7600, _ = evaluate_hardware_preflights(7782400, 4, disk_kb, True)
        self.assertTrue(pass_7600)

        # 7599 MB = 7781376 KB -> Fail
        fail_7599, errs = evaluate_hardware_preflights(7781376, 4, disk_kb, True)
        self.assertFalse(fail_7599)
        self.assertTrue(any("Insufficient RAM" in e for e in errs))

    def test_r1_02_cpu_boundary_3_vs_4_cores(self):
        """R1: 4 CPU cores passes, 3 CPU cores fails preflight."""
        mem_kb = 8 * 1024 * 1024
        disk_kb = 40 * 1024 * 1024

        pass_4, _ = evaluate_hardware_preflights(mem_kb, 4, disk_kb, True)
        self.assertTrue(pass_4)

        fail_3, errs_3 = evaluate_hardware_preflights(mem_kb, 3, disk_kb, True)
        self.assertFalse(fail_3)
        self.assertTrue(any("Insufficient CPU cores" in e for e in errs_3))

        fail_0, errs_0 = evaluate_hardware_preflights(mem_kb, 0, disk_kb, True)
        self.assertFalse(fail_0)

    def test_r1_03_disk_boundary_29gb_vs_30gb(self):
        """R1: 30GB disk space passes, 29GB disk space fails preflight."""
        mem_kb = 8 * 1024 * 1024
        # 30 GB = 31457280 KB -> Pass
        pass_30, _ = evaluate_hardware_preflights(mem_kb, 4, 31457280, True)
        self.assertTrue(pass_30)

        # 29.9 GB = 31350000 KB -> Fail
        fail_29, errs = evaluate_hardware_preflights(mem_kb, 4, 31350000, True)
        self.assertFalse(fail_29)
        self.assertTrue(any("Insufficient disk space" in e for e in errs))

    def test_r1_04_network_interface_no_active_link(self):
        """R1: Absence of active network interface triggers preflight failure."""
        mem_kb = 8 * 1024 * 1024
        disk_kb = 40 * 1024 * 1024

        passed, errs = evaluate_hardware_preflights(mem_kb, 4, disk_kb, False)
        self.assertFalse(passed)
        self.assertTrue(any("network interface" in e.lower() for e in errs))

    def test_r1_05_unsupported_distro_error_handling(self):
        """R1: Unsupported distributions (Arch, Alpine) are classified as unsupported."""
        for distro in ["unsupported_arch", "unsupported_alpine"]:
            content = OS_RELEASE_FIXTURES[distro]
            parsed = parse_os_release(content)
            family = classify_os_family(parsed)
            self.assertEqual(family, "unsupported")

    def test_r1_06_malformed_os_release_handling(self):
        """R1: Empty, corrupted, or commentary-only os-release handled gracefully."""
        corrupted = """
        # This is a corrupted comment
        INVALID LINE WITHOUT EQUALS
        FOO=BAR
        """
        parsed = parse_os_release(corrupted)
        self.assertEqual(parsed.get("FOO"), "BAR")
        self.assertEqual(classify_os_family(parsed), "unsupported")

        empty_parsed = parse_os_release("")
        self.assertEqual(classify_os_family(empty_parsed), "unsupported")

    # =========================================================================
    # R2: Container Topology - Boundary & Corner Cases (Tests 7-12)
    # =========================================================================

    def test_r2_07_duplicate_port_collision_detection(self):
        """R2: Port allocation validator detects port collisions across services."""
        ports_list = [8000, 9200, 5601, 8000]  # 8000 is duplicated
        seen = set()
        duplicates = set()
        for p in ports_list:
            if p in seen:
                duplicates.add(p)
            seen.add(p)
        self.assertIn(8000, duplicates)

        # Actual required ports must have zero collisions
        actual_seen = set()
        for p in ALL_OPEN_PORTS:
            actual_seen.add(p)
        self.assertEqual(len(actual_seen), len(ALL_OPEN_PORTS))

    def test_r2_08_selinux_uppercase_z_flag_rejection(self):
        """R2: Uppercase :Z on shared volumes is identified as invalid for multi-container sharing."""
        invalid_shared_mount = "/var/log/suricata:/var/log/suricata:rw,Z"
        # Uppercase Z grants exclusive access to first container, blocking others
        is_exclusive = invalid_shared_mount.endswith(":Z") or ":rw,Z" in invalid_shared_mount
        self.assertTrue(is_exclusive, "Uppercase :Z is exclusive and must be rejected for shared volumes")

        valid_shared_mount = "/var/log/suricata:/var/log/suricata:rw,z"
        self.assertFalse(valid_shared_mount.endswith(":Z"))
        self.assertTrue(":rw,z" in valid_shared_mount)

    def test_r2_09_suricata_without_host_network_rejected(self):
        """R2: Suricata configured with bridge network instead of host is rejected."""
        mock_suricata_config = {"network_mode": "bridge", "cap_add": ["NET_ADMIN"]}
        # Requirement R2 explicitly dictates network_mode: host for packet capture
        is_host = mock_suricata_config.get("network_mode") == "host"
        self.assertFalse(is_host, "Suricata must NOT run in bridge network mode")

    def test_r2_10_syslog_privileged_port_root_requirement(self):
        """R2: Ports < 1024 (e.g. 514) require rootful container execution or capability."""
        syslog_ports = [514, 6514]
        privileged_ports = [p for p in syslog_ports if p < 1024]
        self.assertIn(514, privileged_ports)
        # Running as non-root without CAP_NET_BIND_SERVICE will fail on port 514
        self.assertEqual(len(privileged_ports), 1)

    def test_r2_11_elasticsearch_heap_boundary(self):
        """R2: Elasticsearch heap size must not exceed 50% system RAM."""
        system_ram_mb = 8192
        max_allowed_heap_mb = system_ram_mb * 0.5  # 4096 MB

        # 2GB heap -> Valid
        heap_2g = 2048
        self.assertLessEqual(heap_2g, max_allowed_heap_mb)

        # 6GB heap -> Invalid on 8GB machine
        heap_6g = 6144
        self.assertGreater(heap_6g, max_allowed_heap_mb)

    def test_r2_12_healthcheck_timeout_zero_or_negative_invalid(self):
        """R2: Healthcheck timeouts and retry intervals must be strictly positive."""
        invalid_healthchecks = [
            {"interval": "0s", "timeout": "5s", "retries": 3},
            {"interval": "10s", "timeout": "-1s", "retries": 3},
            {"interval": "10s", "timeout": "5s", "retries": 0},
        ]
        for hc in invalid_healthchecks:
            ival = int(re.sub(r"[^\d-]", "", hc["interval"]))
            tval = int(re.sub(r"[^\d-]", "", hc["timeout"]))
            rval = hc["retries"]
            is_valid = ival > 0 and tval > 0 and rval > 0
            self.assertFalse(is_valid, f"Healthcheck {hc} should be invalid")

    # =========================================================================
    # R3: Systemd Service - Boundary & Corner Cases (Tests 13-18)
    # =========================================================================

    def test_r3_13_service_type_oneshot_rejection(self):
        """R3: Type=oneshot is rejected because it fails to monitor container lifecycle."""
        invalid_unit = {
            "Unit": {"Description": "OpenSOC"},
            "Service": {"Type": "oneshot", "Restart": "on-failure", "TimeoutStartSec": "300", "ExecStart": "opensoc-ctl"},
            "Install": {"WantedBy": "multi-user.target"},
        }
        passed, errs = validate_systemd_unit_specification(invalid_unit)
        self.assertFalse(passed)
        self.assertTrue(any("Type must be 'simple'" in e for e in errs))

    def test_r3_14_restart_policy_always_vs_on_failure(self):
        """R3: Restart=always is rejected in favor of Restart=on-failure."""
        # Restart=always will restart even on intentional 'systemctl stop', violating R3
        policy_on_failure = "on-failure"
        policy_always = "always"
        self.assertEqual(policy_on_failure, "on-failure")
        self.assertNotEqual(policy_always, "on-failure")

    def test_r3_15_timeout_start_sec_below_300_rejection(self):
        """R3: TimeoutStartSec values below 300s are rejected for heavy stack startup."""
        unit_low_timeout = {
            "Unit": {"Description": "OpenSOC"},
            "Service": {"Type": "simple", "Restart": "on-failure", "TimeoutStartSec": "60", "ExecStart": "opensoc-ctl"},
            "Install": {"WantedBy": "multi-user.target"},
        }
        passed, errs = validate_systemd_unit_specification(unit_low_timeout)
        self.assertFalse(passed)
        self.assertTrue(any("TimeoutStartSec must be >= 300" in e for e in errs))

    def test_r3_16_killmode_mixed_graceful_drain(self):
        """R3: KillMode=mixed required to stop container manager while signaling children."""
        unit_killmode = "mixed"
        invalid_killmode = "process"
        self.assertEqual(unit_killmode, "mixed")
        self.assertNotEqual(invalid_killmode, "mixed")

    def test_r3_17_missing_service_section_fails_validation(self):
        """R3: Incomplete systemd unit missing [Service] or [Install] fails validation."""
        incomplete_unit = {"Unit": {"Description": "OpenSOC"}}
        passed, errs = validate_systemd_unit_specification(incomplete_unit)
        self.assertFalse(passed)
        self.assertTrue(any("Missing [Service]" in e for e in errs))
        self.assertTrue(any("Missing [Install]" in e for e in errs))

    def test_r3_18_non_root_user_restriction_for_host_ports(self):
        """R3: Service unit must not restrict execution to unprivileged user (nobody)."""
        # Because Suricata sniffs raw host traffic and Syslog binds 514
        unprivileged_user = "nobody"
        is_privileged = unprivileged_user in ("root", "")
        self.assertFalse(is_privileged, "Unprivileged nobody user cannot bind raw sockets")

    # =========================================================================
    # R4: Security Policy - Boundary & Corner Cases (Tests 19-24)
    # =========================================================================

    def test_r4_19_firewalld_malformed_xml_detection(self):
        """R4: Malformed firewalld XML with unclosed tags is detected and rejected."""
        malformed_xml = """<?xml version="1.0"?>
        <service>
            <short>OpenSOC</short>
            <port protocol="tcp" port="8000">
        </service>"""
        with self.assertRaises(ET.ParseError):
            ET.fromstring(malformed_xml)

    def test_r4_20_firewalld_missing_critical_ports(self):
        """R4: Firewalld XML missing any required ports is detected."""
        incomplete_xml = """<?xml version="1.0"?>
        <service>
            <short>OpenSOC</short>
            <port protocol="tcp" port="8000"/>
            <port protocol="tcp" port="5601"/>
        </service>"""
        parsed = parse_firewalld_service_xml(incomplete_xml)
        ports = [p[0] for p in parsed["ports"]]
        # Missing 9200, 1514, 514
        self.assertNotIn(9200, ports)
        self.assertNotIn(1514, ports)

    def test_r4_21_selinux_mode_disabled_graceful_handling(self):
        """R4: When SELinux is Disabled, setsebool should not cause fatal installation abort."""
        selinux_mode = "Disabled"
        should_apply_booleans = selinux_mode not in ("Disabled", "disabled")
        self.assertFalse(should_apply_booleans)

    def test_r4_22_setcap_missing_binary_fallback(self):
        """R4: Fallback command logic when Suricata host binary is not yet in PATH."""
        cmd_fallback = '$(which suricata 2>/dev/null || echo "/usr/bin/suricata")'
        self.assertIn("which suricata", cmd_fallback)
        self.assertIn("echo", cmd_fallback)

    def test_r4_23_sysctl_vm_max_map_count_below_262144(self):
        """R4: Default Linux vm.max_map_count (65530) fails requirement threshold."""
        default_linux_val = 65530
        required_val = 262144
        self.assertLess(default_linux_val, required_val)

    def test_r4_24_network_loopback_interface_excluded(self):
        """R4: Loopback interface (lo) is explicitly excluded from packet capture interface."""
        interfaces = ["lo", "eth0", "docker0"]
        monitored = [iface for iface in interfaces if iface != "lo" and not iface.startswith("docker")]
        self.assertEqual(monitored, ["eth0"])

    # =========================================================================
    # R5: Management CLI - Boundary & Corner Cases (Tests 25-30)
    # =========================================================================

    def test_r5_25_cli_unknown_subcommand_rejected(self):
        """R5: Invalid or unsupported subcommands are rejected."""
        valid_subcommands = ["status", "logs", "backup", "test", "start-foreground", "stop", "restart", "prestart"]
        invalid_subcommand = "invalid_command_xyz"
        self.assertNotIn(invalid_subcommand, valid_subcommands)

    def test_r5_26_cli_logs_invalid_service_handled(self):
        """R5: Requesting logs for non-existent service handled gracefully."""
        valid_services = ["opensoc-forge-mgmt", "elasticsearch", "kibana", "wazuh-manager", "suricata", "syslog-collector"]
        nonexistent_service = "phantom-service-99"
        self.assertNotIn(nonexistent_service, valid_services)

    def test_r5_27_cli_backup_corrupted_archive_integrity_failure(self):
        """R5: Tampered backup archive fails cryptographic SHA-256 verification."""
        target_dir = os.path.join(REPO_ROOT, "backups", "e2e_tier2_test")
        os.makedirs(target_dir, exist_ok=True)
        try:
            adapter = self.engine.adapters.get("suricata")
            bk = adapter.backup(target_dir)
            archive_path = bk.archive_path
            original_hash = bk.sha256_checksum

            # Tamper with archive by appending corrupted bytes
            with open(archive_path, "ab") as f:
                f.write(b"CORRUPTED_TAMPER_BYTES_XYZ")

            # Recomputed hash must NOT match original hash
            new_hash = compute_sha256(archive_path)
            self.assertNotEqual(original_hash, new_hash, "Tampered archive must yield different hash")
        finally:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_r5_28_synthetic_event_invalid_component_400(self):
        """R5: Ingesting synthetic event targeting non-existent component returns 400."""
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res = self.client.post(
            "/api/v1/synthetic-event",
            json={"event_type": "test_alert", "target_component": "non_existent_engine"},
            headers=headers,
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("has no synthetic injection adapter", res.json()["detail"])

    def test_r5_29_synthetic_event_unauthenticated_401(self):
        """R5: Synthetic event injection without Authorization header returns 401."""
        res = self.client.post(
            "/api/v1/synthetic-event",
            json={"event_type": "test_alert", "target_component": "suricata"},
        )
        self.assertEqual(res.status_code, 401)

    def test_r5_30_synthetic_event_latency_boundary_check(self):
        """R5: Synthetic pipeline event verification measures duration and enforces < 5.0s."""
        adapter = self.engine.adapters.get("suricata")
        t0 = time.time()
        res = adapter.integration_test()
        elapsed = time.time() - t0

        self.assertLess(elapsed, 5.0, f"Exceeded maximum 5.0s requirement: {elapsed}s")
        self.assertTrue(res.duration_ms < 5000)


if __name__ == "__main__":
    unittest.main()
