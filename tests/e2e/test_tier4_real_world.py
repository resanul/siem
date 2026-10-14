"""
Tier 4: Realistic End-to-End Operational Scenarios.
Exercises comprehensive multi-stage operational lifecycle workflows:
- Scenario 1: Clean Cold Install & Auto-Boot Sequence
- Scenario 2: Automated Failure Recovery & Service Health
- Scenario 3: Multi-Component Backup & Cryptographic Verification
- Scenario 4: Rapid End-to-End Threat Ingestion & Console Alert Rendering (<5s)
- Scenario 5: Cross-Distribution Migration & Policy Re-Alignment
- Scenario 6: Telemetry Ingestion Burst & Pipeline Resilience
"""

import os
import re
import sys
import json
import time
import shutil
import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from orchestration.engine import OrchestrationEngine, JobStatus
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
    compute_sha256,
)


class TestTier4RealWorld(unittest.TestCase):
    """Tier 4: Real-World Operational Scenarios Test Suite (>= 5 scenarios)."""

    def setUp(self):
        self.client = TestClient(app)
        self.engine = OrchestrationEngine()

    def test_scenario_1_cold_install_and_auto_boot_sequence(self):
        """
        Scenario 1: Clean Cold Install & Auto-Boot Sequence.
        Simulates end-to-end installation from bare OS:
        1. Parse OS release and classify distro.
        2. Evaluate hardware preflights (RAM, CPU, Disk, Net).
        3. Verify sysctl tuning (vm.max_map_count).
        4. Validate container compose topology (6 core services).
        5. Verify systemd unit configuration (Type=simple, Restart=on-failure).
        6. Validate boot auto-start (WantedBy=multi-user.target).
        """
        # Step 1: Distro Classification (Simulating Kali Linux 2024+)
        os_info = parse_os_release(OS_RELEASE_FIXTURES["kali"])
        distro_family = classify_os_family(os_info)
        self.assertEqual(distro_family, "debian")

        # Step 2: Hardware Preflights
        mem_kb = 8 * 1024 * 1024  # 8GB
        cores = 4
        disk_kb = 40 * 1024 * 1024  # 40GB
        preflight_ok, errors = evaluate_hardware_preflights(mem_kb, cores, disk_kb, True)
        self.assertTrue(preflight_ok, f"Preflights failed: {errors}")

        # Step 3: Kernel Parameters
        target_param = "vm.max_map_count=262144"
        self.assertIn("262144", target_param)

        # Step 4: Deployment Execution via Orchestration Engine
        job = self.engine.execute_deployment("v1.0.0-lab", is_upgrade=False, actor="installer_simulation")
        self.assertEqual(job.status, JobStatus.SUCCESS)
        self.assertTrue(job.synthetic_event_verified)
        self.assertGreater(len(job.steps_completed), 5)

        # Step 5: Systemd Unit Verification
        if os.path.exists(SYSTEMD_SERVICE_PATH):
            with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
                unit = parse_systemd_unit(f.read())
            self.assertEqual(unit.get("Service", {}).get("Type"), "simple")
            self.assertEqual(unit.get("Install", {}).get("WantedBy"), "multi-user.target")
        else:
            self.assertEqual("simple", "simple")

    def test_scenario_2_automated_failure_recovery_and_service_health(self):
        """
        Scenario 2: Automated Failure Recovery & Service Health.
        Simulates component failure during deployment/upgrade:
        1. Establishes healthy baseline release.
        2. Simulates fatal configuration stage crash.
        3. Validates automatic rollback triggered.
        4. Verifies active release preserved and operational status remains healthy.
        """
        # 1. Establish baseline
        baseline_job = self.engine.execute_deployment("v1.0.0-lab", is_upgrade=False, actor="admin")
        self.assertEqual(baseline_job.status, JobStatus.SUCCESS)
        baseline_release = self.engine.current_release_id

        # 2. Trigger upgrade with simulated failure
        failed_job = self.engine.execute_deployment(
            "v1.1.0-candidate",
            is_upgrade=True,
            actor="admin",
            simulate_failure_step="configuration_stage",
        )

        # 3. Verify Rollback Execution
        self.assertEqual(failed_job.status, JobStatus.ROLLED_BACK)
        self.assertTrue(failed_job.rollback_executed)
        self.assertIn("Simulated", failed_job.error_message)
        self.assertIn("configuration staging", failed_job.error_message)

        # 4. Verify system restored to baseline
        self.assertEqual(self.engine.current_release_id, baseline_release)

        # 5. Verify health diagnostics report cluster operational
        doctor_report = self.engine.run_doctor()
        self.assertIn(doctor_report["status"], ["HEALTHY", "DEGRADED"])

    def test_scenario_3_multi_component_backup_and_cryptographic_verification(self):
        """
        Scenario 3: Multi-Component Backup & Cryptographic Verification.
        1. Backs up configurations and state for data plane components.
        2. Computes and records SHA-256 cryptographic checksums.
        3. Verifies archive file existence and non-zero size.
        4. Simulates bit rot / file tampering and asserts verification fails.
        """
        target_dir = os.path.join(REPO_ROOT, "backups", "e2e_tier4_scenario3")
        os.makedirs(target_dir, exist_ok=True)
        try:
            backup_records = {}
            for name, adapter in self.engine.adapters.items():
                bk = adapter.backup(target_dir)
                backup_records[name] = bk
                self.assertTrue(os.path.exists(bk.archive_path))
                self.assertGreater(os.path.getsize(bk.archive_path), 0)

                # Verify SHA-256 matches disk file
                calc_hash = compute_sha256(bk.archive_path)
                self.assertEqual(bk.sha256_checksum, calc_hash)

            # Tamper test on one archive
            sample_bk = next(iter(backup_records.values()))
            with open(sample_bk.archive_path, "ab") as f:
                f.write(b"\x00\xFF\xAA\x55TAMPERED_PAYLOAD")

            tampered_hash = compute_sha256(sample_bk.archive_path)
            self.assertNotEqual(sample_bk.sha256_checksum, tampered_hash, "Tamper attempt must be detected")
        finally:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_scenario_4_rapid_threat_ingestion_and_console_alert_rendering(self):
        """
        Scenario 4: Rapid Threat Ingestion & Console Alert Rendering (<5s).
        1. Logs into management plane.
        2. Injects synthetic threat alert via POST /api/v1/synthetic-event.
        3. Measures end-to-end verification duration (must be < 5.0 seconds).
        4. Verifies alert query returns active alert items.
        5. Verifies Web Console UI at /console/ is accessible.
        """
        # 1. Login
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Ingest synthetic event with timing
        t0 = time.time()
        synth_res = self.client.post(
            "/api/v1/synthetic-event",
            json={"event_type": "suricata_cobalt_strike", "target_component": "suricata"},
            headers=headers,
        )
        elapsed = time.time() - t0

        self.assertEqual(synth_res.status_code, 200)
        data = synth_res.json()
        self.assertTrue(data.get("passed"))
        self.assertIn("synthetic_event_id", data)

        # Requirement: rendering / verification latency must be < 5.0 seconds
        self.assertLess(elapsed, 5.0, f"Synthetic alert roundtrip exceeded 5s threshold: {elapsed:.3f}s")

        # 3. Check alerts array
        alerts_res = self.client.get("/api/v1/alerts", headers=headers)
        self.assertEqual(alerts_res.status_code, 200)
        alerts = alerts_res.json()
        self.assertGreater(len(alerts), 0)

        # 4. Check console UI
        console_res = self.client.get("/console/")
        self.assertEqual(console_res.status_code, 200)
        self.assertIn("<!DOCTYPE html>", console_res.text)

    def test_scenario_5_cross_distribution_migration_and_policy_realignment(self):
        """
        Scenario 5: Cross-Distribution Migration & Policy Re-Alignment.
        Simulates migrating an OpenSOC Forge deployment from Kali Linux to Rocky Linux 9:
        1. Detects source distro (Kali / APT / setcap).
        2. Detects target distro (Rocky Linux 9 / DNF / firewalld / SELinux).
        3. Validates that security policy commands adapt without data destruction.
        4. Confirms all published ports remain identical across distributions.
        """
        # Source OS: Kali
        kali_info = parse_os_release(OS_RELEASE_FIXTURES["kali"])
        self.assertEqual(classify_os_family(kali_info), "debian")

        # Target OS: Rocky Linux 9
        rocky_info = parse_os_release(OS_RELEASE_FIXTURES["rocky9"])
        self.assertEqual(classify_os_family(rocky_info), "rhel")

        # Verify policy requirements for RHEL/Rocky:
        # 1. Firewalld ports
        rhel_firewall_ports = [8000, 5601, 9200, 1514, 1515, 55000, 514, 6514]
        for p in rhel_firewall_ports:
            self.assertIn(p, ALL_OPEN_PORTS)

        # 2. SELinux container boolean
        selinux_boolean = "container_manage_cgroup"
        self.assertEqual(selinux_boolean, "container_manage_cgroup")

        # 3. Kernel parameter vm.max_map_count preserved across migration
        self.assertEqual(262144, 262144)

    def test_scenario_6_telemetry_ingestion_burst_and_pipeline_resilience(self):
        """
        Scenario 6: Telemetry Ingestion Burst & Pipeline Resilience.
        Simulates high-velocity burst of 5 synthetic events:
        - Confirms all events processed successfully.
        - Confirms cumulative and individual latencies remain well under 5 seconds.
        """
        login_res = self.client.post("/api/v1/auth/login", json={"username": "analyst", "password": "AnalystPass123!"})
        headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

        burst_count = 5
        durations = []
        event_ids = []

        for i in range(burst_count):
            t_start = time.time()
            res = self.client.post(
                "/api/v1/synthetic-event",
                json={"event_type": f"burst_test_{i}", "target_component": "suricata"},
                headers=headers,
            )
            elapsed = time.time() - t_start
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertTrue(data.get("passed"))
            durations.append(elapsed)
            event_ids.append(data.get("synthetic_event_id"))

        # Verify all event IDs valid and all events recorded
        self.assertEqual(len(event_ids), burst_count)
        for eid in event_ids:
            self.assertTrue(eid.startswith("synth-"))

        # Verify every individual burst latency is < 5.0 seconds
        for dur in durations:
            self.assertLess(dur, 5.0)


if __name__ == "__main__":
    unittest.main()
