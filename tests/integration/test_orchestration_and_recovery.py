"""
Integration tests for Orchestration Engine, Idempotency, and Failure Recovery.
Verifies Principles:
- No destructive reinstall on re-run.
- Idempotent execution.
- Recoverable deployments: simulated upgrade failure triggers automatic rollback and verifies pipeline.
- End-to-end synthetic event delivery.
"""

import os
import unittest
from orchestration.engine import JobStatus, OrchestrationEngine


class TestOrchestrationAndRecovery(unittest.TestCase):

    def setUp(self):
        self.engine = OrchestrationEngine()

    def test_dry_run_plan_generation(self):
        plan = self.engine.execute_plan("v1.0.0-lab", is_upgrade=False)
        self.assertTrue(plan["compatible"])
        self.assertIn("elasticsearch", plan["component_plans"])
        self.assertIn("suricata", plan["component_plans"])
        self.assertEqual(plan["risk_assessment"], "LOW")

    def test_clean_installation_and_idempotency(self):
        # 1. First run: Fresh installation
        job1 = self.engine.execute_deployment("v1.0.0-lab", is_upgrade=False, actor="admin")
        self.assertEqual(job1.status, JobStatus.SUCCESS)
        self.assertTrue(job1.synthetic_event_verified)
        self.assertEqual(self.engine.current_release_id, "v1.0.0-lab")

        # 2. Second run: Idempotent re-run must not break or wipe healthy installation
        job2 = self.engine.execute_deployment("v1.0.0-lab", is_upgrade=False, actor="admin")
        self.assertEqual(job2.status, JobStatus.SUCCESS)
        self.assertTrue(job2.synthetic_event_verified)
        self.assertFalse(job2.rollback_executed)

    def test_controlled_upgrade_failure_triggers_automatic_rollback(self):
        # Install baseline release v1.0.0-lab
        self.engine.execute_deployment("v1.0.0-lab", is_upgrade=False, actor="admin")
        baseline_release = self.engine.current_release_id

        # Trigger upgrade with simulated failure at configuration staging
        failed_job = self.engine.execute_deployment(
            "v1.1.0-candidate",
            is_upgrade=True,
            actor="admin",
            simulate_failure_step="configuration_stage",
        )

        # Verification of Recovery Principles:
        # 1. Job marked as ROLLED_BACK
        self.assertEqual(failed_job.status, JobStatus.ROLLED_BACK)
        # 2. Rollback flag is true
        self.assertTrue(failed_job.rollback_executed)
        # 3. Active release was not corrupted to candidate
        self.assertEqual(self.engine.current_release_id, baseline_release)
        # 4. Error message is clearly diagnosed
        self.assertIn("Simulated syntax failure", failed_job.error_message)

    def test_end_to_end_synthetic_event_pipeline(self):
        for comp_name, adapter in self.engine.adapters.items():
            res = adapter.integration_test()
            self.assertTrue(res.passed, f"Synthetic event test failed for {comp_name}")
            self.assertGreater(res.duration_ms, 0)
            self.assertTrue(res.synthetic_event_id.startswith("synth-"))


if __name__ == "__main__":
    unittest.main()
