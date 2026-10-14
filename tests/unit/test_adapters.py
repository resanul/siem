"""
Unit tests for Component Adapters.
Verifies contract compliance, configuration rollback on validation failure,
backup integrity, and refusal of unconfirmed destructive operations.
"""

import os
import unittest
from adapters.elastic.adapter import ElasticAdapter
from adapters.models import AdapterStatus, HealthStatus
from adapters.suricata.adapter import SuricataAdapter
from adapters.syslog.adapter import SyslogAdapter
from adapters.wazuh.adapter import WazuhAdapter


class TestComponentAdapters(unittest.TestCase):

    def setUp(self):
        self.wazuh = WazuhAdapter(simulated=True)
        self.suricata = SuricataAdapter(simulated=True)
        self.elastic = ElasticAdapter(simulated=True)
        self.syslog = SyslogAdapter(simulated=True)
        self.adapters = [self.wazuh, self.suricata, self.elastic, self.syslog]

    def test_discovery_reports_installed_status(self):
        for adapter in self.adapters:
            report = adapter.discover()
            self.assertTrue(report.installed)
            self.assertIsNotNone(report.version)

    def test_healthchecks_return_structured_status(self):
        for adapter in self.adapters:
            hc = adapter.healthcheck()
            self.assertIn(hc.status, [HealthStatus.HEALTHY, HealthStatus.DEGRADED])
            self.assertTrue(hc.process_running)
            self.assertTrue(hc.api_responding)

    def test_wazuh_config_validation_rejects_corrupted_xml(self):
        invalid_xml = "<ossec_config><global><broken_tag></ossec_config>"  # mismatched tags
        res = self.wazuh.validate_configuration(invalid_xml)
        self.assertFalse(res.valid)

        # Applying invalid config must fail and preserve state
        cfg_res = self.wazuh.configure({"ossec_conf": invalid_xml})
        self.assertEqual(cfg_res.status, AdapterStatus.FAILED)
        self.assertIn("Preserving previous working configuration", cfg_res.message)

    def test_suricata_config_validation_rejects_missing_afpacket_and_outputs(self):
        invalid_yaml = "some_key: test\nrule_path: /tmp"
        res = self.suricata.validate_configuration(invalid_yaml)
        self.assertFalse(res.valid)
        self.assertTrue(any("af-packet" in e for e in res.errors))

        cfg_res = self.suricata.configure({"suricata_yaml": invalid_yaml})
        self.assertEqual(cfg_res.status, AdapterStatus.FAILED)

    def test_elastic_rejects_plaintext_password_in_configuration(self):
        unsafe_yaml = """
cluster.name: test
xpack.security.enabled: true
admin_password: PlainTextPassword123!
"""
        res = self.elastic.validate_configuration(unsafe_yaml)
        self.assertFalse(res.valid)
        self.assertTrue(any("Plaintext password" in e for e in res.errors))

    def test_backup_creates_verified_archive_with_sha256(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            bk = self.wazuh.backup(tmpdir)
            self.assertTrue(os.path.exists(bk.archive_path))
            self.assertEqual(len(bk.sha256_checksum), 64)
            self.assertTrue(bk.verification_passed)

    def test_uninstallation_rejects_purge_without_token(self):
        # Attempting data purge without confirmation token must fail
        res = self.elastic.uninstall(purge_data=True, authorization_token="wrong_token")
        self.assertEqual(res.status, AdapterStatus.FAILED)
        self.assertIn("rejected", res.message)

        # With confirmation token, safe uninstall succeeds
        res_ok = self.elastic.uninstall(purge_data=True, authorization_token="CONFIRM_DATA_DESTRUCTION")
        self.assertEqual(res_ok.status, AdapterStatus.SUCCESS)

    def test_diagnostics_collection_redacts_secrets(self):
        diag = self.wazuh.collect_diagnostics()
        self.assertGreater(diag.redacted_items_count, 0)
        self.assertIn("redacted", diag.included_files[0])


if __name__ == "__main__":
    unittest.main()
