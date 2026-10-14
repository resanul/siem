"""
Unit tests for OpenSOC Forge Release Manifest and Compatibility Engine.
Verifies Principles:
- No unvalidated dependency combinations.
- Explicit compatibility validation before installation or upgrades.
- Rejection of incompatible matrices with structured explanations.
"""

import os
import unittest
from compatibility.engine import CompatibilityEngine, parse_semver


class TestManifestAndCompatibility(unittest.TestCase):

    def setUp(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.engine = CompatibilityEngine(
            matrix_path=os.path.join(base_dir, "compatibility", "matrix.yaml"),
            schema_path=os.path.join(base_dir, "releases", "schemas", "release_manifest.json"),
        )
        self.valid_manifest = {
            "manifest_version": "1.0.0",
            "release_id": "v1.0.0-lab",
            "channel": "stable",
            "created_at": "2026-10-14T20:00:00Z",
            "supported_platforms": [
                {"os_family": "ubuntu", "os_version": "22.04", "architectures": ["x86_64"]}
            ],
            "components": {
                "elasticsearch": {"version": "7.17.13", "type": "native_package"},
                "kibana": {"version": "7.17.13", "type": "native_package"},
                "filebeat": {"version": "7.17.13", "type": "native_package"},
                "wazuh_manager": {"version": "4.5.4", "type": "native_package"},
                "wazuh_agent": {"version": "4.5.4", "type": "native_package"},
                "suricata": {"version": "7.0.5", "type": "native_package"},
            },
            "compatibility_constraints": [
                {
                    "rule_id": "ELK-LOCK",
                    "source_component": "elasticsearch",
                    "target_component": "kibana",
                    "constraint": "elasticsearch == kibana",
                }
            ],
            "supported_upgrade_paths": [
                {
                    "from_release": "v0.9.0-alpha",
                    "migration_required": True,
                    "breaking_changes": ["EVE JSON format update"],
                }
            ],
        }

    def test_semver_parsing(self):
        self.assertEqual(parse_semver("7.17.13"), (7, 17, 13))
        self.assertEqual(parse_semver("v4.5.4-rc1"), (4, 5, 4))
        self.assertEqual(parse_semver("8.0"), (8, 0, 0))

    def test_valid_manifest_schema(self):
        valid, errors = self.engine.validate_manifest_schema(self.valid_manifest)
        self.assertTrue(valid, f"Expected valid manifest schema, got errors: {errors}")

    def test_schema_rejects_missing_required_fields(self):
        invalid_manifest = {"release_id": "v1.0.0"}  # missing components, channel, etc.
        valid, errors = self.engine.validate_manifest_schema(invalid_manifest)
        self.assertFalse(valid)
        self.assertGreater(len(errors), 0)

    def test_valid_compatibility_evaluation(self):
        report = self.engine.evaluate_manifest_compatibility(
            self.valid_manifest,
            target_os="ubuntu",
            target_os_version="22.04",
        )
        self.assertTrue(report.compatible)
        self.assertEqual(len(report.issues), 0)

    def test_incompatible_elastic_and_kibana_version_mismatch(self):
        m = self.valid_manifest.copy()
        m["components"] = dict(self.valid_manifest["components"])
        m["components"]["kibana"] = {"version": "7.17.10", "type": "native_package"}  # mismatch with 7.17.13

        report = self.engine.evaluate_manifest_compatibility(m)
        self.assertFalse(report.compatible)
        self.assertTrue(any(i.rule_id == "ELK-MISMATCH" for i in report.issues))

    def test_incompatible_elastic_8_with_legacy_wazuh_4_5(self):
        m = self.valid_manifest.copy()
        m["components"] = dict(self.valid_manifest["components"])
        m["components"]["elasticsearch"] = {"version": "8.12.0", "type": "native_package"}
        m["components"]["kibana"] = {"version": "8.12.0", "type": "native_package"}
        m["components"]["wazuh_manager"] = {"version": "4.5.4", "type": "native_package"}

        report = self.engine.evaluate_manifest_compatibility(m)
        self.assertFalse(report.compatible)
        self.assertTrue(any(i.rule_id == "INCOMPAT-001" for i in report.issues))

    def test_incompatible_wazuh_agent_newer_than_manager(self):
        m = self.valid_manifest.copy()
        m["components"] = dict(self.valid_manifest["components"])
        m["components"]["wazuh_manager"] = {"version": "4.5.4", "type": "native_package"}
        m["components"]["wazuh_agent"] = {"version": "4.8.0", "type": "native_package"}

        report = self.engine.evaluate_manifest_compatibility(m)
        self.assertFalse(report.compatible)
        self.assertTrue(any(i.rule_id == "INCOMPAT-003" for i in report.issues))

    def test_unsupported_operating_system(self):
        report = self.engine.evaluate_manifest_compatibility(
            self.valid_manifest,
            target_os="archlinux",
            target_os_version="rolling",
        )
        self.assertFalse(report.compatible)
        self.assertTrue(any(i.rule_id == "OS-UNSUPPORTED" for i in report.issues))


if __name__ == "__main__":
    unittest.main()
