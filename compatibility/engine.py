"""
OpenSOC Forge - Version and Compatibility Management Engine.
Enforces non-negotiable engineering principles:
1. No unvalidated dependency combinations.
2. Reject deployments when compatibility cannot be established, with clear explanation.
3. Validates upgrade paths, breaking changes, and migration requirements.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import yaml
import jsonschema


@dataclass
class CompatibilityIssue:
    rule_id: str
    severity: str  # CRITICAL, HIGH, WARNING, INFO
    source: str
    target: str
    message: str
    remediation: str


@dataclass
class CompatibilityReport:
    compatible: bool
    manifest_id: str
    target_profile: str
    issues: List[CompatibilityIssue] = field(default_factory=list)
    upgrade_path_valid: bool = True
    breaking_changes: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compatible": self.compatible,
            "manifest_id": self.manifest_id,
            "target_profile": self.target_profile,
            "issues": [
                {
                    "rule_id": i.rule_id,
                    "severity": i.severity,
                    "source": i.source,
                    "target": i.target,
                    "message": i.message,
                    "remediation": i.remediation,
                }
                for i in self.issues
            ],
            "upgrade_path_valid": self.upgrade_path_valid,
            "breaking_changes": self.breaking_changes,
            "remediation_steps": self.remediation_steps,
        }


def parse_semver(v_str: str) -> Tuple[int, int, int]:
    """Parse semantic version string (e.g. '7.17.13' -> (7, 17, 13))."""
    clean_v = re.sub(r"^[vV]", "", v_str).split("-")[0]
    parts = clean_v.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except ValueError:
        return (0, 0, 0)


class CompatibilityEngine:
    """
    Evaluates compatibility matrices, release manifests, and target host environments.
    """

    def __init__(self, matrix_path: Optional[str] = None, schema_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.matrix_path = matrix_path or os.path.join(base_dir, "compatibility", "matrix.yaml")
        self.schema_path = schema_path or os.path.join(base_dir, "releases", "schemas", "release_manifest.json")
        self._load_matrix()
        self._load_schema()

    def _load_matrix(self):
        if os.path.exists(self.matrix_path):
            with open(self.matrix_path, "r", encoding="utf-8") as f:
                self.matrix = yaml.safe_load(f)
        else:
            self.matrix = {"supported_combinations": [], "incompatible_rules": []}

    def _load_schema(self):
        if os.path.exists(self.schema_path):
            with open(self.schema_path, "r", encoding="utf-8") as f:
                import json
                self.schema = json.load(f)
        else:
            self.schema = None

    def validate_manifest_schema(self, manifest_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate manifest against the immutable release manifest JSON schema."""
        if not self.schema:
            return True, []
        validator = jsonschema.Draft7Validator(self.schema)
        errors = [f"{e.json_path}: {e.message}" for e in validator.iter_errors(manifest_dict)]
        return len(errors) == 0, errors

    def evaluate_manifest_compatibility(
        self,
        manifest_dict: Dict[str, Any],
        target_os: str = "ubuntu",
        target_os_version: str = "22.04",
        current_release_id: Optional[str] = None,
    ) -> CompatibilityReport:
        """
        Comprehensive evaluation of component compatibility, OS suitability,
        and upgrade-path safety.
        """
        release_id = manifest_dict.get("release_id", "unknown")
        components = manifest_dict.get("components", {})
        issues: List[CompatibilityIssue] = []
        breaking_changes: List[str] = []
        remediation_steps: List[str] = []

        # 1. Schema Validation
        valid_schema, schema_errs = self.validate_manifest_schema(manifest_dict)
        if not valid_schema:
            for err in schema_errs:
                issues.append(
                    CompatibilityIssue(
                        rule_id="SCHEMA-INVALID",
                        severity="CRITICAL",
                        source="manifest",
                        target="schema",
                        message=f"Manifest schema validation error: {err}",
                        remediation="Correct manifest format to match release_manifest.json schema.",
                    )
                )

        # 2. Target OS Support Check
        supported_platforms = manifest_dict.get("supported_platforms", [])
        os_supported = any(
            p.get("os_family") == target_os and p.get("os_version") in [target_os_version, "*"]
            for p in supported_platforms
        )
        if not os_supported and supported_platforms:
            plat_str = ", ".join([f"{p.get('os_family')} {p.get('os_version')}" for p in supported_platforms])
            issues.append(
                CompatibilityIssue(
                    rule_id="OS-UNSUPPORTED",
                    severity="CRITICAL",
                    source=f"{target_os} {target_os_version}",
                    target=release_id,
                    message=f"Target OS '{target_os} {target_os_version}' is not in the manifest's supported platforms list.",
                    remediation=f"Deploy on one of: {plat_str}",
                )
            )

        # 3. Inter-component Rule Evaluation
        es_ver = components.get("elasticsearch", {}).get("version")
        kibana_ver = components.get("kibana", {}).get("version")
        filebeat_ver = components.get("filebeat", {}).get("version")
        wazuh_ver = components.get("wazuh_manager", {}).get("version")
        wazuh_agent_ver = components.get("wazuh_agent", {}).get("version")
        suricata_ver = components.get("suricata", {}).get("version")

        # Elasticsearch <-> Kibana version parity check
        if es_ver and kibana_ver and es_ver != kibana_ver:
            issues.append(
                CompatibilityIssue(
                    rule_id="ELK-MISMATCH",
                    severity="CRITICAL",
                    source="elasticsearch",
                    target="kibana",
                    message=f"Elasticsearch version ({es_ver}) does not match Kibana version ({kibana_ver}).",
                    remediation="Align Elasticsearch and Kibana versions precisely to prevent API index view failures.",
                )
            )

        # Elasticsearch <-> Filebeat version parity check
        if es_ver and filebeat_ver:
            es_parts = parse_semver(es_ver)
            fb_parts = parse_semver(filebeat_ver)
            if es_parts[0] != fb_parts[0] or es_parts[1] != fb_parts[1]:
                issues.append(
                    CompatibilityIssue(
                        rule_id="FILEBEAT-MISMATCH",
                        severity="WARNING",
                        source="filebeat",
                        target="elasticsearch",
                        message=f"Filebeat version ({filebeat_ver}) major/minor differs from Elasticsearch ({es_ver}).",
                        remediation="Use matching major.minor Filebeat release to ensure index template compatibility.",
                    )
                )

        # Rule INCOMPAT-001: Elastic 8.x + Wazuh 4.5
        if es_ver and wazuh_ver:
            es_parts = parse_semver(es_ver)
            wazuh_parts = parse_semver(wazuh_ver)
            if es_parts[0] >= 8 and wazuh_parts < (4, 8, 0):
                issues.append(
                    CompatibilityIssue(
                        rule_id="INCOMPAT-001",
                        severity="CRITICAL",
                        source="elasticsearch",
                        target="wazuh_manager",
                        message="Elasticsearch >= 8.0.0 is incompatible with Wazuh Manager/Kibana Plugin < 4.8.0.",
                        remediation="Pin Elasticsearch/Kibana to 7.17.x or upgrade Wazuh to >= 4.8.0.",
                    )
                )

        # Rule INCOMPAT-002: Suricata 7.x + Filebeat < 7.16
        if suricata_ver and filebeat_ver:
            suri_parts = parse_semver(suricata_ver)
            fb_parts = parse_semver(filebeat_ver)
            if suri_parts >= (7, 0, 0) and fb_parts < (7, 16, 0):
                issues.append(
                    CompatibilityIssue(
                        rule_id="INCOMPAT-002",
                        severity="HIGH",
                        source="suricata",
                        target="filebeat",
                        message="Suricata 7.x produces EVE JSON v2 fields incompatible with Filebeat < 7.16.",
                        remediation="Upgrade Filebeat to >= 7.17.13 or use OpenSOC Forge normalized ingestion adapter.",
                    )
                )

        # Rule INCOMPAT-003: Wazuh Agent > Wazuh Manager
        if wazuh_ver and wazuh_agent_ver:
            w_parts = parse_semver(wazuh_ver)
            a_parts = parse_semver(wazuh_agent_ver)
            if a_parts > w_parts:
                issues.append(
                    CompatibilityIssue(
                        rule_id="INCOMPAT-003",
                        severity="CRITICAL",
                        source="wazuh_agent",
                        target="wazuh_manager",
                        message=f"Wazuh Agent ({wazuh_agent_ver}) is newer than Wazuh Manager ({wazuh_ver}).",
                        remediation="Upgrade Wazuh Manager before deploying newer agent versions.",
                    )
                )

        # Rule INCOMPAT-004: Ubuntu 24.04 + Wazuh < 4.7
        if target_os == "ubuntu" and target_os_version == "24.04" and wazuh_ver:
            w_parts = parse_semver(wazuh_ver)
            if w_parts < (4, 7, 0):
                issues.append(
                    CompatibilityIssue(
                        rule_id="INCOMPAT-004",
                        severity="HIGH",
                        source="ubuntu_24.04",
                        target="wazuh_manager",
                        message=f"Ubuntu 24.04 systemd/glibc breaks legacy Wazuh Manager {wazuh_ver} daemon startup.",
                        remediation="Use Ubuntu 22.04 LTS or upgrade to Wazuh Manager >= 4.8.2.",
                    )
                )

        # 4. Upgrade Path Evaluation (if upgrading from an existing release)
        upgrade_path_valid = True
        if current_release_id:
            supported_paths = manifest_dict.get("supported_upgrade_paths", [])
            matching_path = next(
                (p for p in supported_paths if p.get("from_release") in [current_release_id, "*"]),
                None,
            )
            if not matching_path:
                upgrade_path_valid = False
                issues.append(
                    CompatibilityIssue(
                        rule_id="UPGRADE-PATH-UNSUPPORTED",
                        severity="CRITICAL",
                        source=current_release_id,
                        target=release_id,
                        message=f"Direct upgrade path from {current_release_id} to {release_id} is not supported.",
                        remediation=f"Supported source releases for this target are: {[p.get('from_release') for p in supported_paths]}",
                    )
                )
            else:
                if matching_path.get("breaking_changes"):
                    breaking_changes.extend(matching_path.get("breaking_changes"))
                if matching_path.get("pre_upgrade_steps"):
                    remediation_steps.extend(matching_path.get("pre_upgrade_steps"))

        # Determine overall compatibility (any CRITICAL issue causes rejection)
        is_compatible = not any(i.severity == "CRITICAL" for i in issues)

        return CompatibilityReport(
            compatible=is_compatible,
            manifest_id=release_id,
            target_profile=manifest_dict.get("profile", "custom"),
            issues=issues,
            upgrade_path_valid=upgrade_path_valid,
            breaking_changes=breaking_changes,
            remediation_steps=remediation_steps,
        )
