"""
OpenSOC Forge - Component Adapter Data Models and Contract Types.
Defines strongly-typed, immutable results and telemetry for all adapter operations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class AdapterStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DEGRADED = "DEGRADED"
    SKIPPED = "SKIPPED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class ComponentType(str, Enum):
    ELASTICSEARCH = "elasticsearch"
    KIBANA = "kibana"
    FILEBEAT = "filebeat"
    WAZUH_MANAGER = "wazuh_manager"
    WAZUH_INDEXER = "wazuh_indexer"
    WAZUH_DASHBOARD = "wazuh_dashboard"
    WAZUH_AGENT = "wazuh_agent"
    SURICATA = "suricata"
    SYSLOG = "syslog"


@dataclass
class VersionInfo:
    component: str
    version: str
    release_channel: str = "stable"
    build_hash: Optional[str] = None
    build_date: Optional[str] = None
    package_type: str = "native"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "version": self.version,
            "release_channel": self.release_channel,
            "build_hash": self.build_hash,
            "build_date": self.build_date,
            "package_type": self.package_type,
        }


@dataclass
class DiscoveryReport:
    component: str
    installed: bool
    version: Optional[str] = None
    binary_path: Optional[str] = None
    service_active: bool = False
    service_enabled: bool = False
    config_path: Optional[str] = None
    ports_listening: List[int] = field(default_factory=list)
    process_pids: List[int] = field(default_factory=list)
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "installed": self.installed,
            "version": self.version,
            "binary_path": self.binary_path,
            "service_active": self.service_active,
            "service_enabled": self.service_enabled,
            "config_path": self.config_path,
            "ports_listening": self.ports_listening,
            "process_pids": self.process_pids,
            "raw_details": self.raw_details,
        }


@dataclass
class PreflightCheckItem:
    name: str
    passed: bool
    current_value: Any
    required_value: Any
    severity: str = "ERROR"  # ERROR or WARNING
    message: str = ""


@dataclass
class PreflightReport:
    component: str
    passed: bool
    checks: List[PreflightCheckItem] = field(default_factory=list)
    blocking_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "passed": self.passed,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "current": str(c.current_value),
                    "required": str(c.required_value),
                    "severity": c.severity,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "blocking_issues": self.blocking_issues,
            "warnings": self.warnings,
        }


@dataclass
class ValidationResult:
    valid: bool
    config_file: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    schema_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "config_file": self.config_file,
            "errors": self.errors,
            "warnings": self.warnings,
            "schema_version": self.schema_version,
        }


@dataclass
class HealthCheckResult:
    component: str
    status: HealthStatus
    process_running: bool
    api_responding: bool
    latency_ms: float = 0.0
    memory_usage_mb: float = 0.0
    disk_free_gb: float = 0.0
    degraded_reasons: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status.value,
            "process_running": self.process_running,
            "api_responding": self.api_responding,
            "latency_ms": self.latency_ms,
            "memory_usage_mb": self.memory_usage_mb,
            "disk_free_gb": self.disk_free_gb,
            "degraded_reasons": self.degraded_reasons,
            "metrics": self.metrics,
            "checked_at": self.checked_at,
        }


@dataclass
class IntegrationTestResult:
    component: str
    passed: bool
    synthetic_event_id: str
    stages: Dict[str, bool] = field(default_factory=dict)  # e.g. {"collector": True, "indexer": True, "query": True}
    duration_ms: float = 0.0
    failure_stage: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "passed": self.passed,
            "synthetic_event_id": self.synthetic_event_id,
            "stages": self.stages,
            "duration_ms": self.duration_ms,
            "failure_stage": self.failure_stage,
            "error_message": self.error_message,
        }


@dataclass
class BackupResult:
    backup_id: str
    component: str
    archive_path: str
    sha256_checksum: str
    size_bytes: int
    created_at: str
    included_paths: List[str] = field(default_factory=list)
    verification_passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "component": self.component,
            "archive_path": self.archive_path,
            "sha256": self.sha256_checksum,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "included_paths": self.included_paths,
            "verification_passed": self.verification_passed,
        }


@dataclass
class RollbackResult:
    rolled_back: bool
    checkpoint_id: str
    component: str
    previous_version: str
    target_version: str
    config_restored: bool
    pipeline_verified: bool
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rolled_back": self.rolled_back,
            "checkpoint_id": self.checkpoint_id,
            "component": self.component,
            "previous_version": self.previous_version,
            "target_version": self.target_version,
            "config_restored": self.config_restored,
            "pipeline_verified": self.pipeline_verified,
            "details": self.details,
        }


@dataclass
class DiagnosticBundle:
    bundle_id: str
    component: str
    created_at: str
    archive_path: str
    redacted_items_count: int
    included_files: List[str] = field(default_factory=list)
    system_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "component": self.component,
            "created_at": self.created_at,
            "archive_path": self.archive_path,
            "redacted_items_count": self.redacted_items_count,
            "included_files": self.included_files,
            "system_summary": self.system_summary,
        }


@dataclass
class AdapterResult:
    operation: str
    component: str
    status: AdapterStatus
    message: str
    actions_taken: List[str] = field(default_factory=list)
    diagnostic_details: Dict[str, Any] = field(default_factory=dict)
    recovery_guidance: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "component": self.component,
            "status": self.status.value,
            "message": self.message,
            "actions_taken": self.actions_taken,
            "diagnostic_details": self.diagnostic_details,
            "recovery_guidance": self.recovery_guidance,
            "duration_seconds": self.duration_seconds,
        }
