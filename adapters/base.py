"""
OpenSOC Forge - Base Component Adapter Interface.
Abstract specification for all security and logging component adapters.
Enforces the 17-method operational contract.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from adapters.models import (
    AdapterResult,
    AdapterStatus,
    BackupResult,
    DiagnosticBundle,
    DiscoveryReport,
    HealthCheckResult,
    IntegrationTestResult,
    PreflightReport,
    RollbackResult,
    ValidationResult,
    VersionInfo,
)


class BaseComponentAdapter(ABC):
    """
    Abstract Component Adapter Interface.
    Every component (Elasticsearch, Kibana, Filebeat, Wazuh Manager, Suricata, Syslog)
    must implement this interface.
    """

    def __init__(self, name: str, component_type: str, config_dir: str = "", data_dir: str = "", log_dir: str = ""):
        self.name = name
        self.component_type = component_type
        self.config_dir = config_dir
        self.data_dir = data_dir
        self.log_dir = log_dir

    @abstractmethod
    def discover(self) -> DiscoveryReport:
        """Discover existing binaries, services, configuration, and ports on the host."""
        pass

    @abstractmethod
    def get_version(self) -> VersionInfo:
        """Retrieve current semantic version and release metadata."""
        pass

    @abstractmethod
    def validate_compatibility(self, manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate whether this component can safely run within the given release manifest."""
        pass

    @abstractmethod
    def preflight(self, profile_config: Dict[str, Any]) -> PreflightReport:
        """Run environment preflight checks (RAM, CPU, disk, ports, OS, permissions)."""
        pass

    @abstractmethod
    def plan_install(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Generate non-destructive dry-run installation plan and proposed changes."""
        pass

    @abstractmethod
    def install(self, manifest: Dict[str, Any], dry_run: bool = False) -> AdapterResult:
        """Execute idempotent package or container installation."""
        pass

    @abstractmethod
    def configure(self, config_params: Dict[str, Any], dry_run: bool = False) -> AdapterResult:
        """Render configuration templates safely into staging before atomic replacement."""
        pass

    @abstractmethod
    def validate_configuration(self, config_path: str) -> ValidationResult:
        """Validate configuration syntax and schema prior to service reload."""
        pass

    @abstractmethod
    def start(self) -> AdapterResult:
        """Start the component service."""
        pass

    @abstractmethod
    def stop(self) -> AdapterResult:
        """Stop the component service gracefully."""
        pass

    @abstractmethod
    def healthcheck(self) -> HealthCheckResult:
        """Multi-level health evaluation (process, authenticated API, disk, memory)."""
        pass

    @abstractmethod
    def integration_test(self) -> IntegrationTestResult:
        """End-to-end ingestion and query verification using a synthetic event."""
        pass

    @abstractmethod
    def upgrade(self, target_manifest: Dict[str, Any], dry_run: bool = False) -> AdapterResult:
        """Stage and apply upgrade following approved path."""
        pass

    @abstractmethod
    def backup(self, target_dir: str) -> BackupResult:
        """Create checksummed backup archive of configurations and metadata."""
        pass

    @abstractmethod
    def restore(self, backup_archive: str) -> AdapterResult:
        """Restore verified backup archive after validating target compatibility."""
        pass

    @abstractmethod
    def rollback(self, checkpoint_id: str) -> RollbackResult:
        """Revert configuration and state to verified checkpoint."""
        pass

    @abstractmethod
    def collect_diagnostics(self) -> DiagnosticBundle:
        """Bundle sanitized logs, metrics, and configs with secrets redacted."""
        pass

    @abstractmethod
    def uninstall(self, purge_data: bool = False, authorization_token: str = "") -> AdapterResult:
        """Safely uninstall component. Purging data strictly requires valid authorization."""
        pass
