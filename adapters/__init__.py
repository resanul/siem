"""
OpenSOC Forge - Component Adapters.
"""

from adapters.base import BaseComponentAdapter
from adapters.elastic.adapter import ElasticAdapter
from adapters.models import (
    AdapterResult,
    AdapterStatus,
    BackupResult,
    DiagnosticBundle,
    DiscoveryReport,
    HealthCheckResult,
    HealthStatus,
    IntegrationTestResult,
    PreflightReport,
    RollbackResult,
    ValidationResult,
    VersionInfo,
)
from adapters.suricata.adapter import SuricataAdapter
from adapters.syslog.adapter import SyslogAdapter
from adapters.wazuh.adapter import WazuhAdapter

__all__ = [
    "BaseComponentAdapter",
    "WazuhAdapter",
    "SuricataAdapter",
    "ElasticAdapter",
    "SyslogAdapter",
    "AdapterResult",
    "AdapterStatus",
    "HealthStatus",
    "HealthCheckResult",
    "DiscoveryReport",
    "PreflightReport",
    "ValidationResult",
    "IntegrationTestResult",
    "BackupResult",
    "RollbackResult",
    "DiagnosticBundle",
    "VersionInfo",
]
