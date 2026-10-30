"""
Production-grade Pydantic schema models for OpenSOC Forge Correlation Engine.
Defines canonical normalized event taxonomy, incident representations,
and detection rule configurations compliant with ECS (Elastic Common Schema).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class NormalizedSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    DNS = "dns"
    HTTP = "http"
    PRIVILEGE = "privilege"
    THREAT = "threat"
    CONFIGURATION = "configuration"


# Alias for backward compatibility and spec alignment
NormalizedCategory = EventCategory


class NormalizedOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class EndpointEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ip: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None
    zone: Optional[str] = None  # e.g. "internal", "dmz", "external"
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    as_org: Optional[str] = None


class UserEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: Optional[str] = None
    domain: Optional[str] = None
    id: Optional[str] = None
    privileges: List[str] = Field(default_factory=list)
    logon_type: Optional[str] = None  # e.g. "2_Interactive", "3_Network", "9_NewCredentials"


class ProcessEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    pid: Optional[int] = None
    name: Optional[str] = None
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    hash_sha256: Optional[str] = None
    user: Optional[str] = None


class FileEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    path: Optional[str] = None
    name: Optional[str] = None
    extension: Optional[str] = None
    size_bytes: Optional[int] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    action: Optional[str] = None  # "created", "modified", "deleted", "accessed"


class HttpEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    method: Optional[str] = None  # "GET", "POST", "CONNECT", "PUT", "DELETE"
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    host: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None


class DnsEntity(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    query_name: Optional[str] = None
    query_type: Optional[str] = None  # "A", "AAAA", "TXT", "CNAME"
    response_code: Optional[str] = None  # "NOERROR", "NXDOMAIN"
    answers: List[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    """
    Canonical normalized telemetry event model representing telemetry across
    Wazuh, Suricata, Squid, Check Point, NetWitness, and Active Directory.
    """
    model_config = ConfigDict(populate_by_name=True)

    event_id: str
    timestamp: datetime
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str  # "wazuh", "suricata", "squid", "checkpoint", "netwitness", "active_directory"
    original_id: Optional[str] = None
    event_category: EventCategory = EventCategory.CONFIGURATION
    event_action: str = "unknown"
    event_outcome: NormalizedOutcome = NormalizedOutcome.UNKNOWN
    severity: NormalizedSeverity = NormalizedSeverity.INFORMATIONAL

    # Entities
    source: EndpointEntity = Field(default_factory=EndpointEntity)
    destination: EndpointEntity = Field(default_factory=EndpointEntity)
    user: UserEntity = Field(default_factory=UserEntity)
    host: EndpointEntity = Field(default_factory=EndpointEntity)
    process: Optional[ProcessEntity] = None
    file: Optional[FileEntity] = None
    http: Optional[HttpEntity] = None
    dns: Optional[DnsEntity] = None

    # Threat Intelligence & Detection Metadata
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Raw passthrough payload
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

    # Convenience properties
    @property
    def src_ip(self) -> Optional[str]:
        return self.source.ip

    @property
    def dest_ip(self) -> Optional[str]:
        return self.destination.ip

    @property
    def user_name(self) -> Optional[str]:
        return self.user.name

    @property
    def hostname(self) -> Optional[str]:
        return self.host.host or self.source.host or self.destination.host

    @property
    def id(self) -> str:
        return self.event_id

    @property
    def category(self) -> EventCategory:
        return self.event_category

    @property
    def action(self) -> str:
        return self.event_action

    @property
    def outcome(self) -> NormalizedOutcome:
        return self.event_outcome

    @property
    def message(self) -> str:
        return self.signature or str(self.raw_payload.get("message") or self.raw_payload.get("full_log", ""))


class CorrelatedIncident(BaseModel):
    """
    Represents a high-fidelity security incident synthesized by correlation logic,
    complete with MITRE ATT&CK mapping, affected entities, and root-cause events.
    """
    model_config = ConfigDict(populate_by_name=True)

    id: str
    rule_id: str
    rule_name: str
    severity: NormalizedSeverity = NormalizedSeverity.HIGH
    risk_score: float = 75.0  # 0.0 to 100.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    entities: Dict[str, List[str]] = Field(default_factory=dict)
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    summary: str = ""
    description: str = ""
    root_cause_events: List[Any] = Field(default_factory=list)
    cooldown_until: Optional[datetime] = None
    status: str = "NEW"
    contributing_sources: List[str] = Field(default_factory=list)
    stage_count: int = 1
    evidence_events: List[Dict[str, Any]] = Field(default_factory=list)

    @property
    def incident_id(self) -> str:
        return self.id

    @property
    def affected_entities(self) -> Dict[str, List[str]]:
        return self.entities


class CorrelationRuleConfig(BaseModel):
    """
    Configuration specification for a correlation rule, specifying sliding windows,
    trigger thresholds, sequence conditions, entity grouping keys, and MITRE mapping.
    """
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    sources: List[str] = Field(default_factory=list)
    window_seconds: int = 300
    threshold: int = 1
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: NormalizedSeverity = NormalizedSeverity.HIGH
    risk_score: float = 75.0
    sequence_stages: Optional[List[Dict[str, Any]]] = None
    entity_keys: List[str] = Field(default_factory=lambda: ["source.ip"])
    cooldown_seconds: int = 600


class EngineStatus(BaseModel):
    """
    Operational metrics and telemetry status for the Correlation Engine.
    """
    model_config = ConfigDict(populate_by_name=True)

    running: bool = True
    events_processed: int = 0
    incidents_generated: int = 0
    active_windows_count: int = 0
    active_entities_count: int = 0
    rules_count: int = 0
    active_rules_count: int = 0
    uptime_seconds: float = 0.0
    last_processed_timestamp: Optional[datetime] = None
