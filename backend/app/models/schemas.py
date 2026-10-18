"""
OpenSOC Forge - API Data Transfer Objects & Schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class AlertSource(str, Enum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    SYSLOG = "syslog"
    ENDPOINT = "endpoint"


class AlertItem(BaseModel):
    id: str
    timestamp: str
    severity: AlertSeverity
    source: AlertSource
    title: str
    description: str
    host: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    is_demo: bool = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class CasePriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseItem(BaseModel):
    id: str
    title: str
    description: str
    severity: AlertSeverity
    priority: CasePriority
    status: CaseStatus
    created_at: str
    updated_at: str
    assigned_to: Optional[str] = None
    linked_alert_ids: List[str] = Field(default_factory=list)
    ioc_indicators: List[str] = Field(default_factory=list)
    investigation_notes: List[Dict[str, Any]] = Field(default_factory=list)


class CaseCreate(BaseModel):
    title: str
    description: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    priority: CasePriority = CasePriority.P3_MEDIUM
    linked_alert_ids: List[str] = Field(default_factory=list)
    ioc_indicators: List[str] = Field(default_factory=list)


class RuleItem(BaseModel):
    id: str
    name: str
    type: str  # sigma, wazuh_xml, suricata_sig
    severity: AlertSeverity
    mitre_technique: str
    status: str  # ACTIVE, TESTING, DISABLED
    description: str
    rule_content: str
    author: str
    version: str
    tested_against_fixtures: bool = True


class RuleCreate(BaseModel):
    name: str
    type: str
    severity: AlertSeverity
    mitre_technique: str
    description: str
    rule_content: str


class RuleTestRequest(BaseModel):
    rule_content: str
    rule_type: str
    sample_log: str


class RuleTestResponse(BaseModel):
    valid_syntax: bool
    matches: bool
    extracted_fields: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    permissions: List[str]


class PlanRequest(BaseModel):
    manifest_id: str
    is_upgrade: bool = False


class DeployRequest(BaseModel):
    manifest_id: str
    is_upgrade: bool = False
    simulate_failure: Optional[str] = None


class RollbackRequest(BaseModel):
    checkpoint_id: str
    reason: str


class BackupRestoreRequest(BaseModel):
    archive_path: str
    confirmation_token: str


class SyntheticEventRequest(BaseModel):
    event_type: str = "suricata_test_alert"
    target_component: str = "suricata"
    payload: Optional[Dict[str, Any]] = None


class EventSearchRequest(BaseModel):
    query: Optional[str] = "*"
    indices: Optional[List[str]] = None
    time_range: Optional[str] = "24h"
    limit: Optional[int] = Field(default=50, ge=1, le=200)

    @field_validator("limit", mode="before")
    @classmethod
    def validate_limit(cls, v: Any) -> int:
        if v is None:
            return 50
        try:
            val = int(v)
            if val < 1:
                return 1
            if val > 200:
                raise ValueError("limit must not exceed 200")
            return val
        except ValueError:
            raise


class EventItem(BaseModel):
    id: str
    timestamp: str
    index: str
    source_type: str
    host: str
    severity: str
    summary: str
    raw: Dict[str, Any] = Field(default_factory=dict)


class EventSearchResponse(BaseModel):
    total_hits: int
    took_ms: int
    indices_searched: List[str] = Field(default_factory=list)
    events: List[EventItem] = Field(default_factory=list)
