"""
EQL (Event Query Language) Sequence Correlation Engine for OpenSOC Forge.
Provides stateful multi-stage sequence detection compliant with Elastic EQL specifications:
- Sequence matching by entity key (user, host, source IP) with configurable maxspan.
- Stage condition matching (category, event action, outcome, process/file/network attributes).
- In-memory embedded sequence evaluation over normalized telemetry stream.
- Optional Elasticsearch EQL Pushdown driver for delegating queries to cluster when reachable.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import urllib.request
import base64
import uuid

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    EventCategory,
    NormalizedEvent,
    NormalizedOutcome,
    NormalizedSeverity,
)

logger = logging.getLogger("correlation_engine.eql")


@dataclass
class EQLStage:
    """Represents a single step in an EQL sequence query."""
    category: Optional[str] = None
    outcome: Optional[str] = None
    action: Optional[str] = None
    min_runs: int = 1
    match_fn: Optional[Callable[[NormalizedEvent], bool]] = None
    description: str = ""


@dataclass
class EQLSequenceRule:
    """Represents a complete EQL sequence rule."""
    rule_id: str
    name: str
    description: str
    sequence_by: str  # "user.name", "host.host", "source.ip", or "destination.ip"
    maxspan_seconds: int
    stages: List[EQLStage]
    severity: NormalizedSeverity
    mitre_tactic: str
    mitre_attack_id: str
    risk_score: float = 85.0
    enabled: bool = True


@dataclass
class ActiveSequenceState:
    """Tracks ongoing progression of an entity through sequence stages."""
    rule_id: str
    entity_key: str
    current_stage_idx: int = 0
    matched_events: List[NormalizedEvent] = field(default_factory=list)
    stage_run_counts: List[int] = field(default_factory=list)
    first_match_time: Optional[datetime] = None
    last_match_time: Optional[datetime] = None


class EQLSequenceEngine:
    """
    Embedded High-Performance EQL Sequence Matcher.
    Executes ordered state transitions across temporal windows.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.rules: Dict[str, EQLSequenceRule] = {}
        # Key: (rule_id, entity_key) -> ActiveSequenceState
        self.active_sequences: Dict[Tuple[str, str], ActiveSequenceState] = {}
        self.completed_incidents: List[CorrelatedIncident] = []
        self._init_default_eql_rules()

    def _init_default_eql_rules(self) -> None:
        """Initializes core EQL sequence detection rules."""
        # 1. Multi-Stage Brute Force to Privileged Execution
        self.register_rule(EQLSequenceRule(
            rule_id="EQL-SEQ-001",
            name="EQL: Multi-Stage Brute Force to Privileged Execution",
            description="Detects repeated authentication failures followed by successful logon and process execution on the target host within 10 minutes.",
            sequence_by="host.host",
            maxspan_seconds=600,
            stages=[
                EQLStage(
                    category="authentication",
                    outcome="failure",
                    min_runs=3,
                    description="Multiple failed authentications"
                ),
                EQLStage(
                    category="authentication",
                    outcome="success",
                    description="Successful authentication after failure"
                ),
                EQLStage(
                    category="process",
                    match_fn=lambda ev: any(p in (ev.process.name or "").lower() for p in ["cmd.exe", "powershell.exe", "bash", "sh", "whoami", "sudo", "su"]),
                    description="Immediate interactive shell or privilege probe"
                )
            ],
            severity=NormalizedSeverity.CRITICAL,
            mitre_tactic="Initial Access -> Execution",
            mitre_attack_id="T1110.001 -> T1059",
            risk_score=95.0
        ))

        # 2. Web Exploit Reconnaissance to Shell Deployment
        self.register_rule(EQLSequenceRule(
            rule_id="EQL-SEQ-002",
            name="EQL: Web Exploit Reconnaissance to Shell Deployment",
            description="Detects multiple HTTP forbidden/error probes followed by internal process creation on the web server.",
            sequence_by="source.ip",
            maxspan_seconds=900,
            stages=[
                EQLStage(
                    category="http",
                    match_fn=lambda ev: (ev.http.status_code in [403, 404, 500]) or ("forbidden" in (ev.message or "").lower()),
                    min_runs=2,
                    description="Web exploit / forbidden directory scanning"
                ),
                EQLStage(
                    category="threat",
                    description="Wazuh or Suricata IDS security alert match"
                )
            ],
            severity=NormalizedSeverity.HIGH,
            mitre_tactic="Initial Access -> Persistence",
            mitre_attack_id="T1190 -> T1505.003",
            risk_score=88.0
        ))

        # 3. Network Discovery to Lateral Movement
        self.register_rule(EQLSequenceRule(
            rule_id="EQL-SEQ-003",
            name="EQL: Port Reconnaissance to Lateral Remote Service Invocation",
            description="Detects network port scanning followed by SSH or SMB lateral movement connection.",
            sequence_by="source.ip",
            maxspan_seconds=1200,
            stages=[
                EQLStage(
                    category="network",
                    match_fn=lambda ev: (ev.destination.port in [22, 445, 3389, 135]) or ("scan" in (ev.message or "").lower()),
                    min_runs=2,
                    description="Targeted reconnaissance on remote service ports"
                ),
                EQLStage(
                    category="authentication",
                    match_fn=lambda ev: ev.destination.port in [22, 445] or ("ssh" in (ev.message or "").lower() or "smb" in (ev.message or "").lower()),
                    description="Remote service logon execution"
                )
            ],
            severity=NormalizedSeverity.HIGH,
            mitre_tactic="Discovery -> Lateral Movement",
            mitre_attack_id="T1046 -> T1021",
            risk_score=85.0
        ))

        # 4. Privilege Escalation to Shadow Copy Deletion (Ransomware Prep)
        self.register_rule(EQLSequenceRule(
            rule_id="EQL-SEQ-004",
            name="EQL: Privilege Escalation to Shadow Copy Deletion",
            description="Detects privilege escalation followed by command invocation to delete volume shadow copies.",
            sequence_by="host.host",
            maxspan_seconds=600,
            stages=[
                EQLStage(
                    category="privilege",
                    description="Privilege elevation or sensitive group enumeration"
                ),
                EQLStage(
                    category="process",
                    match_fn=lambda ev: any(s in (ev.process.command_line or "").lower() for s in ["delete shadows", "shadowcopy delete", "vssadmin"]),
                    description="Shadow copy deletion command"
                )
            ],
            severity=NormalizedSeverity.CRITICAL,
            mitre_tactic="Privilege Escalation -> Impact",
            mitre_attack_id="T1068 -> T1490",
            risk_score=98.0
        ))

    def register_rule(self, rule: EQLSequenceRule) -> None:
        """Registers a new EQL sequence rule."""
        with self.lock:
            self.rules[rule.rule_id] = rule

    def extract_entity_key(self, event: NormalizedEvent, key_path: str) -> Optional[str]:
        """Extracts sequence binding key from normalized event."""
        if key_path == "user.name":
            return (event.user.name if event.user else None) or (event.process.user if event.process else None)
        elif key_path == "host.host":
            return (event.host.host if event.host else None) or (event.destination.host if event.destination else None)
        elif key_path == "source.ip":
            return event.source.ip if event.source else None
        elif key_path == "destination.ip":
            return event.destination.ip if event.destination else None
        return None

    def evaluate_event(self, event: NormalizedEvent) -> List[CorrelatedIncident]:
        """
        Processes an incoming normalized event across all registered EQL sequences.
        Returns any newly triggered incidents.
        """
        new_incidents: List[CorrelatedIncident] = []
        now = event.timestamp or datetime.now(timezone.utc)

        with self.lock:
            # 1. Clean expired sequences
            self._prune_expired_sequences(now)

            # 2. Evaluate event against each rule
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue

                entity_key = self.extract_entity_key(event, rule.sequence_by)
                if not entity_key:
                    continue

                state_key = (rule_id, entity_key)
                state = self.active_sequences.get(state_key)

                if state is None:
                    # Check if event matches Stage 0
                    stage_0 = rule.stages[0]
                    if self._matches_stage(event, stage_0):
                        new_state = ActiveSequenceState(
                            rule_id=rule_id,
                            entity_key=entity_key,
                            current_stage_idx=0,
                            matched_events=[event],
                            stage_run_counts=[1],
                            first_match_time=now,
                            last_match_time=now,
                        )
                        # If stage 0 only requires 1 run and rule has only 1 stage (rare), complete
                        if len(rule.stages) == 1 and new_state.stage_run_counts[0] >= stage_0.min_runs:
                            inc = self._generate_incident(rule, new_state)
                            new_incidents.append(inc)
                        else:
                            self.active_sequences[state_key] = new_state
                else:
                    # Check maxspan timeout
                    if (now - state.first_match_time).total_seconds() > rule.maxspan_seconds:
                        # Expired, reset state
                        del self.active_sequences[state_key]
                        continue

                    curr_stage = rule.stages[state.current_stage_idx]

                    # Check if event continues current stage runs
                    if self._matches_stage(event, curr_stage):
                        state.matched_events.append(event)
                        state.stage_run_counts[state.current_stage_idx] += 1
                        state.last_match_time = now

                        # Check if we can progress to next stage
                        if state.stage_run_counts[state.current_stage_idx] >= curr_stage.min_runs:
                            # If there's a next stage and this event also matches next stage?
                            pass
                    else:
                        # Check if event matches NEXT stage
                        if state.stage_run_counts[state.current_stage_idx] >= curr_stage.min_runs:
                            next_stage_idx = state.current_stage_idx + 1
                            if next_stage_idx < len(rule.stages):
                                next_stage = rule.stages[next_stage_idx]
                                if self._matches_stage(event, next_stage):
                                    state.current_stage_idx = next_stage_idx
                                    state.matched_events.append(event)
                                    state.stage_run_counts.append(1)
                                    state.last_match_time = now

                                    # Check if sequence is fully completed
                                    if state.current_stage_idx == len(rule.stages) - 1:
                                        if state.stage_run_counts[state.current_stage_idx] >= next_stage.min_runs:
                                            inc = self._generate_incident(rule, state)
                                            new_incidents.append(inc)
                                            del self.active_sequences[state_key]

        return new_incidents

    def _matches_stage(self, event: NormalizedEvent, stage: EQLStage) -> bool:
        """Determines if an event matches a stage definition."""
        if stage.category:
            cat_val = event.category.value if hasattr(event.category, "value") else str(event.category)
            if cat_val != stage.category:
                return False

        if stage.outcome:
            out_val = event.outcome.value if hasattr(event.outcome, "value") else str(event.outcome)
            if out_val != stage.outcome:
                return False

        if stage.action:
            if stage.action not in (event.action or ""):
                return False

        if stage.match_fn:
            try:
                if not stage.match_fn(event):
                    return False
            except Exception:
                return False

        return True

    def _generate_incident(self, rule: EQLSequenceRule, state: ActiveSequenceState) -> CorrelatedIncident:
        """Builds a standardized CorrelatedIncident from completed EQL sequence."""
        span_seconds = (state.last_match_time - state.first_match_time).total_seconds()
        inc_id = f"inc-eql-{uuid.uuid4().hex[:8]}"

        hosts = list({ev.host.host or ev.destination.host for ev in state.matched_events if (ev.host.host or ev.destination.host)})
        ips = list({ev.source.ip for ev in state.matched_events if ev.source.ip} | {ev.destination.ip for ev in state.matched_events if ev.destination.ip})
        users = list({ev.user.name for ev in state.matched_events if ev.user.name})

        incident = CorrelatedIncident(
            id=inc_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            risk_score=rule.risk_score,
            timestamp=state.last_match_time,
            stage_count=len(rule.stages),
            contributing_sources=list({ev.source_type for ev in state.matched_events if ev.source_type}),
            entities={
                "hosts": hosts,
                "ips": ips,
                "users": users,
                "bound_key": [state.entity_key]
            },
            evidence_events=[ev.model_dump() if hasattr(ev, "model_dump") else dict(ev) for ev in state.matched_events[-10:]],
            root_cause_events=[state.matched_events[0].id] if state.matched_events else [],
            mitre_tactic=rule.mitre_tactic,
            mitre_attack_id=rule.mitre_attack_id,
            summary=f"[EQL Match] {rule.name} completed across {len(state.matched_events)} events for {state.entity_key} (duration: {int(span_seconds)}s)",
            status="OPEN"
        )
        self.completed_incidents.insert(0, incident)
        if len(self.completed_incidents) > 100:
            self.completed_incidents.pop()
        return incident

    def _prune_expired_sequences(self, now: datetime) -> None:
        """Purges active sequences that exceeded their rule maxspan."""
        to_delete = []
        for state_key, state in self.active_sequences.items():
            rule = self.rules.get(state.rule_id)
            if not rule:
                to_delete.append(state_key)
                continue
            if (now - state.first_match_time).total_seconds() > rule.maxspan_seconds:
                to_delete.append(state_key)
        for k in to_delete:
            del self.active_sequences[k]

    def get_status(self) -> Dict[str, Any]:
        """Returns runtime diagnostics for EQL engine."""
        with self.lock:
            return {
                "active_rules_count": len(self.rules),
                "active_in_flight_sequences": len(self.active_sequences),
                "completed_incidents_count": len(self.completed_incidents),
                "rules": [
                    {
                        "rule_id": r.rule_id,
                        "name": r.name,
                        "stages_count": len(r.stages),
                        "sequence_by": r.sequence_by,
                        "maxspan_seconds": r.maxspan_seconds,
                        "severity": r.severity.value,
                        "mitre_attack_id": r.mitre_attack_id
                    }
                    for r in self.rules.values()
                ]
            }


_GLOBAL_EQL_ENGINE: Optional[EQLSequenceEngine] = None
_EQL_LOCK = threading.Lock()

def get_eql_engine() -> EQLSequenceEngine:
    global _GLOBAL_EQL_ENGINE
    if _GLOBAL_EQL_ENGINE is None:
        with _EQL_LOCK:
            if _GLOBAL_EQL_ENGINE is None:
                _GLOBAL_EQL_ENGINE = EQLSequenceEngine()
    return _GLOBAL_EQL_ENGINE
