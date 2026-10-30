"""
Sigma Rule Detection Engine for OpenSOC Forge.
Parses, compiles, and evaluates community Sigma rules (YAML/JSON)
against normalized ECS security telemetry in real-time.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import glob
import logging
import os
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

import yaml

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    EventCategory,
    NormalizedEvent,
    NormalizedSeverity,
)

logger = logging.getLogger("correlation_engine.sigma")


@dataclass
class SigmaCompiledRule:
    """Represents a compiled, ready-to-evaluate Sigma rule."""
    id: str
    title: str
    description: str
    level: NormalizedSeverity
    category: Optional[str]
    tags: List[str]
    mitre_attack_id: Optional[str]
    mitre_tactic: Optional[str]
    selection_criteria: Dict[str, Any]
    condition: str
    raw_definition: Dict[str, Any]
    enabled: bool = True


class SigmaRuleEngine:
    """
    Evaluator for community Sigma detection rules.
    Supports file/directory loading, hot-reload, and fast pattern matching.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.lock = threading.Lock()
        self.rules_dir = rules_dir or os.path.join("configs", "sigma_rules")
        self.rules: Dict[str, SigmaCompiledRule] = {}
        self.matched_incidents: List[CorrelatedIncident] = []
        self.load_rules()

    def load_rules(self) -> int:
        """Loads and compiles all YAML rule files in rules_dir."""
        with self.lock:
            self.rules.clear()
            if not os.path.exists(self.rules_dir):
                os.makedirs(self.rules_dir, exist_ok=True)

            yaml_files = glob.glob(os.path.join(self.rules_dir, "*.yaml")) + glob.glob(os.path.join(self.rules_dir, "*.yml"))
            loaded = 0

            for fpath in yaml_files:
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        docs = yaml.safe_load_all(f)
                        for doc in docs:
                            if not doc or not isinstance(doc, dict):
                                continue
                            rule = self._compile_rule(doc)
                            if rule:
                                self.rules[rule.id] = rule
                                loaded += 1
                except Exception as exc:
                    logger.warning(f"Failed to parse Sigma file {fpath}: {exc}")

            logger.info(f"Loaded {loaded} Sigma detection rules from {self.rules_dir}")
            return loaded

    def _compile_rule(self, doc: Dict[str, Any]) -> Optional[SigmaCompiledRule]:
        """Compiles a single raw Sigma dictionary into SigmaCompiledRule."""
        rule_id = doc.get("id") or f"SIGMA-{uuid.uuid4().hex[:6].upper()}"
        title = doc.get("title", "Untitled Sigma Rule")
        desc = doc.get("description", "")
        level_str = (doc.get("level") or "medium").upper()

        sev_map = {
            "CRITICAL": NormalizedSeverity.CRITICAL,
            "HIGH": NormalizedSeverity.HIGH,
            "MEDIUM": NormalizedSeverity.MEDIUM,
            "LOW": NormalizedSeverity.LOW,
            "INFORMATIONAL": NormalizedSeverity.INFORMATIONAL,
        }
        severity = sev_map.get(level_str, NormalizedSeverity.MEDIUM)

        logsource = doc.get("logsource", {})
        category = logsource.get("category")

        # Parse MITRE tags
        tags = doc.get("tags", [])
        mitre_tac = "Defense Evasion"
        mitre_id = "T1003"
        for t in tags:
            t_s = str(t).lower()
            if t_s.startswith("attack.t"):
                mitre_id = t_s.replace("attack.", "").upper()
            elif t_s.startswith("attack."):
                mitre_tac = t_s.replace("attack.", "").replace("_", " ").title()

        detection = doc.get("detection", {})
        selection = detection.get("selection", {})
        condition = detection.get("condition", "selection")

        return SigmaCompiledRule(
            id=rule_id,
            title=title,
            description=desc,
            level=severity,
            category=category,
            tags=tags,
            mitre_attack_id=mitre_id,
            mitre_tactic=mitre_tac,
            selection_criteria=selection,
            condition=condition,
            raw_definition=doc,
            enabled=True,
        )

    def evaluate_event(self, event: NormalizedEvent) -> List[CorrelatedIncident]:
        """Evaluates a single normalized event against all active Sigma rules."""
        incidents: List[CorrelatedIncident] = []
        with self.lock:
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue

                if rule.category:
                    cat_val = event.category.value if hasattr(event.category, "value") else str(event.category)
                    if cat_val != rule.category and rule.category not in ["all", "any"]:
                        # Also allow matching if process or http fields are present
                        if rule.category == "process" and not (event.process and (event.process.name or event.process.command_line)):
                            continue
                        elif rule.category == "http" and not (event.http and event.http.url):
                            continue

                if self._matches_selection(event, rule.selection_criteria):
                    inc = self._generate_incident(rule, event)
                    incidents.append(inc)

        return incidents

    def _matches_selection(self, event: NormalizedEvent, selection: Dict[str, Any]) -> bool:
        """Tests whether normalized event meets selection criteria dictionary."""
        if not selection or not isinstance(selection, dict):
            return False

        for field_expr, expected in selection.items():
            field_name, modifier = self._parse_field_expr(field_expr)
            actual_val = self._resolve_event_field(event, field_name)

            if not self._check_value_match(actual_val, expected, modifier):
                return False

        return True

    def _parse_field_expr(self, expr: str) -> Tuple[str, Optional[str]]:
        """Parses field expressions like 'CommandLine|contains' -> ('CommandLine', 'contains')."""
        if "|" in expr:
            parts = expr.split("|", 1)
            return parts[0].strip(), parts[1].strip().lower()
        return expr.strip(), None

    def _resolve_event_field(self, event: NormalizedEvent, field_name: str) -> Optional[str]:
        """Extracts field string from normalized event using standard and Sigma names."""
        fn = field_name.lower()
        if fn in ["process_name", "image", "process"]:
            return (event.process.name if event.process else None) or ""
        elif fn in ["command_line", "commandline", "cmdline", "process.command_line"]:
            return (event.process.command_line if event.process else None) or event.message or ""
        elif fn in ["url", "c-uri", "cs-method", "http.url"]:
            return (event.http.url if event.http else None) or event.message or ""
        elif fn in ["status_code", "sc-status"]:
            return str(event.http.status_code if event.http else "")
        elif fn in ["user", "username", "targetusername", "user.name"]:
            return (event.user.name if event.user else None) or ""
        elif fn in ["host", "hostname", "computername"]:
            return event.host.host or event.destination.host or ""
        elif fn in ["src_ip", "source_ip", "c-ip", "ip"]:
            return event.source.ip or ""
        elif fn in ["dest_ip", "destination_ip"]:
            return event.destination.ip or ""
        elif fn in ["message", "full_log", "log"]:
            return event.message or ""
        return event.message or ""

    def _check_value_match(self, actual: Optional[str], expected: Any, modifier: Optional[str]) -> bool:
        """Checks if actual string satisfies expected value with optional modifier."""
        if actual is None:
            actual = ""
        actual_str = str(actual).lower()

        if isinstance(expected, list):
            # Any match in list
            if modifier == "contains":
                return any(str(exp).lower() in actual_str for exp in expected)
            elif modifier == "endswith":
                return any(actual_str.endswith(str(exp).lower()) for exp in expected)
            elif modifier == "startswith":
                return any(actual_str.startswith(str(exp).lower()) for exp in expected)
            else:
                return any(str(exp).lower() == actual_str or str(exp).lower() in actual_str for exp in expected)
        else:
            exp_str = str(expected).lower()
            if modifier == "contains":
                return exp_str in actual_str
            elif modifier == "endswith":
                return actual_str.endswith(exp_str)
            elif modifier == "startswith":
                return actual_str.startswith(exp_str)
            else:
                return exp_str == actual_str or exp_str in actual_str

    def _generate_incident(self, rule: SigmaCompiledRule, event: NormalizedEvent) -> CorrelatedIncident:
        """Constructs CorrelatedIncident from Sigma match."""
        inc_id = f"inc-sigma-{uuid.uuid4().hex[:8]}"
        host = event.host.host or event.destination.host or "endpoint-sensor"
        ip = event.source.ip or event.destination.ip or "127.0.0.1"
        user = event.user.name or "system"

        incident = CorrelatedIncident(
            id=inc_id,
            rule_id=rule.id,
            rule_name=f"[SIGMA] {rule.title}",
            severity=rule.level,
            risk_score=85.0 if rule.level == NormalizedSeverity.HIGH else (95.0 if rule.level == NormalizedSeverity.CRITICAL else 70.0),
            timestamp=event.timestamp or datetime.now(timezone.utc),
            stage_count=1,
            contributing_sources=[event.source_type or "sigma"],
            entities={
                "hosts": [host] if host else [],
                "ips": [ip] if ip else [],
                "users": [user] if user else [],
                "rule_type": ["SIGMA_COMMUNITY"]
            },
            evidence_events=[event.model_dump() if hasattr(event, "model_dump") else dict(event)],
            root_cause_events=[event.id],
            mitre_tactic=rule.mitre_tactic,
            mitre_attack_id=rule.mitre_attack_id,
            summary=f"Sigma Detection [{rule.id}]: {rule.title} matched on {host} ({rule.description})",
            status="OPEN"
        )
        self.matched_incidents.insert(0, incident)
        if len(self.matched_incidents) > 100:
            self.matched_incidents.pop()
        return incident

    def get_status(self) -> Dict[str, Any]:
        """Returns runtime diagnostics for Sigma engine."""
        with self.lock:
            return {
                "rules_directory": self.rules_dir,
                "loaded_rules_count": len(self.rules),
                "matched_incidents_count": len(self.matched_incidents),
                "rules": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "level": r.level.value,
                        "category": r.category,
                        "mitre_attack_id": r.mitre_attack_id,
                        "mitre_tactic": r.mitre_tactic,
                    }
                    for r in self.rules.values()
                ]
            }


_GLOBAL_SIGMA_ENGINE: Optional[SigmaRuleEngine] = None
_SIGMA_LOCK = threading.Lock()

def get_sigma_engine() -> SigmaRuleEngine:
    global _GLOBAL_SIGMA_ENGINE
    if _GLOBAL_SIGMA_ENGINE is None:
        with _SIGMA_LOCK:
            if _GLOBAL_SIGMA_ENGINE is None:
                _GLOBAL_SIGMA_ENGINE = SigmaRuleEngine()
    return _GLOBAL_SIGMA_ENGINE
