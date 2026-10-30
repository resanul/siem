"""
Correlation Engine Core for OpenSOC Forge.
Implements stateful multi-source security event correlation:
- Sliding time-window ring buffer with millisecond-precision event timestamp sorting.
- Watermarked out-of-order event tolerance and resequencing.
- Threshold counting and cardinality tracking grouped by entity keys.
- Deterministic Finite State Machine (FSM) multi-stage attack sequence engine.
- Unified Entity Tracking Store (IP <-> Host <-> User mappings with composite risk scoring).
- Alert deduplication and cooldown suppression engine.
"""

import bisect
from datetime import datetime, timedelta, timezone
import logging
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
    EngineStatus,
    NormalizedEvent,
    NormalizedSeverity,
)
from backend.app.services.correlation_engine.normalizer import normalize_event
from backend.app.services.correlation_engine.rules import (
    BaseCorrelationRule,
    get_default_rules,
)
from backend.app.services.correlation_engine.storage import CorrelationStorage

logger = logging.getLogger("correlation_engine.engine")


class EntityStore:
    """
    Unified In-Memory Entity Graph & State Store.
    Maintains cross-source mapping across IP addresses, hostnames, and user accounts,
    and calculates composite dynamic entity risk scores (0.0 to 100.0).
    """

    def __init__(self, risk_decay_rate_per_hour: float = 5.0):
        self.lock = threading.Lock()
        self.risk_decay_rate_per_hour = risk_decay_rate_per_hour

        # Relationships
        self.ip_to_hosts: Dict[str, Set[str]] = {}
        self.host_to_ips: Dict[str, Set[str]] = {}
        self.ip_to_users: Dict[str, Set[str]] = {}
        self.user_to_ips: Dict[str, Set[str]] = {}
        self.user_to_hosts: Dict[str, Set[str]] = {}
        self.host_to_users: Dict[str, Set[str]] = {}

        # Entity Risk Scores (0.0 - 100.0)
        self.risk_scores: Dict[str, float] = {}
        self.last_risk_update: Dict[str, datetime] = {}

        # Entity event history (most recent 50 events per entity)
        self.entity_history: Dict[str, List[NormalizedEvent]] = {}

    def update_from_event(self, event: NormalizedEvent) -> None:
        """Update entity relationship graph from normalized event telemetry."""
        with self.lock:
            src_ip = event.source.ip
            dst_ip = event.destination.ip
            host = event.host.host or event.destination.host
            user = event.user.name

            # Canonicalize
            if user:
                user = user.lower()

            for ip in (src_ip, dst_ip):
                if ip:
                    if host:
                        self.ip_to_hosts.setdefault(ip, set()).add(host)
                        self.host_to_ips.setdefault(host, set()).add(ip)
                    if user:
                        self.ip_to_users.setdefault(ip, set()).add(user)
                        self.user_to_ips.setdefault(user, set()).add(ip)

            if host and user:
                self.user_to_hosts.setdefault(user, set()).add(host)
                self.host_to_users.setdefault(host, set()).add(user)

            # Record in history
            now = datetime.now(timezone.utc)
            for ent in filter(None, [src_ip, dst_ip, host, user]):
                hist = self.entity_history.setdefault(ent, [])
                hist.append(event)
                if len(hist) > 50:
                    hist.pop(0)

                # Initialize risk score if new
                if ent not in self.risk_scores:
                    self.risk_scores[ent] = 10.0
                    self.last_risk_update[ent] = now

    def add_risk(self, entity_id: str, points: float) -> float:
        """Increment risk score for an entity, clamped between 0.0 and 100.0."""
        with self.lock:
            self._apply_decay_unlocked(entity_id)
            current = self.risk_scores.get(entity_id, 10.0)
            new_score = max(0.0, min(100.0, current + points))
            self.risk_scores[entity_id] = new_score
            self.last_risk_update[entity_id] = datetime.now(timezone.utc)
            return new_score

    def get_risk(self, entity_id: str) -> float:
        """Get current risk score for an entity with decay applied."""
        with self.lock:
            self._apply_decay_unlocked(entity_id)
            return self.risk_scores.get(entity_id, 10.0)

    def _apply_decay_unlocked(self, entity_id: str) -> None:
        if entity_id not in self.risk_scores:
            return
        last_time = self.last_risk_update.get(entity_id)
        if not last_time:
            return
        now = datetime.now(timezone.utc)
        elapsed_sec = (now - last_time).total_seconds()
        if elapsed_sec >= 60.0:
            elapsed_hours = elapsed_sec / 3600.0
            decay = elapsed_hours * self.risk_decay_rate_per_hour
            self.risk_scores[entity_id] = max(0.0, round(self.risk_scores[entity_id] - decay, 2))
            self.last_risk_update[entity_id] = now

    def resolve_aliases(self, entity: str) -> Set[str]:
        """Resolve all associated aliases (IPs, hosts, users) for an entity identifier."""
        with self.lock:
            aliases: Set[str] = {entity}
            if entity in self.ip_to_hosts:
                aliases.update(self.ip_to_hosts[entity])
            if entity in self.ip_to_users:
                aliases.update(self.ip_to_users[entity])
            if entity in self.host_to_ips:
                aliases.update(self.host_to_ips[entity])
            if entity in self.user_to_ips:
                aliases.update(self.user_to_ips[entity])
            return aliases

    def export_summary(self) -> Dict[str, Any]:
        """Export summary of tracked entities."""
        with self.lock:
            top_risky = sorted(self.risk_scores.items(), key=lambda x: x[1], reverse=True)[:20]
            return {
                "total_tracked_entities": len(self.risk_scores),
                "ip_count": len(self.ip_to_hosts),
                "host_count": len(self.host_to_ips),
                "user_count": len(self.user_to_ips),
                "top_risky_entities": [{"entity": k, "risk_score": round(v, 1)} for k, v in top_risky],
            }

    def reset(self) -> None:
        """Reset entity store state."""
        with self.lock:
            self.ip_to_hosts.clear()
            self.host_to_ips.clear()
            self.ip_to_users.clear()
            self.user_to_ips.clear()
            self.user_to_hosts.clear()
            self.host_to_users.clear()
            self.risk_scores.clear()
            self.last_risk_update.clear()
            self.entity_history.clear()


class CorrelationEngine:
    """
    High-Performance Production-Grade Stateful SIEM Correlation Engine.
    Executes real-time sliding-window rule evaluation across normalized telemetry.
    """

    def __init__(
        self,
        storage: Optional[CorrelationStorage] = None,
        out_of_order_tolerance_seconds: float = 120.0,
        max_buffer_per_entity: int = 1000,
    ):
        self._lock = threading.RLock()
        self.storage = storage or CorrelationStorage()
        self.out_of_order_tolerance_seconds = out_of_order_tolerance_seconds
        self.max_buffer_per_entity = max_buffer_per_entity

        # Engine state
        self.start_time = datetime.now(timezone.utc)
        self.is_running = True
        self.watermark: Optional[datetime] = None
        self.events_processed = 0
        self.incidents_generated = 0
        self.late_events_dropped = 0
        self.suppressed_incidents_count = 0

        # Entity State Store
        self.entity_store = EntityStore()

        # Rule Library: rule_id -> BaseCorrelationRule
        self.rules: Dict[str, BaseCorrelationRule] = get_default_rules()
        self._sync_rules_with_storage()

        # Sliding Window Buffers:
        # Key: (rule_id, entity_key) -> List[NormalizedEvent] (sorted by timestamp)
        self.window_buffers: Dict[Tuple[str, str], List[NormalizedEvent]] = {}

        # Alert Deduplication & Cooldown Tracking:
        # Key: (rule_id, entity_key) -> cooldown_until (datetime)
        self.cooldown_tracker: Dict[Tuple[str, str], datetime] = {}
        # Key: (rule_id, entity_key) -> latest CorrelatedIncident
        self.active_incidents: Dict[Tuple[str, str], CorrelatedIncident] = {}

        # Optional listener callback for integration hooks
        self.incident_callbacks: List[Callable[[CorrelatedIncident], None]] = []

    def _sync_rules_with_storage(self) -> None:
        """Synchronize active rule configurations from persisted storage."""
        try:
            persisted_configs = self.storage.load_rules()
            cfg_map = {c.rule_id: c for c in persisted_configs}
            for rule_id, rule in self.rules.items():
                if rule_id in cfg_map:
                    rule.config = cfg_map[rule_id]
        except Exception as exc:
            logger.warning(f"Failed to sync rules from storage: {exc}")

    def register_incident_callback(self, callback: Callable[[CorrelatedIncident], None]) -> None:
        """Register a callback invoked whenever an incident is generated."""
        with self._lock:
            self.incident_callbacks.append(callback)

    def process_raw(
        self,
        raw_data: Union[Dict[str, Any], str],
        source: Optional[str] = None,
        source_hint: Optional[str] = None,
    ) -> List[CorrelatedIncident]:
        """Convenience method: normalizes raw payload and executes correlation logic."""
        hint = source or source_hint
        normalized = normalize_event(raw_data, source_hint=hint)
        return self.process_event(normalized)

    def process_event(self, event: NormalizedEvent) -> List[CorrelatedIncident]:
        """
        Ingest a normalized event, update sliding-window buffers, advance watermark,
        evaluate all enabled correlation rules, and return any newly triggered incidents.
        """
        with self._lock:
            if not self.is_running:
                return []

            self.events_processed += 1
            evt_time = event.timestamp
            now = datetime.now(timezone.utc)

            # Advance or initialize watermark
            if self.watermark is None or evt_time > self.watermark:
                self.watermark = evt_time

            # Out-of-order tolerance check
            cutoff = self.watermark - timedelta(seconds=self.out_of_order_tolerance_seconds)
            if evt_time < cutoff:
                self.late_events_dropped += 1
                logger.debug(f"Event {event.event_id} dropped: timestamp {evt_time} older than watermark {self.watermark}")
                return []

            # Update Entity Graph Store
            self.entity_store.update_from_event(event)

            new_incidents: List[CorrelatedIncident] = []

            # Evaluate each enabled rule
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue

                # Filter sources if rule specifies explicit sources
                if rule.config.sources and event.source_type not in rule.config.sources:
                    continue

                entity_keys = rule.get_entity_keys(event)
                for e_key in entity_keys:
                    buffer_key = (rule_id, e_key)

                    # Retrieve or create window buffer
                    buf = self.window_buffers.setdefault(buffer_key, [])

                    # Insert in chronological order (watermarked resequencing)
                    self._insert_sorted(buf, event)

                    # Enforce buffer capacity limit
                    if len(buf) > self.max_buffer_per_entity:
                        buf.pop(0)

                    # Prune events older than rule's window_seconds
                    window_cutoff = evt_time.timestamp() - rule.config.window_seconds
                    # Fast prune from left
                    while buf and buf[0].timestamp.timestamp() < window_cutoff:
                        buf.pop(0)

                    # Evaluate rule on current window buffer
                    incident = rule.evaluate_window(buf, e_key, evt_time)
                    if incident:
                        # Check deduplication & cooldown
                        cooldown_key = (rule_id, e_key)
                        cooldown_until = self.cooldown_tracker.get(cooldown_key)

                        if cooldown_until and evt_time < cooldown_until:
                            # In cooldown: suppress duplicate incident creation
                            self.suppressed_incidents_count += 1
                            # Append root-cause events to active incident
                            active_inc = self.active_incidents.get(cooldown_key)
                            if active_inc:
                                active_inc.root_cause_events.extend(incident.root_cause_events)
                                active_inc.evidence_events.extend(incident.evidence_events)
                                # Cap evidence
                                active_inc.root_cause_events = active_inc.root_cause_events[:50]
                                active_inc.evidence_events = active_inc.evidence_events[:20]
                                self.storage.save_incident(active_inc)
                            continue

                        # Cooldown expired or first time: trigger new incident
                        incident.cooldown_until = evt_time + timedelta(seconds=rule.config.cooldown_seconds)
                        self.cooldown_tracker[cooldown_key] = incident.cooldown_until
                        self.active_incidents[cooldown_key] = incident

                        # Update composite risk scores for affected entities
                        risk_delta = 40.0 if incident.severity == NormalizedSeverity.CRITICAL else (
                            25.0 if incident.severity == NormalizedSeverity.HIGH else 15.0
                        )
                        for user in incident.entities.get("users", []):
                            self.entity_store.add_risk(user, risk_delta)
                        for ip in incident.entities.get("ips", []):
                            self.entity_store.add_risk(ip, risk_delta)
                        for host in incident.entities.get("hosts", []):
                            self.entity_store.add_risk(host, risk_delta)

                        # Persist incident
                        self.storage.save_incident(incident)
                        self.incidents_generated += 1
                        new_incidents.append(incident)

                        # Notify callbacks
                        for cb in self.incident_callbacks:
                            try:
                                cb(incident)
                            except Exception as exc:
                                logger.error(f"Error in incident callback: {exc}")

            return new_incidents

    def _insert_sorted(self, buf: List[NormalizedEvent], event: NormalizedEvent) -> None:
        """Insert event into buffer maintaining strict timestamp ascending order."""
        if not buf or event.timestamp >= buf[-1].timestamp:
            buf.append(event)
            return
        if event.timestamp <= buf[0].timestamp:
            buf.insert(0, event)
            return

        # Binary search insertion
        timestamps = [e.timestamp for e in buf]
        idx = bisect.bisect_right(timestamps, event.timestamp)
        buf.insert(idx, event)

    def get_status(self) -> Dict[str, Any]:
        """Return real-time operational status and metrics of the Correlation Engine."""
        with self._lock:
            now = datetime.now(timezone.utc)
            uptime = (now - self.start_time).total_seconds()
            active_rules = sum(1 for r in self.rules.values() if r.enabled)
            active_windows = len(self.window_buffers)
            buffered_events = sum(len(b) for b in self.window_buffers.values())

            return {
                "running": self.is_running,
                "uptime_seconds": round(uptime, 1),
                "events_processed": self.events_processed,
                "incidents_generated": self.incidents_generated,
                "suppressed_incidents_count": self.suppressed_incidents_count,
                "late_events_dropped": self.late_events_dropped,
                "rules_count": len(self.rules),
                "active_rules_count": active_rules,
                "active_windows_count": active_windows,
                "total_buffered_events": buffered_events,
                "watermark": self.watermark.isoformat() if self.watermark else None,
                "entity_store_summary": self.entity_store.export_summary(),
            }

    def start(self) -> None:
        """Start or resume engine evaluation."""
        with self._lock:
            self.is_running = True

    def stop(self) -> None:
        """Pause engine evaluation."""
        with self._lock:
            self.is_running = False

    def reset_state(self) -> None:
        """Reset all in-memory sliding windows, cooldowns, and counters for clean testing."""
        with self._lock:
            self.window_buffers.clear()
            self.cooldown_tracker.clear()
            self.active_incidents.clear()
            self.watermark = None
            self.events_processed = 0
            self.incidents_generated = 0
            self.suppressed_incidents_count = 0
            self.late_events_dropped = 0
            self.entity_store.reset()

    def get_rules(self) -> List[CorrelationRuleConfig]:
        """Return list of all configured correlation rules."""
        with self._lock:
            return [r.config for r in self.rules.values()]

    def get_rule(self, rule_id: str) -> Optional[CorrelationRuleConfig]:
        """Get configuration of a specific rule by ID."""
        with self._lock:
            rule = self.rules.get(rule_id)
            return rule.config if rule else None

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a correlation rule by ID."""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return False
            rule.enabled = True
            self.storage.save_rules([r.config for r in self.rules.values()])
            return True

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a correlation rule by ID."""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return False
            rule.enabled = False
            self.storage.save_rules([r.config for r in self.rules.values()])
            return True

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update configurable parameters of a rule (threshold, window, enabled)."""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return False

            cfg = rule.config
            if "enabled" in updates:
                cfg.enabled = bool(updates["enabled"])
            if "window_seconds" in updates and int(updates["window_seconds"]) > 0:
                cfg.window_seconds = int(updates["window_seconds"])
            if "threshold" in updates and int(updates["threshold"]) > 0:
                cfg.threshold = int(updates["threshold"])
            if "cooldown_seconds" in updates and int(updates["cooldown_seconds"]) >= 0:
                cfg.cooldown_seconds = int(updates["cooldown_seconds"])
            if "severity" in updates:
                try:
                    cfg.severity = NormalizedSeverity(updates["severity"])
                except ValueError:
                    pass
            if "risk_score" in updates:
                cfg.risk_score = float(updates["risk_score"])

            self.storage.save_rules([r.config for r in self.rules.values()])
            return True

    def get_incidents(self, limit: int = 50, offset: int = 0) -> List[CorrelatedIncident]:
        """Retrieve persisted incidents."""
        return self.storage.list_incidents(limit=limit, offset=offset)

    def get_incident(self, incident_id: str) -> Optional[CorrelatedIncident]:
        """Retrieve a specific incident by ID."""
        return self.storage.get_incident(incident_id)

    def get_entities(self) -> Dict[str, Any]:
        """Retrieve entity store state and summary."""
        return self.entity_store.export_summary()

_GLOBAL_ENGINE: Optional[CorrelationEngine] = None
_ENGINE_LOCK = threading.Lock()

def get_correlation_engine() -> CorrelationEngine:
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        with _ENGINE_LOCK:
            if _GLOBAL_ENGINE is None:
                _GLOBAL_ENGINE = CorrelationEngine()
    return _GLOBAL_ENGINE

