"""
Hybrid Correlation Coordinator for OpenSOC Forge.
Unifies the 3 Core Correlation Tiers:
- Tier 1: Real-time In-Memory Stream & Entity Risk Graph Engine (FSM / Sliding-Window)
- Tier 2: EQL Sequence Correlation Engine (Temporal Multi-Stage Attack Chaining)
- Tier 3: Sigma Rule Community Engine (Dynamic YAML Rule Matcher)

Provides unified event ingestion, incident deduplication, persistence, and REST reporting.
"""

from datetime import datetime, timezone
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from backend.app.services.correlation_engine.engine import CorrelationEngine, get_correlation_engine
from backend.app.services.correlation_engine.eql_engine import EQLSequenceEngine, get_eql_engine
from backend.app.services.correlation_engine.normalizer import normalize_event
from backend.app.services.correlation_engine.schema import CorrelatedIncident, NormalizedEvent
from backend.app.services.correlation_engine.sigma_engine import SigmaRuleEngine, get_sigma_engine

logger = logging.getLogger("correlation_engine.hybrid")

STATE_FILE_PATH = os.path.join("configs", "correlation_hybrid_state.json")


class HybridCorrelationCoordinator:
    """
    Enterprise-Grade Hybrid SIEM Correlation Coordinator.
    Orchestrates Stream, EQL, and Sigma engines under a single unified lifecycle.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.stream_engine: CorrelationEngine = get_correlation_engine()
        self.eql_engine: EQLSequenceEngine = get_eql_engine()
        self.sigma_engine: SigmaRuleEngine = get_sigma_engine()

        self.incident_callbacks: List[Callable[[CorrelatedIncident], None]] = []
        self.total_events_processed: int = 0
        self.total_incidents_generated: int = 0
        self.dedup_seen_signatures: Dict[str, float] = {}  # signature -> timestamp
        self._load_persisted_state()

    def register_incident_callback(self, cb: Callable[[CorrelatedIncident], None]) -> None:
        """Registers a callback when any tier produces an incident."""
        with self.lock:
            if cb not in self.incident_callbacks:
                self.incident_callbacks.append(cb)
                # Also wire callback to underlying stream engine
                self.stream_engine.register_incident_callback(cb)

    def process_raw(self, raw_data: Dict[str, Any], source_hint: Optional[str] = None) -> List[CorrelatedIncident]:
        """
        Unified Ingestion Entrypoint:
        Normalizes once, then dispatches in parallel to Stream, EQL, and Sigma engines.
        """
        norm_event = normalize_event(raw_data, source_hint=source_hint)
        if not norm_event:
            return []

        return self.process_normalized(norm_event)

    def process_normalized(self, event: NormalizedEvent) -> List[CorrelatedIncident]:
        """Routes normalized event to all 3 correlation engines and handles deduplication."""
        all_new_incidents: List[CorrelatedIncident] = []

        with self.lock:
            self.total_events_processed += 1

        # 1. Tier 1: Real-time Stream & Entity Risk Graph Engine
        try:
            stream_incidents = self.stream_engine.process_normalized(event)
            if stream_incidents:
                all_new_incidents.extend(stream_incidents)
        except Exception as exc:
            logger.debug(f"Stream engine processing error: {exc}")

        # 2. Tier 2: EQL Sequence Engine
        try:
            eql_incidents = self.eql_engine.evaluate_event(event)
            if eql_incidents:
                all_new_incidents.extend(eql_incidents)
        except Exception as exc:
            logger.debug(f"EQL engine processing error: {exc}")

        # 3. Tier 3: Sigma Rule Community Engine
        try:
            sigma_incidents = self.sigma_engine.evaluate_event(event)
            if sigma_incidents:
                all_new_incidents.extend(sigma_incidents)
        except Exception as exc:
            logger.debug(f"Sigma engine processing error: {exc}")

        # Deduplicate and dispatch callbacks
        valid_incidents: List[CorrelatedIncident] = []
        now_ts = time.time()

        for inc in all_new_incidents:
            # Build unique signature for 60s deduplication window
            ent_keys = "".join(sorted(inc.entities.get("hosts", []) + inc.entities.get("ips", [])))
            sig = f"{inc.rule_id}:{ent_keys}"

            last_seen = self.dedup_seen_signatures.get(sig, 0.0)
            if (now_ts - last_seen) < 60.0:
                # Suppress duplicate incident within 60s
                continue

            self.dedup_seen_signatures[sig] = now_ts
            valid_incidents.append(inc)

            with self.lock:
                self.total_incidents_generated += 1

            # Dispatch callbacks (e.g. bridge_incident_to_alerts)
            for cb in self.incident_callbacks:
                try:
                    cb(inc)
                except Exception as exc:
                    logger.error(f"Error in incident callback: {exc}")

        # Periodically prune dedup cache
        if len(self.dedup_seen_signatures) > 5000:
            cutoff = now_ts - 300.0
            self.dedup_seen_signatures = {k: v for k, v in self.dedup_seen_signatures.items() if v > cutoff}

        return valid_incidents

    def get_status(self) -> Dict[str, Any]:
        """Provides unified health and metrics report across all 3 tiers."""
        stream_diag = self.stream_engine.get_status()
        eql_status = self.eql_engine.get_status()
        sigma_status = self.sigma_engine.get_status()

        total_rules = (
            stream_diag.get("rules_count", 0)
            + eql_status.get("active_rules_count", 0)
            + sigma_status.get("loaded_rules_count", 0)
        )

        return {
            "mode": "HYBRID (STREAM + EQL SEQUENCES + SIGMA COMMUNITY)",
            "tier1_stream": {
                "status": "ACTIVE" if stream_diag.get("running") else "STOPPED",
                "rules_count": stream_diag.get("rules_count", 0),
                "entities_tracked": stream_diag.get("entity_store_summary", {}).get("total_entities", 0),
                "events_buffered": stream_diag.get("total_buffered_events", 0),
            },
            "tier2_eql": {
                "status": "ACTIVE",
                "active_rules_count": eql_status.get("active_rules_count", 0),
                "in_flight_sequences": eql_status.get("active_in_flight_sequences", 0),
                "completed_incidents": eql_status.get("completed_incidents_count", 0),
            },
            "tier3_sigma": {
                "status": "ACTIVE",
                "loaded_rules_count": sigma_status.get("loaded_rules_count", 0),
                "matched_incidents": sigma_status.get("matched_incidents_count", 0),
                "rules_directory": sigma_status.get("rules_directory"),
            },
            "total_active_rules": total_rules,
            "total_events_processed": self.total_events_processed,
            "total_incidents_generated": self.total_incidents_generated,
            "all_rules_summary": {
                "stream_rules": list(self.stream_engine.rules.keys()),
                "eql_rules": [r.get("rule_id") for r in eql_status.get("rules", [])],
                "sigma_rules": [r.get("id") for r in sigma_status.get("rules", [])],
            }
        }

    def _load_persisted_state(self) -> None:
        """Loads persistent engine metrics across service restarts."""
        try:
            if os.path.exists(STATE_FILE_PATH):
                with open(STATE_FILE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.total_events_processed = data.get("total_events_processed", 0)
                    self.total_incidents_generated = data.get("total_incidents_generated", 0)
        except Exception as exc:
            logger.debug(f"Could not load hybrid engine state: {exc}")

    def save_state(self) -> None:
        """Saves persistent metrics to disk."""
        try:
            os.makedirs(os.path.dirname(STATE_FILE_PATH), exist_ok=True)
            with open(STATE_FILE_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "total_events_processed": self.total_events_processed,
                    "total_incidents_generated": self.total_incidents_generated,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                }, f, indent=2)
        except Exception as exc:
            logger.debug(f"Could not save hybrid engine state: {exc}")


_GLOBAL_HYBRID_COORDINATOR: Optional[HybridCorrelationCoordinator] = None
_HYBRID_LOCK = threading.Lock()

def get_hybrid_coordinator() -> HybridCorrelationCoordinator:
    global _GLOBAL_HYBRID_COORDINATOR
    if _GLOBAL_HYBRID_COORDINATOR is None:
        with _HYBRID_LOCK:
            if _GLOBAL_HYBRID_COORDINATOR is None:
                _GLOBAL_HYBRID_COORDINATOR = HybridCorrelationCoordinator()
    return _GLOBAL_HYBRID_COORDINATOR
