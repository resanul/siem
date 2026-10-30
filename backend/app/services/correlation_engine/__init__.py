"""
OpenSOC Forge Enterprise SIEM Correlation Engine Package.
Provides multi-source stateful event correlation, canonical normalization,
sliding-window analysis, threshold and sequence detection, and explainable incident synthesis.
Includes Hybrid Model: Stream FSM + EQL Sequence Engine + Sigma Community Rules.
"""

from typing import Optional

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
    DnsEntity,
    EndpointEntity,
    EngineStatus,
    EventCategory,
    FileEntity,
    HttpEntity,
    NormalizedCategory,
    NormalizedEvent,
    NormalizedOutcome,
    NormalizedSeverity,
    ProcessEntity,
    UserEntity,
)
from backend.app.services.correlation_engine.normalizer import normalize_event
from backend.app.services.correlation_engine.storage import CorrelationStorage
from backend.app.services.correlation_engine.rules import (
    BaseCorrelationRule,
    get_default_rule_configs,
    get_default_rules,
)
from backend.app.services.correlation_engine.engine import (
    CorrelationEngine,
    EntityStore,
)
from backend.app.services.correlation_engine.datasets import (
    generate_all_datasets,
    generate_attack_dataset,
    generate_benign_dataset,
)
from backend.app.services.correlation_engine.eql_engine import (
    EQLSequenceEngine,
    EQLSequenceRule,
    get_eql_engine,
)
from backend.app.services.correlation_engine.sigma_engine import (
    SigmaCompiledRule,
    SigmaRuleEngine,
    get_sigma_engine,
)
from backend.app.services.correlation_engine.hybrid_coordinator import (
    HybridCorrelationCoordinator,
    get_hybrid_coordinator,
)

# Global Engine Singleton
_CORRELATION_ENGINE: Optional[CorrelationEngine] = None


def get_correlation_engine() -> CorrelationEngine:
    """Return the global CorrelationEngine singleton instance."""
    global _CORRELATION_ENGINE
    if _CORRELATION_ENGINE is None:
        _CORRELATION_ENGINE = CorrelationEngine()
    return _CORRELATION_ENGINE


def init_correlation_engine(
    storage: Optional[CorrelationStorage] = None,
    out_of_order_tolerance_seconds: float = 120.0,
    max_buffer_per_entity: int = 1000,
) -> CorrelationEngine:
    """Initialize or re-initialize the global CorrelationEngine singleton."""
    global _CORRELATION_ENGINE
    _CORRELATION_ENGINE = CorrelationEngine(
        storage=storage,
        out_of_order_tolerance_seconds=out_of_order_tolerance_seconds,
        max_buffer_per_entity=max_buffer_per_entity,
    )
    return _CORRELATION_ENGINE


__all__ = [
    # Schema
    "NormalizedSeverity",
    "EventCategory",
    "NormalizedCategory",
    "NormalizedOutcome",
    "EndpointEntity",
    "UserEntity",
    "ProcessEntity",
    "FileEntity",
    "HttpEntity",
    "DnsEntity",
    "NormalizedEvent",
    "CorrelatedIncident",
    "CorrelationRuleConfig",
    "EngineStatus",
    # Normalizer
    "normalize_event",
    # Storage
    "CorrelationStorage",
    # Rules
    "BaseCorrelationRule",
    "get_default_rules",
    "get_default_rule_configs",
    # Engine
    "CorrelationEngine",
    "EntityStore",
    "get_correlation_engine",
    "init_correlation_engine",
    # Hybrid Coordination
    "EQLSequenceEngine",
    "EQLSequenceRule",
    "get_eql_engine",
    "SigmaCompiledRule",
    "SigmaRuleEngine",
    "get_sigma_engine",
    "HybridCorrelationCoordinator",
    "get_hybrid_coordinator",
    # Datasets
    "generate_benign_dataset",
    "generate_attack_dataset",
    "generate_all_datasets",
]
