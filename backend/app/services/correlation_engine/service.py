"""
OpenSOC Forge SIEM Correlation Engine - Service Lifecycle & Alert Bridging.
Manages the background correlation daemon and bridges synthesized CorrelatedIncidents
into OpenSOC Forge's native LIVE_SIMULATION_ALERTS and persistent alert storage.
"""

from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from backend.app.models.schemas import AlertItem, AlertSeverity, AlertSource, AlertStatus
from backend.app.services.correlation_engine import get_correlation_engine
from backend.app.services.correlation_engine.schema import CorrelatedIncident
from backend.app.services.live_telemetry import LIVE_SIMULATION_ALERTS
from backend.app.services.retention_policy import load_persisted_alerts, save_persisted_alerts

logger = logging.getLogger("correlation_engine.service")

_WORKER_THREAD: Optional[threading.Thread] = None
_RUNNING = False
_LOCK = threading.Lock()


def bridge_incident_to_alerts(incident: CorrelatedIncident) -> AlertItem:
    """
    Bridges a CorrelatedIncident into native AlertItem, persisting to configs/persisted_alerts.json
    and in-memory LIVE_SIMULATION_ALERTS with source=AlertSource.CORRELATION.
    This guarantees zero-regression visibility in SIEM Overview, Alerts screen, and Event Search.
    """
    sev_str = incident.severity.value if hasattr(incident.severity, "value") else str(incident.severity)
    try:
        severity = AlertSeverity(sev_str)
    except Exception:
        severity = AlertSeverity.HIGH

    hosts = incident.entities.get("hosts", [])
    ips = incident.entities.get("ips", [])

    host = (
        hosts[0]
        if hosts
        else (
            incident.evidence_events[0].get("host", {}).get("host")
            if incident.evidence_events and isinstance(incident.evidence_events[0], dict)
            else "siem-correlated-engine"
        )
    ) or "siem-correlated-engine"

    src_ip = ips[0] if ips else None
    dest_ip = ips[1] if len(ips) > 1 else None

    ts = incident.timestamp
    if isinstance(ts, datetime):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        ts_str = str(ts)

    title = f"[{incident.rule_id}] {incident.rule_name}"
    description = incident.summary or incident.description or f"Correlated incident triggered by {incident.rule_id}"

    alert_id = incident.id if incident.id.startswith("ALT-") else f"ALT-{incident.id}"

    raw_payload = {
        "incident_id": incident.id,
        "rule_id": incident.rule_id,
        "rule_name": incident.rule_name,
        "risk_score": incident.risk_score,
        "stage_count": incident.stage_count,
        "contributing_sources": incident.contributing_sources,
        "entities": incident.entities,
        "root_cause_events_count": len(incident.root_cause_events),
        "mitre_tactic": incident.mitre_tactic,
        "mitre_attack_id": incident.mitre_attack_id or incident.mitre_technique,
    }

    alert_item = AlertItem(
        id=alert_id,
        timestamp=ts_str,
        severity=severity,
        source=AlertSource.CORRELATION,
        title=title,
        description=description,
        host=host,
        src_ip=src_ip,
        dest_ip=dest_ip,
        mitre_attack_id=incident.mitre_attack_id or incident.mitre_technique,
        mitre_tactic=incident.mitre_tactic,
        status=AlertStatus.NEW,
        raw_payload=raw_payload,
        is_demo=True,
    )

    with _LOCK:
        # 1. Surface in LIVE_SIMULATION_ALERTS
        try:
            # Check if alert already exists, replace or insert at top
            existing_idx = next((i for i, a in enumerate(LIVE_SIMULATION_ALERTS) if a.id == alert_item.id), None)
            if existing_idx is not None:
                LIVE_SIMULATION_ALERTS[existing_idx] = alert_item
            else:
                LIVE_SIMULATION_ALERTS.insert(0, alert_item)
        except Exception as exc:
            logger.error(f"Error inserting into LIVE_SIMULATION_ALERTS: {exc}")

        # 2. Surface in configs/persisted_alerts.json
        try:
            persisted = load_persisted_alerts()
            existing_persisted_idx = next((i for i, a in enumerate(persisted) if a.get("id") == alert_item.id), None)
            alert_dict = alert_item.model_dump()
            if existing_persisted_idx is not None:
                persisted[existing_persisted_idx] = alert_dict
            else:
                persisted.insert(0, alert_dict)
            save_persisted_alerts(persisted)
        except Exception as exc:
            logger.error(f"Error persisting bridged alert: {exc}")

    return alert_item


def _background_worker_loop() -> None:
    """Continuous background worker maintaining correlation engine state and ingesting live telemetry."""
    logger.info("Correlation Engine background daemon loop initialized.")
    processed_alert_ids = set()

    while _RUNNING:
        try:
            engine = get_correlation_engine()
            from backend.app.services.live_telemetry import get_live_alerts_pool
            pool = get_live_alerts_pool()
            for alert in pool:
                src_val = getattr(alert, "source", None)
                src_str = getattr(src_val, "value", str(src_val)) if src_val else ""
                aid = getattr(alert, "id", "")
                
                # Skip already correlated alerts
                if src_str == "correlation" or aid.startswith("ALT-inc-"):
                    continue

                if aid and aid not in processed_alert_ids:
                    processed_alert_ids.add(aid)
                    if len(processed_alert_ids) > 10000:
                        processed_alert_ids.clear()

                    raw_data = alert.model_dump() if hasattr(alert, "model_dump") else (alert.dict() if hasattr(alert, "dict") else dict(alert))
                    engine.process_raw(raw_data, source_hint=src_str)
        except Exception as exc:
            logger.debug(f"Correlation daemon telemetry polling error: {exc}")

        try:
            time.sleep(3.0)
        except Exception:
            break


def init_correlation_engine_on_startup() -> None:
    """
    FastAPI startup hook initializing the correlation engine singleton,
    registering the alert bridging hook, and launching the background daemon.
    """
    global _WORKER_THREAD, _RUNNING
    with _LOCK:
        engine = get_correlation_engine()
        engine.start()

        # Register alert bridge callback if not already registered
        if bridge_incident_to_alerts not in engine.incident_callbacks:
            engine.register_incident_callback(bridge_incident_to_alerts)

        if not _RUNNING:
            _RUNNING = True
            _WORKER_THREAD = threading.Thread(
                target=_background_worker_loop,
                daemon=True,
                name="CorrelationEngineDaemon",
            )
            _WORKER_THREAD.start()
            logger.info("Correlation Engine background daemon worker started.")


def shutdown_correlation_engine() -> None:
    """FastAPI shutdown hook cleanly stopping the correlation engine daemon."""
    global _RUNNING, _WORKER_THREAD
    with _LOCK:
        _RUNNING = False
        try:
            engine = get_correlation_engine()
            engine.stop()
        except Exception as exc:
            logger.warning(f"Error stopping correlation engine: {exc}")
        logger.info("Correlation Engine shutdown completed.")
