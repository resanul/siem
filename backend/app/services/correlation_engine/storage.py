"""
Thread-safe persistence layer for OpenSOC Forge Correlation Engine.
Safely stores and manages correlation rules in `configs/correlation_rules.json`
and generated incidents in `configs/correlated_incidents.json`.
"""

import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
)
from backend.app.services.correlation_engine.rules import get_default_rule_configs

logger = logging.getLogger("correlation_engine.storage")


class CorrelationStorage:
    """Thread-safe persistent storage manager for rules and incidents."""

    def __init__(
        self,
        rules_path: Optional[str] = None,
        incidents_path: Optional[str] = None,
    ):
        base_dir = Path(__file__).resolve().parent.parent.parent.parent
        self.rules_file = Path(rules_path) if rules_path else (base_dir / "configs" / "correlation_rules.json")
        self.incidents_file = Path(incidents_path) if incidents_path else (base_dir / "configs" / "correlated_incidents.json")

        self._lock = threading.Lock()
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        """Ensure parent directories and default rule files exist."""
        try:
            self.rules_file.parent.mkdir(parents=True, exist_ok=True)
            self.incidents_file.parent.mkdir(parents=True, exist_ok=True)

            if not self.rules_file.exists():
                defaults = get_default_rule_configs()
                self.save_rules(defaults)

            if not self.incidents_file.exists():
                self._atomic_write(self.incidents_file, [])
        except Exception as exc:
            logger.error(f"Error initializing correlation storage: {exc}")

    def _atomic_write(self, target_path: Path, data: Any) -> None:
        """Write JSON data atomically using a temp file to prevent partial write corruption."""
        temp_file = target_path.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            if os.name == "nt" and target_path.exists():
                # On Windows, replace can fail if target exists in some file system states; remove first
                try:
                    os.replace(temp_file, target_path)
                except OSError:
                    if target_path.exists():
                        target_path.unlink()
                    temp_file.rename(target_path)
            else:
                temp_file.replace(target_path)
        except Exception as exc:
            logger.error(f"Atomic write failed for {target_path}: {exc}")
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            raise

    def save_rules(self, rules: List[CorrelationRuleConfig]) -> None:
        """Persist list of correlation rule configs."""
        with self._lock:
            try:
                data = [r.model_dump(mode="json") for r in rules]
                self._atomic_write(self.rules_file, data)
            except Exception as exc:
                logger.error(f"Failed to save correlation rules: {exc}")

    def load_rules(self) -> List[CorrelationRuleConfig]:
        """Load correlation rule configs from disk, returning defaults on error or missing."""
        with self._lock:
            if not self.rules_file.exists():
                defaults = get_default_rule_configs()
                self.save_rules(defaults)
                return defaults

            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                if isinstance(raw_data, list):
                    return [CorrelationRuleConfig.model_validate(item) for item in raw_data]
            except Exception as exc:
                logger.warning(f"Failed to parse {self.rules_file}, loading defaults: {exc}")

            defaults = get_default_rule_configs()
            return defaults

    def save_incident(self, incident: CorrelatedIncident) -> None:
        """Persist a single incident, appending or updating existing by ID."""
        with self._lock:
            incidents = self._load_incidents_unlocked()
            # Replace existing or append
            idx = next((i for i, inc in enumerate(incidents) if inc.id == incident.id), None)
            if idx is not None:
                incidents[idx] = incident
            else:
                incidents.insert(0, incident)  # newest first

            # Cap persisted incidents at 1000
            incidents = incidents[:1000]
            self._save_incidents_unlocked(incidents)

    def save_incidents(self, new_incidents: List[CorrelatedIncident]) -> None:
        """Persist multiple incidents."""
        with self._lock:
            incidents = self._load_incidents_unlocked()
            existing_ids = {inc.id for inc in incidents}
            for inc in reversed(new_incidents):
                if inc.id not in existing_ids:
                    incidents.insert(0, inc)
                    existing_ids.add(inc.id)
            incidents = incidents[:1000]
            self._save_incidents_unlocked(incidents)

    def _load_incidents_unlocked(self) -> List[CorrelatedIncident]:
        if not self.incidents_file.exists():
            return []
        try:
            with open(self.incidents_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return [CorrelatedIncident.model_validate(item) for item in data]
        except Exception as exc:
            logger.warning(f"Failed to load incidents from {self.incidents_file}: {exc}")
        return []

    def _save_incidents_unlocked(self, incidents: List[CorrelatedIncident]) -> None:
        try:
            data = [inc.model_dump(mode="json") for inc in incidents]
            self._atomic_write(self.incidents_file, data)
        except Exception as exc:
            logger.error(f"Failed to write incidents to {self.incidents_file}: {exc}")

    def load_incidents(self) -> List[CorrelatedIncident]:
        """Load all persisted incidents."""
        with self._lock:
            return self._load_incidents_unlocked()

    def list_incidents(self, limit: int = 50, offset: int = 0) -> List[CorrelatedIncident]:
        """Retrieve paginated list of incidents."""
        with self._lock:
            all_incidents = self._load_incidents_unlocked()
            return all_incidents[offset : offset + limit]

    def get_incident(self, incident_id: str) -> Optional[CorrelatedIncident]:
        """Retrieve a specific incident by ID."""
        with self._lock:
            for inc in self._load_incidents_unlocked():
                if inc.id == incident_id:
                    return inc
            return None

    def clear_incidents(self) -> None:
        """Clear all stored incidents."""
        with self._lock:
            self._atomic_write(self.incidents_file, [])
