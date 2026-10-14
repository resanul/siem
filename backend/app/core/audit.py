"""
OpenSOC Forge - Tamper-Evident Append-Only Audit Trail.
Maintains cryptographic SHA-256 hash chaining over all administrative
actions, configuration modifications, upgrades, rollbacks, and authentications.
"""

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AuditEntry:
    entry_id: int
    timestamp: str
    actor: str
    role: str
    client_ip: str
    action: str
    resource_type: str
    resource_id: str
    status: str  # SUCCESS, FAILED, DENIED
    details: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def calculate_hash(self) -> str:
        payload = f"{self.entry_id}:{self.timestamp}:{self.actor}:{self.role}:{self.client_ip}:{self.action}:{self.resource_type}:{self.resource_id}:{self.status}:{json.dumps(self.details, sort_keys=True)}:{self.prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditTrail:
    """
    Manages audit logging with hash chain integrity verification.
    """
    _locks: Dict[str, threading.Lock] = {}
    _registry_lock = threading.Lock()

    def __init__(self, log_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.log_path = log_path or os.path.join(base_dir, "configs", "audit_log.jsonl")
        normalized_path = os.path.abspath(self.log_path)
        with AuditTrail._registry_lock:
            if normalized_path not in AuditTrail._locks:
                AuditTrail._locks[normalized_path] = threading.Lock()
            self._lock = AuditTrail._locks[normalized_path]
        self._entries: List[AuditEntry] = []
        self._load_entries()

    def _load_entries(self):
        self._entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            entry = AuditEntry(**data)
                            self._entries.append(entry)
            except Exception:
                pass

    def _read_last_entry_from_disk(self) -> Tuple[int, str]:
        """
        Reads the last valid entry from disk to obtain the last entry_id and entry_hash.
        Returns (last_entry_id, last_entry_hash). If file is absent or empty, returns (0, "0" * 64).
        """
        if not os.path.exists(self.log_path):
            return 0, "0" * 64
        try:
            if os.path.getsize(self.log_path) == 0:
                return 0, "0" * 64
            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    return 0, "0" * 64
                last_data = json.loads(lines[-1])
                return int(last_data.get("entry_id", 0)), str(last_data.get("entry_hash", "0" * 64))
        except Exception:
            return 0, "0" * 64

    def log(
        self,
        actor: str,
        role: str,
        client_ip: str,
        action: str,
        resource_type: str,
        resource_id: str,
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        with self._lock:
            last_id, prev_hash = self._read_last_entry_from_disk()
            entry_id = last_id + 1
            timestamp = datetime.utcnow().isoformat() + "Z"

            entry = AuditEntry(
                entry_id=entry_id,
                timestamp=timestamp,
                actor=actor,
                role=role,
                client_ip=client_ip,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details or {},
                prev_hash=prev_hash,
            )
            entry.entry_hash = entry.calculate_hash()
            self._entries.append(entry)

            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(entry)) + "\n")
                f.flush()

            return entry

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """Verify the cryptographic hash chain of the entire audit log."""
        with self._lock:
            self._load_entries()
            expected_prev = "0" * 64
            for entry in self._entries:
                if entry.prev_hash != expected_prev:
                    return False, entry.entry_id
                if entry.calculate_hash() != entry.entry_hash:
                    return False, entry.entry_id
                expected_prev = entry.entry_hash
            return True, None

    def get_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            self._load_entries()
            return [asdict(e) for e in reversed(self._entries[-limit:])]


audit_service = AuditTrail()
