"""
OpenSOC Forge - Tamper-Evident Append-Only Audit Trail.
Maintains cryptographic SHA-256 hash chaining over all administrative
actions, configuration modifications, upgrades, rollbacks, and authentications.
"""

import hashlib
import json
import os
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

    def __init__(self, log_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.log_path = log_path or os.path.join(base_dir, "configs", "audit_log.jsonl")
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
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        entry_id = len(self._entries) + 1
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

        return entry

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """Verify the cryptographic hash chain of the entire audit log."""
        expected_prev = "0" * 64
        for entry in self._entries:
            if entry.prev_hash != expected_prev:
                return False, entry.entry_id
            if entry.calculate_hash() != entry.entry_hash:
                return False, entry.entry_id
            expected_prev = entry.entry_hash
        return True, None

    def get_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [asdict(e) for e in reversed(self._entries[-limit:])]


audit_service = AuditTrail()
