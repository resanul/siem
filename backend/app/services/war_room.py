"""
OpenSOC Forge - Incident War Room & NIST SP 800-61r2 Response Service.
Provides collaborative crisis coordination, NIST incident lifecycle tracking, and digital evidence locker.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class ChecklistItem:
    id: str
    phase: str
    task: str
    completed: bool = False
    completed_by: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class EvidenceItem:
    id: str
    evidence_type: str  # FILE_HASH, NETWORK_IOC, MEMORY_DUMP, PCAP, LOG_EXTRACT
    value: str
    description: str
    source_host: str
    custody_officer: str
    recorded_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class WarRoomTimelineEntry:
    id: str
    author: str
    role: str
    message: str
    action_type: str  # NOTE, CONTAINMENT_ACTION, FORENSIC_UPDATE, ESCALATION
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class IncidentWarRoom:
    case_id: str
    title: str
    incident_commander: str
    threat_actor: str
    criticality: str
    checklist: List[ChecklistItem]
    evidence_locker: List[EvidenceItem]
    timeline: List[WarRoomTimelineEntry]
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class WarRoomService:
    """
    Manages crisis War Rooms for high-priority security incidents.
    """

    def __init__(self) -> None:
        self.rooms: Dict[str, IncidentWarRoom] = {}

    def get_or_create_room(self, case_id: str, title: str = "Active Security Incident", commander: str = "SecOps Lead") -> IncidentWarRoom:
        if case_id in self.rooms:
            return self.rooms[case_id]

        default_checklist = [
            # Preparation & Detection
            ChecklistItem("NIST-1", "Detection & Analysis", "Confirm alert fidelity and eliminate false positive indicators"),
            ChecklistItem("NIST-2", "Detection & Analysis", "Identify Patient Zero and determine blast radius across endpoints"),
            ChecklistItem("NIST-3", "Detection & Analysis", "Preserve non-volatile evidence (RAM dump, event logs, EVE JSON)"),
            # Containment
            ChecklistItem("NIST-4", "Containment", "Execute host network isolation via EDR/SOAR playbook"),
            ChecklistItem("NIST-5", "Containment", "Revoke compromised Active Directory / Cloud OAuth refresh tokens"),
            ChecklistItem("NIST-6", "Containment", "Shun attacker C2 IP addresses and domains at the perimeter firewall"),
            # Eradication & Recovery
            ChecklistItem("NIST-7", "Eradication", "Remove scheduled tasks, rogue services, and malicious persistence keys"),
            ChecklistItem("NIST-8", "Eradication", "Remediate root cause vulnerability (patch CVE / reset service passwords)"),
            ChecklistItem("NIST-9", "Recovery", "Restore verified clean system state from immutable snapshot"),
            ChecklistItem("NIST-10", "Lessons Learned", "Draft Root Cause Analysis (RCA) and deploy updated Sigma detection rules"),
        ]

        default_evidence = [
            EvidenceItem("EVD-001", "FILE_HASH", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Dropped payload SHA-256", "wkstn-finance-04", commander),
            EvidenceItem("EVD-002", "NETWORK_IOC", "198.51.100.84:1389", "Outbound malicious LDAP C2 destination", "web-app-dmz-01", commander),
        ]

        default_timeline = [
            WarRoomTimelineEntry("TL-001", commander, "Incident Commander", f"War room convened for incident {case_id}. Triage initiated.", "NOTE"),
            WarRoomTimelineEntry("TL-002", "soc_analyst", "Incident Responder", "Host network containment initiated via OpenSOC SOAR playbook.", "CONTAINMENT_ACTION"),
        ]

        room = IncidentWarRoom(
            case_id=case_id,
            title=title,
            incident_commander=commander,
            threat_actor="Suspected FIN7 / Lazarus Group affiliate",
            criticality="CRITICAL",
            checklist=default_checklist,
            evidence_locker=default_evidence,
            timeline=default_timeline,
        )
        self.rooms[case_id] = room
        return room

    def toggle_task(self, case_id: str, task_id: str, username: str) -> Dict[str, Any]:
        room = self.get_or_create_room(case_id)
        for item in room.checklist:
            if item.id == task_id:
                item.completed = not item.completed
                item.completed_by = username if item.completed else None
                item.completed_at = datetime.utcnow().isoformat() + "Z" if item.completed else None
                # Add timeline entry
                status_str = "completed" if item.completed else "reopened"
                room.timeline.append(
                    WarRoomTimelineEntry(
                        id=f"TL-{uuid.uuid4().hex[:6].upper()}",
                        author=username,
                        role="Investigator",
                        message=f"Checklist item '{item.task}' {status_str}.",
                        action_type="NOTE",
                    )
                )
                return {"task_id": item.id, "completed": item.completed, "phase": item.phase}
        raise KeyError(f"Task {task_id} not found in room {case_id}")

    def add_evidence(self, case_id: str, evidence_type: str, value: str, description: str, host: str, officer: str) -> Dict[str, Any]:
        room = self.get_or_create_room(case_id)
        ev_id = f"EVD-{uuid.uuid4().hex[:6].upper()}"
        ev = EvidenceItem(
            id=ev_id,
            evidence_type=evidence_type,
            value=value,
            description=description,
            source_host=host,
            custody_officer=officer,
        )
        room.evidence_locker.append(ev)
        room.timeline.append(
            WarRoomTimelineEntry(
                id=f"TL-{uuid.uuid4().hex[:6].upper()}",
                author=officer,
                role="Evidence Custodian",
                message=f"Secured forensic evidence {ev_id} ({evidence_type}): {value[:32]}...",
                action_type="FORENSIC_UPDATE",
            )
        )
        return {
            "id": ev.id,
            "evidence_type": ev.evidence_type,
            "value": ev.value,
            "description": ev.description,
            "source_host": ev.source_host,
            "custody_officer": ev.custody_officer,
            "recorded_at": ev.recorded_at,
        }

    def add_timeline_entry(self, case_id: str, author: str, role: str, message: str, action_type: str = "NOTE") -> Dict[str, Any]:
        room = self.get_or_create_room(case_id)
        entry = WarRoomTimelineEntry(
            id=f"TL-{uuid.uuid4().hex[:6].upper()}",
            author=author,
            role=role,
            message=message,
            action_type=action_type,
        )
        room.timeline.append(entry)
        return {
            "id": entry.id,
            "author": entry.author,
            "role": entry.role,
            "message": entry.message,
            "action_type": entry.action_type,
            "timestamp": entry.timestamp,
        }

    def get_room_data(self, case_id: str) -> Dict[str, Any]:
        room = self.get_or_create_room(case_id)
        completed_tasks = sum(1 for c in room.checklist if c.completed)
        total_tasks = len(room.checklist)
        nist_progress_pct = round((completed_tasks / total_tasks * 100), 1) if total_tasks else 0.0

        return {
            "case_id": room.case_id,
            "title": room.title,
            "incident_commander": room.incident_commander,
            "threat_actor": room.threat_actor,
            "criticality": room.criticality,
            "nist_progress_percent": nist_progress_pct,
            "checklist": [
                {
                    "id": c.id,
                    "phase": c.phase,
                    "task": c.task,
                    "completed": c.completed,
                    "completed_by": c.completed_by,
                    "completed_at": c.completed_at,
                }
                for c in room.checklist
            ],
            "evidence_locker": [
                {
                    "id": e.id,
                    "evidence_type": e.evidence_type,
                    "value": e.value,
                    "description": e.description,
                    "source_host": e.source_host,
                    "custody_officer": e.custody_officer,
                    "recorded_at": e.recorded_at,
                }
                for e in room.evidence_locker
            ],
            "timeline": [
                {
                    "id": t.id,
                    "author": t.author,
                    "role": t.role,
                    "message": t.message,
                    "action_type": t.action_type,
                    "timestamp": t.timestamp,
                }
                for t in room.timeline
            ],
            "created_at": room.created_at,
        }


war_room_service = WarRoomService()
