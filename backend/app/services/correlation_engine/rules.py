"""
Production-grade Detection Rule Library for OpenSOC Forge Correlation Engine.
Implements the 6 core multi-source correlation rules mapped to MITRE ATT&CK:
1. RULE-CORR-001: Multi-Source Brute Force & Credential Stuffing (T1110)
2. RULE-CORR-002: Port Scan to Exploit Chain (T1046 -> T1190)
3. RULE-CORR-003: Lateral Movement via Pass-the-Hash / Remote Execution (T1021)
4. RULE-CORR-004: Web Exploit to Data Exfiltration (T1190 -> T1048/T1071)
5. RULE-CORR-005: Privilege Escalation & Persistence (T1078/T1098 -> T1068)
6. RULE-CORR-006: Multi-Stage APT Campaign (multi-source killchain, 1800s window)
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from backend.app.services.correlation_engine.schema import (
    CorrelatedIncident,
    CorrelationRuleConfig,
    EventCategory,
    NormalizedEvent,
    NormalizedOutcome,
    NormalizedSeverity,
)


class BaseCorrelationRule(ABC):
    """Abstract base class for stateful correlation rules."""

    def __init__(self, config: CorrelationRuleConfig):
        self.config = config

    @property
    def rule_id(self) -> str:
        return self.config.rule_id

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @enabled.setter
    def enabled(self, val: bool) -> None:
        self.config.enabled = val

    @abstractmethod
    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        """Extract all candidate grouping keys from an event for this rule."""
        pass

    @abstractmethod
    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        """Evaluate the time-window buffer of events for a specific entity."""
        pass


class RuleCorr001MultiSourceBruteForce(BaseCorrelationRule):
    """
    RULE-CORR-001: Multi-Source Brute Force & Distributed Credential Stuffing
    Detects aggregate count of failed authentication events >= threshold (default 10)
    across Active Directory (Event 4625) and Wazuh (auth failures) within 300s.
    Elevates severity to CRITICAL (risk 95) if followed by a successful logon within 60s.
    """

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-001",
            name="Multi-Source Brute Force & Distributed Credential Stuffing",
            description="Aggregated authentication failures across AD and Linux hosts matching user or source IP.",
            enabled=True,
            sources=["active_directory", "wazuh"],
            window_seconds=300,
            threshold=10,
            mitre_attack_id="T1110",
            mitre_tactic="TA0006",
            mitre_technique="T1110.001",
            severity=NormalizedSeverity.HIGH,
            risk_score=75.0,
            entity_keys=["user.name", "source.ip"],
            cooldown_seconds=600,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        if event.user.name:
            return [f"user:{event.user.name.strip().lower()}"]
        if event.source.ip:
            return [f"src_ip:{event.source.ip.strip()}"]
        return []

    def _is_failed_auth(self, event: NormalizedEvent) -> bool:
        if event.source_type == "active_directory":
            return event.original_id == "4625" or event.event_action == "logon_failed"
        if event.source_type == "wazuh":
            return event.event_action == "logon_failed" or (
                event.event_category == EventCategory.AUTHENTICATION
                and event.event_outcome == NormalizedOutcome.FAILURE
            )
        return False

    def _is_success_auth(self, event: NormalizedEvent) -> bool:
        if event.source_type == "active_directory":
            return event.original_id == "4624" or event.event_action == "logon_success"
        if event.source_type == "wazuh":
            return event.event_action == "logon_success" or (
                event.event_category == EventCategory.AUTHENTICATION
                and event.event_outcome == NormalizedOutcome.SUCCESS
            )
        return False

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        # Filter events within window_seconds
        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]

        failed_events = [e for e in active_events if self._is_failed_auth(e)]
        if len(failed_events) < self.config.threshold:
            return None

        # Sort failed events by timestamp
        failed_events.sort(key=lambda x: x.timestamp)
        first_failure = failed_events[0]
        last_failure = failed_events[-1]

        # Check for subsequent successful logon within 60s of failures (escalation)
        escalated = False
        success_events = [
            e for e in active_events
            if self._is_success_auth(e) and e.timestamp >= first_failure.timestamp
        ]
        if success_events:
            escalated = True

        sev = NormalizedSeverity.CRITICAL if escalated else self.config.severity
        risk = 95.0 if escalated else self.config.risk_score

        # Entity extraction
        users: Set[str] = set()
        ips: Set[str] = set()
        hosts: Set[str] = set()
        sub_statuses: Set[str] = set()
        event_ids: List[str] = []

        for e in failed_events:
            event_ids.append(e.event_id)
            if e.user.name:
                users.add(e.user.name)
            if e.source.ip:
                ips.add(e.source.ip)
            if e.host.host:
                hosts.add(e.host.host)
            if e.signature:
                sub_statuses.add(e.signature)

        time_span = (last_failure.timestamp - first_failure.timestamp).total_seconds()
        target_entity = entity_key.split(":", 1)[1] if ":" in entity_key else entity_key

        summary = (
            f"Multi-Source Brute Force attack detected against {target_entity} "
            f"({len(failed_events)} failed attempts across {len(ips)} IPs in {time_span:.1f}s)"
        )
        if escalated:
            summary += " [ESCALATED: Followed by SUCCESSFUL Authentication]"

        incident_id = f"inc-bf-{uuid.uuid4().hex[:8]}"
        incident = CorrelatedIncident(
            id=incident_id,
            rule_id=self.rule_id,
            rule_name=self.config.name,
            severity=sev,
            risk_score=risk,
            timestamp=last_failure.timestamp,
            entities={
                "users": sorted(list(users)),
                "ips": sorted(list(ips)),
                "hosts": sorted(list(hosts)),
            },
            mitre_attack_id=self.config.mitre_attack_id,
            mitre_tactic=self.config.mitre_tactic,
            mitre_technique=self.config.mitre_technique,
            summary=summary,
            description=(
                f"Detected {len(failed_events)} authentication failures in {time_span:.1f}s "
                f"from sources across Active Directory and Wazuh endpoints. "
                f"Entity key: {entity_key}. Escalated: {escalated}."
            ),
            root_cause_events=[
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "source_type": e.source_type,
                    "user": e.user.name,
                    "src_ip": e.source.ip,
                    "action": e.event_action,
                }
                for e in failed_events[:25]
            ],
            contributing_sources=sorted(list({e.source_type for e in failed_events})),
            stage_count=2 if escalated else 1,
            evidence_events=[e.raw_payload for e in failed_events[:10]],
        )
        return incident


class RuleCorr002PortScanToExploit(BaseCorrelationRule):
    """
    RULE-CORR-002: Port Scan to Exploit Chain (T1046 -> T1190)
    Stage 1: Check Point firewall logs where action is drop/reject originating from
             source IP S to destination IP D targeting >= 15 distinct destination ports within 60s.
    Stage 2: Followed by Suricata alert within 240s where src_ip == S, dest_ip == D,
             and alert severity in [CRITICAL, HIGH].
    """

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-002",
            name="Sequential Port Sweep to Network Exploit Attempt",
            description="Firewall port sweep followed by NIDS exploit signature on target asset.",
            enabled=True,
            sources=["checkpoint", "suricata"],
            window_seconds=300,
            threshold=15,  # 15 distinct ports
            mitre_attack_id="T1046",
            mitre_tactic="TA0043",
            mitre_technique="T1190",
            severity=NormalizedSeverity.CRITICAL,
            risk_score=90.0,
            entity_keys=["source.ip", "destination.ip"],
            cooldown_seconds=900,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        if event.source.ip and event.destination.ip:
            return [f"pair:{event.source.ip.strip()}->{event.destination.ip.strip()}"]
        return []

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        # Filter active events within total window (300s)
        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]
        active_events.sort(key=lambda x: x.timestamp)

        # Separate Check Point drops and Suricata exploit alerts
        cp_drops = [
            e for e in active_events
            if e.source_type == "checkpoint" and e.event_action in ("firewall_drop", "drop")
        ]
        suricata_exploits = [
            e for e in active_events
            if e.source_type == "suricata" and (
                e.severity in (NormalizedSeverity.CRITICAL, NormalizedSeverity.HIGH)
                or e.event_category == EventCategory.THREAT
            )
        ]

        if not cp_drops or not suricata_exploits:
            return None

        # Verify Stage 1: Check Point port sweep (>= 15 distinct destination ports within 60s)
        # Sliding sub-window check for 60 seconds
        sweep_detected = False
        sweep_events: List[NormalizedEvent] = []
        distinct_ports: Set[int] = set()

        for i, start_evt in enumerate(cp_drops):
            t_start = start_evt.timestamp.timestamp()
            current_ports: Set[int] = set()
            sub_window: List[NormalizedEvent] = []
            for candidate in cp_drops[i:]:
                if candidate.timestamp.timestamp() - t_start <= 60.0:
                    if candidate.destination.port:
                        current_ports.add(candidate.destination.port)
                    sub_window.append(candidate)
                else:
                    break
            if len(current_ports) >= self.config.threshold:
                sweep_detected = True
                sweep_events = sub_window
                distinct_ports = current_ports
                break

        if not sweep_detected or not sweep_events:
            return None

        sweep_end_time = sweep_events[-1].timestamp.timestamp()

        # Verify Stage 2: Suricata exploit occurring after sweep begins, within 240s of sweep
        matching_exploits = [
            e for e in suricata_exploits
            if e.timestamp.timestamp() >= sweep_events[0].timestamp.timestamp()
            and e.timestamp.timestamp() - sweep_end_time <= 240.0
        ]
        if not matching_exploits:
            return None

        exploit_evt = matching_exploits[0]
        attacker_ip = exploit_evt.source.ip or sweep_events[0].source.ip
        victim_ip = exploit_evt.destination.ip or sweep_events[0].destination.ip

        summary = (
            f"Port Sweep to Exploit Chain: {attacker_ip} swept {len(distinct_ports)} ports "
            f"on {victim_ip} followed by NIDS exploit '{exploit_evt.signature}'"
        )

        incident_id = f"inc-scan-exploit-{uuid.uuid4().hex[:8]}"
        return CorrelatedIncident(
            id=incident_id,
            rule_id=self.rule_id,
            rule_name=self.config.name,
            severity=self.config.severity,
            risk_score=self.config.risk_score,
            timestamp=exploit_evt.timestamp,
            entities={
                "ips": [attacker_ip, victim_ip] if attacker_ip and victim_ip else [],
                "hosts": [exploit_evt.host.host] if exploit_evt.host.host else [],
                "ports": [str(p) for p in sorted(list(distinct_ports))[:20]],
            },
            mitre_attack_id="T1046,T1190",
            mitre_tactic="TA0043,TA0001",
            mitre_technique="T1046,T1190",
            summary=summary,
            description=(
                f"Adversary at {attacker_ip} performed firewall port sweep across {len(distinct_ports)} ports "
                f"and subsequently executed public-facing exploit against {victim_ip} within "
                f"{(exploit_evt.timestamp - sweep_events[-1].timestamp).total_seconds():.1f}s."
            ),
            root_cause_events=[
                {
                    "stage": "1_port_sweep",
                    "event_count": len(sweep_events),
                    "distinct_ports": len(distinct_ports),
                    "first_event": sweep_events[0].event_id,
                    "last_event": sweep_events[-1].event_id,
                },
                {
                    "stage": "2_exploit",
                    "event_id": exploit_evt.event_id,
                    "signature": exploit_evt.signature,
                    "signature_id": exploit_evt.signature_id,
                    "timestamp": exploit_evt.timestamp.isoformat(),
                },
            ],
            contributing_sources=["checkpoint", "suricata"],
            stage_count=2,
            evidence_events=[e.raw_payload for e in (sweep_events[:5] + [exploit_evt])],
        )


class RuleCorr003LateralMovement(BaseCorrelationRule):
    """
    RULE-CORR-003: Lateral Movement via Pass-the-Hash / Remote Execution (T1021)
    Stage 1: Active Directory Event 4624 with LogonType 3 (Network) or 9 (NewCredentials)
             on target host H for user U.
    Stage 2: Followed within 180s on the SAME target host H by Wazuh process execution event
             matching lateral tools (cmd.exe, powershell.exe, psexec.exe, wmic.exe, rundll32.exe).
    """

    LATERAL_PROCESSES = {
        "powershell.exe",
        "cmd.exe",
        "psexec.exe",
        "wmic.exe",
        "rundll32.exe",
        "sc.exe",
        "certutil.exe",
    }

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-003",
            name="Lateral Movement via Network Logon and Host Remote Execution",
            description="AD network logon followed by suspicious administrative process execution on target host.",
            enabled=True,
            sources=["active_directory", "wazuh"],
            window_seconds=180,
            threshold=2,
            mitre_attack_id="T1021.002",
            mitre_tactic="TA0008",
            mitre_technique="T1021.002",
            severity=NormalizedSeverity.CRITICAL,
            risk_score=88.0,
            entity_keys=["host.name", "user.name"],
            cooldown_seconds=600,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        keys = []
        host_val = event.host.host or event.destination.host or event.destination.ip
        if host_val:
            keys.append(f"host:{host_val.strip().lower()}")
        if event.user.name:
            keys.append(f"user:{event.user.name.strip().lower()}")
        return keys

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]
        active_events.sort(key=lambda x: x.timestamp)

        # Stage 1: AD 4624 LogonType 3 or 9
        ad_logons = [
            e for e in active_events
            if e.source_type == "active_directory"
            and e.original_id == "4624"
            and e.user.logon_type in ("3", "9")
        ]

        # Stage 2: Wazuh process execution matching lateral tools
        wazuh_procs = [
            e for e in active_events
            if e.source_type == "wazuh"
            and (
                e.event_category == EventCategory.PROCESS
                or (e.process and (
                    (e.process.name and e.process.name.lower() in self.LATERAL_PROCESSES)
                    or (e.process.command_line and any(p in e.process.command_line.lower() for p in self.LATERAL_PROCESSES))
                ))
                or any(p in (e.signature or "").lower() for p in ("powershell", "cmd.exe", "psexec", "wmic", "rundll32"))
            )
        ]

        if not ad_logons or not wazuh_procs:
            return None

        # Verify Stage 1 is followed within 180s by Stage 2
        for logon in ad_logons:
            t_logon = logon.timestamp.timestamp()
            matching_procs = [
                p for p in wazuh_procs
                if p.timestamp.timestamp() >= t_logon
                and p.timestamp.timestamp() - t_logon <= 180.0
            ]
            if matching_procs:
                proc = matching_procs[0]
                target_host = logon.host.host or proc.host.host or "target_host"
                user_name = logon.user.name or proc.user.name or "unknown_user"
                proc_name = (
                    (proc.process.name if proc.process else None)
                    or (proc.process.command_line if proc.process else None)
                    or proc.signature
                    or "powershell.exe"
                )

                summary = (
                    f"Lateral Movement detected on {target_host} by user '{user_name}': "
                    f"Network Logon (Type {logon.user.logon_type}) followed by process '{proc_name}'"
                )

                incident_id = f"inc-lat-{uuid.uuid4().hex[:8]}"
                return CorrelatedIncident(
                    id=incident_id,
                    rule_id=self.rule_id,
                    rule_name=self.config.name,
                    severity=self.config.severity,
                    risk_score=self.config.risk_score,
                    timestamp=proc.timestamp,
                    entities={
                        "hosts": [target_host],
                        "users": [user_name],
                        "ips": [logon.source.ip] if logon.source.ip else [],
                    },
                    mitre_attack_id="T1021.002",
                    mitre_tactic="TA0008,TA0002",
                    mitre_technique="T1021.002,T1059.001",
                    summary=summary,
                    description=(
                        f"Active Directory logged network authentication (LogonType {logon.user.logon_type}) "
                        f"for user {user_name} on {target_host}, immediately followed within "
                        f"{(proc.timestamp - logon.timestamp).total_seconds():.1f}s by administrative execution "
                        f"of {proc_name}."
                    ),
                    root_cause_events=[
                        {
                            "stage": "1_network_logon",
                            "event_id": logon.event_id,
                            "timestamp": logon.timestamp.isoformat(),
                            "source_ip": logon.source.ip,
                            "logon_type": logon.user.logon_type,
                        },
                        {
                            "stage": "2_remote_exec",
                            "event_id": proc.event_id,
                            "timestamp": proc.timestamp.isoformat(),
                            "process": proc_name,
                            "command_line": proc.process.command_line if proc.process else None,
                        },
                    ],
                    contributing_sources=["active_directory", "wazuh"],
                    stage_count=2,
                    evidence_events=[logon.raw_payload, proc.raw_payload],
                )

        return None


class RuleCorr004WebExploitToExfil(BaseCorrelationRule):
    """
    RULE-CORR-004: Web Exploit to Data Exfiltration (T1190 -> T1048/T1071)
    Stage 1: Suricata NIDS alert targeting internal web server W (destination.ip == W)
             matching web application attacks (web-application-attack, SQLi, Log4j, etc.).
    Stage 2: Followed within 600s from the SAME server W (Squid client_ip == W) by:
             Squid outbound HTTP CONNECT or POST with bytes >= 5,000,000 (5 MB) OR >= 20 POST requests within 60s.
    """

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-004",
            name="Web Application Exploitation to High-Volume Exfiltration",
            description="NIDS web application exploit alert followed by anomalous proxy outbound exfiltration.",
            enabled=True,
            sources=["suricata", "squid"],
            window_seconds=600,
            threshold=1,
            mitre_attack_id="T1190,T1048",
            mitre_tactic="TA0001,TA0010",
            mitre_technique="T1190,T1048",
            severity=NormalizedSeverity.CRITICAL,
            risk_score=92.0,
            entity_keys=["destination.ip"],
            cooldown_seconds=1200,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        keys = []
        if event.source_type == "suricata" and event.destination.ip:
            keys.append(f"server_ip:{event.destination.ip.strip()}")
        elif event.source_type == "squid" and event.source.ip:
            keys.append(f"server_ip:{event.source.ip.strip()}")
        return keys

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]
        active_events.sort(key=lambda x: x.timestamp)

        # Stage 1: Suricata web exploit alerts
        suricata_alerts = [
            e for e in active_events
            if e.source_type == "suricata" and (
                e.event_category == EventCategory.THREAT
                or "exploit" in (e.signature or "").lower()
                or "log4j" in (e.signature or "").lower()
                or "sqli" in (e.signature or "").lower()
                or "web" in (e.signature or "").lower()
            )
        ]

        # Stage 2: Squid high volume or high frequency POST/CONNECT
        squid_exfil = [
            e for e in active_events
            if e.source_type == "squid" and e.http and (
                (e.http.bytes_out and e.http.bytes_out >= 5000000)
                or e.http.method in ("POST", "CONNECT")
            )
        ]

        if not suricata_alerts or not squid_exfil:
            return None

        for alert in suricata_alerts:
            t_alert = alert.timestamp.timestamp()
            subsequent_squid = [
                s for s in squid_exfil
                if s.timestamp.timestamp() >= t_alert
                and s.timestamp.timestamp() - t_alert <= 600.0
            ]
            if not subsequent_squid:
                continue

            # Check Condition 1: High outbound bytes >= 5MB
            heavy_outbound = [s for s in subsequent_squid if s.http and s.http.bytes_out and s.http.bytes_out >= 5000000]
            # Check Condition 2: >= 20 POST requests within 60s
            post_requests = [s for s in subsequent_squid if s.http and s.http.method == "POST"]
            high_frequency_post = len(post_requests) >= 20

            if heavy_outbound or high_frequency_post:
                trigger_squid = heavy_outbound[0] if heavy_outbound else post_requests[-1]
                server_ip = alert.destination.ip or trigger_squid.source.ip or "web_server"
                bytes_exfil = trigger_squid.http.bytes_out if (trigger_squid.http and trigger_squid.http.bytes_out) else 0

                summary = (
                    f"Web Exploit to Exfiltration: {server_ip} compromised via '{alert.signature}' "
                    f"followed by {bytes_exfil / (1024*1024):.1f} MB egress via Squid proxy"
                )

                incident_id = f"inc-web-exfil-{uuid.uuid4().hex[:8]}"
                return CorrelatedIncident(
                    id=incident_id,
                    rule_id=self.rule_id,
                    rule_name=self.config.name,
                    severity=self.config.severity,
                    risk_score=self.config.risk_score,
                    timestamp=trigger_squid.timestamp,
                    entities={
                        "ips": [server_ip] + ([trigger_squid.destination.ip] if trigger_squid.destination.ip else []),
                        "hosts": [alert.host.host] if alert.host.host else [],
                        "urls": [trigger_squid.http.url] if (trigger_squid.http and trigger_squid.http.url) else [],
                    },
                    mitre_attack_id="T1190,T1048",
                    mitre_tactic="TA0001,TA0010",
                    mitre_technique="T1190,T1048",
                    summary=summary,
                    description=(
                        f"NIDS alert '{alert.signature}' detected targeting {server_ip}. "
                        f"Within {(trigger_squid.timestamp - alert.timestamp).total_seconds():.1f}s, "
                        f"the server initiated outbound proxy egress transferring {bytes_exfil} bytes "
                        f"to external destination."
                    ),
                    root_cause_events=[
                        {
                            "stage": "1_web_exploit",
                            "event_id": alert.event_id,
                            "timestamp": alert.timestamp.isoformat(),
                            "signature": alert.signature,
                            "attacker_ip": alert.source.ip,
                        },
                        {
                            "stage": "2_exfiltration",
                            "event_id": trigger_squid.event_id,
                            "timestamp": trigger_squid.timestamp.isoformat(),
                            "method": trigger_squid.http.method if trigger_squid.http else "POST",
                            "bytes": bytes_exfil,
                            "url": trigger_squid.http.url if trigger_squid.http else None,
                        },
                    ],
                    contributing_sources=["suricata", "squid"],
                    stage_count=2,
                    evidence_events=[alert.raw_payload, trigger_squid.raw_payload],
                )

        return None


class RuleCorr005PrivilegeEscalation(BaseCorrelationRule):
    """
    RULE-CORR-005: Privilege Escalation & Persistence (T1078/T1098 -> T1068)
    Stage 1: Active Directory Event 4728 (Member Added to "Domain Admins", "Administrators")
             or Event 4720 (User Created) for user U.
    Stage 2: Followed within 300s by Wazuh rootcheck/privilege alert (rule.id in 510, 516, 517, 7001)
             OR sensitive FIM mutation (/etc/sudoers, /etc/shadow, SAM) involving user U.
    """

    SENSITIVE_FILES = {"/etc/sudoers", "/etc/shadow", "sam", "c:\\windows\\system32\\config\\sam"}

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-005",
            name="Privileged Group Modification with Host Escalation Anomaly",
            description="AD privileged group assignment followed by endpoint rootcheck or sensitive FIM mutation.",
            enabled=True,
            sources=["active_directory", "wazuh"],
            window_seconds=300,
            threshold=1,
            mitre_attack_id="T1098,T1068",
            mitre_tactic="TA0004,TA0003",
            mitre_technique="T1098,T1068",
            severity=NormalizedSeverity.HIGH,
            risk_score=85.0,
            entity_keys=["user.name"],
            cooldown_seconds=600,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        keys = []
        if event.user.name:
            keys.append(f"user:{event.user.name.strip().lower()}")
        return keys

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]
        active_events.sort(key=lambda x: x.timestamp)

        # Stage 1: AD 4728 (privileged group) or 4720
        ad_priv = [
            e for e in active_events
            if e.source_type == "active_directory"
            and (
                e.original_id == "4728"
                or e.original_id == "4720"
                or e.event_action in ("group_member_added", "user_created")
            )
        ]

        # Stage 2: Wazuh rootcheck or sensitive FIM
        wazuh_alerts = [
            e for e in active_events
            if e.source_type == "wazuh"
            and (
                e.event_action == "rootcheck_detected"
                or e.original_id in ("510", "516", "517", "7001")
                or (
                    e.event_category == EventCategory.FILE
                    and e.file
                    and any(sf in (e.file.path or "").lower() for sf in self.SENSITIVE_FILES)
                )
                or any(sf in (e.signature or "").lower() for sf in ("sudoers", "shadow", "sam", "rootcheck"))
            )
        ]

        if not ad_priv or not wazuh_alerts:
            return None

        for priv in ad_priv:
            t_priv = priv.timestamp.timestamp()
            matching_wazuh = [
                w for w in wazuh_alerts
                if w.timestamp.timestamp() >= t_priv
                and w.timestamp.timestamp() - t_priv <= 300.0
            ]
            if matching_wazuh:
                wazuh_evt = matching_wazuh[0]
                user_name = priv.user.name or wazuh_evt.user.name or "escalated_user"
                host_name = wazuh_evt.host.host or priv.host.host or "domain_host"
                file_path = wazuh_evt.file.path if wazuh_evt.file else None

                summary = (
                    f"Privilege Escalation & Persistence: user '{user_name}' added to privileged group "
                    f"followed by host anomaly on {host_name}"
                )
                if file_path:
                    summary += f" ({file_path} modified)"

                incident_id = f"inc-priv-esc-{uuid.uuid4().hex[:8]}"
                return CorrelatedIncident(
                    id=incident_id,
                    rule_id=self.rule_id,
                    rule_name=self.config.name,
                    severity=self.config.severity,
                    risk_score=self.config.risk_score,
                    timestamp=wazuh_evt.timestamp,
                    entities={
                        "users": [user_name],
                        "hosts": [host_name],
                    },
                    mitre_attack_id="T1098,T1068",
                    mitre_tactic="TA0004,TA0003",
                    mitre_technique="T1098,T1068",
                    summary=summary,
                    description=(
                        f"Active Directory Event {priv.original_id} granted elevated privileges to {user_name}. "
                        f"Within {(wazuh_evt.timestamp - priv.timestamp).total_seconds():.1f}s, "
                        f"Wazuh detected endpoint privilege escalation / FIM mutation '{wazuh_evt.signature}' "
                        f"on {host_name}."
                    ),
                    root_cause_events=[
                        {
                            "stage": "1_directory_privilege_grant",
                            "event_id": priv.event_id,
                            "timestamp": priv.timestamp.isoformat(),
                            "user": user_name,
                            "action": priv.event_action,
                        },
                        {
                            "stage": "2_host_escalation_fim",
                            "event_id": wazuh_evt.event_id,
                            "timestamp": wazuh_evt.timestamp.isoformat(),
                            "action": wazuh_evt.event_action,
                            "file": file_path,
                            "signature": wazuh_evt.signature,
                        },
                    ],
                    contributing_sources=["active_directory", "wazuh"],
                    stage_count=2,
                    evidence_events=[priv.raw_payload, wazuh_evt.raw_payload],
                )

        return None


class RuleCorr006MultiStageAPT(BaseCorrelationRule):
    """
    RULE-CORR-006: Multi-Stage APT Campaign (multi-source, 1800s window)
    Correlates at least 4 distinct attack stages across at least 4 sources:
    - Stage 1: Recon (Check Point port drop or Suricata scan)
    - Stage 2: Exploit (Suricata exploit alert severity 1 or 2)
    - Stage 3: C2 Beaconing (Squid proxy CONNECT/GET)
    - Stage 4: Lateral Movement (AD 4624 LogonType 3/9 or 4769 ticket request)
    - Stage 5: Exfiltration (NetWitness high volume egress > 10MB or session anomaly)
    """

    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        cfg = config or CorrelationRuleConfig(
            rule_id="RULE-CORR-006",
            name="Multi-Stage APT Killchain (Recon -> Exploit -> C2 -> Lateral -> Exfil)",
            description="Comprehensive multi-stage APT campaign correlated across firewall, NIDS, proxy, AD, and NetWitness.",
            enabled=True,
            sources=["checkpoint", "suricata", "squid", "active_directory", "netwitness"],
            window_seconds=1800,
            threshold=4,  # minimum 4 stages
            mitre_attack_id="T1046,T1190,T1071,T1021,T1041",
            mitre_tactic="TA0043,TA0001,TA0011,TA0008,TA0010",
            mitre_technique="T1046,T1190,T1071,T1021,T1041",
            severity=NormalizedSeverity.CRITICAL,
            risk_score=98.0,
            entity_keys=["destination.ip", "source.ip", "user.name"],
            cooldown_seconds=3600,
        )
        super().__init__(cfg)

    def get_entity_keys(self, event: NormalizedEvent) -> List[str]:
        keys = []
        if event.destination.ip:
            keys.append(f"ip:{event.destination.ip.strip()}")
        if event.source.ip:
            keys.append(f"ip:{event.source.ip.strip()}")
        if event.user.name:
            keys.append(f"user:{event.user.name.strip().lower()}")
        return keys

    def evaluate_window(
        self,
        events: List[NormalizedEvent],
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelatedIncident]:
        if not self.enabled or not events:
            return None

        window_start = current_time.timestamp() - self.config.window_seconds
        active_events = [e for e in events if e.timestamp.timestamp() >= window_start]
        active_events.sort(key=lambda x: x.timestamp)

        detected_stages: Dict[str, NormalizedEvent] = {}

        for e in active_events:
            # Stage 1: Recon (Check Point drop or Suricata flow anomaly)
            if "stage_1_recon" not in detected_stages:
                if (e.source_type == "checkpoint" and e.event_action == "firewall_drop") or (
                    e.source_type == "suricata" and e.event_category == EventCategory.NETWORK
                ):
                    detected_stages["stage_1_recon"] = e

            # Stage 2: Exploit (Suricata exploit alert)
            if "stage_2_exploit" not in detected_stages:
                if e.source_type == "suricata" and (
                    e.severity in (NormalizedSeverity.CRITICAL, NormalizedSeverity.HIGH)
                    or "exploit" in (e.signature or "").lower()
                ):
                    detected_stages["stage_2_exploit"] = e

            # Stage 3: C2 (Squid proxy CONNECT or periodic request)
            if "stage_3_c2" not in detected_stages:
                if e.source_type == "squid" and e.http:
                    detected_stages["stage_3_c2"] = e

            # Stage 4: Lateral (AD 4624 LogonType 3 or 4769)
            if "stage_4_lateral" not in detected_stages:
                if e.source_type == "active_directory" and (
                    (e.original_id == "4624" and e.user.logon_type in ("3", "9"))
                    or e.original_id in ("4768", "4769")
                ):
                    detected_stages["stage_4_lateral"] = e

            # Stage 5: Exfiltration (NetWitness heavy egress or anomaly)
            if "stage_5_exfil" not in detected_stages:
                if e.source_type == "netwitness" and (
                    e.severity in (NormalizedSeverity.CRITICAL, NormalizedSeverity.HIGH)
                    or (e.http and e.http.bytes_out and e.http.bytes_out >= 10000000)
                    or "exfiltration" in (e.signature or "").lower()
                    or "anomalous" in e.event_action.lower()
                ):
                    detected_stages["stage_5_exfil"] = e

        # Requires at least 4 distinct stages
        if len(detected_stages) < 4:
            return None

        stage_names = sorted(list(detected_stages.keys()))
        sources_involved = sorted(list({e.source_type for e in detected_stages.values()}))
        latest_evt = max(detected_stages.values(), key=lambda x: x.timestamp)
        first_evt = min(detected_stages.values(), key=lambda x: x.timestamp)
        duration_sec = (latest_evt.timestamp - first_evt.timestamp).total_seconds()

        # Entity extraction
        ips: Set[str] = set()
        users: Set[str] = set()
        hosts: Set[str] = set()
        for e in detected_stages.values():
            if e.source.ip:
                ips.add(e.source.ip)
            if e.destination.ip:
                ips.add(e.destination.ip)
            if e.user.name:
                users.add(e.user.name)
            if e.host.host:
                hosts.add(e.host.host)

        summary = (
            f"Multi-Stage APT Campaign verified across {len(sources_involved)} telemetry sources "
            f"({len(detected_stages)} killchain stages detected over {duration_sec:.1f}s)"
        )

        incident_id = f"inc-apt-{uuid.uuid4().hex[:8]}"
        return CorrelatedIncident(
            id=incident_id,
            rule_id=self.rule_id,
            rule_name=self.config.name,
            severity=self.config.severity,
            risk_score=self.config.risk_score,
            timestamp=latest_evt.timestamp,
            entities={
                "ips": sorted(list(ips)),
                "users": sorted(list(users)),
                "hosts": sorted(list(hosts)),
            },
            mitre_attack_id=self.config.mitre_attack_id,
            mitre_tactic=self.config.mitre_tactic,
            mitre_technique=self.config.mitre_technique,
            summary=summary,
            description=(
                f"Full adversary attack lifecycle detected across {sources_involved}. "
                f"Stages: {stage_names}. Spans {duration_sec:.1f} seconds. "
                f"Entity context: {entity_key}."
            ),
            root_cause_events=[
                {
                    "stage": s_name,
                    "source": evt.source_type,
                    "event_id": evt.event_id,
                    "action": evt.event_action,
                    "signature": evt.signature,
                    "timestamp": evt.timestamp.isoformat(),
                }
                for s_name, evt in detected_stages.items()
            ],
            contributing_sources=sources_involved,
            stage_count=len(detected_stages),
            evidence_events=[e.raw_payload for e in detected_stages.values()],
        )


def get_default_rules() -> Dict[str, BaseCorrelationRule]:
    """Factory function producing instances of all 6 production correlation rules."""
    rules: List[BaseCorrelationRule] = [
        RuleCorr001MultiSourceBruteForce(),
        RuleCorr002PortScanToExploit(),
        RuleCorr003LateralMovement(),
        RuleCorr004WebExploitToExfil(),
        RuleCorr005PrivilegeEscalation(),
        RuleCorr006MultiStageAPT(),
    ]
    return {r.rule_id: r for r in rules}


def get_default_rule_configs() -> List[CorrelationRuleConfig]:
    """Return default configuration objects for all 6 correlation rules."""
    return [r.config for r in get_default_rules().values()]
