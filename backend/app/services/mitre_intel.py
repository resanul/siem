"""
OpenSOC Forge - MITRE ATT&CK Coverage Matrix, Threat Intel & Forensic Process Trees.
Provides enterprise adversary mapping, IOC hunting, and parent-child process lineage.
"""

from typing import Any, Dict, List, Optional


def get_mitre_attack_matrix() -> Dict[str, Any]:
    """
    Returns the 12-tactic enterprise MITRE ATT&CK coverage matrix
    with active detection rules and simulated adversary sighting flags.
    """
    tactics = [
        {
            "id": "TA0001",
            "name": "Initial Access",
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing App", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1566", "name": "Phishing Attachment", "coverage": "ACTIVE", "rules": 2, "sighting": True},
                {"id": "T1078", "name": "Valid Accounts", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0002",
            "name": "Execution",
            "techniques": [
                {"id": "T1059.001", "name": "PowerShell Encoded CLI", "coverage": "ACTIVE", "rules": 4, "sighting": True},
                {"id": "T1059.004", "name": "Unix Shell Script", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1204", "name": "User Execution", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0003",
            "name": "Persistence",
            "techniques": [
                {"id": "T1505.003", "name": "Web Shell", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1053", "name": "Scheduled Task/Cron", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1547", "name": "Boot/Autostart Execution", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0004",
            "name": "Privilege Escalation",
            "techniques": [
                {"id": "T1548.003", "name": "Sudo Caching / SUID", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1068", "name": "Exploitation for Privilege", "coverage": "ACTIVE", "rules": 2, "sighting": False},
            ],
        },
        {
            "id": "TA0005",
            "name": "Defense Evasion",
            "techniques": [
                {"id": "T1490", "name": "Inhibit System Recovery", "coverage": "ACTIVE", "rules": 2, "sighting": True},
                {"id": "T1070", "name": "Indicator Removal on Host", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1027", "name": "Obfuscated Files or Info", "coverage": "ACTIVE", "rules": 3, "sighting": True},
            ],
        },
        {
            "id": "TA0006",
            "name": "Credential Access",
            "techniques": [
                {"id": "T1003", "name": "OS Credential Dumping", "coverage": "ACTIVE", "rules": 4, "sighting": False},
                {"id": "T1558.003", "name": "Kerberoasting", "coverage": "ACTIVE", "rules": 2, "sighting": True},
                {"id": "T1110", "name": "Brute Force Password Guessing", "coverage": "ACTIVE", "rules": 3, "sighting": True},
            ],
        },
        {
            "id": "TA0007",
            "name": "Discovery",
            "techniques": [
                {"id": "T1087", "name": "Account Discovery", "coverage": "ACTIVE", "rules": 2, "sighting": True},
                {"id": "T1046", "name": "Network Service Scanning", "coverage": "ACTIVE", "rules": 3, "sighting": False},
            ],
        },
        {
            "id": "TA0008",
            "name": "Lateral Movement",
            "techniques": [
                {"id": "T1021.002", "name": "SMB / Admin Shares", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1021.001", "name": "Remote Desktop Protocol", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1550", "name": "Pass the Hash / Ticket", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0009",
            "name": "Collection",
            "techniques": [
                {"id": "T1560", "name": "Archive Collected Data", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1005", "name": "Data from Local System", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0010",
            "name": "Command and Control",
            "techniques": [
                {"id": "T1071.001", "name": "Web Protocols (HTTP/S C2)", "coverage": "ACTIVE", "rules": 4, "sighting": True},
                {"id": "T1071.004", "name": "DNS Tunneling / Beacon", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1573", "name": "Encrypted Channel", "coverage": "ACTIVE", "rules": 2, "sighting": False},
            ],
        },
        {
            "id": "TA0011",
            "name": "Exfiltration",
            "techniques": [
                {"id": "T1048", "name": "Exfiltration Over Asymmetric Net", "coverage": "ACTIVE", "rules": 2, "sighting": False},
                {"id": "T1567", "name": "Exfiltration Over Web Service", "coverage": "PARTIAL", "rules": 1, "sighting": False},
            ],
        },
        {
            "id": "TA0012",
            "name": "Impact",
            "techniques": [
                {"id": "T1486", "name": "Data Encrypted for Impact", "coverage": "ACTIVE", "rules": 3, "sighting": True},
                {"id": "T1489", "name": "Service Stop", "coverage": "ACTIVE", "rules": 2, "sighting": False},
            ],
        },
    ]

    total_techniques = sum(len(t["techniques"]) for t in tactics)
    active_covered = sum(sum(1 for tech in t["techniques"] if tech["coverage"] == "ACTIVE") for t in tactics)
    coverage_pct = round((active_covered / total_techniques) * 100, 1)

    return {
        "framework_version": "MITRE ATT&CK Enterprise v14.1",
        "total_tactics": len(tactics),
        "total_techniques": total_techniques,
        "active_covered_techniques": active_covered,
        "coverage_percentage": coverage_pct,
        "tactics": tactics,
    }


def get_threat_intel_feed() -> List[Dict[str, Any]]:
    """Returns curated threat intelligence indicators (CISA KEV, AlienVault OTX, AbuseIPDB)."""
    return [
        {
            "indicator": "198.51.100.84",
            "type": "IPv4",
            "reputation": "MALICIOUS",
            "confidence": 98,
            "threat_actor": "Log4j Automated Scanner",
            "malware_family": "Mirai / JNDI Botnet",
            "source": "AbuseIPDB & CISA KEV",
            "last_seen": "2026-10-14 20:12Z",
            "hits_in_cluster": 42,
        },
        {
            "indicator": "203.0.113.42",
            "type": "IPv4",
            "reputation": "MALICIOUS",
            "confidence": 95,
            "threat_actor": "Cobalt Strike C2",
            "malware_family": "Cobalt Strike Malleable",
            "source": "AlienVault OTX",
            "last_seen": "2026-10-14 20:25Z",
            "hits_in_cluster": 18,
        },
        {
            "indicator": "9f1c7d24a8b834e098df23a54b98c3924a08152bcde4578129034ac1239851f9",
            "type": "SHA-256",
            "reputation": "MALICIOUS",
            "confidence": 100,
            "threat_actor": "FIN7",
            "malware_family": "LockBit 3.0 Encryptor",
            "source": "MISP / CISA KEV",
            "last_seen": "2026-10-14 18:30Z",
            "hits_in_cluster": 3,
        },
        {
            "indicator": "update.stage.c2service.cc",
            "type": "Domain",
            "reputation": "SUSPICIOUS",
            "confidence": 88,
            "threat_actor": "APT29 Cozy Bear",
            "malware_family": "DNS Tunneling Stager",
            "source": "ThreatFox",
            "last_seen": "2026-10-14 19:40Z",
            "hits_in_cluster": 7,
        },
    ]


def get_process_lineage(alert_id: str) -> Dict[str, Any]:
    """Returns interactive parent-child process tree for deep forensic triage."""
    return {
        "alert_id": alert_id,
        "host": "workstation-corp-88",
        "root_process": {
            "name": "winword.exe",
            "pid": 4812,
            "user": "CORP\\finance01",
            "cli": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"D:\\invoice.iso\\contract.docx\"",
            "children": [
                {
                    "name": "cmd.exe",
                    "pid": 5014,
                    "user": "CORP\\finance01",
                    "cli": "C:\\Windows\\system32\\cmd.exe /c powershell.exe -enc SQBYAE0A...",
                    "children": [
                        {
                            "name": "powershell.exe",
                            "pid": 5120,
                            "user": "CORP\\finance01",
                            "cli": "powershell.exe -NoP -NonI -W Hidden -enc SQBYAE0A...",
                            "children": [
                                {
                                    "name": "vssadmin.exe",
                                    "pid": 5240,
                                    "user": "NT AUTHORITY\\SYSTEM",
                                    "cli": "vssadmin.exe delete shadows /all /quiet",
                                    "children": [],
                                },
                                {
                                    "name": "whoami.exe",
                                    "pid": 5280,
                                    "user": "CORP\\finance01",
                                    "cli": "whoami /groups /priv",
                                    "children": [],
                                },
                            ],
                        }
                    ],
                }
            ],
        },
    }
