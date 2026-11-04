"""
Enterprise Active Directory & Network Topology Memory Service
Maintains persistent enterprise-grade mapping of users, hostnames, branch subnets,
and Head Office departments for Trust Bank Limited (TBLBD.COM).

Guarantees:
1. Strict isolation of analyst workstation: '10.102.11.222' and 'ISRCD-0222'
   are exclusively reserved for 'resanul' (Information Security & Risk Division).
2. Deterministic, persistent IP and workstation resolution for all 4,418+ AD accounts.
3. Realistic branch networks (10.x.x.x) and Head Office divisions (172.31.x.x).
"""

import os
import json
import hashlib
from typing import Dict, Any, Optional

TOPOLOGY_DB_PATHS = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "enterprise_ad_topology.json"),
    "/opt/opensoc-forge/data/enterprise_ad_topology.json"
]

# Static master enterprise directory for known bank entities
KNOWN_TBLBD_ENTITIES: Dict[str, Dict[str, Any]] = {
    # Analyst Workstation (Strictly Isolated)
    "resanul": {
        "workstation": "ISRCD-0222",
        "ip": "10.102.11.222",
        "department": "Information Security & Risk Compliance (ISRCD)",
        "role": "Lead SOC Security Analyst / Admin",
        "domain": "TBLBD.COM",
        "email": "resanul@tblbd.com"
    },
    "isrcd-0222": {
        "workstation": "ISRCD-0222",
        "ip": "10.102.11.222",
        "department": "Information Security & Risk Compliance (ISRCD)",
        "role": "Security Analyst Workstation",
        "domain": "TBLBD.COM"
    },
    "isrcd-test.tblbd.com": {
        "workstation": "ISRCD-TEST",
        "ip": "10.102.11.45",
        "department": "ISRCD Lab & Security Testing",
        "role": "Security Testing Endpoint",
        "domain": "TBLBD.COM"
    },
    # IT Infrastructure & Server Admins
    "administrator": {
        "workstation": "TBL-DC-MGT01",
        "ip": "172.31.100.10",
        "department": "IT Systems Infrastructure",
        "role": "Domain Administrator",
        "domain": "TBLBD.COM",
        "email": "admin@tblbd.com"
    },
    "tbl-it-157": {
        "workstation": "TBL-IT-157",
        "ip": "10.102.11.127",
        "department": "IT Operations & Support",
        "role": "IT Field Admin Workstation",
        "domain": "TBLBD.COM"
    },
    "svc_backup": {
        "workstation": "TBL-BKUP-01",
        "ip": "172.31.150.25",
        "department": "Enterprise Backup Services",
        "role": "System Service Account",
        "domain": "TBLBD.COM"
    },
    "svc_wazuh": {
        "workstation": "DASHBOARD-11",
        "ip": "172.31.105.11",
        "department": "SOC SIEM Ingestion",
        "role": "SIEM Collector Service",
        "domain": "TBLBD.COM"
    },
    "oracle_dba": {
        "workstation": "TBL-CBS-DB01",
        "ip": "172.22.1.231",
        "department": "Core Banking Database Operations",
        "role": "Database Administrator",
        "domain": "TBLBD.COM"
    },
    # Head Office Divisions (Employees identified from CrowdStrike IDP)
    "shaila.parvin": {
        "workstation": "TBL-OPS-WS14",
        "ip": "172.31.72.48",
        "department": "Operations Division",
        "role": "Senior Operations Officer",
        "domain": "TBLBD.COM",
        "email": "shaila.parvin@tblbd.com"
    },
    "anwar.3115": {
        "workstation": "TBL-CBG-WS09",
        "ip": "172.31.85.112",
        "department": "Consumer Banking Group",
        "role": "Relationship Manager",
        "domain": "TBLBD.COM",
        "email": "anwar.3115@tblbd.com"
    },
    "abu.baker": {
        "workstation": "TBL-TF-WS03",
        "ip": "172.31.94.36",
        "department": "Trade Finance Division",
        "role": "Trade Services Officer",
        "domain": "TBLBD.COM",
        "email": "abu.baker@tblbd.com"
    },
    "hossain.belayet": {
        "workstation": "TBL-CORP-WS21",
        "ip": "172.31.110.15",
        "department": "Corporate Banking Division",
        "role": "Corporate Banking Executive",
        "domain": "TBLBD.COM",
        "email": "hossain.belayet@tblbd.com"
    },
    "baytul.islam": {
        "workstation": "TBL-TREAS-WS05",
        "ip": "172.31.120.40",
        "department": "Treasury & Investment Division",
        "role": "FX & Money Market Dealer",
        "domain": "TBLBD.COM",
        "email": "baytul.islam@tblbd.com"
    },
    "sazidul.islam": {
        "workstation": "TBL-OPS-MGR01",
        "ip": "172.31.72.10",
        "department": "Manager Operation & Delivery",
        "role": "Operations Manager",
        "domain": "TBLBD.COM",
        "email": "sazidul.islam@tblbd.com"
    },
    "mahmud.haque": {
        "workstation": "TBL-DS-WS04",
        "ip": "172.31.90.18",
        "department": "Digital Salary Department",
        "role": "Digital Payroll Specialist",
        "domain": "TBLBD.COM",
        "email": "mahmud.haque@tblbd.com"
    },
    "nasrina.nasim": {
        "workstation": "TBL-CC-WS12",
        "ip": "172.31.62.15",
        "department": "Call Center Division",
        "role": "Customer Support Officer",
        "domain": "TBLBD.COM",
        "email": "nasrina.nasim@tblbd.com"
    },
    "rafi.saqlain": {
        "workstation": "TBL-CAD-WS02",
        "ip": "172.31.115.22",
        "department": "Credit Administration Division (CAD)",
        "role": "Credit Analyst",
        "domain": "TBLBD.COM",
        "email": "rafi.saqlain@tblbd.com"
    },
    "khoalied.hasan": {
        "workstation": "TBL-TBSL-WS01",
        "ip": "172.31.130.55",
        "department": "Trust Bank Securities Ltd (TBSL)",
        "role": "Securities Trader",
        "domain": "TBLBD.COM",
        "email": "khoalied.hasan@tblbd.com"
    },
    "trustbank_zoom": {
        "workstation": "TBL-VCONF-01",
        "ip": "172.31.65.10",
        "department": "Video Conferencing Infrastructure",
        "role": "Conference Room System Account",
        "domain": "TBLBD.COM"
    },
    "ekyc.support": {
        "workstation": "TBL-EKYC-SRV01",
        "ip": "172.31.80.14",
        "department": "Digital Banking Support",
        "role": "e-KYC Processing Engine",
        "domain": "TBLBD.COM"
    },
    "tbl.support": {
        "workstation": "TBL-HELPDESK-01",
        "ip": "172.31.50.20",
        "department": "Central Helpdesk",
        "role": "ServiceDesk Admin",
        "domain": "TBLBD.COM"
    },
    # Branch Managers & Branch Workstations (CrowdStrike alert telemetry)
    "fen.m": {
        "workstation": "TBL-FENI-WS01",
        "ip": "10.35.22.45",
        "department": "Feni Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "fen.m@tblbd.com"
    },
    "utr.m": {
        "workstation": "TBL-UTRA-WS01",
        "ip": "10.20.14.88",
        "department": "Uttara Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "utr.m@tblbd.com"
    },
    "bgr.sm": {
        "workstation": "TBL-BGRA-WS01",
        "ip": "10.42.18.31",
        "department": "Bogra Branch",
        "role": "Senior Branch Manager",
        "domain": "TBLBD.COM",
        "email": "bgr.sm@tblbd.com"
    },
    "kus.m": {
        "workstation": "TBL-KUSH-WS01",
        "ip": "10.45.30.22",
        "department": "Kushtia Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "kus.m@tblbd.com"
    },
    "ben.m": {
        "workstation": "TBL-BENA-WS01",
        "ip": "10.60.12.50",
        "department": "Benapole Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "ben.m@tblbd.com"
    },
    "mdp.m": {
        "workstation": "TBL-MDPR-WS01",
        "ip": "10.55.16.14",
        "department": "Madaripur Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "mdp.m@tblbd.com"
    },
    "kng.m": {
        "workstation": "TBL-KRNG-WS01",
        "ip": "10.25.10.18",
        "department": "Keraniganj Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "kng.m@tblbd.com"
    },
    "gpr.m": {
        "workstation": "TBL-GPLP-WS01",
        "ip": "10.50.19.25",
        "department": "Gopalpur Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "gpr.m@tblbd.com"
    },
    "shc.m": {
        "workstation": "TBL-SHCP-WS01",
        "ip": "10.65.20.12",
        "department": "Sherpur Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "shc.m@tblbd.com"
    },
    "tit.m": {
        "workstation": "TBL-TITAS-WS01",
        "ip": "10.30.15.42",
        "department": "Titas Branch",
        "role": "Branch Manager",
        "domain": "TBLBD.COM",
        "email": "tit.m@tblbd.com"
    },
    # Real Endpoints Discovered from CrowdStrike IDP Tenant
    "munshigonj-55.tblbd.com": {
        "workstation": "TBL-MUNSHI-55",
        "ip": "10.15.55.10",
        "department": "Munshiganj Branch",
        "role": "Branch Terminal",
        "domain": "TBLBD.COM"
    },
    "tbl-alp-32.tblbd.com": {
        "workstation": "TBL-ALP-32",
        "ip": "10.70.32.14",
        "department": "Al Amin Pahartali Branch",
        "role": "Branch Cash Counter",
        "domain": "TBLBD.COM"
    },
    "tbl-alp-06.tblbd.com": {
        "workstation": "TBL-ALP-06",
        "ip": "10.70.06.12",
        "department": "Al Amin Pahartali Branch",
        "role": "Branch Customer Service",
        "domain": "TBLBD.COM"
    },
    "tbl-pb-217.tblbd.com": {
        "workstation": "TBL-PB-217",
        "ip": "10.10.21.70",
        "department": "Principal Branch (Dhaka)",
        "role": "Principal Clearing Terminal",
        "domain": "TBLBD.COM"
    },
    "rmt-62.tblbd.com": {
        "workstation": "TBL-RMT-62",
        "ip": "10.12.62.15",
        "department": "Ramna Branch",
        "role": "Branch Remittance Officer",
        "domain": "TBLBD.COM"
    },
    "icnc-10.tblbd.com": {
        "workstation": "TBL-ICNC-10",
        "ip": "10.80.10.24",
        "department": "Islamic Banking ICNC Unit",
        "role": "Islamic Banking Counter",
        "domain": "TBLBD.COM"
    },
    "desktop-76d0bs3.tblbd.com": {
        "workstation": "TBL-DESK-76D0",
        "ip": "172.31.75.108",
        "department": "Corporate Credit Division",
        "role": "Credit Evaluation Desktop",
        "domain": "TBLBD.COM"
    },
    "desktop-lt7rg59.tblbd.com": {
        "workstation": "TBL-DESK-LT7R",
        "ip": "172.31.82.91",
        "department": "Card Division & Remittance",
        "role": "Card Issuance Terminal",
        "domain": "TBLBD.COM"
    }
}

class EnterpriseTopologyManager:
    _instance = None
    _memory: Dict[str, Dict[str, Any]] = {}
    _dirty_count: int = 0

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EnterpriseTopologyManager, cls).__new__(cls)
            cls._instance._init_memory()
        return cls._instance

    def _init_memory(self):
        # 1. Seed with known entities
        self._memory = dict(KNOWN_TBLBD_ENTITIES)
        
        # 2. Load persistent file if exists
        for p in TOPOLOGY_DB_PATHS:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        disk_data = json.load(f)
                        if isinstance(disk_data, dict):
                            self._memory.update(disk_data)
                    break
                except Exception as e:
                    print(f"[TopologyManager] Error reading {p}: {e}")

        # Ensure analyst workstation is never corrupted by disk data
        self._memory["resanul"] = KNOWN_TBLBD_ENTITIES["resanul"]
        self._memory["isrcd-0222"] = KNOWN_TBLBD_ENTITIES["isrcd-0222"]
        self._save_to_disk()

    def _save_to_disk(self):
        target_dir = None
        for p in TOPOLOGY_DB_PATHS:
            d = os.path.dirname(p)
            if os.path.isdir(d):
                target_dir = d
                break
        if not target_dir:
            return
        
        save_path = os.path.join(target_dir, "enterprise_ad_topology.json")
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(self._memory, f, indent=2)
            self._dirty_count = 0
        except Exception as e:
            print(f"[TopologyManager] Could not persist to {save_path}: {e}")

    def save_changes(self):
        if self._dirty_count > 0:
            self._save_to_disk()

    def resolve_entity(self, identifier: Optional[str]) -> Dict[str, str]:
        """
        Given a user name, SAM account, email, or hostname, return:
        {
            "ip": "172.31.72.48",
            "workstation": "TBL-OPS-WS14",
            "department": "Operations Division",
            "domain": "TBLBD.COM"
        }
        Guarantees that 10.102.11.222 is ONLY given to resanul.
        """
        if not identifier:
            return {
                "ip": "172.31.100.80",
                "workstation": "TBL-CORP-GEN01",
                "department": "Head Office",
                "domain": "TBLBD.COM"
            }

        clean_id = str(identifier).strip().lower()
        if "@" in clean_id:
            clean_id = clean_id.split("@")[0]
        if "\\" in clean_id:
            clean_id = clean_id.split("\\")[-1]

        # 1. Exact match in memory
        if clean_id in self._memory:
            item = self._memory[clean_id]
            return {
                "ip": item.get("ip", "172.31.100.80"),
                "workstation": item.get("workstation", "TBL-CORP-GEN01"),
                "department": item.get("department", "Corporate"),
                "domain": item.get("domain", "TBLBD.COM")
            }

        # 2. Check for Exchange HealthMailbox
        if "healthmailbox" in clean_id:
            res = {
                "ip": "172.31.150.12",
                "workstation": "TBL-EXCH-01",
                "department": "Exchange Server Subsystem",
                "domain": "TBLBD.COM"
            }
            self._memory[clean_id] = res
            self._dirty_count += 1
            if self._dirty_count >= 10:
                self._save_to_disk()
            return res

        # 3. Deterministic Enterprise Fallback for Branch or Head Office Accounts
        h = int(hashlib.md5(clean_id.encode("utf-8")).hexdigest()[:8], 16)

        # Detect Branch Managers or Branch Accounts (e.g. *.m, *.sm)
        if clean_id.endswith(".m") or clean_id.endswith(".sm") or ".br" in clean_id:
            branch_sub = (h % 80) + 10  # 10.10.x.x to 10.90.x.x
            host_sub = (h % 240) + 10
            host_num = (h % 30) + 1
            b_code = clean_id.split(".")[0].upper()[:4]
            ip_val = f"10.{branch_sub}.{host_sub}.{host_num}"
            # Safety check: never produce analyst IP
            if ip_val == "10.102.11.222":
                ip_val = "10.102.11.223"
            res = {
                "ip": ip_val,
                "workstation": f"TBL-{b_code}-WS{host_num:02d}",
                "department": f"{b_code} Branch Banking Unit",
                "domain": "TBLBD.COM"
            }
        else:
            # Head Office Division Departments
            departments = [
                ("Operations Division", 72, "OPS"),
                ("Consumer Banking Group", 85, "CBG"),
                ("Trade Finance Division", 94, "TF"),
                ("Corporate Banking", 110, "CORP"),
                ("Treasury Division", 120, "TREAS"),
                ("Credit Administration", 115, "CAD"),
                ("Digital Banking Division", 80, "DIGI"),
                ("Card Operations", 68, "CARD"),
                ("Financial Administration", 92, "FAD"),
                ("Human Resources Division", 78, "HRD"),
                ("Audit & Compliance Internal", 88, "AUD")
            ]
            dept_info = departments[h % len(departments)]
            dept_name, sub_third, prefix = dept_info
            host_num = (h % 220) + 10
            ws_id = (h % 60) + 1
            ip_val = f"172.31.{sub_third}.{host_num}"
            res = {
                "ip": ip_val,
                "workstation": f"TBL-{prefix}-WS{ws_id:02d}",
                "department": dept_name,
                "domain": "TBLBD.COM"
            }

        # Save to persistent memory
        self._memory[clean_id] = res
        self._dirty_count += 1
        if self._dirty_count >= 10:
            self._save_to_disk()
        return res

# Global Singleton
topology_manager = EnterpriseTopologyManager()
