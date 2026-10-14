"""
OpenSOC Forge E2E Test Suite - Shared Helpers, Parsers, and Contract Validators.
Provides opaque-box test utilities for Requirements R1 through R5.
"""

import os
import re
import sys
import json
import tarfile
import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple

# Base repository paths
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INSTALL_SCRIPT_PATH = os.path.join(REPO_ROOT, "install.sh")
DOCKER_COMPOSE_PATH = os.path.join(REPO_ROOT, "docker-compose.yml")
PODMAN_COMPOSE_PATH = os.path.join(REPO_ROOT, "podman-compose.yml")
SYSTEMD_SERVICE_PATH = os.path.join(REPO_ROOT, "systemd", "opensoc-forge.service")
CLI_TOOL_PATH = os.path.join(REPO_ROOT, "bin", "opensoc-ctl")
ENV_EXAMPLE_PATH = os.path.join(REPO_ROOT, ".env.example")
FIREWALLD_XML_PATH = os.path.join(REPO_ROOT, "configs", "firewalld", "opensoc-forge.xml")
SYSCTL_CONF_PATH = os.path.join(REPO_ROOT, "configs", "sysctl", "99-opensoc-forge.conf")
CERT_SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "generate_certs.sh")
FRONTEND_INDEX_PATH = os.path.join(REPO_ROOT, "frontend", "index.html")

# Canonical requirement port allocations (R2 & R4)
REQUIRED_SERVICE_PORTS = {
    "opensoc-forge-mgmt": [8000],
    "elasticsearch": [9200, 9300],
    "kibana": [5601],
    "wazuh-manager": [1514, 1515, 55000],
    "suricata": [],  # host networking mode
    "syslog-collector": [514, 6514],
}

ALL_OPEN_PORTS = [8000, 5601, 9200, 1514, 1515, 55000, 514, 6514]

# Reference specifications for OS classification
OS_RELEASE_FIXTURES = {
    "kali": """NAME="Kali GNU/Linux"
VERSION="2024.3"
ID=kali
ID_LIKE=debian
VERSION_ID="2024.3"
PRETTY_NAME="Kali GNU/Linux 2024.3"
""",
    "debian12": """PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
""",
    "ubuntu24": """NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
""",
    "rhel9": """NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
""",
    "rocky9": """NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
""",
    "almalinux9": """NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
""",
    "fedora40": """NAME="Fedora Linux"
VERSION="40 (Workstation Edition)"
ID=fedora
VERSION_ID=40
PRETTY_NAME="Fedora Linux 40 (Workstation Edition)"
""",
    "unsupported_arch": """NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
""",
    "unsupported_alpine": """NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.0
PRETTY_NAME="Alpine Linux v3.20"
""",
}


def parse_os_release(content: str) -> Dict[str, str]:
    """Parses standard /etc/os-release key-value format."""
    data = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            data[key] = val
    return data


def classify_os_family(os_data: Dict[str, str]) -> str:
    """
    Classifies OS family according to Requirement R1:
    - debian: Kali, Debian, Ubuntu
    - rhel: RHEL 9, Rocky 9, AlmaLinux 9, Fedora
    - unsupported: Others
    """
    os_id = os_data.get("ID", "").lower()
    id_like = os_data.get("ID_LIKE", "").lower()

    if os_id in ("kali", "debian", "ubuntu") or "debian" in id_like:
        return "debian"
    elif os_id in ("rhel", "rocky", "almalinux", "fedora") or any(
        k in id_like for k in ("rhel", "fedora", "centos")
    ):
        return "rhel"
    return "unsupported"


def evaluate_hardware_preflights(
    mem_total_kb: int,
    cpu_cores: int,
    disk_avail_kb: int,
    has_active_net: bool,
) -> Tuple[bool, List[str]]:
    """
    Evaluates hardware preflight conditions against R1 thresholds:
    - RAM >= 8GB (VM threshold: 7600 MB = 7782400 KB)
    - CPU >= 4 cores
    - Disk >= 30 GB (31457280 KB)
    - Network interface active (operstate UP)
    """
    errors = []
    # 7600 MB VM threshold
    if mem_total_kb < 7782400:
        errors.append(
            f"Insufficient RAM: {mem_total_kb // 1024}MB detected. Minimum 8GB (7600MB VM threshold) required."
        )

    if cpu_cores < 4:
        errors.append(
            f"Insufficient CPU cores: {cpu_cores} detected. Minimum 4 cores required."
        )

    if disk_avail_kb < 31457280:
        errors.append(
            f"Insufficient disk space: {disk_avail_kb // (1024 * 1024)}GB available. Minimum 30GB required."
        )

    if not has_active_net:
        errors.append("No active non-loopback network interface with operstate UP found.")

    return len(errors) == 0, errors


def parse_systemd_unit(content: str) -> Dict[str, Dict[str, str]]:
    """Parses a systemd INI-style unit file into sections and directives."""
    unit: Dict[str, Dict[str, str]] = {}
    current_section = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            if current_section not in unit:
                unit[current_section] = {}
        elif current_section and "=" in line:
            key, val = line.split("=", 1)
            unit[current_section][key.strip()] = val.strip()

    return unit


def validate_systemd_unit_specification(unit: Dict[str, Dict[str, str]]) -> Tuple[bool, List[str]]:
    """Validates systemd unit directives according to Requirement R3."""
    errors = []
    if "Unit" not in unit:
        errors.append("Missing [Unit] section")
    if "Service" not in unit:
        errors.append("Missing [Service] section")
    if "Install" not in unit:
        errors.append("Missing [Install] section")

    service = unit.get("Service", {})
    install = unit.get("Install", {})

    if service.get("Type") != "simple":
        errors.append(f"Service Type must be 'simple', got '{service.get('Type')}'")

    if service.get("Restart") != "on-failure":
        errors.append(f"Restart must be 'on-failure', got '{service.get('Restart')}'")

    timeout_start = service.get("TimeoutStartSec", "0")
    try:
        t_val = int(re.sub(r"[^\d]", "", timeout_start) or "0")
        if t_val < 300:
            errors.append(f"TimeoutStartSec must be >= 300, got '{timeout_start}'")
    except ValueError:
        errors.append(f"Invalid TimeoutStartSec value: '{timeout_start}'")

    if install.get("WantedBy") != "multi-user.target":
        errors.append(f"WantedBy must be 'multi-user.target', got '{install.get('WantedBy')}'")

    exec_start = service.get("ExecStart", "")
    if "opensoc-ctl" not in exec_start:
        errors.append(f"ExecStart must invoke opensoc-ctl, got '{exec_start}'")

    return len(errors) == 0, errors


def parse_firewalld_service_xml(xml_content: str) -> Dict[str, Any]:
    """Parses firewalld XML service definition and extracts ports."""
    root = ET.fromstring(xml_content)
    short = root.findtext("short", default="")
    description = root.findtext("description", default="")
    ports = []
    for p in root.findall("port"):
        port_num = int(p.attrib.get("port", "0"))
        protocol = p.attrib.get("protocol", "tcp")
        ports.append((port_num, protocol))
    return {
        "short": short,
        "description": description,
        "ports": ports,
    }


def compute_sha256(filepath: str) -> str:
    """Calculates SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()
