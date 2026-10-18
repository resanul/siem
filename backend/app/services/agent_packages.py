"""
OpenSOC Forge - Agent Package Repository & Offline Distribution Service.
Provides on-demand caching and internal distribution of Wazuh agent installers
for air-gapped and restricted enterprise environments.
"""

import os
import time
import hashlib
from typing import Dict, Any, List
from backend.app.services.proxy_manager import safe_urlopen

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads", "agents")

AGENT_CATALOG: Dict[str, Dict[str, Any]] = {
    "linux-deb": {
        "id": "linux-deb",
        "os_name": "Ubuntu / Debian / Kali",
        "platform": "linux",
        "format": "deb",
        "arch": "amd64 (x86_64)",
        "version": "4.9.2-1",
        "filename": "wazuh-agent.deb",
        "canonical_name": "wazuh-agent_4.9.2-1_amd64.deb",
        "remote_url": "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb",
        "approx_size_mb": 10.7,
        "manager_port": 1514
    },
    "linux-rpm": {
        "id": "linux-rpm",
        "os_name": "RHEL 8/9 / Rocky / CentOS / Alma",
        "platform": "linux",
        "format": "rpm",
        "arch": "x86_64",
        "version": "4.9.2-1",
        "filename": "wazuh-agent.rpm",
        "canonical_name": "wazuh-agent-4.9.2-1.x86_64.rpm",
        "remote_url": "https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm",
        "approx_size_mb": 10.9,
        "manager_port": 1514
    },
    "windows": {
        "id": "windows",
        "os_name": "Windows 10 / 11 / Server",
        "platform": "windows",
        "format": "msi",
        "arch": "x64",
        "version": "4.9.2-1",
        "filename": "wazuh-agent.msi",
        "canonical_name": "wazuh-agent-4.9.2-1.msi",
        "remote_url": "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi",
        "approx_size_mb": 7.2,
        "manager_port": 1514
    },
    "macos": {
        "id": "macos",
        "os_name": "macOS (Apple Silicon & Intel)",
        "platform": "darwin",
        "format": "pkg",
        "arch": "universal",
        "version": "4.9.2-1",
        "filename": "wazuh-agent.pkg",
        "canonical_name": "wazuh-agent-4.9.2-1.pkg",
        "remote_url": "https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.2-1.pkg",
        "approx_size_mb": 34.1,
        "manager_port": 1514
    }
}


def ensure_downloads_dir() -> str:
    """Ensures local agent downloads directory exists."""
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    return DOWNLOADS_DIR


def get_package_file_info(pkg_id: str) -> Dict[str, Any]:
    """Returns local cache status, size, and paths for a specific package."""
    meta = AGENT_CATALOG.get(pkg_id)
    if not meta:
        return {"cached": False, "size_bytes": 0, "size_mb": 0}

    ensure_downloads_dir()
    filepath = os.path.join(DOWNLOADS_DIR, meta["filename"])
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        return {
            "cached": True,
            "filepath": filepath,
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "last_modified": time.ctime(os.path.getmtime(filepath))
        }
    return {"cached": False, "size_bytes": 0, "size_mb": 0}


def get_all_packages_catalog(server_host: str = "", server_port: int = 7070) -> List[Dict[str, Any]]:
    """Returns the full catalog of supported agents with cache status and download URLs."""
    host = server_host or "127.0.0.1"
    catalog = []

    for pkg_id, meta in AGENT_CATALOG.items():
        info = get_package_file_info(pkg_id)
        local_url = f"/downloads/agents/{meta['filename']}"
        full_local_url = f"http://{host}:{server_port}{local_url}"

        # Generate command templates
        if pkg_id == "linux-deb":
            offline_cmd = (
                f"curl -sSL {full_local_url} -o /tmp/wazuh-agent.deb && "
                f"sudo WAZUH_MANAGER='{host}' dpkg -i /tmp/wazuh-agent.deb && "
                f"sudo /var/ossec/bin/agent-auth -m {host} && "
                f"sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent"
            )
            online_cmd = (
                f"wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && "
                f"echo \"deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\" | sudo tee /etc/apt/sources.list.d/wazuh.list && "
                f"sudo apt-get update && sudo WAZUH_MANAGER='{host}' apt-get install -y wazuh-agent && "
                f"sudo /var/ossec/bin/agent-auth -m {host} && "
                f"sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent"
            )
        elif pkg_id == "linux-rpm":
            offline_cmd = (
                f"curl -sSL {full_local_url} -o /tmp/wazuh-agent.rpm && "
                f"sudo WAZUH_MANAGER='{host}' rpm -ivh /tmp/wazuh-agent.rpm && "
                f"sudo /var/ossec/bin/agent-auth -m {host} && "
                f"sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent"
            )
            online_cmd = (
                f"sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && "
                f"sudo tee /etc/yum.repos.d/wazuh.repo > /dev/null << 'EOF'\n[wazuh]\nname=Wazuh repository\nbaseurl=https://packages.wazuh.com/4.x/yum/\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nEOF\n"
                f"sudo WAZUH_MANAGER='{host}' dnf install -y wazuh-agent && "
                f"sudo /var/ossec/bin/agent-auth -m {host} && "
                f"sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent"
            )
        elif pkg_id == "windows":
            offline_cmd = (
                f"Invoke-WebRequest -Uri \"{full_local_url}\" -OutFile \"$env:TEMP\\wazuh-agent.msi\"; "
                f"Start-Process msiexec.exe -Wait -ArgumentList '/i', \"$env:TEMP\\wazuh-agent.msi\", '/q', "
                f"\"WAZUH_MANAGER='{host}'\", \"WAZUH_REGISTRATION_SERVER='{host}'\"; Start-Service WazuhSvc"
            )
            online_cmd = (
                f"Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/{meta['canonical_name']} -OutFile \"$env:TEMP\\wazuh-agent.msi\"; "
                f"Start-Process msiexec.exe -Wait -ArgumentList '/i', \"$env:TEMP\\wazuh-agent.msi\", '/q', "
                f"\"WAZUH_MANAGER='{host}'\", \"WAZUH_REGISTRATION_SERVER='{host}'\"; Start-Service WazuhSvc"
            )
        else:
            offline_cmd = (
                f"curl -so /tmp/wazuh-agent.pkg {full_local_url} && "
                f"echo \"WAZUH_MANAGER='{host}'\" > /tmp/wazuh_envs && "
                f"sudo installer -pkg /tmp/wazuh-agent.pkg -target / && "
                f"sudo /Library/Ossec/bin/wazuh-control start"
            )
            online_cmd = (
                f"curl -so /tmp/wazuh-agent.pkg {meta['remote_url']} && "
                f"echo \"WAZUH_MANAGER='{host}'\" > /tmp/wazuh_envs && "
                f"sudo installer -pkg /tmp/wazuh-agent.pkg -target / && "
                f"sudo /Library/Ossec/bin/wazuh-control start"
            )

        entry = {
            **meta,
            **info,
            "local_url": local_url,
            "full_local_url": full_local_url,
            "offline_1liner": offline_cmd,
            "online_1liner": online_cmd,
            "agentless_syslog_cmd": f"echo \"*.* @{host}:514\" | sudo tee /etc/rsyslog.d/siem.conf && sudo systemctl restart rsyslog"
        }
        catalog.append(entry)

    return catalog


def cache_package_from_remote(pkg_id: str) -> Dict[str, Any]:
    """
    Downloads the specified agent package from the official Wazuh CDN into the local cache.
    Routes through corporate proxy if configured.
    """
    meta = AGENT_CATALOG.get(pkg_id)
    if not meta:
        return {"success": False, "message": f"Unknown package identifier '{pkg_id}'."}

    ensure_downloads_dir()
    dest_path = os.path.join(DOWNLOADS_DIR, meta["filename"])
    canonical_dest_path = os.path.join(DOWNLOADS_DIR, meta["canonical_name"])

    t0 = time.time()
    try:
        req = meta["remote_url"]
        with safe_urlopen(req, timeout=45) as resp:
            content = resp.read()

        with open(dest_path, "wb") as f:
            f.write(content)

        # Also write canonical name for direct versioned references
        if canonical_dest_path != dest_path:
            with open(canonical_dest_path, "wb") as f:
                f.write(content)

        duration = round(time.time() - t0, 2)
        size_mb = round(len(content) / (1024 * 1024), 2)
        return {
            "success": True,
            "pkg_id": pkg_id,
            "filename": meta["filename"],
            "version": meta["version"],
            "size_mb": size_mb,
            "duration_sec": duration,
            "message": f"Successfully cached {meta['filename']} ({size_mb} MB) in {duration}s."
        }
    except Exception as e:
        return {
            "success": False,
            "pkg_id": pkg_id,
            "message": f"Failed to download package: {str(e)}"
        }
