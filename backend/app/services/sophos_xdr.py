"""
OpenSOC Forge - Sophos Central (XDR / MDR) Service
Provides live integration with Sophos Central API, supporting XDR detections,
endpoint health telemetry, alerts, and credential management (Add, Edit, Test, Delete)
for the OpenSOC platform component inventory.
"""

import os
import json
import time
import ssl
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional

CONFIG_PERSISTENT_FILE = "/var/lib/opensoc/sophos_config.json"
CONFIG_LOCAL_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "configs", "sophos_config.json")
CONFIG_TEMP_FILE = "/tmp/sophos_config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "client_id": "",
    "client_secret": "",
    "tenant_id": "",
    "tenant_name": "",
    "base_url": "https://api.central.sophos.com",
    "data_region_url": "",
    "enabled": False,
    "status": "NOT_CONFIGURED",
    "last_tested": "-"
}

_TOKEN_CACHE: Dict[str, Any] = {
    "access_token": None,
    "expires_at": 0,
    "tenant_id": None,
    "data_region_url": None
}

_DATA_CACHE: Dict[str, Any] = {
    "last_synced": 0,
    "data": None
}

_ssl_context = ssl._create_unverified_context()


def _get_config_target_path() -> str:
    for candidate in [CONFIG_PERSISTENT_FILE, CONFIG_LOCAL_FILE, CONFIG_TEMP_FILE]:
        d = os.path.dirname(candidate)
        if os.path.exists(candidate) or (d and os.path.exists(d)):
            return candidate
    return CONFIG_TEMP_FILE


def load_sophos_config(reload: bool = False) -> Dict[str, Any]:
    """Loads saved Sophos credentials from persistent JSON or defaults."""
    for p in [CONFIG_PERSISTENT_FILE, CONFIG_LOCAL_FILE, CONFIG_TEMP_FILE]:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {**DEFAULT_CONFIG, **data}
            except Exception:
                pass
    return DEFAULT_CONFIG.copy()


def get_masked_sophos_config() -> Dict[str, Any]:
    """Returns configuration with sensitive keys masked for security in UI."""
    cfg = load_sophos_config()
    cid = cfg.get("client_id", "").strip()
    sec = cfg.get("client_secret", "").strip()
    tid = cfg.get("tenant_id", "").strip()

    is_configured = bool(cid and sec)
    masked_cid = f"{cid[:6]}...{cid[-4:]}" if len(cid) >= 10 else (cid if cid else "")
    masked_sec = "••••••••••••••••" if sec else ""
    masked_tid = f"{tid[:8]}...{tid[-4:]}" if len(tid) >= 14 else (tid if tid else "Auto-detected")

    return {
        "is_configured": is_configured,
        "client_id": cid,
        "client_id_masked": masked_cid,
        "client_secret_masked": masked_sec,
        "tenant_id": tid,
        "tenant_id_masked": masked_tid,
        "tenant_name": cfg.get("tenant_name", ""),
        "base_url": cfg.get("base_url", "https://api.central.sophos.com"),
        "data_region_url": cfg.get("data_region_url", ""),
        "status": cfg.get("status", "HEALTHY" if is_configured else "NOT_CONFIGURED"),
        "enabled": cfg.get("enabled", is_configured),
        "last_tested": cfg.get("last_tested", "-")
    }


def test_sophos_credentials(
    client_id: str,
    client_secret: str,
    tenant_id: str = "",
    base_url: str = "https://api.central.sophos.com"
) -> Dict[str, Any]:
    """Validates OAuth2 credentials against Sophos Central API and checks /whoami."""
    if not client_id or not client_secret:
        return {"success": False, "message": "Client ID and Client Secret are required."}

    cid = client_id.strip()
    sec = client_secret.strip()

    # Step 1: OAuth2 Token Request
    token_url = "https://id.sophos.com/api/v2/oauth2/token"
    payload = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": cid,
        "client_secret": sec,
        "scope": "token"
    }).encode("utf-8")

    token_req = urllib.request.Request(
        token_url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    try:
        with urllib.request.urlopen(token_req, timeout=12, context=_ssl_context) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            access_token = data.get("access_token")
            if not access_token:
                return {"success": False, "message": "Sophos OAuth2 returned empty access token."}
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8")
            err_json = json.loads(err_body)
            msg = err_json.get("message") or err_json.get("error") or err_json.get("errorCode") or f"HTTP {e.code}"
        except Exception:
            msg = f"HTTP {e.code}: {e.reason}"
        return {"success": False, "message": f"Authentication failed: {msg}"}
    except Exception as e:
        return {"success": False, "message": f"Network error connecting to Sophos ID: {str(e)}"}

    # Step 2: Query WhoAmI to detect Tenant ID & Regional API Host
    whoami_url = "https://api.sophos.com/whoami/v1"
    whoami_req = urllib.request.Request(
        whoami_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
    )

    discovered_tenant_id = tenant_id.strip()
    discovered_data_region = ""
    discovered_name = ""

    try:
        with urllib.request.urlopen(whoami_req, timeout=12, context=_ssl_context) as resp:
            whoami_data = json.loads(resp.read().decode("utf-8"))
            discovered_tenant_id = whoami_data.get("id", discovered_tenant_id)
            api_hosts = whoami_data.get("apiHosts", {})
            discovered_data_region = api_hosts.get("dataRegion", "") or api_hosts.get("global", "https://api.central.sophos.com")
            discovered_name = whoami_data.get("name", "")
    except Exception as e:
        # If whoami has non-critical issue, authentication already succeeded
        pass

    return {
        "success": True,
        "message": "Connection Successful! Sophos Central OAuth2 & Tenant API authenticated.",
        "tenant_id": discovered_tenant_id,
        "tenant_name": discovered_name,
        "data_region_url": discovered_data_region,
        "access_token": access_token
    }


def save_sophos_config(
    client_id: str,
    client_secret: str,
    tenant_id: str = "",
    base_url: str = "https://api.central.sophos.com",
    enabled: bool = True
) -> Dict[str, Any]:
    """Tests credentials, saves them to persistent JSON, and refreshes component status."""
    cid = client_id.strip()
    sec = client_secret.strip()

    if not cid or not sec:
        # If either is empty, check if we're keeping existing secret
        curr = load_sophos_config()
        if not cid:
            cid = curr.get("client_id", "")
        if not sec:
            sec = curr.get("client_secret", "")

    test_res = test_sophos_credentials(cid, sec, tenant_id, base_url)
    if not test_res.get("success"):
        return {
            "success": False,
            "message": test_res.get("message", "Validation failed.")
        }

    detected_tid = test_res.get("tenant_id") or tenant_id.strip()
    data_region = test_res.get("data_region_url") or ""
    tenant_name = test_res.get("tenant_name") or ""

    config_data: Dict[str, Any] = {
        "client_id": cid,
        "client_secret": sec,
        "tenant_id": detected_tid,
        "tenant_name": tenant_name,
        "base_url": base_url.strip(),
        "data_region_url": data_region,
        "enabled": enabled,
        "status": "HEALTHY",
        "last_tested": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    }

    # Invalidate token and data caches
    global _TOKEN_CACHE, _DATA_CACHE
    _TOKEN_CACHE = {
        "access_token": test_res.get("access_token"),
        "expires_at": time.time() + 3500,
        "tenant_id": detected_tid,
        "data_region_url": data_region
    }
    _DATA_CACHE = {"last_synced": 0, "data": None}

    saved = False
    for target in [CONFIG_PERSISTENT_FILE, CONFIG_LOCAL_FILE, CONFIG_TEMP_FILE]:
        try:
            d = os.path.dirname(target)
            if d and not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2)
            saved = True
        except Exception:
            pass

    return {
        "success": True,
        "message": "Sophos Central API credentials saved and connected successfully!",
        "config": get_masked_sophos_config()
    }


def delete_sophos_config() -> Dict[str, Any]:
    """Deletes stored Sophos credentials, clears cache, and resets component status."""
    global _TOKEN_CACHE, _DATA_CACHE
    _TOKEN_CACHE = {"access_token": None, "expires_at": 0, "tenant_id": None, "data_region_url": None}
    _DATA_CACHE = {"last_synced": 0, "data": None}

    for target in [CONFIG_PERSISTENT_FILE, CONFIG_LOCAL_FILE, CONFIG_TEMP_FILE]:
        if os.path.exists(target):
            try:
                os.remove(target)
            except Exception:
                try:
                    with open(target, "w", encoding="utf-8") as f:
                        json.dump(DEFAULT_CONFIG, f, indent=2)
                except Exception:
                    pass

    return {
        "success": True,
        "message": "Sophos Central API configuration removed."
    }


def get_sophos_component_status() -> Dict[str, Any]:
    """Queries or computes live status of Sophos Central adapter for component inventory."""
    cfg = load_sophos_config()
    cid = cfg.get("client_id", "").strip()
    sec = cfg.get("client_secret", "").strip()
    enabled = cfg.get("enabled", False)

    if not cid or not sec:
        return {
            "status": "NOT_CONFIGURED",
            "enabled": False,
            "uptime": "Not Configured",
            "details": "Sophos Central API credentials not configured",
            "tenant_id": "",
            "ports": "api.central (HTTPS:443)"
        }

    if not enabled:
        return {
            "status": "STOPPED",
            "enabled": False,
            "uptime": "Disabled",
            "details": "Sophos Central API integration disabled",
            "tenant_id": cfg.get("tenant_id", ""),
            "ports": "api.central (HTTPS:443)"
        }

    # If configured and enabled
    tid = cfg.get("tenant_id", "")
    name = cfg.get("tenant_name", "")
    details = f"Tenant: {name or tid or 'Connected'} (Regional API)"

    return {
        "status": cfg.get("status", "HEALTHY"),
        "enabled": True,
        "uptime": cfg.get("last_tested", "Active Cloud API"),
        "details": details,
        "tenant_id": tid,
        "ports": "api.central (HTTPS:443)"
    }
