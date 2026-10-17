"""
OpenSOC Forge - Central Platform Proxy Manager.
Enables enterprise environments with strict outbound firewalls to route all
Threat Intelligence, Feeds, API key verifications, and GitHub updates
through a configured corporate HTTP/HTTPS proxy.
"""

import os
import json
import time
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "configs")
CONFIG_FILE = os.path.join(CONFIG_DIR, "proxy_config.json")
ENV_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), ".env")

DEFAULT_NO_PROXY = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

# Create relaxed SSL context for enterprise inspection proxies
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def get_global_opener() -> urllib.request.OpenerDirector:
    """Returns an OpenerDirector configured with both active ProxyHandler and SSLContext."""
    cfg = load_proxy_config()
    enabled = bool(cfg.get("enabled", False))
    http_proxy = cfg.get("http_proxy", "").strip()
    https_proxy = cfg.get("https_proxy", "").strip() or http_proxy

    handlers = [urllib.request.HTTPSHandler(context=_ssl_ctx)]
    if enabled and (http_proxy or https_proxy):
        active = https_proxy or http_proxy
        handlers.append(urllib.request.ProxyHandler({
            "http": http_proxy or active,
            "https": https_proxy or active
        }))
    return urllib.request.build_opener(*handlers)


def safe_urlopen(req, timeout: int = 10):
    """Executes HTTP/S request through the configured corporate proxy and relaxed SSL context."""
    return get_global_opener().open(req, timeout=timeout)


def load_proxy_config() -> Dict[str, Any]:
    """Loads saved proxy settings from JSON config or environment variables."""
    cfg: Dict[str, Any] = {
        "enabled": False,
        "http_proxy": "",
        "https_proxy": "",
        "no_proxy": DEFAULT_NO_PROXY,
        "status": "DISABLED",
        "last_tested": None,
        "latency_ms": None
    }

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    cfg.update(data)
        except Exception as e:
            print(f"[ProxyManager] Error reading {CONFIG_FILE}: {e}")

    # Fallback to system environment if not configured in JSON
    if not cfg["http_proxy"]:
        env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
        if env_proxy:
            cfg["http_proxy"] = env_proxy
            cfg["https_proxy"] = env_proxy
            cfg["enabled"] = True
            cfg["status"] = "ACTIVE"

    return cfg


def apply_global_proxy(config: Dict[str, Any]) -> None:
    """
    Applies the proxy configuration across Python runtime:
    1. Sets os.environ for subprocesses and httpx
    2. Installs a global urllib.request opener with ProxyHandler
    3. Updates .env file for persistence across service restarts
    """
    enabled = bool(config.get("enabled", False))
    http_proxy = config.get("http_proxy", "").strip()
    https_proxy = config.get("https_proxy", "").strip() or http_proxy
    no_proxy = config.get("no_proxy", "").strip() or DEFAULT_NO_PROXY

    if enabled and (http_proxy or https_proxy):
        active_proxy = https_proxy or http_proxy
        os.environ["HTTP_PROXY"] = http_proxy or active_proxy
        os.environ["HTTPS_PROXY"] = https_proxy or active_proxy
        os.environ["http_proxy"] = http_proxy or active_proxy
        os.environ["https_proxy"] = https_proxy or active_proxy
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy

        # Build and install global opener with ProxyHandler
        proxy_dict = {
            "http": http_proxy or active_proxy,
            "https": https_proxy or active_proxy
        }
        handler = urllib.request.ProxyHandler(proxy_dict)
        https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
        opener = urllib.request.build_opener(handler, https_handler)
        urllib.request.install_opener(opener)
        print(f"[ProxyManager] Global Proxy ACTIVE -> {active_proxy}")
    else:
        # Clear proxy from environment
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]:
            os.environ.pop(key, None)
        # Restore default opener
        https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
        opener = urllib.request.build_opener(https_handler)
        urllib.request.install_opener(opener)
        print("[ProxyManager] Global Proxy DISABLED (Direct Connection)")

    # Persist in .env
    _persist_env(enabled, http_proxy, https_proxy, no_proxy)


def save_proxy_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Saves proxy settings to configs/proxy_config.json and applies globally."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    cfg = load_proxy_config()

    enabled = bool(payload.get("enabled", False))
    http_proxy = payload.get("http_proxy", "").strip()
    https_proxy = payload.get("https_proxy", "").strip() or http_proxy
    no_proxy = payload.get("no_proxy", "").strip() or DEFAULT_NO_PROXY

    cfg["enabled"] = enabled
    cfg["http_proxy"] = http_proxy
    cfg["https_proxy"] = https_proxy
    cfg["no_proxy"] = no_proxy
    cfg["status"] = "ACTIVE" if (enabled and http_proxy) else "DISABLED"

    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[ProxyManager] Error writing {CONFIG_FILE}: {e}")

    apply_global_proxy(cfg)
    return cfg


def test_proxy_connection(proxy_url: str, target_url: str = "https://otx.alienvault.com") -> Dict[str, Any]:
    """Tests if a candidate proxy can reach target internet services."""
    proxy = proxy_url.strip()
    if not proxy:
        return {"status": "error", "success": False, "message": "Proxy URL cannot be empty."}

    if not proxy.startswith(("http://", "https://")):
        proxy = f"http://{proxy}"

    t0 = time.time()
    try:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        https_handler = urllib.request.HTTPSHandler(context=_ssl_ctx)
        opener = urllib.request.build_opener(handler, https_handler)
        req = urllib.request.Request(target_url, headers={"User-Agent": "OpenSOC-Forge/1.0"})

        with opener.open(req, timeout=7) as resp:
            latency_ms = round((time.time() - t0) * 1000, 1)
            return {
                "status": "success",
                "success": True,
                "proxy": proxy,
                "target": target_url,
                "http_status": resp.status,
                "latency_ms": latency_ms,
                "message": f"Successfully connected through proxy! (Latency: {latency_ms} ms)"
            }
    except urllib.error.HTTPError as e:
        latency_ms = round((time.time() - t0) * 1000, 1)
        # Any HTTP response code (including 401/403 from API endpoints) confirms network path is working!
        return {
            "status": "success",
            "success": True,
            "proxy": proxy,
            "target": target_url,
            "http_status": e.code,
            "latency_ms": latency_ms,
            "message": f"Proxy connected to {target_url} (HTTP {e.code}, Latency: {latency_ms} ms)"
        }
    except Exception as e:
        latency_ms = round((time.time() - t0) * 1000, 1)
        return {
            "status": "error",
            "success": False,
            "proxy": proxy,
            "target": target_url,
            "latency_ms": latency_ms,
            "message": f"Proxy connection failed: {str(e)}"
        }


def init_proxy_on_startup() -> None:
    """Initializes global proxy configuration when the FastAPI backend starts."""
    cfg = load_proxy_config()
    apply_global_proxy(cfg)


def _persist_env(enabled: bool, http_proxy: str, https_proxy: str, no_proxy: str) -> None:
    """Updates .env file with proxy parameters for process survival."""
    if not os.path.exists(ENV_FILE):
        return

    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        skip_keys = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "PROXY_ENABLED"}
        for line in lines:
            key = line.split("=")[0].strip() if "=" in line else ""
            if key not in skip_keys:
                new_lines.append(line)

        if enabled and (http_proxy or https_proxy):
            new_lines.append(f"PROXY_ENABLED=true\n")
            new_lines.append(f"HTTP_PROXY={http_proxy}\n")
            new_lines.append(f"HTTPS_PROXY={https_proxy or http_proxy}\n")
            new_lines.append(f"NO_PROXY={no_proxy}\n")
        else:
            new_lines.append("PROXY_ENABLED=false\n")

        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception as e:
        print(f"[ProxyManager] Failed to update .env: {e}")
