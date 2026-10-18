from backend.app.services.proxy_manager import safe_urlopen
"""
OpenSOC Forge - GitHub IOC Backup & Synchronization Engine.
Handles automated verification, pull comparison, and twice-daily push of
collected threat intelligence indicators to GitHub.
"""

import os
import json
import base64
import hashlib
import threading
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from backend.app.services.ioc_storage import (
    get_offline_db_stats,
    export_iocs_snapshot,
    record_github_sync_log,
    EXPORT_JSON_FILE,
    BACKEND_DATA_JSON
)

_ssl_ctx = ssl._create_unverified_context()
_SCHEDULER_THREAD: Optional[threading.Thread] = None
_LAST_SYNC_RESULT: Dict[str, Any] = {
    "status": "idle",
    "message": "GitHub synchronization initialized and ready.",
    "last_sync_time": None,
    "last_commit_sha": None,
    "total_indicators": 0
}


def _get_threat_config() -> Dict[str, Any]:
    from backend.app.services.mitre_intel import load_threat_intel_config
    return load_threat_intel_config()


def get_local_snapshot_data() -> Tuple[str, int, str]:
    """
    Returns (raw_json_str, total_indicators, sha256_hash) of local IOC snapshot.
    """
    target = EXPORT_JSON_FILE if os.path.exists(EXPORT_JSON_FILE) else BACKEND_DATA_JSON
    if not os.path.exists(target):
        export_iocs_snapshot()

    if not os.path.exists(target):
        return "", 0, ""

    try:
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()
        parsed = json.loads(content)
        total = len(parsed.get("indicators", []))
        # Hash normalized indicators representation for consistent comparison
        indicators_str = json.dumps(parsed.get("indicators", []), sort_keys=True)
        h = hashlib.sha256(indicators_str.encode("utf-8")).hexdigest()
        return content, total, h
    except Exception as e:
        print(f"Error reading local IOC snapshot: {e}")
        return "", 0, ""


def sync_iocs_to_github(force_push: bool = False) -> Dict[str, Any]:
    """
    Executes the GitHub synchronization workflow:
    1. Reads local IOC snapshot.
    2. Pulls remote file from GitHub repository.
    3. Verifies if remote data is identical to local data.
    4. If identical, skips push (reports 'identical').
    5. If changed or missing, commits and pushes to GitHub repository.
    """
    global _LAST_SYNC_RESULT
    cfg = _get_threat_config()
    token = cfg.get("github_token", "").strip()
    repo = cfg.get("github_repo", "resanul/siem").strip() or "resanul/siem"
    branch = cfg.get("github_branch", "master").strip() or "master"
    file_path = cfg.get("github_file_path", "data/threat_intel_iocs.json").strip() or "data/threat_intel_iocs.json"

    # Export latest snapshot from database first
    export_iocs_snapshot()
    local_content, total_iocs, local_hash = get_local_snapshot_data()

    if not local_content or total_iocs == 0:
        res = {
            "status": "warning",
            "message": "Local offline IOC database is empty. No indicators to push.",
            "total_indicators": 0
        }
        _LAST_SYNC_RESULT = res
        return res

    if not token:
        res = {
            "status": "pending_token",
            "message": "Data saved to offline SQLite DB. To enable automated push, configure your GitHub Personal Access Token in [API Keys & Providers].",
            "total_indicators": total_iocs,
            "offline_stored": True,
            "repo": repo,
            "branch": branch
        }
        _LAST_SYNC_RESULT = res
        return res

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OpenSOC-Forge-ThreatIntel/1.0"
    }

    # Step 1: Pull existing remote file from GitHub to check if data is identical
    remote_sha = None
    remote_identical = False
    try:
        check_url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
        req = urllib.request.Request(check_url, headers=headers)
        with safe_urlopen(req, timeout=12) as r:
            remote_meta = json.loads(r.read())
            remote_sha = remote_meta.get("sha")
            raw_b64 = remote_meta.get("content", "")
            if raw_b64:
                try:
                    remote_raw = base64.b64decode(raw_b64.encode("ascii")).decode("utf-8", errors="ignore")
                    remote_parsed = json.loads(remote_raw)
                    remote_indicators = remote_parsed.get("indicators", [])
                    remote_hash = hashlib.sha256(json.dumps(remote_indicators, sort_keys=True).encode("utf-8")).hexdigest()
                    if remote_hash == local_hash and not force_push:
                        remote_identical = True
                except Exception:
                    pass
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # File does not exist remotely yet, will create
            remote_sha = None
        elif e.code in [401, 403]:
            res = {
                "status": "auth_error",
                "message": f"GitHub authentication failed (HTTP {e.code}). Please verify your GitHub Personal Access Token.",
                "total_indicators": total_iocs
            }
            record_github_sync_log(total_iocs, "PULL_VERIFY", "", "AUTH_ERROR", res["message"])
            _LAST_SYNC_RESULT = res
            return res
        else:
            res = {
                "status": "error",
                "message": f"GitHub API check failed: HTTP {e.code} ({e.reason})",
                "total_indicators": total_iocs
            }
            _LAST_SYNC_RESULT = res
            return res
    except Exception as e:
        res = {
            "status": "error",
            "message": f"Network error checking GitHub remote: {str(e)}",
            "total_indicators": total_iocs
        }
        _LAST_SYNC_RESULT = res
        return res

    # If data is verified identical, skip redundant push
    if remote_identical:
        msg = f"Data verified: Remote GitHub dataset ({repo}:{branch}) is already up-to-date with local offline DB ({total_iocs:,} IOCs)."
        record_github_sync_log(total_iocs, "VERIFY_PULL", remote_sha or "", "UNCHANGED", msg)
        res = {
            "status": "identical",
            "message": msg,
            "total_indicators": total_iocs,
            "sha": remote_sha,
            "repo": repo,
            "branch": branch,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        _LAST_SYNC_RESULT = res
        return res

    # Step 2: Push changes to GitHub
    commit_msg = f"chore(ioc-db): automated threat intelligence update [{total_iocs:,} indicators]"
    put_data = {
        "message": commit_msg,
        "content": base64.b64encode(local_content.encode("utf-8")).decode("ascii"),
        "branch": branch
    }
    if remote_sha:
        put_data["sha"] = remote_sha

    try:
        put_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
        req = urllib.request.Request(
            put_url,
            data=json.dumps(put_data).encode("utf-8"),
            headers=headers,
            method="PUT"
        )
        with safe_urlopen(req, timeout=20) as r:
            resp_data = json.loads(r.read())
            new_sha = resp_data.get("commit", {}).get("sha", "") or resp_data.get("content", {}).get("sha", "")
            msg = f"Successfully pushed {total_iocs:,} offline indicators to GitHub ({repo}:{branch})"
            record_github_sync_log(total_iocs, "PUSH", new_sha, "SUCCESS", msg)
            res = {
                "status": "pushed",
                "message": msg,
                "commit_sha": new_sha[:8] if new_sha else "",
                "total_indicators": total_iocs,
                "repo": repo,
                "branch": branch,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            }
            _LAST_SYNC_RESULT = res
            return res
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = json.loads(e.read()).get("message", "")
        except Exception:
            pass
        if e.code == 403 and "Resource not accessible by personal access token" in err_body:
            msg = (
                f"GitHub Permission Error (HTTP 403): Personal Access Token lacks write permission. "
                f"For Fine-grained PAT: GitHub Settings -> Developer settings -> Personal access tokens -> "
                f"Repository permissions -> set 'Contents' to 'Read and write' for repository '{repo}'. "
                f"For Classic PAT: ensure the 'repo' scope is selected."
            )
        elif e.code in [401, 403]:
            msg = f"GitHub Authentication Error (HTTP {e.code}): {err_body or e.reason}. Verify token and repo write access for {repo}."
        else:
            msg = f"Failed to push to GitHub: HTTP {e.code} ({err_body or e.reason})"
        record_github_sync_log(total_iocs, "PUSH", "", "ERROR", msg)
        res = {
            "status": "error",
            "message": msg,
            "total_indicators": total_iocs
        }
        _LAST_SYNC_RESULT = res
        return res
    except Exception as e:
        msg = f"Error during GitHub push: {str(e)}"
        record_github_sync_log(total_iocs, "PUSH", "", "ERROR", msg)
        res = {
            "status": "error",
            "message": msg,
            "total_indicators": total_iocs
        }
        _LAST_SYNC_RESULT = res
        return res


def test_github_connection(token: str, repo: str = "resanul/siem") -> Dict[str, Any]:
    """Verifies that the provided GitHub token has write/push permissions to repo."""
    if not token or not token.strip():
        return {"status": "error", "message": "No GitHub token provided"}

    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OpenSOC-Forge-ThreatIntel/1.0"
    }

    try:
        req = urllib.request.Request(f"https://api.github.com/repos/{repo.strip()}", headers=headers)
        with safe_urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
            permissions = data.get("permissions", {})
            can_push = permissions.get("push", False)
            if can_push:
                return {
                    "status": "success",
                    "message": f"GitHub connection verified! Write/push permissions confirmed for {data.get('full_name')}."
                }
            return {
                "status": "warning",
                "message": f"Connected to {data.get('full_name')}, but token lacks 'push' (repo write) permission."
            }
    except urllib.error.HTTPError as e:
        if e.code in [401, 403]:
            return {"status": "error", "message": "Authentication failed: Invalid GitHub token or insufficient scope (requires 'repo')."}
        elif e.code == 404:
            return {"status": "error", "message": f"Repository '{repo}' not found or token has no access."}
        return {"status": "error", "message": f"GitHub API error: HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "message": f"Connection error: {str(e)}"}


def _background_scheduler_loop():
    """
    Background worker that runs every 12 hours (twice a day):
    1. Collects latest feeds from all active providers.
    2. Saves them into offline SQLite DB.
    3. Verifies remote GitHub state and pushes dataset.
    """
    # Initial warm-up delay after startup (45 seconds)
    time.sleep(45)

    TWELVE_HOURS_SEC = 12 * 3600

    while True:
        try:
            from backend.app.services.mitre_intel import get_threat_intel_feed
            # Fetch latest live feeds with force refresh
            feeds = get_threat_intel_feed(force_refresh=True)
            if feeds:
                from backend.app.services.ioc_storage import save_iocs_to_db
                save_iocs_to_db(feeds)

            # Sync to GitHub with pull verification
            sync_iocs_to_github()
        except Exception as e:
            print(f"Error in 12-hour GitHub sync scheduler: {e}")

        # Sleep for 12 hours before next automatic push
        time.sleep(TWELVE_HOURS_SEC)


def start_github_sync_scheduler():
    """Starts the 12-hour twice daily GitHub sync worker thread."""
    global _SCHEDULER_THREAD
    if _SCHEDULER_THREAD is not None and _SCHEDULER_THREAD.is_alive():
        return
    _SCHEDULER_THREAD = threading.Thread(target=_background_scheduler_loop, daemon=True, name="GitHubIOCSyncWorker")
    _SCHEDULER_THREAD.start()
    print("GitHub Threat Intel 12-hour automated sync scheduler started.")


def get_sync_status() -> Dict[str, Any]:
    """Returns current sync status and DB metadata."""
    stats = get_offline_db_stats()
    return {
        "sync_result": _LAST_SYNC_RESULT,
        "db_stats": stats,
        "scheduler_active": _SCHEDULER_THREAD is not None and _SCHEDULER_THREAD.is_alive()
    }
