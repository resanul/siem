import paramiko
import hashlib
import os

files_to_verify = [
    "frontend/index.html",
    "backend/app/main.py",
    "backend/app/api/v1/api.py",
    "backend/app/services/live_telemetry.py",
    "backend/app/services/sophos_xdr.py",
    "backend/app/services/crowdstrike_identity.py",
    "backend/app/services/network_telemetry.py",
    "backend/app/services/host_storage.py",
    "backend/app/services/ioc_storage.py",
    "backend/app/services/event_search.py",
    "backend/app/services/mitre_intel.py",
    "backend/app/services/github_sync.py",
    "backend/app/services/retention_policy.py",
    "backend/app/services/proxy_manager.py",
    "backend/app/services/agent_packages.py",
    "backend/app/core/config.py",
    "docs/CHAT_HISTORY.md",
    "CHAT_HISTORY.md",
    "frontend/vendor/world_map_data.js"
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

all_ok = True
results = []

for rel_path in files_to_verify:
    if not os.path.exists(rel_path):
        results.append((rel_path, "LOCAL_MISSING"))
        all_ok = False
        continue
    
    with open(rel_path, "r", encoding="utf-8", errors="ignore") as f:
        local_text = f.read().replace("\r\n", "\n")
    
    stdin, stdout, stderr = ssh.exec_command(f"cat /opt/opensoc-forge/{rel_path}")
    remote_text = stdout.read().decode("utf-8", errors="ignore").replace("\r\n", "\n")
    
    if not remote_text:
        results.append((rel_path, "REMOTE_MISSING"))
        all_ok = False
    elif local_text == remote_text:
        results.append((rel_path, "100% IDENTICAL"))
    else:
        results.append((rel_path, f"DIFF (len local {len(local_text)} vs remote {len(remote_text)})"))
        all_ok = False

ssh.close()

print(f"Overall status: {'ALL 100% IDENTICAL' if all_ok else 'SOME DIFFS DETECTED'}")
for path, status in results:
    print(f"  [{status}] {path}")
