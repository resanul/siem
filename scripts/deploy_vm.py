"""
OpenSOC Forge - Remote VM Automated Deployment & Git Sync Script.
Updates target VM directly from GitHub, syncs runtime directories,
restarts management containers, and validates platform health.
"""

import os
import sys
import time
import argparse
import paramiko
import urllib.request
import json

DEFAULT_HOST = os.getenv("OPENSOC_TARGET_HOST", "192.168.10.177")
DEFAULT_USER = os.getenv("OPENSOC_TARGET_USER", "resanul")
DEFAULT_PASS = os.getenv("OPENSOC_TARGET_PASS", "1100")
DEFAULT_PORT = int(os.getenv("OPENSOC_TARGET_PORT", "7070"))


def main():
    parser = argparse.ArgumentParser(description="1-Click OpenSOC Forge VM Deploy & Sync")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Target VM IP address")
    parser.add_argument("--user", default=DEFAULT_USER, help="SSH username")
    parser.add_argument("--password", default=DEFAULT_PASS, help="SSH password")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Web Console Port")
    args = parser.parse_args()

    print("=" * 80)
    print("  OpenSOC Forge -- 1-Click Remote VM Git Update & Deploy")
    print(f"  Target: {args.user}@{args.host} (Web Console Port: {args.port})")
    print("=" * 80)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"\n[1/5] Connecting to {args.host} via SSH...")
        client.connect(args.host, username=args.user, password=args.password, timeout=15)
        print("      Connected successfully!")
    except Exception as e:
        print(f"      [ERROR] SSH Connection failed: {e}")
        sys.exit(1)

    steps = [
        ("Fixing repository ownership", f"echo {args.password} | sudo -S chown -R {args.user}:{args.user} /home/{args.user}/siem"),
        ("Resetting local repository state to match remote", f"git -C /home/{args.user}/siem fetch origin && git -C /home/{args.user}/siem reset --hard origin/master"),
        ("Pulling latest code from GitHub (master branch)", f"git -C /home/{args.user}/siem pull origin master"),
        ("Retrieving latest commit details", f"git -C /home/{args.user}/siem log -1 --pretty=format:'%h - %s (%cr)'"),
        ("Synchronizing backend assets to /opt/opensoc-forge", f"echo {args.password} | sudo -S cp -rf /home/{args.user}/siem/backend /opt/opensoc-forge/"),
        ("Synchronizing frontend assets to /opt/opensoc-forge", f"echo {args.password} | sudo -S cp -rf /home/{args.user}/siem/frontend /opt/opensoc-forge/"),
        ("Restarting opensoc-forge-mgmt container", f"echo {args.password} | sudo -S podman restart opensoc-forge-mgmt"),
    ]

    latest_commit = "Unknown"
    for idx, (label, cmd) in enumerate(steps, 2):
        print(f"\n[{idx}/7] {label}...")
        stdin, stdout, stderr = client.exec_command(cmd)
        status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        err = stderr.read().decode("utf-8", errors="ignore").strip()

        if label.startswith("Retrieving latest commit"):
            latest_commit = out
            print(f"      Commit: {latest_commit}")
        elif out:
            print(f"      Output: {out}")

        if err and "password" not in err.lower():
            print(f"      Log: {err}")

        if status != 0:
            print(f"      [ERROR] Step failed with status code {status}")
            client.close()
            sys.exit(status)

    client.close()

    # Step 7: Local/Remote HTTP Health check
    console_url = f"http://{args.host}:{args.port}/console/"
    api_url = f"http://{args.host}:{args.port}/"
    print(f"\n[7/7] Validating HTTP health at {api_url}...")
    
    time.sleep(3)
    healthy = False
    for attempt in range(1, 10):
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "OpenSOC-Deployer/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    print(f"      Health Check: HTTP 200 OK | Status: {data.get('status', 'ONLINE')} | Platform: {data.get('platform')}")
                    healthy = True
                    break
        except Exception:
            time.sleep(1)

    print("\n" + "=" * 80)
    if healthy:
        print("  SUCCESS: OpenSOC Forge is updated from Git and running!")
        print(f"  Latest Commit : {latest_commit}")
        print(f"  Web Console   : {console_url}")
    else:
        print("  Update completed, but HTTP health probe did not respond immediately.")
        print(f"  Please allow a few moments and browse: {console_url}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
