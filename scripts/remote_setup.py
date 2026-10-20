import sys
import io
# Ensure stdout/stderr handles all unicode safely on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import paramiko
import time

HOST = "192.168.10.177"
USER = "resanul"
PASS = "1100"

def run_cmd(ssh, cmd, sudo=False):
    if sudo:
        cmd = f"echo {PASS} | sudo -S bash -c {repr(cmd)}"
    safe_display = cmd[:120].encode('ascii', errors='replace').decode('ascii')
    print(f"\n>>> Running: {safe_display}...", flush=True)
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
    
    while True:
        line = stdout.readline()
        if not line:
            break
        # Print safely replacing unmappable chars
        safe_line = line.rstrip().encode('ascii', errors='replace').decode('ascii')
        print("    " + safe_line, flush=True)
        
    status = stdout.channel.recv_exit_status()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    if err and "password" not in err.lower():
        safe_err = err[:300].encode('ascii', errors='replace').decode('ascii')
        print("    [STDERR]:", safe_err, flush=True)
    return status

def main():
    print("=" * 80, flush=True)
    print(f"Connecting to {USER}@{HOST}...", flush=True)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASS, timeout=10)
    print("Connected successfully!", flush=True)

    # 1. Pull latest commits in /home/resanul/siem
    print("\n[Step 1] Pulling latest commits in /home/resanul/siem...", flush=True)
    run_cmd(ssh, 'cd /home/resanul/siem && git pull origin master')
    run_cmd(ssh, 'git -C /home/resanul/siem log -1 --oneline')

    # 2. Make scripts executable
    run_cmd(ssh, 'chmod +x /home/resanul/siem/install.sh /home/resanul/siem/bin/* /home/resanul/siem/scripts/*')

    # 3. Resume / Execute install.sh
    print("\n[Step 2] Executing sudo ./install.sh --skip-preflight...", flush=True)
    status = run_cmd(ssh, 'cd /home/resanul/siem && ./install.sh --skip-preflight', sudo=True)
    print(f"\nInstall script finished with exit status: {status}", flush=True)

    # 4. Check systemd service status
    print("\n[Step 3] Checking opensoc-forge.service...", flush=True)
    run_cmd(ssh, 'systemctl status opensoc-forge --no-pager -l', sudo=True)

    # 5. Check container statuses
    print("\n[Step 4] Checking podman containers...", flush=True)
    run_cmd(ssh, 'podman ps -a', sudo=True)

    ssh.close()

if __name__ == "__main__":
    main()
