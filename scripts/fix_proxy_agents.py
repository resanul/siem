import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

def run_sudo(c):
    stdin, stdout, stderr = ssh.exec_command(f"echo '@#Trust2025##' | sudo -S bash -c \"{c}\"")
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return out, err

test_sh = """
cat << 'EOF' > /tmp/fix_squid.sh
#!/bin/bash
usermod -a -G squid wazuh 2>/dev/null || true
setfacl -R -m u:wazuh:rx /var/log/squid 2>/dev/null || true
setfacl -R -d -m u:wazuh:rx /var/log/squid 2>/dev/null || true
chmod 755 /var/log/squid
chmod 644 /var/log/squid/access.log 2>/dev/null || true
systemctl restart wazuh-agent
systemctl is-active wazuh-agent
tail -n 1 /var/log/squid/access.log
EOF
chmod 755 /tmp/fix_squid.sh
"""
run_sudo(test_sh)

proxies = ["172.31.105.12", "172.31.105.13", "172.31.105.8", "172.31.105.7"]

for p in proxies:
    print(f"\n--- TARGET: {p} ---")
    cmd = f"""sudo -u squidmon scp -o StrictHostKeyChecking=no /tmp/fix_squid.sh resanul@{p}:/tmp/fix_squid.sh && sudo -u squidmon ssh -o StrictHostKeyChecking=no resanul@{p} 'echo \"@#Trust2025##\" | sudo -S /tmp/fix_squid.sh'"""
    out, err = run_sudo(cmd)
    print("OUTPUT:\n", out.strip())
    if err and 'password' not in err.lower():
        print("ERR:\n", err.strip())

ssh.close()
