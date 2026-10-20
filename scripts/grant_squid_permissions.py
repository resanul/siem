import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

def run_sudo(cmd):
    stdin, stdout, stderr = ssh.exec_command(f"echo '@#Trust2025##' | sudo -S bash -c \"{cmd}\"")
    out = stdout.read().decode('utf-8', errors='replace')
    return out

proxies = ["172.31.105.12", "172.31.105.13", "172.31.105.8", "172.31.105.7"]

for p in proxies:
    print(f"\n=== CHECKING & FIXING PERMISSIONS ON {p} ===")
    fix_cmd = f"""ssh -i /var/lib/squidmon/.ssh/id_ed25519 -o StrictHostKeyChecking=no resanul@{p} '
echo "@#Trust2025##" | sudo -S bash -c "
# 1. Add wazuh user to squid group
usermod -a -G squid wazuh 2>/dev/null || true
# 2. Grant ACL read permission to wazuh user on squid log directory and files
setfacl -R -m u:wazuh:rx /var/log/squid 2>/dev/null || true
setfacl -R -d -m u:wazuh:rx /var/log/squid 2>/dev/null || true
# 3. Test if wazuh can read access.log
sudo -u wazuh head -n 1 /var/log/squid/access.log 2>&1
# 4. Restart wazuh-agent to sync new agent.conf immediately
systemctl restart wazuh-agent
systemctl is-active wazuh-agent
"
' """
    out = run_sudo(fix_cmd)
    print(out)

ssh.close()
