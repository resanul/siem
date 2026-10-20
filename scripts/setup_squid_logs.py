import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

def run_sudo(cmd):
    stdin, stdout, stderr = ssh.exec_command(f"echo '@#Trust2025##' | sudo -S bash -c \"{cmd}\"")
    out = stdout.read().decode('utf-8', errors='replace')
    err = stderr.read().decode('utf-8', errors='replace')
    return out, err

print("=== 1. CHECK GROUPS ===")
out, _ = run_sudo("/var/ossec/bin/agent_groups -l 2>/dev/null || true")
print(out)

print("=== 2. WRITE CENTRALIZED AGENT.CONF ===")
agent_conf_content = """<agent_config os="Linux">
  <!-- Squid Proxy Access & Cache Log Ingestion -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/squid/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/squid/cache.log</location>
  </localfile>
</agent_config>
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/agent.conf', 'w') as f:
    f.write(agent_conf_content)
sftp.close()

out, _ = run_sudo("""
cp -f /tmp/agent.conf /var/ossec/etc/shared/default/agent.conf
chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf
chmod 660 /var/ossec/etc/shared/default/agent.conf
/var/ossec/bin/verify-agent-conf
echo "Agent conf verification completed."
""")
print(out)

print("=== 3. RESTART WAZUH MANAGER SERVICE ===")
out, _ = run_sudo("""
systemctl restart wazuh-manager
sleep 2
systemctl is-active wazuh-manager
""")
print(out)

print("=== 4. TEST SSH CONNECTIVITY TO THE 4 PROXY SERVERS FROM 105.11 ===")
proxies = ["172.31.105.12", "172.31.105.13", "172.31.105.8", "172.31.105.7"]
for p in proxies:
    check_cmd = f"ssh -i /var/lib/squidmon/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o ConnectTimeout=3 resanul@{p} 'id; ls -ld /var/log/squid; ls -la /var/log/squid/access.log' 2>&1 || true"
    out, _ = run_sudo(check_cmd)
    print(f"[{p}] -> {out.strip()}")

ssh.close()
