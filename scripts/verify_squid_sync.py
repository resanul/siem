import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

def run_sudo(cmd):
    stdin, stdout, stderr = ssh.exec_command(f"echo '@#Trust2025##' | sudo -S bash -c \"{cmd}\"")
    return stdout.read().decode('utf-8', errors='replace')

print("=== CHECK ALERTS.JSON ===")
print(run_sudo("tail -n 2 /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 'No alerts.json'"))

ssh.close()
