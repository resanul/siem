import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

def run_sudo(cmd):
    stdin, stdout, stderr = ssh.exec_command(f"echo @#Trust2025## | sudo -S {cmd}")
    return stdout.read().decode('utf-8', errors='replace')

print("=== 1. WAZUH AGENT CONTROL ===")
print(run_sudo("/var/ossec/bin/agent_control -l"))

print("=== 2. WAZUH ALERTS SEVERITY DISTRIBUTION (last 5000 alerts) ===")
py_script = """
import json, collections
levels = collections.Counter()
groups = collections.Counter()
mitre = collections.Counter()
total = 0
with open('/var/ossec/logs/alerts/alerts.json', 'r', errors='ignore') as f:
    for line in f:
        try:
            ev = json.loads(line)
            total += 1
            lvl = ev.get('rule', {}).get('level', 0)
            levels[lvl] += 1
            for g in ev.get('rule', {}).get('groups', []):
                groups[g] += 1
            for m in ev.get('rule', {}).get('mitre', {}).get('id', []):
                mitre[m] += 1
        except: pass
print(f'Total alerts in alerts.json: {total}')
print('Rule levels (sample):', levels.most_common(10))
print('Top groups:', groups.most_common(10))
print('Top MITRE IDs:', mitre.most_common(10))
"""
print(run_sudo(f"python3 -c \"{py_script}\""))

print("=== 3. SURICATA ALERTS & STATS ===")
suricata_script = """
import json, collections
total_eve = 0
event_types = collections.Counter()
alerts = 0
high_alerts = 0
with open('/var/log/suricata/eve.json', 'r', errors='ignore') as f:
    for line in f:
        try:
            ev = json.loads(line)
            total_eve += 1
            et = ev.get('event_type')
            event_types[et] += 1
            if et == 'alert':
                alerts += 1
                sev = ev.get('alert', {}).get('severity', 3)
                if sev <= 2:
                    high_alerts += 1
        except: pass
print(f'Total eve.json events: {total_eve}')
print('Event types:', event_types)
print(f'Suricata alerts: {alerts}, High/Critical: {high_alerts}')
"""
print(run_sudo(f"python3 -c \"{suricata_script}\""))

print("=== 4. KERNEL INTERFACE PACKET RATE (EPS calculation) ===")
print(run_sudo("cat /proc/net/dev | grep -v 'lo:'"))

ssh.close()
