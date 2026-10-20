import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

code = """import json, collections, os

eve_ips = collections.Counter()
if os.path.exists('/var/log/suricata/eve.json'):
    with open('/var/log/suricata/eve.json', 'r', errors='ignore') as f:
        for line in f:
            try:
                ev = json.loads(line)
                for ip in [ev.get('src_ip'), ev.get('dest_ip')]:
                    if not ip: continue
                    if not (ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) or ':' in ip):
                        eve_ips[ip] += 1
            except: pass

alerts_ips = collections.Counter()
if os.path.exists('/var/ossec/logs/alerts/alerts.json'):
    with open('/var/ossec/logs/alerts/alerts.json', 'r', errors='ignore') as f:
        for line in f:
            try:
                ev = json.loads(line)
                data = ev.get('data', {})
                for ip in [data.get('srcip'), data.get('dstip')]:
                    if not ip: continue
                    if not (ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) or ':' in ip):
                        alerts_ips[ip] += 1
            except: pass

print(f"Unique public IPs in eve.json: {len(eve_ips)}")
print("Top in eve.json:", eve_ips.most_common(15))
print(f"Unique public IPs in alerts.json: {len(alerts_ips)}")
print("Top in alerts.json:", alerts_ips.most_common(15))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/scan_ips.py', 'w') as f:
    f.write(code)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S python3 /tmp/scan_ips.py')
print(stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
