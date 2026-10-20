import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

code = """
import json, collections
ips = collections.Counter()
with open('/var/log/suricata/eve.json') as f:
    lines = f.readlines()
    for l in lines[-20000:]:
        try:
            ev = json.loads(l)
            for ip in [ev.get('src_ip'), ev.get('dest_ip')]:
                if not ip: continue
                if not (ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) or ':' in ip):
                    ips[ip] += 1
        except: pass
print('Public IPs in last 20k eve.json lines:', len(ips))
print(ips.most_common(20))
"""

stdin, stdout, stderr = ssh.exec_command(f'python3 -c "{code}"')
print(stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
