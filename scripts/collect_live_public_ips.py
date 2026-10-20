import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

code = """import json, socket, collections, os

dns_cache = {}
def resolve_host(host):
    if not host or host in ('-', 'localhost', 'error', '/'): return None
    host = host.split(':')[0].strip().lstrip('/')
    if not host: return None
    # Check if already IP
    parts = host.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if not (host.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.'))):
            return host
        return None
    if host in dns_cache:
        return dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
        if not ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')):
            dns_cache[host] = ip
            return ip
    except Exception:
        pass
    dns_cache[host] = None
    return None

public_ips = collections.Counter()

# 1. From eve.json
if os.path.exists('/var/log/suricata/eve.json'):
    with open('/var/log/suricata/eve.json', 'r', errors='ignore') as f:
        for line in f.readlines()[-15000:]:
            try:
                ev = json.loads(line)
                for ip in [ev.get('src_ip'), ev.get('dest_ip')]:
                    if not ip: continue
                    if not (ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) or ':' in ip):
                        public_ips[ip] += 1
            except: pass

# 2. From recent alerts.json (Squid + others)
if os.path.exists('/var/ossec/logs/alerts/alerts.json'):
    st = os.stat('/var/ossec/logs/alerts/alerts.json')
    chunk = min(st.st_size, 4194304) # last 4MB
    with open('/var/ossec/logs/alerts/alerts.json', 'r', errors='ignore') as f:
        f.seek(st.st_size - chunk)
        f.readline()
        for line in f:
            try:
                ev = json.loads(line)
                data = ev.get('data', {})
                url = data.get('url', '')
                if url:
                    resolved = resolve_host(url)
                    if resolved:
                        public_ips[resolved] += 1
                for ip in [data.get('srcip'), data.get('dstip')]:
                    if ip and not (ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) or ':' in ip):
                        public_ips[ip] += 1
            except: pass

print(f"Total live unique public IPs discovered: {len(public_ips)}")
for ip, cnt in public_ips.most_common(25):
    print(f"  {ip:20} -> {cnt:4} events")
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/run_public_ips.py', 'w') as f:
    f.write(code)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S python3 /tmp/run_public_ips.py')
print(stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
