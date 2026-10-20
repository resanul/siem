import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.12', username='resanul', password='@#Trust2025##')

stdin, stdout, stderr = ssh.exec_command('ss -tan state established')
lines = stdout.read().decode('utf-8', errors='ignore').splitlines()
ssh.close()

public_ips = set()
for l in lines[1:]:
    parts = l.split()
    if len(parts) >= 5:
        r_addr = parts[4].rsplit(':', 1)[0].strip('[]')
        if r_addr and not r_addr.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')) and ':' not in r_addr:
            public_ips.add(r_addr)

print(f"Total established external public IPs on 172.31.105.12: {len(public_ips)}")
print("Sample public IPs:", list(public_ips)[:15])
