import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

# Tail stats.log
stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S tail -n 25 /var/log/suricata/stats.log')
print("--- LATEST SURICATA STATS.LOG ---")
print(stdout.read().decode())

# Tail eve.json
stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S tail -n 5 /var/log/suricata/eve.json')
print("--- LATEST EVE.JSON ---")
print(stdout.read().decode())

# Check interface traffic counters via /proc/net/dev or ip -s link
stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S cat /proc/net/dev')
print("--- INTERFACE COUNTERS ---")
print(stdout.read().decode())

ssh.close()
