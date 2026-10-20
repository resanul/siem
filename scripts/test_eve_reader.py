import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

py_code = """
import json
import os
import time

eve_file = "/var/log/suricata/eve.json"
t0 = time.time()
file_size = os.path.getsize(eve_file)
read_bytes = min(file_size, 1024 * 1024)

with open(eve_file, "r", encoding="utf-8", errors="replace") as f:
    f.seek(file_size - read_bytes)
    f.readline()
    lines = f.readlines()

print(f"Read {len(lines)} lines in {(time.time() - t0)*1000:.1f}ms")

types = {}
for line in lines:
    try:
        ev = json.loads(line)
        et = ev.get("event_type", "other")
        types[et] = types.get(et, 0) + 1
    except:
        pass

print("Event types in last 1MB:", types)
"""

stdin, stdout, stderr = ssh.exec_command("cat > /tmp/test_eve.py << 'EOF'\n" + py_code + "\nEOF")
stdout.channel.recv_exit_status()

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S python3 /tmp/test_eve.py')
print(stdout.read().decode())
print("STDERR:", stderr.read().decode())

ssh.close()
