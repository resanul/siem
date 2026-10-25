import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sftp = ssh.open_sftp()
for local, tmp_dest in [
    ("backend/app/services/netwitness_siem.py", "/tmp/netwitness_siem.py"),
    ("backend/app/services/event_search.py", "/tmp/event_search.py"),
    ("backend/app/api/v1/api.py", "/tmp/api.py"),
]:
    print(f"Uploading {local} -> {tmp_dest}")
    sftp.put(local, tmp_dest)
sftp.close()

# Copy to /opt/opensoc-forge and restart service
cmd = """echo "@#Trust2025##" | sudo -S cp /tmp/netwitness_siem.py /opt/opensoc-forge/backend/app/services/netwitness_siem.py && \\
echo "@#Trust2025##" | sudo -S cp /tmp/event_search.py /opt/opensoc-forge/backend/app/services/event_search.py && \\
echo "@#Trust2025##" | sudo -S cp /tmp/api.py /opt/opensoc-forge/backend/app/api/v1/api.py && \\
echo "@#Trust2025##" | sudo -S systemctl restart opensoc-forge.service
"""

stdin, stdout, stderr = ssh.exec_command(cmd)
print("Deploy stdout:", stdout.read().decode())
print("Deploy stderr:", stderr.read().decode())

time.sleep(3)

# Test new NetWitness API endpoint on localhost:7070
stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/api/v1/netwitness/status")
res = stdout.read().decode()
print("NETWITNESS STATUS API RESPONSE:\n", res[:500])

ssh.close()
