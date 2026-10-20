import time
import json
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)
sftp = ssh.open_sftp()

print("Uploading live_telemetry.py...")
sftp.put("backend/app/services/live_telemetry.py", "/tmp/live_telemetry.py")

print("Uploading network_telemetry.py...")
sftp.put("backend/app/services/network_telemetry.py", "/tmp/network_telemetry.py")

print("Uploading api.py...")
sftp.put("backend/app/api/v1/api.py", "/tmp/api.py")

print("Uploading index.html...")
sftp.put("frontend/index.html", "/tmp/index.html")
sftp.close()

# Move into place using sudo and restart opensoc-forge
cmd = 'echo "@#Trust2025##" | sudo -S cp /tmp/live_telemetry.py /opt/opensoc-forge/backend/app/services/live_telemetry.py && echo "@#Trust2025##" | sudo -S cp /tmp/network_telemetry.py /opt/opensoc-forge/backend/app/services/network_telemetry.py && echo "@#Trust2025##" | sudo -S cp /tmp/api.py /opt/opensoc-forge/backend/app/api/v1/api.py && echo "@#Trust2025##" | sudo -S cp /tmp/index.html /opt/opensoc-forge/frontend/index.html && echo "@#Trust2025##" | sudo -S systemctl restart opensoc-forge.service'

stdin, stdout, stderr = ssh.exec_command(cmd)
print("Deploy stdout:", stdout.read().decode("utf-8"))
print("Deploy stderr:", stderr.read().decode("utf-8"))

time.sleep(2)

# Verify /api/v1/overview components
stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/api/v1/overview")
res_str = stdout.read().decode("utf-8")
try:
    data = json.loads(res_str)
    print("STATUS:", data.get("status"))
    print("COMPONENTS:")
    for c in data.get("components", []):
        print(f"  - {c.get('name')}: status={c.get('status')} | enabled={c.get('enabled')}")
except Exception as e:
    print("Raw output:", res_str[:500])

ssh.close()
