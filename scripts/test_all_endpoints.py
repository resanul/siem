import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/api/v1/health/diagnostics")
data = json.loads(stdout.read().decode("utf-8"))
print("DIAGNOSTICS CHECKS:")
for chk in data.get("checks", []):
    print(f"  - {chk.get('target')}: status={chk.get('status')} | {chk.get('detail')}")

stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/api/v1/network/telemetry")
net = json.loads(stdout.read().decode("utf-8"))
print("NETWORK STATUS:", net.get("status"))
print("INTERFACE:", net.get("interface"))

ssh.close()
