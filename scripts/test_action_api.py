import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

# Stop suricata
cmd_stop = "curl -s -X POST -H 'Content-Type: application/json' -d '{\"action\": \"stop\"}' http://127.0.0.1:7070/api/v1/components/suricata/action"
stdin, stdout, stderr = ssh.exec_command(cmd_stop)
print("STOP API Response:", stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("systemctl is-active suricata")
print("Suricata status after stop:", stdout.read().decode("utf-8").strip())

# Start suricata
cmd_start = "curl -s -X POST -H 'Content-Type: application/json' -d '{\"action\": \"start\"}' http://127.0.0.1:7070/api/v1/components/suricata/action"
stdin, stdout, stderr = ssh.exec_command(cmd_start)
print("START API Response:", stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("systemctl is-active suricata")
print("Suricata status after start:", stdout.read().decode("utf-8").strip())

ssh.close()
