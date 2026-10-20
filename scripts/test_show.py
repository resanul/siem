import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("sudo /usr/bin/systemctl show -p MainPID,ActiveEnterTimestamp,ActiveState suricata")
print("Suricata show:\n" + stdout.read().decode("utf-8", errors="replace"))

ssh.close()
