import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("rpm -qa | grep -i -E 'elastic|indexer'")
print("Installed packages:")
print(stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("systemctl list-unit-files | grep -i -E 'elastic|indexer|wazuh'")
print("Unit files:")
print(stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("find / -maxdepth 3 -name '*elastic*' 2>/dev/null")
print("Elastic files:")
print(stdout.read().decode("utf-8"))

ssh.close()
