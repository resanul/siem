import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("cat /etc/filebeat/filebeat.yml 2>/dev/null | grep -E 'hosts:|output.elasticsearch'")
print("Filebeat config:\n", stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("rpm -qa | grep -E 'filebeat|wazuh|indexer'")
print("Installed Wazuh & Elastic packages:\n", stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("grep -i -C 3 'indexer' /var/ossec/etc/ossec.conf 2>/dev/null")
print("Wazuh ossec.conf indexer ref:\n", stdout.read().decode("utf-8"))

ssh.close()
