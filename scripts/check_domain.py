import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command('grep -m 2 "challenges.cloudflare.com" /var/ossec/logs/alerts/alerts.json')
print("alerts.json match:")
print(stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command('grep -m 2 "challenges.cloudflare.com" /var/log/suricata/eve.json')
print("eve.json match:")
print(stdout.read().decode("utf-8"))

ssh.close()
