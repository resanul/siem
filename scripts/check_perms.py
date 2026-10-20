import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S ls -la /var/log/suricata/eve.json /var/log/suricata/')
print(stdout.read().decode())

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S cat /etc/systemd/system/opensoc-forge.service')
print("--- OPENSOC-FORGE.SERVICE ---")
print(stdout.read().decode())

ssh.close()
