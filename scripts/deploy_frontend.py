import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sftp = ssh.open_sftp()
print("Uploading frontend/index.html...")
sftp.put("frontend/index.html", "/tmp/index.html")
sftp.close()

cmd = 'echo "@#Trust2025##" | sudo -S cp /tmp/index.html /opt/opensoc-forge/frontend/index.html && echo "@#Trust2025##" | sudo -S systemctl restart opensoc-forge.service'
stdin, stdout, stderr = ssh.exec_command(cmd)
print("Deploy stdout:", stdout.read().decode())
print("Deploy stderr:", stderr.read().decode())

time.sleep(3)

# Verify HTTP 200 and presence of RSA NetWitness SIEM
stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/ | grep -o 'RSA NetWitness SIEM'")
print("CURL CHECK:", stdout.read().decode())

ssh.close()
