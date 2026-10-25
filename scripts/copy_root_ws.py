import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

cmd = 'echo "@#Trust2025##" | sudo -S cp -r /home/resanul/.local/lib/python3.9/site-packages/websocket* /usr/local/lib/python3.9/site-packages/ 2>&1'
stdin, stdout, stderr = ssh.exec_command(cmd)
print("CP OUT:", stdout.read().decode())

stdin, stdout, stderr = ssh.exec_command("echo '@#Trust2025##' | sudo -S python3 -c 'import websocket; print(\"ROOT WEBSOCKET IMPORT SUCCESSFUL!\", websocket.__file__)'")
print("TEST ROOT IMPORT:", stdout.read().decode())

ssh.close()
