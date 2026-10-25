import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sftp = ssh.open_sftp()
sftp.put("CHAT_HISTORY.md", "/tmp/CHAT_HISTORY.md")
sftp.put("docs/CHAT_HISTORY.md", "/tmp/docs_CHAT_HISTORY.md")
sftp.close()

cmd = 'echo "@#Trust2025##" | sudo -S cp /tmp/CHAT_HISTORY.md /opt/opensoc-forge/CHAT_HISTORY.md && echo "@#Trust2025##" | sudo -S cp /tmp/docs_CHAT_HISTORY.md /opt/opensoc-forge/docs/CHAT_HISTORY.md'
stdin, stdout, stderr = ssh.exec_command(cmd)
stdout.read()

ssh.close()
print("Chat histories deployed!")
