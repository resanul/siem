import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sudoers_cmd = 'echo "@#Trust2025##" | sudo -S bash -c "echo \\"resanul ALL=(ALL) NOPASSWD: /usr/bin/systemctl\\" > /etc/sudoers.d/opensoc-services"'
stdin, stdout, stderr = ssh.exec_command(sudoers_cmd)
stderr.read()

stdin, stdout, stderr = ssh.exec_command("sudo /usr/bin/systemctl is-active suricata")
print("Suricata status:", stdout.read().decode("utf-8", errors="replace").strip())

stdin, stdout, stderr = ssh.exec_command("sudo /usr/bin/systemctl is-active wazuh-manager")
print("Wazuh status:", stdout.read().decode("utf-8", errors="replace").strip())

ssh.close()
