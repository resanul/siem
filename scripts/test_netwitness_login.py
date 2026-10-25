import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sftp = ssh.open_sftp()
sftp.put("scripts/nw_survey_net.py", "/tmp/nw_survey_net.py")
sftp.close()

stdin, stdout, stderr = ssh.exec_command("python3 /tmp/nw_survey_net.py")
out = stdout.read().decode()
err = stderr.read().decode()
print("STDOUT:\n", out)
if err:
    print("STDERR:\n", err)

ssh.close()
