import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("ss -tlpn")
print("All listening ports:")
for line in stdout.read().decode("utf-8").splitlines():
    if any(p in line for p in ["9200", "9300", "5601", "7070", "1514", "55000", "9201"]):
        print(" ", line)

stdin, stdout, stderr = ssh.exec_command("ps aux | grep -i elastic | grep -v grep")
print("Elasticsearch process:")
print(stdout.read().decode("utf-8"))

stdin, stdout, stderr = ssh.exec_command("env | grep -i ELASTIC")
print("Environment ELASTIC:")
print(stdout.read().decode("utf-8"))

ssh.close()
