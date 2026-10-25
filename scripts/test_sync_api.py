import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("curl -s -X POST 'http://127.0.0.1:7070/api/v1/netwitness/sync?log_limit=50&net_limit=30'", timeout=45)
res = stdout.read().decode()
print("SYNC API RESPONSE:\n", res)

stdin, stdout, stderr = ssh.exec_command("curl -s 'http://127.0.0.1:7070/api/v1/events/search?query=NetWitness&limit=5'")
ev_res = stdout.read().decode()
print("\nEVENT SEARCH WITH NETWITNESS QUERY:\n", ev_res[:600])

ssh.close()
