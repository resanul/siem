import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

stdin, stdout, stderr = ssh.exec_command("ls -la /opt/opensoc-forge/configs/netwitness*")
print("LS OUTPUT:\n", stdout.read().decode())

stdin, stdout, stderr = ssh.exec_command("python3 -c 'from backend.app.services.event_search import event_search_service; from backend.app.models.schemas import EventSearchRequest; res = event_search_service.search_events(EventSearchRequest(query=\"\", time_range=\"all\", limit=10)); print(\"Total:\", res.total_hits, \"Events:\", len(res.events)); nw = [e for e in res.events if \"netwitness\" in e.index]; print(\"NW:\", len(nw))'")
print("PYTHON TEST:\n", stdout.read().decode(), stderr.read().decode())

ssh.close()
