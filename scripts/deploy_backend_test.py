import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

sftp = ssh.open_sftp()
for local, remote in [
    ("backend/app/services/netwitness_siem.py", "/opt/opensoc-forge/backend/app/services/netwitness_siem.py"),
    ("backend/app/services/event_search.py", "/opt/opensoc-forge/backend/app/services/event_search.py"),
    ("backend/app/api/v1/api.py", "/opt/opensoc-forge/backend/app/api/v1/api.py")
]:
    print(f"Uploading {local} -> {remote}")
    sftp.put(local, remote)
sftp.close()

# Test import and sync
stdin, stdout, stderr = ssh.exec_command("python3 -c 'from backend.app.services.netwitness_siem import netwitness_client; res = netwitness_client.sync_to_opensoc(log_limit=20, net_limit=10); print(res)'", timeout=30)
out = stdout.read().decode()
err = stderr.read().decode()
print("SYNC RESULT:\n", out)
if err:
    print("SYNC ERROR:\n", err)

ssh.close()
