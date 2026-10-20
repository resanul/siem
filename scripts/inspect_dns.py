import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("172.31.105.11", username="resanul", password="@#Trust2025##", timeout=10)

cmd = """python3 -c '
import json
with open("/var/log/suricata/eve.json", "r") as f:
    # read last 2000 lines
    import os
    f.seek(max(0, os.path.getsize("/var/log/suricata/eve.json") - 1000000))
    for line in f:
        try:
            ev = json.loads(line)
            if ev.get("event_type") == "dns":
                src = ev.get("src_ip")
                dst = ev.get("dest_ip")
                dns = ev.get("dns", {})
                print(f"src: {src} -> dst: {dst} | type: {dns.get(\"type\")} | query: {dns.get(\"rrname\")}")
        except:
            pass
' | tail -n 15"""

stdin, stdout, stderr = ssh.exec_command(cmd)
print("Suricata DNS lines:")
print(stdout.read().decode("utf-8"))

# Also check /etc/resolv.conf
stdin, stdout, stderr = ssh.exec_command("cat /etc/resolv.conf")
print("resolv.conf:")
print(stdout.read().decode("utf-8"))

ssh.close()
