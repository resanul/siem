import paramiko
import time
import json
import urllib.request

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

sftp = ssh.open_sftp()
print("Uploading backend/app/services/network_telemetry.py...")
sftp.put('backend/app/services/network_telemetry.py', '/tmp/network_telemetry.py')

print("Uploading frontend/index.html...")
sftp.put('frontend/index.html', '/tmp/index.html')
sftp.close()

# Copy to /opt/opensoc-forge and restart
cmd = """
echo @#Trust2025## | sudo -S cp /tmp/network_telemetry.py /opt/opensoc-forge/backend/app/services/network_telemetry.py
echo @#Trust2025## | sudo -S cp /tmp/index.html /opt/opensoc-forge/frontend/index.html
echo @#Trust2025## | sudo -S systemctl restart opensoc-forge.service
sleep 2
systemctl status opensoc-forge.service --no-pager
"""

stdin, stdout, stderr = ssh.exec_command(cmd)
out_text = stdout.read().decode('utf-8', errors='replace')
print(out_text.encode('ascii', errors='replace').decode())
err_text = stderr.read().decode('utf-8', errors='replace')
if err_text:
    print(err_text.encode('ascii', errors='replace').decode())

# Now verify the API response
print("Checking /api/v1/network/telemetry...")
time.sleep(2)
stdin, stdout, stderr = ssh.exec_command("curl -s http://127.0.0.1:7070/api/v1/network/telemetry")
resp_text = stdout.read().decode('utf-8', errors='replace')
try:
    data = json.loads(resp_text)
    map_nodes = data.get("map_nodes", [])
    metrics = data.get("metrics", {})
    public_ips = metrics.get("public_ips", {})
    print(f"Status: {data.get('status')}")
    print(f"Total Unique Public IPs: {public_ips.get('total')}")
    print(f"Source WAN IPs: {public_ips.get('source')}, Destination WAN IPs: {public_ips.get('destination')}")
    print(f"Map Nodes Rendered: {len(map_nodes)}")
    print(f"Top 10 Map Nodes:")
    for n in map_nodes[:10]:
        print(f"  - {n.get('ip')} ({n.get('domain')}): {n.get('city')}, {n.get('country')} [{n.get('lat')}, {n.get('lon')}] - {n.get('count')} events")
except Exception as e:
    print(f"Error parsing response: {e}")
    print(resp_text[:500])

ssh.close()
