import json

with open("/tmp/nw_investigate_endpoints.txt") as f:
    raw = f.read().strip()

# SockJS frame format: a["..."]
if raw.startswith("a["):
    frames = json.loads(raw[1:])
    stomp_msg = frames[0]
else:
    stomp_msg = raw

idx = stomp_msg.find("\n\n")
body = stomp_msg[idx+2:].rstrip("\x00")
data = json.loads(body)

print("=== Investigate Endpoints (Devices) ===")
for item in data.get("data", []):
    host_info = item.get("meta", {}).get("host", {})
    print(f"Name: {item.get('displayName')} | Service: {item.get('name')} | ID: {item.get('id')} | IP: {host_info.get('ipv4')} | Port: {item.get('port')} | Version: {item.get('version')}")
