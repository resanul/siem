import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

inspect_cmd = """python3 - << 'EOF'
import json
import collections

eve_file = "/var/log/suricata/eve.json"
event_counts = collections.Counter()
src_ips = collections.Counter()
dest_ips = collections.Counter()
flows = []
dns_queries = []
http_requests = []
tls_sessions = []
anomalies = []

with open(eve_file, "r") as f:
    for idx, line in enumerate(f):
        if not line.strip(): continue
        try:
            ev = json.loads(line)
        except:
            continue
        etype = ev.get("event_type", "unknown")
        event_counts[etype] += 1
        
        src = ev.get("src_ip")
        dst = ev.get("dest_ip")
        if src: src_ips[src] += 1
        if dst: dest_ips[dst] += 1
        
        if etype == "dns" and len(dns_queries) < 5:
            dns_queries.append(ev)
        elif etype == "http" and len(http_requests) < 5:
            http_requests.append(ev)
        elif etype == "tls" and len(tls_sessions) < 5:
            tls_sessions.append(ev)
        elif etype == "flow" and len(flows) < 5:
            flows.append(ev)
        elif etype == "alert" and len(anomalies) < 5:
            anomalies.append(ev)

print(f"Total lines in eve.json: {sum(event_counts.values())}")
print("Event type distribution:", dict(event_counts))
print("Top 5 Source IPs:", src_ips.most_common(5))
print("Top 5 Dest IPs:", dest_ips.most_common(5))
if dns_queries:
    print("Sample DNS query:", dns_queries[0].get("dns"))
if tls_sessions:
    print("Sample TLS session:", tls_sessions[0].get("tls"))
if flows:
    print("Sample flow:", flows[0].get("flow"))
EOF
"""

stdin, stdout, stderr = ssh.exec_command(inspect_cmd)
print(stdout.read().decode())
print("STDERR:", stderr.read().decode())
ssh.close()
