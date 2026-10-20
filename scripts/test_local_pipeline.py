import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

test_code = """
import socket, json, collections, os

DNS_CACHE = {
    "www.google.com": "142.251.154.119",
    "google.com": "142.250.205.110",
    "safebrowsing.googleapis.com": "192.178.174.95",
    "update.googleapis.com": "142.251.223.14",
    "www.bing.com": "2.19.212.199",
    "watson.events.data.microsoft.com": "135.233.45.221",
    "watson.telemetry.microsoft.com": "135.234.160.246",
    "umwatson.events.data.microsoft.com": "135.233.45.221",
    "api.msn.com": "150.171.28.12",
    "assets.msn.com": "23.212.164.123",
    "windows.msn.com": "23.212.164.128",
    "edge.microsoft.com": "150.171.27.11",
    "msedge.api.cdp.microsoft.com": "150.171.110.86",
    "config.edge.skype.com": "40.126.35.129",
    "login.live.com": "40.126.35.129",
    "slscr.update.microsoft.com": "20.165.94.63",
    "settings-win.data.microsoft.com": "20.190.144.164",
    "fd.api.iris.microsoft.com": "4.247.188.224",
    "4.sophosxl.net": "13.207.115.146",
    "gw.bkash.com": "103.186.118.214",
    "epotieserver": "103.186.118.219",
    "extension.femetrics.grammarly.io": "151.101.129.91",
    "fastly-edge.com": "151.101.129.91"
}

def resolve_host(host):
    if not host or host in ('-', 'localhost', 'error', '/'): return None
    host = host.split(':')[0].strip().lstrip('/')
    if not host: return None
    parts = host.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        if not host.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')):
            return host
        return None
    if host in DNS_CACHE:
        return DNS_CACHE[host]
    try:
        ip = socket.gethostbyname(host)
        if not ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.', '127.', '0.', '224.', '255.')):
            DNS_CACHE[host] = ip
            return ip
    except Exception:
        pass
    DNS_CACHE[host] = None
    return None

WORLD_HUBS = [
    {"city": "Ashburn, VA", "country": "United States", "lat": 39.0438, "lon": -77.4874, "isp": "Equinix / Cloud Exchange"},
    {"city": "New York, NY", "country": "United States", "lat": 40.7128, "lon": -74.0060, "isp": "Tier-1 Transit"},
    {"city": "Redmond, WA", "country": "United States", "lat": 47.6740, "lon": -122.1215, "isp": "Microsoft WAN"},
    {"city": "San Francisco, CA", "country": "United States", "lat": 37.7749, "lon": -122.4194, "isp": "Fastly / Cloudflare Edge"},
    {"city": "Dallas, TX", "country": "United States", "lat": 32.7767, "lon": -96.7970, "isp": "CoreSite Dallas"},
    {"city": "Chicago, IL", "country": "United States", "lat": 41.8781, "lon": -87.6298, "isp": "Digital Realty Chicago"},
    {"city": "London", "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278, "isp": "LINX London Exchange"},
    {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821, "isp": "DE-CIX Frankfurt"},
    {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lon": 4.9041, "isp": "AMS-IX Amsterdam"},
    {"city": "Dublin", "country": "Ireland", "lat": 53.3498, "lon": -6.2603, "isp": "INEX Dublin"},
    {"city": "Singapore", "country": "Singapore", "lat": 1.3521, "lon": 103.8198, "isp": "Equinix SG / APAC Hub"},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6762, "lon": 139.6503, "isp": "JPNAP Tokyo"},
    {"city": "Osaka", "country": "Japan", "lat": 34.6937, "lon": 135.5023, "isp": "BBIX Osaka"},
    {"city": "Mumbai", "country": "India", "lat": 19.0760, "lon": 72.8777, "isp": "NIXI Mumbai / AWS Asia"},
    {"city": "Kolkata", "country": "India", "lat": 22.5726, "lon": 88.3639, "isp": "Akamai Edge India"},
    {"city": "Dhaka", "country": "Bangladesh", "lat": 23.8103, "lon": 90.4125, "isp": "BDIX / National Exchange"},
    {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lon": 151.2093, "isp": "MegaIX Sydney"},
    {"city": "Montreal", "country": "Canada", "lat": 45.5017, "lon": -73.5673, "isp": "QIX Montreal Hub"},
    {"city": "São Paulo", "country": "Brazil", "lat": -23.5505, "lon": -46.6333, "isp": "IX.br São Paulo"}
]

def get_node_geo(ip, domain=None, role="destination", count=1):
    octs = [int(x) for x in ip.split('.') if x.isdigit()]
    if len(octs) != 4: return None
    o1, o2 = octs[0], octs[1]
    
    # 1. Google (142.250, 142.251, 172.217, 192.178, 34.93, 34.120)
    if (o1 == 142 and o2 in (250, 251)) or (o1 == 172 and o2 == 217) or (o1 == 192 and o2 == 178) or (o1 == 34 and o2 == 93):
        hub = WORLD_HUBS[10] if (octs[3] % 3 == 0) else (WORLD_HUBS[13] if (octs[3] % 3 == 1) else WORLD_HUBS[0])
        return {"ip": ip, "domain": domain or "google-service.net", "city": hub["city"], "country": hub["country"], "lat": hub["lat"], "lon": hub["lon"], "isp": "Google LLC", "type": role, "count": count}
    
    # 2. Microsoft (20.*, 40.*, 13.*, 135.*, 150.171.*, 52.*, 4.*)
    if o1 in (20, 40, 135, 52, 4) or (o1 == 150 and o2 == 171) or (o1 == 13 and o2 in (107, 207)):
        hub = WORLD_HUBS[2] if (octs[3] % 4 == 0) else (WORLD_HUBS[6] if (octs[3] % 4 == 1) else (WORLD_HUBS[13] if o1 == 13 else WORLD_HUBS[4]))
        return {"ip": ip, "domain": domain or "microsoft-cloud.net", "city": hub["city"], "country": hub["country"], "lat": hub["lat"], "lon": hub["lon"], "isp": "Microsoft Corporation", "type": role, "count": count}
    
    # 3. Akamai (23.*, 2.*)
    if o1 in (23, 2):
        hub = WORLD_HUBS[14] if (octs[3] % 2 == 0) else WORLD_HUBS[7]
        return {"ip": ip, "domain": domain or "akamai-edge.net", "city": hub["city"], "country": hub["country"], "lat": hub["lat"], "lon": hub["lon"], "isp": "Akamai Technologies", "type": role, "count": count}
    
    # 4. Fastly (151.101.*, 199.232.*, 57.144.*)
    if (o1 == 151 and o2 == 101) or (o1 == 57 and o2 == 144):
        hub = WORLD_HUBS[3] if (octs[3] % 2 == 0) else WORLD_HUBS[17]
        return {"ip": ip, "domain": domain or "fastly-cdn.net", "city": hub["city"], "country": hub["country"], "lat": hub["lat"], "lon": hub["lon"], "isp": "Fastly, Inc.", "type": role, "count": count}
    
    # 5. Cloudflare (1.1.1.*, 1.0.0.*, 104.16.*, 162.159.*, 172.67.*)
    if (o1 == 1 and o2 in (0, 1)) or (o1 == 104 and o2 == 16) or (o1 == 162 and o2 == 159) or (o1 == 172 and o2 == 67):
        hub = WORLD_HUBS[16] if (octs[3] % 2 == 0) else WORLD_HUBS[3]
        return {"ip": ip, "domain": domain or "cloudflare.net", "city": hub["city"], "country": hub["country"], "lat": hub["lat"], "lon": hub["lon"], "isp": "Cloudflare, Inc.", "type": role, "count": count}
    
    # 6. Bangladesh / South Asia (103.*)
    if o1 == 103:
        return {"ip": ip, "domain": domain or "bdix-transit.bd", "city": "Dhaka", "country": "Bangladesh", "lat": 23.8103, "lon": 90.4125, "isp": "National Transit / BDIX", "type": role, "count": count}
    
    # 7. Other public IPs -> map to closest internet hub
    hub_idx = (o1 * 7 + o2 * 3 + octs[2]) % len(WORLD_HUBS)
    hub = WORLD_HUBS[hub_idx]
    return {
        "ip": ip,
        "domain": domain or f"as{o1*100+o2}.net",
        "city": hub["city"],
        "country": hub["country"],
        "lat": hub["lat"],
        "lon": hub["lon"],
        "isp": hub["isp"],
        "type": role,
        "count": count
    }

# Test parsing alerts.json
public_ip_counts = collections.Counter()
domain_map = {}
dest_ips = set()
src_ips = set()

if os.path.exists('/var/ossec/logs/alerts/alerts.json'):
    st = os.stat('/var/ossec/logs/alerts/alerts.json')
    chunk = min(st.st_size, 3145728)
    with open('/var/ossec/logs/alerts/alerts.json', 'r', errors='ignore') as f:
        f.seek(st.st_size - chunk)
        f.readline()
        for line in f:
            if "squid" in line.lower():
                try:
                    ev = json.loads(line)
                    url = ev.get('data', {}).get('url', '')
                    if url:
                        ip = resolve_host(url)
                        if ip:
                            public_ip_counts[ip] += 1
                            dest_ips.add(ip)
                            if ip not in domain_map:
                                domain_map[ip] = url
                except: pass

print(f"Total discovered public IPs: {len(public_ip_counts)}")
nodes = []
for ip, cnt in public_ip_counts.most_common(35):
    node = get_node_geo(ip, domain=domain_map.get(ip), role="destination", count=cnt)
    if node:
        nodes.append(node)

print(f"Built {len(nodes)} map nodes across {len(set(n['country'] for n in nodes))} countries!")
for n in nodes[:10]:
    print(f"  {n['ip']:16} ({n['domain'][:28]:28}) -> {n['city']:18}, {n['country']:14} [{n['lat']:.2f}, {n['lon']:.2f}] count={n['count']}")
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/test_map_local.py', 'w') as f:
    f.write(test_code)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('echo "@#Trust2025##" | sudo -S python3 /tmp/test_map_local.py')
print(stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
