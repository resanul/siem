import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

script = """import os, re, json, collections

print("=== 1. SURICATA STATS.LOG ===")
if os.path.exists('/var/log/suricata/stats.log'):
    with open('/var/log/suricata/stats.log', 'r') as f:
        lines = f.readlines()[-300:]
        for l in lines:
            if any(k in l for k in ['capture.kernel_packets', 'capture.kernel_drops', 'decoder.pkts', 'flow.tcp', 'flow.udp', 'app_layer.flow.http', 'app_layer.flow.tls', 'app_layer.flow.dns', 'detect.alerts']):
                print(l.strip())

print("\\n=== 2. REAL EVE.JSON ===")
if os.path.exists('/var/log/suricata/eve.json'):
    event_counts = collections.Counter()
    flows = set()
    dns_queries = set()
    http_uris = []
    tls_snis = []
    external_ips = collections.Counter()
    private_srcs = set()
    private_dsts = set()

    with open('/var/log/suricata/eve.json', 'r') as f:
        lines = f.readlines()[-10000:]
        for line in lines:
            try:
                ev = json.loads(line)
            except: continue
            et = ev.get('event_type')
            event_counts[et] += 1
            fid = ev.get('flow_id')
            if fid: flows.add(fid)
            
            src = ev.get('src_ip', '')
            dst = ev.get('dest_ip', '')
            for ip in [src, dst]:
                if ip.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.')):
                    if ip == src: private_srcs.add(ip)
                    else: private_dsts.add(ip)
                elif ip and not ip.startswith(('127.', '0.', '255.')):
                    external_ips[ip] += 1
                    
            if et == 'dns':
                dns = ev.get('dns', {})
                rr = dns.get('rrname') or (dns.get('query', [{}])[0].get('rrname') if isinstance(dns.get('query'), list) and dns.get('query') else '')
                if rr: dns_queries.add(rr)
            elif et == 'http':
                h = ev.get('http', {})
                if h.get('url'): http_uris.append(h.get('url'))
            elif et == 'tls':
                t = ev.get('tls', {})
                if t.get('sni'): tls_snis.append(t.get('sni'))

    print('Event Types in last 10k lines:', dict(event_counts))
    print('Unique flows in sample:', len(flows))
    print('Unique DNS queries in sample:', len(dns_queries), list(dns_queries)[:5])
    print('HTTP URIs count:', len(http_uris), http_uris[:3])
    print('TLS SNIs count:', len(tls_snis), tls_snis[:3])
    print('Top external IPs:', external_ips.most_common(10))
    print('Private sources:', list(private_srcs))
    print('Private destinations:', list(private_dsts))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/inspect_stats.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('echo \'@#Trust2025##\' | sudo -S python3 /tmp/inspect_stats.py')
out = stdout.read().decode('utf-8', errors='replace')
err = stderr.read().decode('utf-8', errors='replace')
print("STDOUT:\n" + out)
if err and 'password' not in err.lower():
    print("STDERR:\n" + err)
ssh.close()
