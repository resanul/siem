import sys, paramiko
sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

script = """import json, os, time, collections

class RealtimeTelemetryCollector:
    def __init__(self, eve_path='/var/log/suricata/eve.json'):
        self.eve_path = eve_path
        self.dns_queries = set()
        self.flow_ids = set()
        self.http_count = 0
        self.tls_count = 0
        self.ssh_count = 0
        self.anomalies_count = 0
        self.hourly = collections.defaultdict(lambda: collections.Counter())
        self.private_srcs = set()
        self.private_dsts = set()
        self.external_ips = set()
        self.events_tab = []
        self.flows_tab = []
        self.dns_tab = []
        self.http_tab = []
        self.tls_tab = []
        self.anomalies_tab = []
        self.total_eve_events = 0

    def scan_initial(self, max_initial_bytes=10000000): # last 10MB
        if not os.path.exists(self.eve_path): return
        st = os.stat(self.eve_path)
        size = st.st_size
        start_pos = max(0, size - max_initial_bytes)
        with open(self.eve_path, 'r', encoding='utf-8', errors='replace') as f:
            if start_pos > 0:
                f.seek(start_pos)
                f.readline()
            for line in f:
                self._process_line(line)

    def _process_line(self, line):
        if not line.strip(): return
        try:
            ev = json.loads(line)
        except: return
        self.total_eve_events += 1
        et = ev.get('event_type')
        ts = ev.get('timestamp', '')
        hr = ts[11:13] + ':00' if len(ts) >= 13 else '12:00'
        
        fid = ev.get('flow_id')
        if fid: self.flow_ids.add(fid)
        
        src = ev.get('src_ip', '')
        dst = ev.get('dest_ip', '')
        src_port = ev.get('src_port', 0)
        dst_port = ev.get('dest_port', 0)
        proto = (ev.get('proto') or 'TCP').upper()
        
        if src.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.')):
            self.private_srcs.add(src)
        elif src:
            self.external_ips.add(src)
            
        if dst.startswith(('10.', '172.16.', '172.2', '172.3', '192.168.')):
            self.private_dsts.add(dst)
        elif dst:
            self.external_ips.add(dst)

        if et == 'dns':
            self.hourly[hr]['dns'] += 1
            dns = ev.get('dns', {})
            q = dns.get('rrname') or (dns.get('query', [{}])[0].get('rrname') if isinstance(dns.get('query'), list) and dns.get('query') else '')
            if q: self.dns_queries.add(q)
            if len(self.dns_tab) < 50:
                self.dns_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'client_ip': src,
                    'query': q,
                    'type': dns.get('rrtype', 'A'),
                    'rcode': dns.get('rcode', 'NOERROR'),
                    'server_ip': dst,
                    'vendor': 'CoreDNS / Local Resolver'
                })
        elif et == 'http':
            self.http_count += 1
            self.hourly[hr]['http'] += 1
            h = ev.get('http', {})
            if len(self.http_tab) < 50:
                self.http_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'client_ip': src,
                    'method': h.get('http_method', 'GET'),
                    'url': h.get('url', '/'),
                    'status': h.get('status', 200),
                    'user_agent': h.get('http_user_agent', 'Internal Health Probe')[:40],
                    'vendor': 'Squid Proxy / Web Gateway'
                })
        elif et == 'tls':
            self.tls_count += 1
            self.hourly[hr]['tls'] += 1
            t = ev.get('tls', {})
            if len(self.tls_tab) < 50:
                self.tls_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'client_ip': src,
                    'server_ip': dst,
                    'sni': t.get('sni', 'encrypted.tunnel'),
                    'version': t.get('version', 'TLS 1.3'),
                    'ja4': t.get('ja4', 't13d1516h2_8daaf6152771'),
                    'issuer': t.get('issuerdn', 'Enterprise CA')[:35],
                    'vendor': 'TLS Decryptor / Suricata'
                })
        elif et == 'flow':
            self.hourly[hr]['flow'] += 1
            fl = ev.get('flow', {})
            if len(self.flows_tab) < 50:
                self.flows_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'src': f'{src}:{src_port}',
                    'dst': f'{dst}:{dst_port}',
                    'proto': proto,
                    'app_proto': (ev.get('app_proto') or 'TCP').upper(),
                    'bytes_in': fl.get('bytes_toserver', 0),
                    'bytes_out': fl.get('bytes_toclient', 0),
                    'packets': fl.get('pkts_toserver', 0) + fl.get('pkts_toclient', 0),
                    'duration': f'{fl.get("age", 1):.1f}s',
                    'vendor': 'Suricata Flow Engine'
                })
        elif et == 'ssh':
            self.ssh_count += 1
            self.hourly[hr]['ssh'] += 1
        elif et == 'alert' or et == 'anomaly':
            self.anomalies_count += 1
            an = ev.get('alert', {}) or ev.get('anomaly', {})
            if len(self.anomalies_tab) < 50:
                self.anomalies_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'severity': 'HIGH',
                    'type': an.get('event', 'POLICY_ANOMALY'),
                    'src_ip': src,
                    'dst_ip': dst,
                    'desc': an.get('signature', an.get('event', 'Signature anomaly')),
                    'mitre': 'T1046: Network Service Discovery'
                })

        if src or dst:
            if len(self.events_tab) < 100:
                det = f"{et.upper()} event"
                if et == 'http': det = f"HTTP {ev.get('http',{}).get('http_method','GET')} {ev.get('http',{}).get('url','/')}"
                elif et == 'dns': det = f"DNS query {ev.get('dns',{}).get('rrname','')}"
                elif et == 'ssh': det = "SSH encrypted session"
                elif et == 'fileinfo': det = f"File: {ev.get('fileinfo',{}).get('filename','file')}"
                self.events_tab.insert(0, {
                    'timestamp': ts.replace('T', ' ')[:19],
                    'vendor': 'Suricata NIDS',
                    'action': 'network_flow' if et == 'flow' else et,
                    'proto': proto,
                    'src': f'{src}:{src_port}' if src_port else src,
                    'dst': f'{dst}:{dst_port}' if dst_port else dst,
                    'bytes': f"{ev.get('flow',{}).get('bytes_toclient', 1024):,} B",
                    'details': det
                })

t0 = time.time()
c = RealtimeTelemetryCollector()
c.scan_initial(max_initial_bytes=10000000) # 10MB
dur = time.time() - t0
print(f'Initial scan took {dur:.2f}s')
print('Total events:', c.total_eve_events)
print('Flow IDs:', len(c.flow_ids))
print('DNS queries:', len(c.dns_queries))
print('HTTP count:', c.http_count)
print('TLS count:', c.tls_count)
print('Private sources:', len(c.private_srcs))
print('Private destinations:', len(c.private_dsts))
print('External IPs:', len(c.external_ips))
"""

sftp = ssh.open_sftp()
with sftp.open('/tmp/test_collector.py', 'w') as f:
    f.write(script)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('python3 /tmp/test_collector.py')
print(stdout.read().decode('utf-8', errors='replace'))
ssh.close()
