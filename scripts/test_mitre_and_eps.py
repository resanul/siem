import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

py_cmd = '''import os, glob, xml.etree.ElementTree as ET, time

# 1. Total Unique MITRE ATT&CK Techniques in Wazuh & Suricata rules
mitre_ids = set()
for rpath in glob.glob('/var/ossec/ruleset/rules/*.xml') + glob.glob('/var/ossec/etc/rules/*.xml'):
    try:
        tree = ET.parse(rpath)
        for mitre in tree.findall('.//mitre/id'):
            if mitre.text:
                mitre_ids.add(mitre.text.strip())
    except: pass

print(f"Total Unique MITRE ATT&CK Techniques in rules: {len(mitre_ids)}")

# 2. Real EPS Calculation (measure over 1.0 second)
def get_packet_and_log_count():
    pkts = 0
    try:
        with open('/proc/net/dev') as f:
            for l in f.readlines()[2:]:
                parts = l.strip().split()
                if len(parts) >= 11 and parts[0] != 'lo:':
                    pkts += int(parts[2]) + int(parts[10])
    except: pass
    alert_lines = 0
    try:
        alert_lines = os.stat('/var/ossec/logs/alerts/alerts.json').st_size
    except: pass
    return pkts, alert_lines

p1, a1 = get_packet_and_log_count()
time.sleep(1.0)
p2, a2 = get_packet_and_log_count()

pkt_eps = p2 - p1
# Average log line size is ~300 bytes
log_eps = (a2 - a1) / 300.0
total_real_eps = round(pkt_eps * 0.1 + log_eps, 1)
print(f"Packet delta/s: {pkt_eps}, Log size delta/s: {a2 - a1} B, Estimated real EPS: {total_real_eps}")
'''

sftp = ssh.open_sftp()
with sftp.file('/tmp/test_wazuh_real.py', 'w') as f:
    f.write(py_cmd)
sftp.close()

stdin, stdout, stderr = ssh.exec_command('echo @#Trust2025## | sudo -S python3 /tmp/test_wazuh_real.py')
print(stdout.read().decode())
print(stderr.read().decode())
ssh.close()
