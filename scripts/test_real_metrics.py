import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=15)

py_code = """
with open('/proc/net/dev', 'r') as f:
    dev_lines = f.readlines()

total_rx_pkts = 0
total_tx_pkts = 0
total_rx_bytes = 0
total_tx_bytes = 0

for line in dev_lines[2:]:
    parts = line.strip().split()
    iface = parts[0].rstrip(':')
    if iface != 'lo':
        total_rx_bytes += int(parts[1])
        total_rx_pkts += int(parts[2])
        total_tx_bytes += int(parts[9])
        total_tx_pkts += int(parts[10])

total_packets = total_rx_pkts + total_tx_pkts
print(f'Real Interface Total Packets: {total_packets:,} (RX: {total_rx_pkts:,}, TX: {total_tx_pkts:,})')
print(f'Real Interface Total Bytes: {total_rx_bytes + total_tx_bytes:,}')

import subprocess
out = subprocess.check_output(['ss', '-tan', 'state', 'established']).decode().splitlines()
print(f'Active Established Sockets: {len(out) - 1}')
for s in out[1:6]:
    print(' ', s)
"""

stdin, stdout, stderr = ssh.exec_command("cat > /tmp/test_metrics.py << 'EOF'\n" + py_code + "\nEOF")
stdout.channel.recv_exit_status()

stdin, stdout, stderr = ssh.exec_command('python3 /tmp/test_metrics.py')
print(stdout.read().decode())
print("STDERR:", stderr.read().decode())

ssh.close()
