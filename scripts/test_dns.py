import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

code = """
import socket

domains = [
    'www.google.com', 'www.bing.com', 'watson.events.data.microsoft.com',
    'safebrowsing.googleapis.com', 'api.msn.com', 'gw.bkash.com',
    'edge.microsoft.com', 'login.live.com', '4.sophosxl.net',
    'slscr.update.microsoft.com', 'assets.msn.com'
]

for d in domains:
    try:
        ip = socket.gethostbyname(d)
        print(f'{d:35} -> {ip}')
    except Exception as e:
        print(f'{d:35} -> ERROR: {e}')
"""

stdin, stdout, stderr = ssh.exec_command(f'python3 -c "{code}"')
print(stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
