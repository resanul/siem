import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##')

stdin, stdout, stderr = ssh.exec_command('python3 -c "import urllib.request; print(urllib.request.urlopen(\'http://ip-api.com/json/8.8.8.8\', timeout=2).read().decode())"')
print('IP-API response:\n', stdout.read().decode('utf-8', errors='ignore'))
ssh.close()
