import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=10)

sftp = ssh.open_sftp()
print("Uploading threat_news_service.py, api.py, and frontend/index.html...")
sftp.put('backend/app/services/threat_news_service.py', '/tmp/threat_news_service.py')
sftp.put('backend/app/api/v1/api.py', '/tmp/api.py')
sftp.put('frontend/index.html', '/tmp/index.html')
sftp.close()

sudo_cmd = """echo '@#Trust2025##' | sudo -S bash -c "
cp /tmp/threat_news_service.py /opt/opensoc-forge/backend/app/services/threat_news_service.py
cp /tmp/api.py /opt/opensoc-forge/backend/app/api/v1/api.py
cp /tmp/index.html /opt/opensoc-forge/frontend/index.html
chown -R resanul:resanul /opt/opensoc-forge
systemctl restart opensoc-forge
sleep 2
systemctl is-active opensoc-forge
" """

stdin, stdout, stderr = ssh.exec_command(sudo_cmd)
print("Sudo output:", stdout.read().decode('utf-8'))
print("Sudo error:", stderr.read().decode('utf-8'))

ssh.close()
print("Threat news deployment completed successfully!")
