import paramiko
import time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('172.31.105.11', username='resanul', password='@#Trust2025##', timeout=10)

sftp = ssh.open_sftp()
print("Uploading NetWitness 30-day storage files...")
sftp.put('backend/app/services/netwitness_storage.py', '/tmp/netwitness_storage.py')
sftp.put('backend/app/services/netwitness_siem.py', '/tmp/netwitness_siem.py')
sftp.put('backend/app/services/retention_policy.py', '/tmp/retention_policy.py')
sftp.put('backend/app/main.py', '/tmp/main.py')
sftp.put('backend/app/api/v1/api.py', '/tmp/api.py')
sftp.put('frontend/index.html', '/tmp/index.html')
sftp.close()

sudo_cmd = """echo '@#Trust2025##' | sudo -S bash -c "
cp /tmp/netwitness_storage.py /opt/opensoc-forge/backend/app/services/netwitness_storage.py
cp /tmp/netwitness_siem.py /opt/opensoc-forge/backend/app/services/netwitness_siem.py
cp /tmp/retention_policy.py /opt/opensoc-forge/backend/app/services/retention_policy.py
cp /tmp/main.py /opt/opensoc-forge/backend/app/main.py
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
print("Deployment completed successfully!")
