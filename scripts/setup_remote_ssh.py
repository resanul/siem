import paramiko

def main():
    with open(r'C:\Users\USER\.ssh\id_ed25519.pub', 'r') as f:
        key = f.read().strip()
    
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect('192.168.10.177', username='resanul', password='1100', timeout=5)
    
    cmd = f'mkdir -p ~/.ssh && grep -qF "{key}" ~/.ssh/authorized_keys 2>/dev/null || echo "{key}" >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'
    stdin, stdout, stderr = c.exec_command(cmd)
    stdout.channel.recv_exit_status()
    print("SSH Key authorized successfully!")
    c.close()

if __name__ == '__main__':
    main()
