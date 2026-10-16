import paramiko
import sys

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.10.177', username='resanul', password='1100', timeout=15)

    commands = [
        "echo 1100 | sudo -S chown -R resanul:resanul /home/resanul/siem",
        "git -C /home/resanul/siem pull origin master",
        "echo 1100 | sudo -S cp -rf /home/resanul/siem/backend /opt/opensoc-forge/",
        "echo 1100 | sudo -S cp -rf /home/resanul/siem/frontend /opt/opensoc-forge/",
        "echo 1100 | sudo -S podman restart opensoc-forge-mgmt",
    ]

    for c in commands:
        print(f"Executing: {c}")
        stdin, stdout, stderr = client.exec_command(c)
        status = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')
        if out:
            print("OUT:", out.strip())
        if err:
            print("ERR:", err.strip())
        if status != 0:
            print(f"Failed with exit code: {status}")
            sys.exit(status)

    print("\nDeployment successfully finished!")
    client.close()

if __name__ == '__main__':
    main()
