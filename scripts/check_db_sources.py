import paramiko

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect('192.168.10.177', username='resanul', password='1100')

    cmd = "echo 1100 | sudo -S podman exec opensoc-forge-mgmt python3 -c 'import sqlite3; conn=sqlite3.connect(\"/var/lib/opensoc/threat_intel_iocs.db\"); print(conn.cursor().execute(\"SELECT source, count(*) FROM iocs GROUP BY source\").fetchall())'"
    stdin, stdout, stderr = c.exec_command(cmd)
    print("STDOUT:", stdout.read().decode())
    print("STDERR:", stderr.read().decode())
    c.close()

if __name__ == '__main__':
    main()
