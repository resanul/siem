import os
import requests
import urllib3
urllib3.disable_warnings()

# Disable proxy for internal subnet
os.environ['NO_PROXY'] = 'localhost,127.0.0.1,172.31.*'
os.environ['no_proxy'] = 'localhost,127.0.0.1,172.31.*'

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

nodes = [
    ("Broker / SA Primary", "172.31.101.34", 50003),
    ("Log Concentrator", "172.31.101.36", 50005),
    ("Log Decoder", "172.31.101.37", 50002),
    ("Network Concentrator", "172.31.101.38", 50005),
    ("Network Decoder", "172.31.101.39", 50004),
]

session = requests.Session()
session.trust_env = False  # bypass proxies entirely!

print("=== Direct Core API Probe with Proxy Bypassed ===")

for name, host, port in nodes:
    for proto in ["https", "http"]:
        url = f"{proto}://{host}:{port}/sys/info"
        try:
            r = session.get(url, auth=(USER, PASS), verify=False, timeout=5)
            print(f"[{r.status_code}] {name} ({proto}://{host}:{port}/sys/info): {r.text[:120]}")
            if r.status_code == 200:
                break
        except Exception as e:
            print(f"ERR {name} ({proto}://{host}:{port}): {e}")
