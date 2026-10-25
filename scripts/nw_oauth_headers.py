import requests
import json
import urllib3
urllib3.disable_warnings()

s = requests.Session()
s.trust_env = False
s.verify = False

resp = s.post("https://172.31.101.34/oauth/token", data={
    "grant_type": "password",
    "username": "resanul",
    "password": "CF!WF*$zRvAKh*R7Pv^9",
    "client_id": "netwitness"
}, headers={"Content-Type": "application/x-www-form-urlencoded"})

print("OAuth Response Status:", resp.status_code)
print("OAuth Response Headers:")
for k, v in resp.headers.items():
    print(f"  {k}: {v}")
