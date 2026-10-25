import requests
import json
import uuid
import urllib3
urllib3.disable_warnings()

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

s = requests.Session()
s.trust_env = False
s.verify = False

# 1. OAuth
oauth_resp = s.post(f"https://{NW_HOST}/oauth/token", data={
    "grant_type": "password",
    "username": USER,
    "password": PASS,
    "client_id": "netwitness"
}, headers={"Content-Type": "application/x-www-form-urlencoded"})

token = oauth_resp.json()["access_token"]

# 2. Form login
s.post(f"https://{NW_HOST}/j_spring_security_check", data={
    "username": USER,
    "password": PASS,
    "submit": "Login"
}, headers={"User-Agent": "Mozilla/5.0"})

csrf = s.cookies.get("CSRF-TOKEN", "")
print("CSRF Token:", csrf)

# Set common headers
headers = {
    "X-CSRF-TOKEN": csrf,
    "X-XSRF-TOKEN": csrf,
    "rsa-x-csrf-token": csrf,
    "Authorization": f"Bearer {token}",
    "User-Agent": "Mozilla/5.0",
}

server_id = "000"
session_id = uuid.uuid4().hex[:8]

# SockJS open connection
r_open = s.post(f"https://{NW_HOST}/api/administration/socket/{server_id}/{session_id}/xhr", headers=headers, timeout=5)
print("XHR open status:", r_open.status_code, "text:", repr(r_open.text[:200]))

# STOMP CONNECT frame
stomp_connect = f"CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\nAuthorization:Bearer {token}\n\n\x00"
send_url = f"https://{NW_HOST}/api/administration/socket/{server_id}/{session_id}/xhr_send"
r_send = s.post(send_url, data=json.dumps([stomp_connect]), headers={**headers, "Content-Type": "text/plain;charset=UTF-8"})
print("STOMP connect send status:", r_send.status_code, "text:", r_send.text)

r_poll = s.post(f"https://{NW_HOST}/api/administration/socket/{server_id}/{session_id}/xhr", headers=headers, timeout=5)
print("STOMP connect poll status:", r_poll.status_code, "text:", repr(r_poll.text[:300]))
