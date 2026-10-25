import websocket
import ssl
import json
import requests
import uuid
import time
import urllib3
urllib3.disable_warnings()

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

s = requests.Session()
s.trust_env = False
s.verify = False

oauth_resp = s.post(f"https://{NW_HOST}/oauth/token", data={
    "grant_type": "password",
    "username": USER,
    "password": PASS,
    "client_id": "netwitness"
}, headers={"Content-Type": "application/x-www-form-urlencoded"})

token = oauth_resp.json()["access_token"]
csrf = oauth_resp.headers.get("X-CSRF-TOKEN")
cookie_str = "; ".join([f"{k}={v}" for k, v in s.cookies.get_dict().items()])

ws_url = f"wss://{NW_HOST}/api/investigate/socket/000/{uuid.uuid4().hex[:8]}/websocket"
ws = websocket.create_connection(
    ws_url,
    sslopt={"cert_reqs": ssl.CERT_NONE},
    header=[
        f"Cookie: {cookie_str}",
        f"X-CSRF-TOKEN: {csrf}",
        f"authorization: Bearer {token}",
        "User-Agent: Mozilla/5.0"
    ],
    timeout=10
)
ws.recv() # SockJS 'o'
ws.send(json.dumps([
    "CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\n"
    f"X-CSRF-TOKEN:{csrf}\nauthorization:Bearer {token}\n\n\x00"
]))
ws.recv() # CONNECTED

# 1. Test event count on Log-Concentrator
# Service ID of Log Concentrator: 1467c1d0-18f8-41fc-a7e2-a62097955f87
now = int(time.time())
past_24h = now - 86400

count_payload = {
    "serviceId": "1467c1d0-18f8-41fc-a7e2-a62097955f87",
    "query": "",
    "startTime": past_24h,
    "endTime": now
}

ws.send(json.dumps(["SUBSCRIBE\nid:sub-count\ndestination:/user/queue/investigate/events/count\n\n\x00"]))
ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/count\ncontent-type:application/json\n\n{json.dumps(count_payload)}\x00"]))

print("Sent count request for past 24 hours...")
for _ in range(5):
    raw = ws.recv()
    if "MESSAGE" in raw:
        print("Received Count Response:", raw[:500])
        break

ws.close()
