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

# Log Concentrator ID: 1467c1d0-18f8-41fc-a7e2-a62097955f87
endpoint_id = "1467c1d0-18f8-41fc-a7e2-a62097955f87"
now = int(time.time())
past_24h = now - 86400

# Try event count with exact filter structure
count_req = {
    "filter": [
        {"field": "endpointId", "value": endpoint_id},
        {"field": "threshold", "value": 100000},
        {"field": "timeRange", "range": {"from": past_24h, "to": now}},
        {"field": "query", "value": ""},
        {"field": "searchTerm", "value": ""}
    ],
    "stream": {
        "limit": 100,
        "batch": 100
    }
}

sub_id = "sub-cnt-1"
ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/events/count\n\n\x00"]))
ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/count\ncontent-type:application/json\n\n{json.dumps(count_req)}\x00"]))

print("Sent count request...")
for _ in range(5):
    try:
        raw = ws.recv()
        print("Recv:", repr(raw[:200]))
        if "MESSAGE" in raw:
            print("\n=== GOT EVENT COUNT! ===")
            print(raw)
            break
    except Exception as e:
        print("Recv error:", e)
        break

ws.close()
