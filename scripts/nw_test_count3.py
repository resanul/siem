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
    timeout=15
)
ws.recv() # 'o'
ws.send(json.dumps([
    "CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\n"
    f"X-CSRF-TOKEN:{csrf}\nauthorization:Bearer {token}\n\n\x00"
]))
ws.recv() # CONNECTED

endpoint_id = "1467c1d0-18f8-41fc-a7e2-a62097955f87" # Log-Concentrator
now = int(time.time())
past_24h = now - 86400

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

sub_id = "sub-cnt-prog"
ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/events/count\n\n\x00"]))
ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/count\ncontent-type:application/json\n\n{json.dumps(count_req)}\x00"]))

print("Listening for stream updates...")
for i in range(15):
    raw = ws.recv()
    if raw.startswith("a["):
        frames = json.loads(raw[1:])
        stomp_msg = frames[0]
        idx = stomp_msg.find("\n\n")
        body = stomp_msg[idx+2:].rstrip("\x00")
        try:
            data = json.loads(body)
            meta = data.get("meta", {})
            print(f"Update {i}: Percent: {meta.get('percent')}% | Desc: {meta.get('description')} | Data: {data.get('data')}")
            if meta.get("percent") == "100" or data.get("data") is not None:
                print("\n=== FINAL RESULT ===")
                print(json.dumps(data, indent=2))
                break
        except Exception as e:
            print("Parse err:", e, body[:100])
    elif raw == "h": # heartbeat
        pass

ws.close()
