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
    timeout=20
)
ws.recv()
ws.send(json.dumps([
    "CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\n"
    f"X-CSRF-TOKEN:{csrf}\nauthorization:Bearer {token}\n\n\x00"
]))
ws.recv()

# Network Concentrator ID: f3574b67-5559-483c-8a01-e6add64b2c20
net_endpoint_id = "f3574b67-5559-483c-8a01-e6add64b2c20"
now = int(time.time())
past_24h = now - 86400

net_stream_req = {
    "filter": [
        {"field": "endpointId", "value": net_endpoint_id},
        {"field": "timeRange", "range": {"from": past_24h, "to": now}},
        {"field": "query", "value": ""},
        {"field": "searchTerm", "value": ""}
    ],
    "stream": {
        "limit": 10,
        "batch": 10
    }
}

sub_id = "sub-net-stream"
ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/events\n\n\x00"]))
ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/stream\ncontent-type:application/json\n\n{json.dumps(net_stream_req)}\x00"]))

events = []
for _ in range(10):
    raw = ws.recv()
    if raw.startswith("a["):
        frames = json.loads(raw[1:])
        stomp_msg = frames[0]
        idx = stomp_msg.find("\n\n")
        body = stomp_msg[idx+2:].rstrip("\x00")
        try:
            msg_obj = json.loads(body)
            data = msg_obj.get("data")
            if isinstance(data, list) and len(data) > 0:
                events.extend(data)
                print(f"Network Concentrator events sample: {len(data)}")
                print(json.dumps(data[0], indent=2))
                break
        except:
            pass

ws.close()
