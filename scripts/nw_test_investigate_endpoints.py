import websocket
import ssl
import json
import requests
import uuid
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
conn_resp = ws.recv()
print("STOMP connect:", conn_resp[:60])

# Subscribe to /user/queue/investigate/endpoints
sub_id = "sub-endpoints"
ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/endpoints\n\n\x00"]))

# Request endpoints
ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/endpoints\ncontent-type:application/json\n\n{{}}\x00"]))

for i in range(5):
    raw = ws.recv()
    if "MESSAGE" in raw:
        print("\n=== RAW ENDPOINTS MESSAGE ===")
        print(raw[:1500])
        # save full message
        with open("/tmp/nw_investigate_endpoints.txt", "w") as f:
            f.write(raw)
        break

ws.close()
