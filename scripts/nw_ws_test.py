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

# 1. OAuth
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
print("OAuth Token acquired.")

# 2. Form login
s.post(f"https://{NW_HOST}/j_spring_security_check", data={
    "username": USER,
    "password": PASS,
    "submit": "Login"
}, headers={"User-Agent": "Mozilla/5.0"})

cookie_str = "; ".join([f"{k}={v}" for k, v in s.cookies.get_dict().items()])

# 3. SockJS WebSocket URL
server_id = "123"
session_id = uuid.uuid4().hex[:8]
ws_url = f"wss://{NW_HOST}/api/administration/socket/{server_id}/{session_id}/websocket"

print("Connecting to:", ws_url)
ws = websocket.create_connection(
    ws_url,
    sslopt={"cert_reqs": ssl.CERT_NONE},
    header=[
        f"Cookie: {cookie_str}",
        f"Authorization: Bearer {token}",
        "User-Agent: Mozilla/5.0"
    ],
    timeout=5
)

print("WebSocket connection opened successfully!")

# Receive SockJS open frame 'o'
msg = ws.recv()
print("SockJS Initial frame:", repr(msg))

# Send STOMP CONNECT frame
stomp_connect = f"CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\nAuthorization:Bearer {token}\n\n\x00"
# In SockJS, client sends json array of strings: '["CONNECT..."]'
ws.send(json.dumps([stomp_connect]))

# Receive STOMP CONNECTED frame
msg2 = ws.recv()
print("STOMP Connect response frame:", repr(msg2))

# Subscribe to services queue
sub_id = "sub-1"
stomp_sub = f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/administration/service/get-all\n\n\x00"
ws.send(json.dumps([stomp_sub]))

# Send request to get all services
stomp_send = f"SEND\ndestination:/ws/administration/service/get-all\ncontent-type:application/json\n\n{{}}\x00"
ws.send(json.dumps([stomp_send]))

# Receive service list response
for _ in range(5):
    res = ws.recv()
    print("Received frame:\n", repr(res[:500]))
    if "MESSAGE" in res or "node" in res.lower() or "service" in res.lower():
        print("\n=== FULL MESSAGE BODY ===")
        print(res)
        break

ws.close()
