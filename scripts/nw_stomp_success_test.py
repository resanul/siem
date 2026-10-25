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
print("Acquired Token len:", len(token), "CSRF:", csrf)

cookie_str = "; ".join([f"{k}={v}" for k, v in s.cookies.get_dict().items()])

server_id = "111"
session_id = uuid.uuid4().hex[:8]
ws_url = f"wss://{NW_HOST}/api/administration/socket/{server_id}/{session_id}/websocket"

ws = websocket.create_connection(
    ws_url,
    sslopt={"cert_reqs": ssl.CERT_NONE},
    header=[
        f"Cookie: {cookie_str}",
        f"X-CSRF-TOKEN: {csrf}",
        f"authorization: Bearer {token}",
        "User-Agent: Mozilla/5.0"
    ],
    timeout=8
)

print("WebSocket connected!")
open_frame = ws.recv()
print("SockJS open frame:", repr(open_frame))

# STOMP CONNECT with exact headers
connect_frame = (
    "CONNECT\n"
    "accept-version:1.1,1.0\n"
    "heart-beat:10000,10000\n"
    f"X-CSRF-TOKEN:{csrf}\n"
    f"authorization:Bearer {token}\n\n"
    "\x00"
)

ws.send(json.dumps([connect_frame]))
res = ws.recv()
print("STOMP Connect response frame:", repr(res))

if "CONNECTED" in res:
    print(">>> STOMP CONNECTED SUCCESSFULLY! <<<")
    # Now subscribe to /user/queue/administration/service/get-all
    sub_frame = (
        "SUBSCRIBE\n"
        "id:sub-services\n"
        "destination:/user/queue/administration/service/get-all\n\n"
        "\x00"
    )
    ws.send(json.dumps([sub_frame]))
    
    # Send request
    req_frame = (
        "SEND\n"
        "destination:/ws/administration/service/get-all\n"
        "content-type:application/json\n\n"
        "{}\x00"
    )
    ws.send(json.dumps([req_frame]))
    
    # Receive response
    for _ in range(5):
        frame = ws.recv()
        print("Data frame:", repr(frame[:300]))
        if "MESSAGE" in frame:
            print("\n=== GOT SERVICES LIST! ===")
            print(frame)
            break

ws.close()
