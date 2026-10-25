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

print(f"Logged in as {USER}. Token len: {len(token)}, CSRF: {csrf}")

def stomp_query(endpoint, sub_dest, req_dest, payload):
    ws_url = f"wss://{NW_HOST}{endpoint}/000/{uuid.uuid4().hex[:8]}/websocket"
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
    ws.recv() # open 'o'
    ws.send(json.dumps([
        "CONNECT\naccept-version:1.1,1.0\nheart-beat:10000,10000\n"
        f"X-CSRF-TOKEN:{csrf}\nauthorization:Bearer {token}\n\n\x00"
    ]))
    res = ws.recv()
    if "CONNECTED" not in res:
        print("Failed to connect to", endpoint, res)
        ws.close()
        return None
    
    sub_id = "sub-" + uuid.uuid4().hex[:6]
    ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:{sub_dest}\n\n\x00"]))
    ws.send(json.dumps([f"SEND\ndestination:{req_dest}\ncontent-type:application/json\n\n{json.dumps(payload)}\x00"]))
    
    messages = []
    for _ in range(6):
        try:
            raw = ws.recv()
            if "MESSAGE" in raw:
                # parse STOMP body
                idx = raw.find("\n\n")
                if idx != -1:
                    body = raw[idx+2:].rstrip("\x00\n\"']")
                    # unescape if json string
                    try:
                        parsed = json.loads(body.encode().decode('unicode_escape', errors='ignore'))
                    except:
                        try:
                            # clean string
                            clean = body.replace('\\"', '"').replace('\\\\', '\\')
                            parsed = json.loads(clean)
                        except:
                            parsed = body
                    messages.append(parsed)
                    break
        except Exception as e:
            print("Recv err:", e)
            break
    ws.close()
    return messages

print("\n--- Testing 1: Investigate Service Hierarchy ---")
hier = stomp_query(
    "/api/investigate/socket",
    "/user/queue/investigate/service-hierarchy",
    "/ws/investigate/service-hierarchy",
    {}
)
print("Hierarchy Result:")
print(json.dumps(hier, indent=2)[:1000])

print("\n--- Testing 2: Respond Alerts ---")
alerts = stomp_query(
    "/api/respond/socket",
    "/user/queue/respond/alerts",
    "/ws/respond/alerts",
    {"pageNumber": 1, "pageSize": 10}
)
print("Alerts Result:")
print(json.dumps(alerts, indent=2)[:1000])
