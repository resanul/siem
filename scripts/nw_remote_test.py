import urllib.request
import urllib.parse
import ssl
import json
import base64
import http.cookiejar

ctx = ssl._create_unverified_context()
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

print("=== RSA NetWitness Connectivity & Auth Test ===")

print("\n--- Step 1: Testing Web Login GET /login ---")
try:
    req = urllib.request.Request(f"https://{NW_HOST}/login", headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=10) as resp:
        print("GET /login status:", resp.getcode())
        content = resp.read().decode("utf-8", errors="ignore")
        print("Cookies:", [c.name for c in cj])
        print("Page preview (first 400 chars):\n", content[:400].strip())
except Exception as e:
    print("GET /login error:", e)

print("\n--- Step 2: Testing POST to Web Login (Spring Security / Form login) ---")
for endpoint in ["/login", "/j_spring_security_check", "/login.do"]:
    try:
        login_url = f"https://{NW_HOST}{endpoint}"
        payload = urllib.parse.urlencode({
            "username": USER,
            "password": PASS,
            "submit": "Login"
        }).encode("utf-8")
        req = urllib.request.Request(login_url, data=payload, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0"
        })
        with opener.open(req, timeout=10) as resp:
            print(f"POST {endpoint} status:", resp.getcode(), "URL:", resp.geturl())
            print("Cookies after POST:", [c.name for c in cj])
    except Exception as e:
        print(f"POST {endpoint} error:", e)

print("\n--- Step 3: Testing OAuth2 /oauth/token ---")
try:
    oauth_url = f"https://{NW_HOST}/oauth/token"
    payload = urllib.parse.urlencode({
        "grant_type": "password",
        "username": USER,
        "password": PASS,
        "client_id": "netwitness"
    }).encode("utf-8")
    req = urllib.request.Request(oauth_url, data=payload, headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    })
    with opener.open(req, timeout=10) as resp:
        print("OAuth status:", resp.getcode())
        data = json.loads(resp.read().decode())
        print("OAuth keys:", list(data.keys()))
        if "access_token" in data:
            print("Access Token received successfully! (len:", len(data["access_token"]), ")")
except Exception as e:
    print("OAuth error:", e)

print("\n--- Step 4: Testing Core REST API with Basic Auth on Concentrator / Decoders ---")
nodes = [
    ("Log Concentrator", "172.31.101.36", 50005),
    ("Log Decoder", "172.31.101.37", 50002),
    ("Network Concentrator", "172.31.101.38", 50005),
    ("Network Decoder", "172.31.101.39", 50004),
    ("Broker / SA Core", "172.31.101.34", 50003),
]
for name, host, port in nodes:
    try:
        url = f"http://{host}:{port}/sys/info"  # or https
        auth = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": auth, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"HTTP {name} ({host}:{port}) -> Status {resp.getcode()}:", resp.read().decode()[:150])
    except Exception as e:
        # try https
        try:
            url = f"https://{host}:{port}/sys/info"
            req = urllib.request.Request(url, headers={"Authorization": auth, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                print(f"HTTPS {name} ({host}:{port}) -> Status {resp.getcode()}:", resp.read().decode()[:150])
        except Exception as e2:
            print(f"{name} ({host}:{port}) error: HTTP: {e} | HTTPS: {e2}")

print("\n--- Step 5: Testing SSH Login on 172.31.101.34 ---")
try:
    import paramiko as pk
    c = pk.SSHClient()
    c.set_missing_host_key_policy(pk.AutoAddPolicy())
    c.connect(NW_HOST, username=USER, password=PASS, timeout=5)
    print(f"SSH login to {NW_HOST} as {USER} -> SUCCESS!")
    stdin, stdout, stderr = c.exec_command("hostname; uname -a")
    print("SSH output:", stdout.read().decode().strip())
    c.close()
except Exception as e:
    print(f"SSH login to {NW_HOST} error:", e)
