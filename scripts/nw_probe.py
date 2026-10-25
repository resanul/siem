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

# Get OAuth token
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
    oauth_data = json.loads(resp.read().decode())
    token = oauth_data.get("access_token")
    user_info = oauth_data.get("user")
    print("User Info from OAuth:", user_info)
    print("Token Type:", oauth_data.get("token_type"))
    print("Expires in:", oauth_data.get("expires_in"))

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json"
}

# Test various NetWitness endpoints
endpoints = [
    "/rsa/api/system/version",
    "/rsa/api/hosts",
    "/rsa/api/services",
    "/rsa/api/investigation/services",
    "/rsa/api/incidents",
    "/rsa/api/alerts",
    "/rsa/api/rules",
    "/rsa/api/context/system/version",
    "/rsa/api/license",
    "/investigate/api/services",
    "/investigate/api/core/services",
    "/admin/api/services",
    "/admin/api/hosts",
    "/rsa/api/health",
    "/rsa/api/users/current",
    "/rsa/api/core/devices",
]

print("\n--- Probing RSA NetWitness API Endpoints ---")
for ep in endpoints:
    url = f"https://{NW_HOST}{ep}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with opener.open(req, timeout=8) as r:
            body = r.read().decode("utf-8", errors="ignore")
            print(f"[OK 200] {ep} -> Length: {len(body)}")
            print("Preview:", body[:300].strip())
            print("-" * 50)
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] {ep}")
    except Exception as e:
        print(f"[ERR] {ep}: {e}")
