import urllib.request
import urllib.parse
import ssl
import json
import http.cookiejar
import re

ctx = ssl._create_unverified_context()
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

# Login
oauth_url = f"https://{NW_HOST}/oauth/token"
payload = urllib.parse.urlencode({
    "grant_type": "password",
    "username": USER,
    "password": PASS,
    "client_id": "netwitness"
}).encode("utf-8")
req = urllib.request.Request(oauth_url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
with opener.open(req) as resp:
    token = json.loads(resp.read().decode())["access_token"]

login_url = f"https://{NW_HOST}/j_spring_security_check"
payload = urllib.parse.urlencode({"username": USER, "password": PASS, "submit": "Login"}).encode("utf-8")
opener.open(urllib.request.Request(login_url, data=payload, headers={"User-Agent": "Mozilla/5.0"}))

# Read error body for /admin/services and /investigation/events
for path in ["/admin/services", "/admin/eventsources", "/investigation/events", "/investigation/navigate"]:
    url = f"https://{NW_HOST}{path}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0"
    })
    try:
        with opener.open(req) as r:
            print(f"SUCCESS {path}:", r.read().decode()[:300])
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore')
        print(f"ERROR {e.code} for {path}:")
        print(err_body[:500])
        print("="*60)
