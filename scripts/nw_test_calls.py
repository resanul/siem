import urllib.request
import urllib.parse
import ssl
import json
import http.cookiejar

ctx = ssl._create_unverified_context()
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))

NW_HOST = "172.31.101.34"
USER = "resanul"
PASS = "CF!WF*$zRvAKh*R7Pv^9"

# 1. OAuth
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
    token = oauth_data["access_token"]
    print("Token acquired successfully!")

# 2. Form login to get full JSESSIONID session
login_url = f"https://{NW_HOST}/j_spring_security_check"
payload = urllib.parse.urlencode({
    "username": USER,
    "password": PASS,
    "submit": "Login"
}).encode("utf-8")
req = urllib.request.Request(login_url, data=payload, headers={"User-Agent": "Mozilla/5.0"})
with opener.open(req, timeout=10) as resp:
    print("Logged in via Spring Security, current URL:", resp.geturl())

test_paths = [
    "/admin/services",
    "/admin/eventsources",
    "/presidio/api/alerts",
    "/investigate/events",
    "/investigation/events",
    "/investigation/navigate",
    "/investigation/services",
    "/admin/api/services",
    "/admin/hosts",
    "/endpoint/api/v1/hosts",
    "/api/incident",
    "/api/incidents",
    "/api/alert",
    "/api/alerts",
    "/api/services",
    "/api/device",
    "/api/devices"
]

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0"
}

for p in test_paths:
    url = f"https://{NW_HOST}{p}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=5) as r:
            body = r.read().decode("utf-8", errors="ignore")
            content_type = r.headers.get("Content-Type", "")
            print(f"[{r.getcode()}] {p} ({content_type}, len={len(body)})")
            if "html" not in content_type:
                print("   DATA PREVIEW:", body[:300])
            else:
                print("   HTML TITLE:", body[:200].replace('\n', ' '))
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] {p}")
    except Exception as e:
        print(f"[ERR] {p}: {e}")
