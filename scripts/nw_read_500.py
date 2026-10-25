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

login_url = f"https://{NW_HOST}/j_spring_security_check"
payload = urllib.parse.urlencode({"username": USER, "password": PASS, "submit": "Login"}).encode("utf-8")
opener.open(urllib.request.Request(login_url, data=payload, headers={"User-Agent": "Mozilla/5.0"}))

url = f"https://{NW_HOST}/admin/services"
req = urllib.request.Request(url, headers={
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest"
})

try:
    with opener.open(req) as r:
        print("Success:", r.read().decode())
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', errors='ignore')
    # search for exception message or stacktrace
    clean = re.sub(r'<style.*?</style>', '', body, flags=re.DOTALL)
    clean = re.sub(r'<script.*?</script>', '', clean, flags=re.DOTALL)
    clean = re.sub(r'<[^>]+>', '\n', clean)
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    print("Exception details:")
    print("\n".join(lines[:40]))
