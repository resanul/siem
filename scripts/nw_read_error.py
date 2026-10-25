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

login_url = f"https://{NW_HOST}/j_spring_security_check"
payload = urllib.parse.urlencode({"username": USER, "password": PASS, "submit": "Login"}).encode("utf-8")
opener.open(urllib.request.Request(login_url, data=payload, headers={"User-Agent": "Mozilla/5.0"}))

url = f"https://{NW_HOST}/admin/services"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
with opener.open(req) as r:
    print("Content-Type:", r.headers.get("Content-Type"))
    body = r.read().decode("utf-8", errors="ignore")
    print("Length:", len(body))
    print("Preview:\n", body[:2000])
