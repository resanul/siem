import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

idx = js.find("stompClient.connect(")
if idx != -1:
    print("Code around stompClient.connect:")
    print(js[max(0, idx-400):idx+500])
