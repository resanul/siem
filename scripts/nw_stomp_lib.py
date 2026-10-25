import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

# search for "Stomp.over" or "new Client" or "Stomp"
idx = js.find("Stomp.over")
if idx == -1:
    idx = js.find(".over(")

if idx != -1:
    print("Found around .over:\n", js[max(0, idx-200):idx+400])

# Also search for "clientInboundChannel" or csrf in websocket
idx_csrf = js.find("csrf")
print("CSRF occurrences:", len(re.findall(r'csrf', js, re.I)))

# Search for how socket headers are constructed
matches = re.findall(r'(\bheaders\s*:\s*\{[^\}]*?\})', js)
for m in matches[:10]:
    print("Header pattern:", m)
