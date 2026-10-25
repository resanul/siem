import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

# Search for /investigate/events/stream or /investigate/events/count
for endpoint in ["/investigate/events/count", "/investigate/events/stream", "/investigate/timeline"]:
    idx = js.find(endpoint)
    if idx != -1:
        print(f"=== Found {endpoint} ===")
        print(js[max(0, idx-300):idx+400])
        print("="*60)
