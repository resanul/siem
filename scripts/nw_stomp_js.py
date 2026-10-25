import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

# search for stomp connect headers
matches = re.findall(r'(\w*(?:stomp|ws|socket)\w*.*?connect\([^)]*\))', js, re.IGNORECASE)
print(f"Found {len(matches)} connect calls:")
for m in matches[:10]:
    print(" ", m[:150])

# search for "CONNECT" frame building or headers sent in STOMP
headers_matches = re.findall(r'\{[^\}]*?(?:Authorization|csrf|passcode|login)[^\}]*?\}', js)
print(f"\nFound {len(headers_matches)} header blocks:")
for h in headers_matches[:15]:
    print(" ", h[:120])
