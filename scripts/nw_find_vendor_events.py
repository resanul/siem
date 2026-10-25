import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

matches = [m.start() for m in re.finditer(r'core-event-count', js)]
print(f"Found {len(matches)} occurrences of core-event-count:")
for idx in matches[:5]:
    print("Match at", idx)
    print(js[max(0, idx-200):idx+400])
    print("="*60)
