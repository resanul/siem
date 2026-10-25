import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

for script in ['/assets/vendor-4f020a8b93148d2e745abf3a89c72c59.js', '/assets/chunk.707.f7c4c74151cac2f7ef2b.js', '/assets/chunk.143.8588cbc9f4afbe83040a.js', '/assets/sa-b66914c774bf3289f032e8a1edc2b3a1.js']:
    url = f"https://{NW_HOST}{script}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, context=ctx) as r:
        js = r.read().decode('utf-8', errors='ignore')
    print(f"File {script}: size={len(js)}")
    
    # search for /endpoint or url patterns
    urls = set(re.findall(r'["\'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+)["\']', js))
    candidates = [u for u in urls if any(k in u for k in ['service', 'investigat', 'device', 'host', 'alert', 'incident', 'query', 'event', 'meta', 'token', 'user', 'session', 'broker', 'concentrator', 'decoder'])]
    print(f"Matched candidates in {script} ({len(candidates)}):")
    for c in sorted(candidates)[:20]:
        print("  ", c)
