import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

for name in ["engine.js", "investigate-events.js", "assets/engine.js"]:
    url = f"https://{NW_HOST}/engines-dist/investigate-events/{name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, context=ctx) as r:
            print(f"File {name}: Found! Size: {len(r.read())}")
    except Exception as e:
        print(f"File {name}: {e}")
