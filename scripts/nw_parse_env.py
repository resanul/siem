import urllib.request
import urllib.parse
import ssl
import json
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/login"
with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), context=ctx) as r:
    html = r.read().decode('utf-8', errors='ignore')

m = re.search(r'<meta name="sa/config/environment" content="([^"]+)"', html)
if m:
    decoded = urllib.parse.unquote(m.group(1))
    env_config = json.loads(decoded)
    print("Keys in sa/config/environment:")
    for k in sorted(env_config.keys()):
        print(f"  {k}: {repr(env_config[k])[:80]}")
    
    # Check for endpoints or url configs
    print("\nFull JSON config saved to /tmp/sa_env.json")
    with open("/tmp/sa_env.json", "w") as f:
        json.dump(env_config, f, indent=2)
else:
    print("Could not find meta tag!")
