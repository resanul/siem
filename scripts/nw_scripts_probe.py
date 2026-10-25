import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

req = urllib.request.Request(f"https://{NW_HOST}/login", headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    html = r.read().decode('utf-8', errors='ignore')

# Find all script src
scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
print("Scripts found in HTML:", scripts)

# Also let's search in the html for API prefixes or endpoints
for m in re.finditer(r'/(?:api|platform|sa|monolith|rest)/[a-zA-Z0-9_\-/]+', html):
    print("API candidate:", m.group(0))
