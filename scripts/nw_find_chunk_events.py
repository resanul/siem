import urllib.request
import ssl
import re

ctx = ssl._create_unverified_context()
NW_HOST = "172.31.101.34"

url = f"https://{NW_HOST}/assets/chunk.707.f7c4c74151cac2f7ef2b.js"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, context=ctx) as r:
    js = r.read().decode('utf-8', errors='ignore')

print("chunk.707 size:", len(js))
idx = js.find("core-event-count")
if idx != -1:
    print("Found core-event-count:\n", js[max(0, idx-200):idx+400])
else:
    print("core-event-count not found in chunk.707")

idx2 = js.find("events/count")
if idx2 != -1:
    print("Found events/count:\n", js[max(0, idx2-200):idx2+400])
else:
    print("events/count not found in chunk.707")
