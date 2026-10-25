import urllib.request
import json

url = "http://172.31.105.11:7070/api/v1/events/search?query=index:netwitness*&time_range=7d&limit=10"
with urllib.request.urlopen(url) as r:
    data = json.loads(r.read())

events = data.get("events", [])
print(f"Events matching index:netwitness*: {len(events)}")
for e in events[:5]:
    print(f"[{e['timestamp']}] [{e['index']}] {e['host']} - {e['summary']}")
