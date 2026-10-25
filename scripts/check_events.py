import urllib.request
import json

url = "http://172.31.105.11:7070/api/v1/events/search?time_range=7d&limit=100"
with urllib.request.urlopen(url) as r:
    data = json.loads(r.read())

events = data.get("events", [])
nw_events = [e for e in events if "netwitness" in e.get("index", "")]
print(f"Total events returned: {len(events)}")
print(f"NetWitness events found: {len(nw_events)}")

if nw_events:
    sample = nw_events[0]
    print("\nSample NetWitness Event in OpenSOC Forge:")
    print(f"  ID: {sample['id']}")
    print(f"  Index: {sample['index']}")
    print(f"  Source Type: {sample['source_type']}")
    print(f"  Host: {sample['host']}")
    print(f"  Summary: {sample['summary']}")
    print(f"  Timestamp: {sample['timestamp']}")
