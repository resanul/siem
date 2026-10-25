import json

with open("/tmp/sa_env.json") as f:
    data = json.load(f)

sr = data.get("socketRoutes", {})
print("Socket modules found:", list(sr.keys()))
for mod in ["investigate", "admin", "respond", "core", "event", "services", "system"]:
    for k in sr.keys():
        if mod in k.lower():
            print(f"\n--- Module: {k} ---")
            print(json.dumps(sr[k], indent=2)[:500])
