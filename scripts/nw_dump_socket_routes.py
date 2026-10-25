import json

with open("/tmp/sa_env.json") as f:
    data = json.load(f)

sr = data.get("socketRoutes", {})
targets = [
    "core-service", "core-hierarchy", "core-event", "core-event-count",
    "core-summary", "core-event-timeline", "core-event-log", "events",
    "alerts", "incidents", "data-sources"
]

for t in targets:
    if t in sr:
        print(f"=== {t} ===")
        print(json.dumps(sr[t], indent=2))
