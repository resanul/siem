import json

with open("/tmp/sa_env.json") as f:
    data = json.load(f)

print("socketRoutes:\n", json.dumps(data.get("socketRoutes"), indent=2))
print("\nAPP:\n", json.dumps(data.get("APP"), indent=2))
print("\nember-simple-auth:\n", json.dumps(data.get("ember-simple-auth"), indent=2))
