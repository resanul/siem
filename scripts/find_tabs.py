import re

with open("frontend/index.html", "r", encoding="utf-8") as f:
    text = f.read()

matches = [m.start() for m in re.finditer(r'activeTab === ["\']\w+["\']', text)]
print(f"Total activeTab checks: {len(matches)}")
found = set()
for m in matches:
    val = text[m:m+40].split("&&")[0].strip()
    found.add(val)

for x in sorted(found):
    print(" ", x)
