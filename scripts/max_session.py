import re

with open("CHAT_HISTORY.md", "r", encoding="utf-8") as f:
    text = f.read()

sessions = re.findall(r'### Session (\d+)', text)
print("Sessions found:", [int(s) for s in sessions])
print("Max session:", max([int(s) for s in sessions]))
