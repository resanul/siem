with open("CHAT_HISTORY.md", "r", encoding="utf-8") as f:
    text = f.read()

idx = text.find("Session 22")
print("Session 22 idx:", idx)
if idx != -1:
    print(text[idx:idx+300])
