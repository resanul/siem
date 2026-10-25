with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = [m.start() for m in re.finditer(r'currentScreen\s*===\s*["\']search["\']', text)]
print("Matches for currentScreen === 'search':", matches)
for idx in matches:
    print("--- Section at", idx, "---")
    print(text[max(0, idx-50):idx+350])
