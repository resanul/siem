with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = [m.start() for m in re.finditer(r'sortCol|sortAsc', text)]
print("Matches for sortCol/sortAsc:", len(matches))
for idx in matches[:5]:
    print("Match at", idx)
    print(text[max(0, idx-50):idx+250])
    print("="*50)
