with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = [m.start() for m in re.finditer(r'currentScreen === ["\']endpoint_xdr["\']', text)]
print("Matches:", matches)
for idx in matches:
    print(text[max(0, idx-30):idx+500])
    print("="*60)
