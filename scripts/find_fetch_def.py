with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = [m.start() for m in re.finditer(r'fetchSophosTelemetry', text)]
print("All matches for fetchSophosTelemetry:", matches)
for idx in matches:
    print(text[max(0, idx-50):idx+250])
    print("="*50)
