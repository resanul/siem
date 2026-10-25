with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
matches = re.findall(r'const\s+\[([a-zA-Z0-9_]+),\s*set([a-zA-Z0-9_]+)\]\s*=\s*React\.useState\(["\']overview["\']\)', text)
print("useState for overview:", matches)

tab_state = re.findall(r'([a-zA-Z0-9_]+)\s*===\s*["\']search["\']', text)
print("Variable compared to 'search':", set(tab_state))
