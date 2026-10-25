with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
tabs = re.findall(r'id:\s*["\']([a-zA-Z0-9_\-]+)["\'],\s*label:\s*["\']([^"\']+)["\']', text)
print("Tabs/Nav items found:", tabs[:25])

active_tab = re.findall(r'activeTab\s*===\s*["\']([a-zA-Z0-9_\-]+)["\']', text)
print("Active tabs compared in code:", set(active_tab))
