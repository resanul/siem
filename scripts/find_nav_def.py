with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

import re
idx = text.find("('overview', 'Overview Dashboard')")
if idx == -1:
    idx = text.find('id: "overview"')
if idx == -1:
    idx = text.find("id: 'overview'")

print("Index:", idx)
if idx != -1:
    print(text[max(0, idx-100):idx+500])
