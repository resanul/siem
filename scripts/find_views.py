import re

with open('frontend/index.html', 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

views = re.findall(r'id=["\']view-([a-zA-Z0-9_\-]+)["\']', text)
print('Views found:', views)

navs = re.findall(r'id=["\']nav-([a-zA-Z0-9_\-]+)["\']', text)
print('Nav items:', navs)
