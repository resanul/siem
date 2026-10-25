with open('frontend/index.html', 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

import re
matches = re.findall(r'<aside[^>]*>.*?</aside>', text, re.DOTALL)
if matches:
    print("ASIDE found len:", len(matches[0]))
    # print nav links
    links = re.findall(r'<a[^>]+href=["\']#([^"\']+)["\']', matches[0])
    print("Links in aside:", links)
    btns = re.findall(r'onclick=["\']([^"\']+)["\']', matches[0])
    print("Onclick buttons in aside:", btns[:10])
else:
    print("No aside found, searching for sidebar...")
    sidebar = re.findall(r'class=["\'][^"\']*sidebar[^"\']*["\'][^>]*>.*?</div', text, re.DOTALL)
    print("Sidebar matches:", len(sidebar))
