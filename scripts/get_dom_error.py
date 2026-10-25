import subprocess
import os
import re

html_path = os.path.abspath("frontend/index.html")
edge_cmd = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "--headless",
    "--disable-gpu",
    "--dump-dom",
    f"file:///{html_path}"
]

proc = subprocess.run(edge_cmd, capture_output=True, timeout=12, text=True, encoding="utf-8", errors="ignore")
dom = proc.stdout

pre_match = re.search(r'<pre[^>]*>(.*?)</pre>', dom, re.DOTALL)
if pre_match:
    print("UI Diagnostics Error message:\n", pre_match.group(1).strip())
else:
    print("No <pre> found, searching diagnostics snippet:")
    idx = dom.find("UI Diagnostics")
    print(dom[idx:idx+600])
