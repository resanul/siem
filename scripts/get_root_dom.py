import subprocess
import os

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

idx = dom.find('id="root"')
if idx != -1:
    snippet = dom[idx:idx+1500].encode('ascii', 'replace').decode()
    print(snippet)
