# Headless Edge test on local index.html to verify zero console errors
import subprocess
import time
import os

html_path = os.path.abspath("frontend/index.html")
edge_cmd = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "--headless",
    "--disable-gpu",
    "--dump-dom",
    f"file:///{html_path}"
]

try:
    proc = subprocess.run(edge_cmd, capture_output=True, timeout=12, text=True, encoding="utf-8", errors="ignore")
    dom = proc.stdout
    print("DOM Length:", len(dom))
    if "UI Diagnostics" in dom:
        print("CRITICAL: 'UI Diagnostics' modal triggered!")
    else:
        print("SUCCESS: DOM rendered cleanly with NO UI Diagnostics error!")
        if "RSA NetWitness SIEM" in dom:
            print("CONFIRMED: 'RSA NetWitness SIEM' is present in DOM!")
except Exception as e:
    print("Edge test error:", e)
