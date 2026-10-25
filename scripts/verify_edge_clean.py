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

# Check if #root contains the app or the error
if '<div class="flex h-screen overflow-hidden bg-[#080c14]">' in dom:
    print("SUCCESS: The full OpenSOC Forge Application rendered into #root!")
else:
    print("FAILURE: Full app not rendered in #root!")

if "RSA NetWitness SIEM" in dom:
    print("CONFIRMED: 'RSA NetWitness SIEM' nav button is present in the rendered DOM!")
