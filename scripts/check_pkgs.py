import subprocess
import sys

print("Python version:", sys.version)
for pkg in ["requests", "urllib3", "websocket", "websockets", "stomp", "aiohttp"]:
    try:
        __import__(pkg)
        print(f"Package {pkg}: AVAILABLE")
    except ImportError:
        print(f"Package {pkg}: NOT available")
