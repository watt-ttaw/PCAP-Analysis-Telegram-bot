"""Start the Mini App backend plus a Cloudflare quick tunnel and register the tunnel URL.

Needs: cloudflared on PATH, env TELEGRAM_TOKEN.   Run: python run_dev.py
Writes the current URL to data/miniapp_url.txt (your bot reads it for its button).
"""
import os
import re
import subprocess
import sys
import threading

import requests

PORT = os.environ.get("PORT", "8000")
DATA = os.environ.get("DATA_DIR", "data")
TOKEN = os.environ["TELEGRAM_TOKEN"]

api = subprocess.Popen([sys.executable, "-m", "uvicorn", "server:app", "--port", PORT])
tun = subprocess.Popen(["cloudflared", "tunnel", "--url", f"http://localhost:{PORT}"],
                       stderr=subprocess.PIPE, text=True)
url = None
for line in tun.stderr:
    m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
    if m:
        url = m.group(0)
        break
threading.Thread(target=lambda: [None for _ in tun.stderr], daemon=True).start()  # keep pipe drained

if not url:
    api.terminate()
    sys.exit("Could not get a tunnel URL from cloudflared.")

os.makedirs(DATA, exist_ok=True)
open(f"{DATA}/miniapp_url.txt", "w").write(url)
r = requests.post(f"https://api.telegram.org/bot{TOKEN}/setChatMenuButton", json={
    "menu_button": {"type": "web_app", "text": "Analyze PCAP", "web_app": {"url": url}}})
print("Mini App URL:", url)
print("Menu button updated." if r.ok else f"Could not set menu button: {r.text}")
try:
    api.wait()
except KeyboardInterrupt:
    pass
finally:
    api.terminate()
    tun.terminate()
