"""FastAPI backend for the PCAP analyzer Telegram Mini App.

Env: TELEGRAM_TOKEN (required), OPENROUTER_API_KEY (optional, AI summary),
     ALLOWED_USER_IDS (optional, comma-separated), MAX_UPLOAD_MB=50, DAILY_LIMIT=10,
     REPORT_TTL_MIN=120, DATA_DIR=data
"""
import hashlib
import hmac
import json
import os
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl

import requests
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse

from report import build_report

BOT_TOKEN = os.environ["TELEGRAM_TOKEN"]
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.abspath(os.environ.get("DATA_DIR", "data"))
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "10"))
TTL = int(os.environ.get("REPORT_TTL_MIN", "120")) * 60
ALLOWED = {int(x) for x in os.environ.get("ALLOWED_USER_IDS", "").split(",") if x.strip()}
os.makedirs(f"{DATA}/jobs", exist_ok=True)
os.makedirs(f"{DATA}/active", exist_ok=True)

app = FastAPI()
pool = ThreadPoolExecutor(max_workers=2)  # at most 2 analyses at once
usage = {}  # (user_id, day) -> uploads today (resets on restart)


def auth(authorization):
    """Verify Telegram's signed initData and return the user id."""
    if not authorization or not authorization.startswith("tma "):
        raise HTTPException(401, "Please open this from Telegram.")
    pairs = dict(parse_qsl(authorization[4:], keep_blank_values=True))
    got = pairs.pop("hash", "")
    check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    want = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    try:
        fresh = time.time() - int(pairs.get("auth_date", 0)) < 86400
        uid = json.loads(pairs["user"])["id"]
    except (KeyError, ValueError):
        raise HTTPException(401, "Invalid session. Reopen the app.")
    if not hmac.compare_digest(got, want) or not fresh:
        raise HTTPException(401, "Invalid or expired session. Reopen the app.")
    if ALLOWED and uid not in ALLOWED:
        raise HTTPException(403, "You are not on the tester list yet.")
    return uid


def jdir(job_id):
    if not job_id.isalnum():
        raise HTTPException(404, "Report not found or expired.")
    return f"{DATA}/jobs/{job_id}"


def write_status(job_id, **kw):
    p = f"{jdir(job_id)}/status.json"
    s = json.load(open(p)) if os.path.exists(p) else {}
    s.update(kw)
    json.dump(s, open(p, "w"))


def read_status(job_id, uid, need_done=False):
    p = f"{jdir(job_id)}/status.json"
    if not os.path.exists(p):
        raise HTTPException(404, "Report not found or expired.")
    s = json.load(open(p))
    if s["user"] != uid:  # users can only see their own reports
        raise HTTPException(404, "Report not found or expired.")
    if need_done and s["state"] != "done":
        raise HTTPException(409, "Report is not ready yet.")
    return s


def run_job(job_id):
    d = jdir(job_id)
    write_status(job_id, state="running")
    try:
        _, data = build_report(f"{d}/upload.pcap", f"{d}/report.pdf",
                               ai=bool(os.environ.get("OPENROUTER_API_KEY")), return_data=True)
        json.dump(data, open(f"{d}/analysis.json", "w"))
        write_status(job_id, state="done")
    except Exception as e:
        write_status(job_id, state="error",
                     error=str(e)[:300] if isinstance(e, ValueError) else "Analysis failed.")
    finally:
        try:
            os.remove(f"{d}/upload.pcap")  # never keep the raw capture
        except OSError:
            pass


def tg(method, data, files=None):
    r = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
                      data=data, files=files, timeout=60)
    if not r.ok:
        raise HTTPException(502, "Telegram could not deliver the message. Have you started the bot?")


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), authorization: str = Header(None)):
    uid = auth(authorization)
    day = (uid, time.strftime("%Y-%m-%d"))
    if usage.get(day, 0) >= DAILY_LIMIT:
        raise HTTPException(429, "Daily limit reached. Try again tomorrow.")
    job_id = uuid.uuid4().hex
    os.makedirs(jdir(job_id))
    size = 0
    with open(f"{jdir(job_id)}/upload.pcap", "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_MB * 1024 * 1024:
                break
            out.write(chunk)
    if size > MAX_MB * 1024 * 1024:
        shutil.rmtree(jdir(job_id), ignore_errors=True)
        raise HTTPException(413, f"File too large (max {MAX_MB} MB).")
    usage[day] = usage.get(day, 0) + 1
    write_status(job_id, user=uid, state="queued")
    pool.submit(run_job, job_id)
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def job(job_id: str, authorization: str = Header(None)):
    s = read_status(job_id, auth(authorization))
    return {"state": s["state"], "error": s.get("error")}


@app.get("/api/reports/{job_id}")
def report(job_id: str, authorization: str = Header(None)):
    read_status(job_id, auth(authorization), need_done=True)
    return FileResponse(f"{jdir(job_id)}/analysis.json", media_type="application/json")


@app.post("/api/reports/{job_id}/pdf")
def send_pdf(job_id: str, authorization: str = Header(None)):
    uid = auth(authorization)
    read_status(job_id, uid, need_done=True)
    with open(f"{jdir(job_id)}/report.pdf", "rb") as f:
        tg("sendDocument", {"chat_id": uid, "caption": "Your network analysis report"},
           {"document": ("network_report.pdf", f)})
    return {"ok": True}


@app.post("/api/reports/{job_id}/discuss")
def discuss(job_id: str, authorization: str = Header(None)):
    uid = auth(authorization)
    read_status(job_id, uid, need_done=True)
    json.dump({"job_id": job_id}, open(f"{DATA}/active/{uid}.json", "w"))
    tg("sendMessage", {"chat_id": uid, "text": "Your report is ready. Ask me anything about it, "
                       "for example: what looks suspicious? Which device used the most data?"})
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "webapp", "index.html"))


def cleaner():
    while True:
        time.sleep(600)
        for j in os.listdir(f"{DATA}/jobs"):
            p = f"{DATA}/jobs/{j}"
            if time.time() - os.path.getmtime(p) > TTL:
                shutil.rmtree(p, ignore_errors=True)


threading.Thread(target=cleaner, daemon=True).start()
