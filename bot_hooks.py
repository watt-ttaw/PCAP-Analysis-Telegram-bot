"""Drop-in pieces for your existing bot (python-telegram-bot v20+).

Register in your bot:
    app.add_handler(CommandHandler("analyze", analyze_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, question_handler))
In question_handler, replace `fallback` with your bot's current text handler.
`answer_question(user_id, text)` is plain Python, so you can call it from any library.
Env: OPENROUTER_API_KEY, optional OPENROUTER_MODEL, DATA_DIR (same as the server).
"""
import asyncio
import json
import os
import re
from collections import defaultdict, deque

import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

DATA = os.path.abspath(os.environ.get("DATA_DIR", "data"))
history = defaultdict(lambda: deque(maxlen=6))  # last few messages per user


def active_analysis(user_id):
    try:
        job = json.load(open(f"{DATA}/active/{user_id}.json"))["job_id"]
        d = json.load(open(f"{DATA}/jobs/{job}/analysis.json"))
    except (OSError, ValueError, KeyError):
        return None  # no active report, or it expired
    d.pop("charts", None)  # the model gets findings, never images or raw packets
    return d


def answer_question(user_id, question):
    """Answer from the user's latest report; returns None if they have no active report."""
    d = active_analysis(user_id)
    key = os.environ.get("OPENROUTER_API_KEY")
    if not d or not key:
        return None
    system = ("You explain one network capture analysis to a student. Use ONLY the JSON report below. "
              "If it does not contain the answer, say so. Be concise, plain language, no markdown. "
              "Findings are heuristics, not proof.\n\nREPORT:\n" + json.dumps(d)[:12000])
    msgs = [{"role": "system", "content": system}, *history[user_id],
            {"role": "user", "content": question}]
    try:
        r = requests.post("https://openrouter.ai/api/v1/chat/completions",
                          headers={"Authorization": f"Bearer {key}"},
                          json={"model": os.environ.get("OPENROUTER_MODEL", "openrouter/auto"),
                                "messages": msgs}, timeout=60)
        r.raise_for_status()
        text = re.sub(r"[*#`]", "", r.json()["choices"][0]["message"]["content"]).strip()
    except Exception:
        return "Sorry, I couldn't reach the AI service. Try again in a moment."
    history[user_id].extend([{"role": "user", "content": question},
                             {"role": "assistant", "content": text}])
    return text


async def analyze_cmd(update, context):
    url = open(f"{DATA}/miniapp_url.txt").read().strip()  # written by run_dev.py
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("Open PCAP analyzer", web_app=WebAppInfo(url=url))]])
    await update.message.reply_text("Tap to upload a capture and see the report.", reply_markup=kb)


async def fallback(update, context):
    pass  # replace with your existing text handler


async def question_handler(update, context):
    reply = await asyncio.to_thread(answer_question, update.effective_user.id, update.message.text)
    if reply:
        await update.message.reply_text(reply)
    else:
        await fallback(update, context)
