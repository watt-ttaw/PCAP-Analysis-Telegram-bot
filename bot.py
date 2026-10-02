import asyncio
import os
import tempfile

from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

import analyzer
import llm

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
if not TOKEN:
    raise SystemExit("BOT_TOKEN not found. Check your .env file.")

MAX_BYTES = 20 * 1024 * 1024  # Telegram Bot API download limit

# Optional: restrict the bot to specific Telegram user IDs (comma separated in .env)
ALLOWED = {
    int(x) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x.strip().isdigit()
}


def is_allowed(update: Update) -> bool:
    return not ALLOWED or update.effective_user.id in ALLOWED


async def send_long(update: Update, text: str):
    """Telegram messages are limited to 4096 characters."""
    for i in range(0, len(text), 4000):
        await update.message.reply_text(text[i : i + 4000])


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    await update.message.reply_text(
        "Send me a .pcap or .pcapng file (max 20 MB).\n"
        "I will analyze it with tshark and add an AI explanation.\n\n"
        "After that, just type a question and I will answer it about your capture.\n"
        "Use /reset to clear the conversation."
    )


async def reset(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    context.user_data.clear()
    await update.message.reply_text("Cleared. Send a new capture whenever you are ready.")


async def my_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"Your Telegram user ID: {update.effective_user.id}")


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return

    doc = update.message.document
    name = (doc.file_name or "").lower()

    if not name.endswith((".pcap", ".pcapng", ".cap")):
        await update.message.reply_text("Please send a .pcap or .pcapng file.")
        return
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text("File too large (limit 20 MB).")
        return

    await update.message.reply_text("Got it. Analyzing...")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "upload.pcap")
        tg_file = await doc.get_file()
        await tg_file.download_to_drive(path)

        if not analyzer.is_pcap(path):
            await update.message.reply_text(
                "That does not look like a valid capture file."
            )
            return

        try:
            report = await asyncio.to_thread(analyzer.summary, path)
            report_text = analyzer.format_report(report)
        except Exception as e:
            print("Analysis error:", repr(e))
            await update.message.reply_text(f"Analysis failed: {type(e).__name__}")
            return
    # the uploaded file is deleted here; only the text summary continues

    # Remember this report so the user can ask follow-up questions
    context.user_data["report"] = report_text
    context.user_data["history"] = []

    # AI explanation (falls back to the raw report if the LLM call fails)
    try:
        ai_text = await asyncio.to_thread(llm.explain, report_text)
        await send_long(update, "AI ANALYSIS\n" + "=" * 11 + "\n" + ai_text)
    except Exception as e:
        print("LLM error:", e)
        await update.message.reply_text(f"AI summary unavailable: {e}")

    await send_long(update, report_text)
    await update.message.reply_text(
        "You can now ask me questions about this capture, for example: "
        "'which IP sent the most data?'"
    )


async def chat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update):
        return
    question = (update.message.text or "").strip()
    if not question:
        return

    report = context.user_data.get("report", "")
    history = context.user_data.setdefault("history", [])

    await context.bot.send_chat_action(update.effective_chat.id, "typing")
    try:
        answer = await asyncio.to_thread(llm.chat, report, history, question)
    except Exception as e:
        print("LLM error:", e)
        await update.message.reply_text(f"AI unavailable: {e}")
        return

    history.append({"role": "user", "content": question[:1000]})
    history.append({"role": "assistant", "content": answer})
    del history[:-8]  # keep only the last 8 messages
    await send_long(update, answer)


def main():
    print("tshark path:", analyzer.TSHARK)
    print("LLM model:", os.getenv("OPENROUTER_MODEL", llm.DEFAULT_MODEL))
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("reset", reset))
    app.add_handler(CommandHandler("id", my_id))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat))
    print("Bot is running. Press Ctrl+C to stop.")
    app.run_polling()


if __name__ == "__main__":
    main()
