# Wireshark Telegram Analyzer

A Telegram bot and Mini App that turns a packet capture (`.pcap` / `.pcapng`) into a plain-language network report. Record traffic on your phone with PCAPdroid, upload it, read the findings inside Telegram, get a PDF, and ask follow-up questions in chat.

![Report screen](docs/report.png)

## What it does

- **Upload in a Mini App.** Pick a capture file inside Telegram and watch the analysis progress.
- **Read the report in the app.** A verdict at the top, flagged items, charts, top conversations, and the DNS, TLS and HTTP names seen in the traffic.
- **Get a PDF.** One tap sends a formatted forensics-style report to your chat.
- **Ask questions in chat.** The bot answers about your report using an LLM that only sees the report's findings, never the raw packets.
- **Or just send a file.** Dropping a capture straight into the chat still works.

| Upload | Report | PDF | Chat |
|---|---|---|---|
| ![Upload](docs/upload.png) | ![Report](docs/report.png) | ![PDF](docs/pdf.png) | ![Chat](docs/chat.png) |

A sample capture and the report generated from it are in [`sample/`](sample/). The capture is synthetic (made-up addresses) with a port scan, regular beaconing, cleartext traffic and an odd DNS name planted in it.

## How it works

```
Phone / laptop capture (PCAPdroid, Wireshark)
        |
        v
 Telegram Mini App  --upload-->  FastAPI server  --tshark-->  pandas analysis
        ^                              |                           |
        |                              |                  charts + indicators
        +------ report JSON -----------+                           |
                                       +---- ReportLab PDF <-------+
 Telegram bot  <-- PDF / "ask in chat" --+
        |
        +--> LLM (OpenRouter) answers questions from the report text
```

1. The Mini App sends the file to the server, authenticated with Telegram's signed `initData`.
2. `tshark` extracts packet fields. `pandas` builds the statistics, `matplotlib` and `networkx` draw the charts, and `ReportLab` renders the PDF.
3. Simple rule-based checks flag possible port scans, beaconing, unusual DNS names, cleartext protocols and traffic bursts.
4. The raw capture is deleted right after analysis. Reports expire after about two hours.

## Tech stack

Python, FastAPI, python-telegram-bot, tshark (Wireshark), pandas, matplotlib, networkx, ReportLab, Telegram Mini Apps (plain HTML/JS), OpenRouter (LLM), Cloudflare Tunnel (for local development).

## Setup

You need Python 3.10+, [Wireshark](https://www.wireshark.org/) (with the TShark component), [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/), and a bot token from [@BotFather](https://t.me/BotFather).

```bash
git clone https://github.com/watt-ttaw/<repo-name>.git
cd <repo-name>
python -m venv .venv
.venv\Scripts\activate            # Windows (use source .venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
copy .env.example .env            # then fill in your values
```

Edit `.env`. The same bot token goes in both `BOT_TOKEN` (used by `bot.py`) and `TELEGRAM_TOKEN` (used by the Mini App server).

| Variable | Required | Purpose |
|---|---|---|
| `BOT_TOKEN` | yes | Bot token from BotFather (for `bot.py`) |
| `TELEGRAM_TOKEN` | yes | The same token (for `server.py` and `run_dev.py`) |
| `OPENROUTER_API_KEY` | no | Enables the AI summary and chat answers |
| `OPENROUTER_MODEL` | no | Which model to use |
| `ALLOWED_USER_IDS` | no | Comma-separated Telegram user IDs allowed to use the bot |
| `TSHARK_PATH` | no | Full path to `tshark` if it is not on your PATH |
| `MAX_UPLOAD_MB` | no | Mini App upload limit (default 50) |
| `DAILY_LIMIT` | no | Uploads per user per day (default 10) |
| `REPORT_TTL_MIN` | no | Minutes before a report is deleted (default 120) |

## Run it

Open two terminals in the project folder.

```bash
python run_dev.py     # starts the web server and a Cloudflare tunnel, and sets the bot's menu button
python bot.py         # starts the bot
```

Then open your bot in Telegram, press **Start**, and tap **Analyze PCAP**.

`run_dev.py` uses a free Cloudflare quick tunnel, so the address changes each time you restart it and the app only works while your computer is on. Send `/analyze` again after a restart to get a fresh button.

### Bot commands

| Command | What it does |
|---|---|
| `/start` | Shows how to use the bot |
| `/analyze` | Sends a button that opens the Mini App |
| `/reset` | Clears the conversation |
| `/id` | Shows your Telegram user ID |

## Getting a capture from your phone

On Android, install [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), set the dump mode to PCAP file, tap Start, use your phone for a minute, stop, and share the file. For any phone, you can also share your laptop's hotspot and capture on it with Wireshark or tshark.

## Project structure

```
bot.py            Telegram bot: commands, file uploads, follow-up chat
analyzer.py       tshark-based analysis used for files sent in chat
llm.py            LLM calls for explanations and answers
report.py         Report engine: analysis, charts, indicators, PDF
server.py         FastAPI backend for the Mini App (auth, upload, jobs)
run_dev.py        Starts the server and tunnel, registers the Mini App URL
webapp/index.html The Mini App interface
sample/           Synthetic capture and the report generated from it
```

## Security and privacy

- Every Mini App request is verified against Telegram's signed `initData`, and users can only see their own reports.
- Uploads are size-limited, rate-limited per user, and analysed with a timeout.
- Raw captures are deleted immediately after analysis. Reports and PDFs are deleted after a short time.
- Text from a capture is escaped before it is shown or put in the PDF.
- The AI summary and chat answers send the report's findings (addresses, domain names, counts) to the LLM provider. Do not upload captures you are not comfortable sharing with that provider.
- Only analyse traffic from networks and devices you own or have permission to monitor.

## Limitations

- The indicators are simple heuristics. Normal traffic (CDNs, games, keep-alives) can trigger them, so treat them as hints, not proof.
- Encrypted traffic (HTTPS, QUIC) shows metadata only: addresses, server names, sizes and timing.
- This is a triage aid, not a certified forensic tool.
- It currently runs on one machine, and the daily limit counter resets when the server restarts.

## Roadmap

- [ ] Dockerfile with tshark included
- [ ] Deploy to a cloud host with a permanent HTTPS address
- [ ] Protocol and TLS counts in the chat context
- [ ] Per-app attribution from PCAPdroid PCAPNG files
- [ ] Live capture mode for a local network
- [ ] Automated tests

## License

MIT, see [LICENSE](LICENSE).

## Author

Built by Al-Ameen Ibraheem, a computer engineering student.
[GitHub](https://github.com/watt-ttaw) | [LinkedIn](https://www.linkedin.com/in/al-ameen-ibraheem-2876bb362)
