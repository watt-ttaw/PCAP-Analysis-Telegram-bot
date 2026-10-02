# PCAP Analysis Telegram Bot

A Telegram bot that analyzes Wireshark capture files with **tshark** and explains them in plain English using an LLM through **OpenRouter**. Send it a `.pcap` or `.pcapng` file, get a structured report and an AI verdict, then ask follow-up questions in normal language.

<!-- Add your screenshots here once you have them:
![AI analysis in Telegram](docs/screenshots/telegram-analysis.png)
![Follow-up question](docs/screenshots/telegram-chat.png)
-->

## Features

- **Automatic PCAP triage**: packet count, duration, total bytes, protocol hierarchy and top IP conversations.
- **Network indicators**: most queried DNS names, failed DNS lookups, TLS server names (SNI) and HTTP requests.
- **Simple red-flag checks**: possible port scans and executable or script downloads over plain HTTP.
- **AI analysis**: a short explanation with notable findings, things to check manually, and a verdict (normal, suspicious or inconclusive).
- **Chat about your capture**: after an analysis, type questions such as "Which IP sent the most data?" and get answers based on that capture.
- **Graceful fallback**: if the AI call fails, you still receive the full tshark report.

## How it works

```
Telegram user sends a .pcap / .pcapng file
        |
        v
bot.py       downloads it to a temp folder, checks size and file signature
        |
        v
analyzer.py  runs tshark and builds a text summary
        |
        v
llm.py       sends ONLY the text summary to an LLM via OpenRouter
        |
        v
bot.py       replies with the AI analysis + the raw report, then deletes the file
```

## Requirements

- Python 3.10 or newer
- [Wireshark](https://www.wireshark.org/download.html) installed (it includes `tshark`)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- An [OpenRouter](https://openrouter.ai) API key (optional: without it the bot still sends the tshark report)

## Setup

### Windows

```bat
git clone https://github.com/watt-ttaw/pcap-analysis-bot.git
cd pcap-analysis-bot
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` and fill in your values (see Configuration), then start the bot:

```bat
python bot.py
```

On Windows you can also double-click `start-bot.bat`. The bot finds `tshark.exe` in `C:\Program Files\Wireshark` automatically, so you do not need to edit PATH.

### Linux (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y tshark python3-venv
git clone https://github.com/watt-ttaw/pcap-analysis-bot.git
cd pcap-analysis-bot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python bot.py
```

## Configuration

Settings live in a `.env` file (never commit this file).

| Variable | Required | Description |
|---|---|---|
| `BOT_TOKEN` | Yes | Telegram bot token from @BotFather, including the numbers before the colon |
| `OPENROUTER_API_KEY` | For AI features | API key from openrouter.ai |
| `OPENROUTER_MODEL` | No | Model ID. Defaults to `openrouter/free`, which picks from the free catalog. Free model IDs change often, so check openrouter.ai/models |
| `ALLOWED_USER_IDS` | No | Comma-separated Telegram user IDs allowed to use the bot. Leave empty to allow everyone. Send `/id` to the bot to find your ID |

## Usage

| Command | What it does |
|---|---|
| `/start` | Shows instructions |
| `/reset` | Clears the current capture and conversation |
| `/id` | Shows your Telegram user ID |

1. Send a `.pcap`, `.pcapng` or `.cap` file as a document (max 20 MB).
2. Wait a few seconds for the AI analysis and the raw report.
3. Type a question about the capture, for example "Is this DNS traffic normal?"

Good places to find sample captures: the [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) and [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) (open only the PCAP file, never run anything extracted from malware exercises).

## Project structure

```
bot.py            Telegram handlers: commands, file upload, follow-up chat
analyzer.py       tshark wrapper and report builder
llm.py            OpenRouter client (analysis and chat prompts)
requirements.txt  Python dependencies
start-bot.bat     Windows launcher
.env.example      Template for your settings
```

## Limitations

- **20 MB file limit**: Telegram's standard Bot API only lets bots download files up to 20 MB. Larger captures can be filtered in Wireshark and re-exported.
- **The AI sees a summary, not packets**: it can miss details and it can be wrong. Treat its verdict as a starting point and verify in Wireshark.
- **Basic heuristics**: the port-scan check flags a source that sends SYN packets to 50 or more distinct IP and port pairs. The download check only sees plain HTTP. Encrypted traffic hides most content.
- **Free models vary**: results can differ between runs, and free tiers have rate limits.
- **Memory is temporary**: the saved capture and chat history live in the running process and disappear on restart.

## Security and privacy

- The capture file stays on the machine running the bot and is deleted right after analysis. Only the **text summary** (IPs, domain names and counts) is sent to OpenRouter and the underlying model provider. Free models may log prompts, so use captures that are yours or public.
- Uploaded files are validated by size and file signature, and tshark is called without a shell and with a timeout.
- Nothing inside a capture is ever executed.
- Text inside captures (domains, URLs, user-agents) can be attacker-controlled, so the prompts instruct the model to treat the report as untrusted data. The model's output is only displayed, never run.
- Use `ALLOWED_USER_IDS` to stop strangers from using your bot and your API quota.
- Secrets belong in `.env`, which is excluded by `.gitignore`. If a token leaks, revoke it with `/revoke` in @BotFather.
- Only analyze traffic you own or have permission to inspect.

## Roadmap

- [ ] Defang domains in reports (`example[.]com`) for malware captures
- [ ] Beaconing detection (regular-interval connections)
- [ ] IOC enrichment with VirusTotal, URLhaus and AbuseIPDB
- [ ] Docker image
- [ ] Always-on hosting on Oracle Cloud
- [ ] Phishing email header analysis

## Disclaimer

This project is for learning and defensive analysis. Its findings are automated hints, not proof. Always confirm important results manually.

## Author

Ibraheem Al-Ameen Olatunji
GitHub: [watt-ttaw](https://github.com/watt-ttaw) | LinkedIn: [al-ameen-ibraheem](https://www.linkedin.com/in/al-ameen-ibraheem-2876bb362)

## License

MIT. Add a `LICENSE` file to the repository (GitHub can create one for you under Add file > Create new file > type `LICENSE`).
