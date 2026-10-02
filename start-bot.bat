@echo off
title PCAP Analysis Bot
cd /d "%~dp0"
call venv\Scripts\activate
python bot.py
echo.
echo The bot has stopped. Read any messages above, then press a key to close.
pause
