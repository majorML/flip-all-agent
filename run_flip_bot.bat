@echo off
title Flip Security Bot Runner
cd /d "C:\Users\USER\.gemini\antigravity\scratch\major-switch-bot"
set PYTHONUTF8=1
set PYTHONUNBUFFERED=1

:loop
echo [%date% %time%] Starting Flip Discord Bot...
python discord_bot.py
echo [%date% %time%] Bot exited with code %errorlevel%. Restarting in 3 seconds...
timeout /t 3 /nobreak >nul
goto loop
