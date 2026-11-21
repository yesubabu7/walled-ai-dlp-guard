@echo off
rem Start Walled DLP Guard. Quit from the tray icon or press Ctrl+C here (restores proxy settings).
cd /d "%~dp0"
.venv\Scripts\python.exe dlp_guard.py %*
