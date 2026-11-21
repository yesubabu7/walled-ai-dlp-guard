@echo off
rem Restore proxy settings and remove the local certificate.
cd /d "%~dp0"
.venv\Scripts\python.exe dlp_guard.py --uninstall
pause
