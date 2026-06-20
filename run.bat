@echo off
title Whale2XSSHunter Launcher

echo ==================================================
echo          Whale2XSSHunter Launcher
echo ==================================================
echo.

if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [*] Upgrading pip...
python -m pip install --upgrade pip >nul

echo [*] Installing requirements...
pip install -r requirements.txt

echo.
echo [✓] Environment Ready
echo.
echo ==================================================
echo             Starting Scanner
echo ==================================================
echo.

python xss_scanner.py %*

pause
