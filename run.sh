#!/bin/bash

clear

echo "==========================================="
echo "        Whale2XSSHunter Launcher"
echo "==========================================="
echo

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "[!] Python not found."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    $PYTHON -m venv venv
fi

source venv/bin/activate

echo "[*] Upgrading pip..."
$PYTHON -m pip install --upgrade pip

echo "[*] Installing requirements..."
$PYTHON -m pip install -r requirements.txt

echo
echo "[✓] Environment Ready"
echo "[*] Starting Whale2XSSHunter..."
echo

$PYTHON xss_scanner.py "$@"
