#!/bin/bash

clear

echo "=================================================="
echo "         Whale2XSSHunter Launcher"
echo "=================================================="
echo

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[*] Upgrading pip..."
python -m pip install --upgrade pip --quiet

echo "[*] Installing requirements..."
pip install -r requirements.txt

echo
echo "[✓] Environment Ready"
echo
echo "=================================================="
echo "            Starting Scanner"
echo "=================================================="
echo

python xss_scanner.py "$@"
