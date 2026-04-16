#!/usr/bin/env bash
set -e

echo "============================================"
echo " PhishGuard v3.0 — Hybrid Threat Scanner"
echo "============================================"
echo ""

command -v python3 >/dev/null 2>&1 || { echo "[ERROR] Python 3 not found."; exit 1; }

if [ ! -d "venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[2/4] Activating virtual environment..."
source venv/bin/activate

echo "[3/4] Installing dependencies..."
pip install -r requirements.txt -q

echo "[4/4] Installing Playwright Chromium browser..."
python -m playwright install chromium

echo ""
echo "[READY] Backend running at http://127.0.0.1:8000"
echo "[INFO]  Open phishing-detector.html in your browser"
echo "[INFO]  Press Ctrl+C to stop"
echo ""

uvicorn main:app --host 127.0.0.1 --port 8000 --reload
