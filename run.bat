@echo off
title PhishGuard v3 — Hybrid Scanner

echo ============================================
echo  PhishGuard v3.0 — Hybrid Threat Scanner
echo ============================================
echo.

python --version >nul 2>&1 || (echo [ERROR] Python not found. Install from python.org & pause & exit /b 1)

if not exist venv (
    echo [1/4] Creating virtual environment...
    python -m venv venv
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate

echo [3/4] Installing dependencies...
pip install -r requirements.txt -q

echo [4/4] Installing Playwright Chromium browser...
python -m playwright install chromium

echo.
echo [READY] Backend running at http://127.0.0.1:8000
echo [INFO]  Open phishing-detector.html in your browser
echo [INFO]  Press Ctrl+C to stop
echo.

uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
