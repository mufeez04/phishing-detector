# PhishGuard v3.0 — Hybrid URL Threat Intelligence System

> **Final Year Project** — Real-Time Phishing URL Detection combining Static Rule Analysis + Dynamic Browser Sandbox Scanning

---

## 📌 Overview

PhishGuard uses a **Hybrid scan engine** that runs two analysis pipelines simultaneously and fuses them into a single **0–100 risk score**:

| Engine | Technique | Checks |
|--------|-----------|--------|
| **Static** | Rule-based heuristics | DNS, WHOIS, SSL, SPF/DMARC, URL syntax, blacklists, redirect chain |
| **Dynamic** | Playwright headless Chromium | Live screenshot, credential forms, JS obfuscation, urgency language, brand impersonation, exfiltration requests |

---

## 🚀 Quick Start

### Windows
```
Double-click run.bat
```

### Mac / Linux
```bash
chmod +x run.sh
./run.sh
```

Then open `phishing-detector.html` in your browser.

---

## 🛠 Manual Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🔑 API Keys (optional but recommended)

Create `.env` (copy from `.env.example`):

```env
GOOGLE_SAFE_BROWSING_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

| Service | Where to get | Cost |
|---------|-------------|------|
| Google Safe Browsing | [console.cloud.google.com](https://console.cloud.google.com) | Free |
| Urlscan.io | [urlscan.io/user/signup](https://urlscan.io/user/signup/) | Free |

Without these keys the scanner still works — it just skips those two checks.

---

## 📡 API Reference

### `POST /scan`
```json
{
  "url": "https://example.com",
  "scan_mode": "hybrid"
}
```

**Response fields:**
- `riskScore` — 0–100 integer
- `verdict` — `SAFE` / `LOW RISK` / `SUSPICIOUS` / `HIGH RISK` / `CRITICAL THREAT`
- `threats` — list of check results (each with `name`, `score`, `status`, `detail`, `type`)
- `dynamic` — full sandbox output including `screenshot_b64`, `risk_signals`, etc.
- `dns`, `ssl`, `whois`, `redirects`, `syntax`, `blacklists`

### `GET /health`
Returns version and feature availability.

---

## 🔎 Detection Checks (18+)

### Static (rule-based)
1. SSL certificate validity & expiry
2. DNS resolution (A / MX / NS records)
3. SPF / DMARC email authentication
4. WHOIS domain age (< 30 days = red flag)
5. WHOIS privacy shield detection
6. Blacklist — OpenPhish live feed
7. Blacklist — URLhaus / Abuse.ch API
8. Blacklist — Google Safe Browsing
9. Blacklist — Urlscan.io sandbox verdict
10. URL syntax: length, dashes, subdomains, @-trick
11. Suspicious TLD detection (.tk, .xyz, .click…)
12. Suspicious keyword matching
13. Punycode / IDN homoglyph detection
14. Redirect chain length & cross-domain detection
15. IP-based URL detection

### Dynamic (Playwright browser sandbox)
16. Brand impersonation (PayPal, Google, Apple…)
17. Credential harvesting (password field after redirect)
18. JavaScript obfuscation detection (eval, atob, fromCharCode…)
19. Urgency language / social engineering phrases
20. Popup / new tab behaviour
21. Data exfiltration request monitoring
22. Hidden iframes
23. Live page screenshot

---

## 📊 Risk Score Scale

| Score | Verdict |
|-------|---------|
| 0 – 15 | ✅ SAFE |
| 16 – 35 | 🔵 LOW RISK |
| 36 – 55 | 🟡 SUSPICIOUS |
| 56 – 75 | 🟠 HIGH RISK |
| 76 – 100 | 🔴 CRITICAL THREAT |

---

## 📂 Repository Structure

```
phishguard/
├── main.py                   ← FastAPI backend (hybrid scan engine)
├── phishing-detector.html    ← Frontend (single-file, no build step)
├── requirements.txt
├── run.bat                   ← Windows one-click launcher
├── run.sh                    ← Mac / Linux launcher
├── .env.example              ← API key template
├── .gitignore
└── README.md
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, FastAPI, uvicorn |
| Async HTTP | aiohttp |
| DNS | dnspython |
| WHOIS | python-whois |
| SSL | Python stdlib `ssl` + `certifi` |
| Browser sandbox | Playwright (Chromium) |
| Frontend | Vanilla HTML/CSS/JS (no framework) |

---

*Built for Final Year Project submission — PhishGuard v3.0*
