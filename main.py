"""
PhishGuard v3.0 — Hybrid URL Threat Intelligence API
Static + Dynamic Browser Sandbox scanning
Run: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import sys
import base64
import ipaddress
import os
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
import logging

import aiohttp
import certifi
import dns.resolver
import dns.exception
import whois
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Windows event loop fix (must be BEFORE any async code) ──────
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# ── Playwright (optional — graceful fallback if missing) ─────────
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────
# APP
# ──────────────────────────────────────────────────────────────────

app = FastAPI(title="PhishGuard Hybrid API", version="3.0.0")
@app.get("/")
async def home():
    return {"message": "Phishing Detection API is running 🚀"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    scan_mode: str = "hybrid"   # always "hybrid" from frontend

# ──────────────────────────────────────────────────────────────────
# CONFIGURATION  (set via environment variables or .env)
# ──────────────────────────────────────────────────────────────────

GSB_API_KEY      = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "AIzaSyAmXK7XhrPEyMquc3hLY4WEEd-PgXFkIsE")
URLSCAN_API_KEY  = os.getenv("URLSCAN_API_KEY", "019d3f50-a0cf-777b-a2d6-1f436605293c")

SUSPICIOUS_TLDS = {
    "tk","ml","cf","ga","gq","xyz","top","click","link","work","party","date",
    "faith","review","trade","science","bid","download","accountant","loan",
    "win","stream","gdn","racing","icu","buzz","surf","cyou","monster","vip",
}

SUSPICIOUS_KEYWORDS = {
    "login","signin","sign-in","verify","account","secure","update","confirm",
    "banking","password","credential","support","helpdesk","invoice","payment",
    "paypal","ebay","amazon","apple","microsoft","google","facebook","instagram",
    "netflix","dropbox","onedrive","wellsfargo","chase","citibank","bankofamerica",
    "barclays",
}

TRUSTED_DOMAINS = {
    "google.com","youtube.com","facebook.com","instagram.com","twitter.com",
    "x.com","linkedin.com","microsoft.com","apple.com","amazon.com","netflix.com",
    "github.com","wikipedia.org","reddit.com","whatsapp.com","telegram.org",
    "dropbox.com","paypal.com","ebay.com","yahoo.com","bing.com","live.com",
    "office.com","outlook.com","zoom.us","slack.com","spotify.com",
    "cloudflare.com","fastly.net",
}

BRANDS = [
    "paypal","google","facebook","apple","microsoft","amazon","netflix",
    "instagram","bank","chase","wellsfargo","citibank","barclays","hsbc",
    "twitter","linkedin","dropbox","onedrive",
]

URGENCY_PHRASES = [
    "account suspended","verify your account","confirm your identity",
    "unusual activity","limited time","act now","your account will be",
    "click here immediately","update your payment","account locked",
    "security alert","immediate action required","expires in",
    "unauthorized access","suspicious login","verify now",
]

# In-memory cache for OpenPhish feed
_bl_cache: dict = {"openphish": set(), "last_refresh": 0}

# ──────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────

def is_trusted_domain(hostname: str) -> bool:
    hostname = hostname.lower()
    if hostname in TRUSTED_DOMAINS:
        return True
    for trusted in TRUSTED_DOMAINS:
        if hostname.endswith("." + trusted):
            return True
    return False

# ──────────────────────────────────────────────────────────────────
# STATIC — DNS
# ──────────────────────────────────────────────────────────────────

async def dns_lookup(hostname: str) -> dict:
    result = {
        "resolved": False,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "is_ip": False,
        "spf_found": False,
        "dmarc_found": False,
        "error": None,
    }

    # If already an IP address
    try:
        ipaddress.ip_address(hostname)
        result.update({"is_ip": True, "resolved": True, "a_records": [hostname]})
        return result
    except ValueError:
        pass

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 3
    resolver.lifetime = 6

    # A records
    try:
        answers = resolver.resolve(hostname, "A")
        result["a_records"] = [str(r) for r in answers]
        result["resolved"] = True
    except Exception as e:
        result["error"] = str(e)

    # MX / NS / TXT
    for rtype in ("MX", "NS", "TXT"):
        try:
            answers = resolver.resolve(hostname, rtype)
            key = f"{rtype.lower()}_records"
            if rtype == "MX":
                result[key] = [str(r.exchange).rstrip(".") for r in answers]
            else:
                result[key] = [str(r) for r in answers]
        except Exception:
            pass

    # SPF / DMARC from TXT
    for txt in result.get("txt_records", []):
        txt_lower = str(txt).lower()
        if "v=spf1" in txt_lower:
            result["spf_found"] = True
        if "v=dmarc1" in txt_lower:
            result["dmarc_found"] = True

    return result

# ──────────────────────────────────────────────────────────────────
# STATIC — WHOIS
# ──────────────────────────────────────────────────────────────────

def whois_lookup(hostname: str) -> dict:
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "age_days": None,
        "country": None,
        "status": [],
        "name_servers": [],
        "dnssec": None,
        "privacy_protected": False,
        "error": None,
    }
    try:
        w = whois.whois(hostname)
        result["registrar"] = w.registrar

        def to_dt(v):
            if isinstance(v, list):
                v = v[0]
            if isinstance(v, datetime):
                return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
            return None

        created = to_dt(w.creation_date)
        expires = to_dt(w.expiration_date)
        updated = to_dt(w.updated_date)

        if created:
            result["creation_date"] = created.strftime("%Y-%m-%d")
            result["age_days"] = (datetime.now(timezone.utc) - created).days
        if expires:
            result["expiration_date"] = expires.strftime("%Y-%m-%d")
        if updated:
            result["updated_date"] = updated.strftime("%Y-%m-%d")

        result["country"] = w.country
        if w.status:
            result["status"] = [w.status] if isinstance(w.status, str) else list(w.status)[:3]
        if w.name_servers:
            ns = w.name_servers
            result["name_servers"] = (
                [ns] if isinstance(ns, str) else [str(x).lower() for x in list(ns)[:4]]
            )
        result["dnssec"] = getattr(w, "dnssec", None)

        registrant = getattr(w, "name", "") or ""
        if any(p in str(registrant).lower() for p in ["privacy","redacted","protected","proxy","whoisguard"]):
            result["privacy_protected"] = True

    except Exception as e:
        result["error"] = str(e)[:200]

    return result

# ──────────────────────────────────────────────────────────────────
# STATIC — SSL
# ──────────────────────────────────────────────────────────────────

def ssl_lookup(hostname: str, port: int = 443) -> dict:
    result = {
        "present": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "self_signed": False,
        "version": None,
        "serial_number": None,
        "sans": [],
        "sig_algorithm": None,
        "status": "MISSING",
        "error": None,
    }
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["present"] = True

                def parse_dn(pairs):
                    return {k: v for item in pairs for k, v in item}

                issuer  = parse_dn(cert.get("issuer", []))
                subject = parse_dn(cert.get("subject", []))

                result["issuer"]      = issuer.get("organizationName") or issuer.get("commonName", "Unknown")
                result["subject"]     = subject.get("commonName", hostname)
                result["self_signed"] = issuer.get("commonName") == subject.get("commonName")

                def parse_ssl_date(s):
                    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
                        try:
                            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                        except ValueError:
                            continue
                    return None

                na = parse_ssl_date(cert.get("notAfter", ""))
                nb = parse_ssl_date(cert.get("notBefore", ""))

                if nb:
                    result["not_before"] = nb.strftime("%Y-%m-%d")
                if na:
                    result["not_after"]       = na.strftime("%Y-%m-%d")
                    days_left                  = (na - datetime.now(timezone.utc)).days
                    result["days_until_expiry"] = days_left
                    result["valid"]            = days_left > 0
                    if days_left <= 0:
                        result["status"] = "EXPIRED"
                    elif result["self_signed"]:
                        result["status"] = "SELF-SIGNED"
                    else:
                        result["status"] = "VALID"

                result["sans"]          = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"][:6]
                result["version"]       = ssock.version()
                result["sig_algorithm"] = cert.get("signatureAlgorithm")
                sn = cert.get("serialNumber")
                result["serial_number"] = sn[:20] if sn else None

    except ssl.SSLCertVerificationError as e:
        result.update({"present": True, "valid": False, "status": "INVALID", "error": str(e)[:200]})
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result.update({"error": str(e)[:200], "status": "MISSING"})
    except Exception as e:
        result["error"] = str(e)[:200]

    return result

# ──────────────────────────────────────────────────────────────────
# STATIC — BLACKLISTS
# ──────────────────────────────────────────────────────────────────

async def refresh_openphish(session: aiohttp.ClientSession):
    now = datetime.now().timestamp()
    if now - _bl_cache["last_refresh"] < 1800:
        return
    try:
        async with session.get("https://openphish.com/feed.txt", timeout=aiohttp.ClientTimeout(total=10)) as r:
            text = await r.text()
            _bl_cache["openphish"] = {line.strip().lower() for line in text.splitlines() if line.strip()}
            _bl_cache["last_refresh"] = now
    except Exception:
        pass


async def check_openphish(url: str, session: aiohttp.ClientSession) -> dict:
    await refresh_openphish(session)
    listed = url.lower() in _bl_cache["openphish"]
    return {
        "source": "OpenPhish",
        "listed": listed,
        "detail": "URL found in live phishing feed" if listed else "Not listed",
        "type": "static",
    }


async def check_urlhaus(url: str, session: aiohttp.ClientSession) -> dict:
    try:
        async with session.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=aiohttp.ClientTimeout(total=8),
        ) as r:
            data = await r.json(content_type=None)
            if data.get("query_status") == "is_listed":
                threat = data.get("threat", "malware")
                tags   = data.get("tags") or []
                return {
                    "source": "URLhaus (abuse.ch)",
                    "listed": True,
                    "detail": f"Listed as {threat}. Tags: {', '.join(tags) if tags else 'none'}",
                    "type": "static",
                }
            return {"source": "URLhaus (abuse.ch)", "listed": False, "detail": "Not listed", "type": "static"}
    except Exception as e:
        return {"source": "URLhaus (abuse.ch)", "listed": False, "detail": f"Skipped: {str(e)[:60]}", "type": "static"}


async def check_google_safe_browsing(url: str, session: aiohttp.ClientSession) -> dict:
    if not GSB_API_KEY:
        return {
            "source": "Google Safe Browsing",
            "listed": False,
            "detail": "No API key — add GOOGLE_SAFE_BROWSING_KEY to .env",
            "type": "static",
        }
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "3.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with session.post(endpoint, json=body, timeout=aiohttp.ClientTimeout(total=8)) as r:
            data    = await r.json()
            matches = data.get("matches", [])
            if matches:
                types = list({m["threatType"] for m in matches})
                return {"source": "Google Safe Browsing", "listed": True, "detail": f"Threats: {', '.join(types)}", "type": "static"}
            return {"source": "Google Safe Browsing", "listed": False, "detail": "Not listed", "type": "static"}
    except Exception as e:
        return {"source": "Google Safe Browsing", "listed": False, "detail": f"Error: {str(e)[:60]}", "type": "static"}


async def check_urlscan(url: str, session: aiohttp.ClientSession) -> dict:
     try:
        headers = {
            "API-Key": "019d3f50-a0cf-777b-a2d6-1f436605293c",   # 🔥 PUT HERE
            "Content-Type": "application/json"
        }
        base = {
        "source": "Urlscan.io",
        "listed": False,
        "detail": "Skipped — no URLSCAN_API_KEY in .env",
        "screenshot_url": None,
        "scan_url": None,
        "score": None,
        "tags": [],
        "type": "dynamic",
    }
    if not URLSCAN_API_KEY:
        return base
    try:
        async with session.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            headers={"Content-Type": "application/json", "API-Key": URLSCAN_API_KEY},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as r:
            submit  = await r.json()
            scan_id = submit.get("uuid")
            if not scan_id:
                base["detail"] = "Submission failed: " + submit.get("message", "unknown")
                return base

        await asyncio.sleep(12)

        async with session.get(
            f"https://urlscan.io/api/v1/result/{scan_id}/",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            if r.status == 404:
                await asyncio.sleep(6)
                async with session.get(f"https://urlscan.io/api/v1/result/{scan_id}/",
                                       timeout=aiohttp.ClientTimeout(total=10)) as retry:
                    result = await retry.json()
            else:
                result = await r.json()

        verdicts  = result.get("verdicts", {}).get("overall", {})
        malicious = verdicts.get("malicious", False)
        score     = verdicts.get("score", 0)
        tags      = verdicts.get("tags", [])

        return {
            "source": "Urlscan.io",
            "listed": malicious,
            "detail": f"{'MALICIOUS' if malicious else ('Suspicious' if score > 50 else 'Clean')} — score {score}/100",
            "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
            "scan_url": f"https://urlscan.io/result/{scan_id}/",
            "score": score,
            "tags": tags,
            "type": "dynamic",
        }
    except Exception as e:
        base["detail"] = f"Error: {str(e)[:80]}"
        return base

# ──────────────────────────────────────────────────────────────────
# STATIC — URL SYNTAX HEURISTICS
# ──────────────────────────────────────────────────────────────────

def analyse_syntax(url: str, parsed: urllib.parse.ParseResult) -> dict:
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    flags    = []
    score    = 0

    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        flags.append("IP address used instead of domain")
        score += 30
    except ValueError:
        pass

    url_len = len(url)
    if url_len > 100:
        flags.append(f"Very long URL ({url_len} chars)")
        score += 15
    elif url_len > 75:
        flags.append(f"Long URL ({url_len} chars)")
        score += 8

    if "@" in url:
        flags.append("@ symbol in URL (spoofing trick)")
        score += 35

    if "//" in path:
        flags.append("Double slash in path (obfuscation)")
        score += 10

    labels = hostname.split(".")
    tld    = labels[-1] if labels else ""
    subdomain_count = max(0, len(labels) - 2)

    if subdomain_count >= 4:
        flags.append(f"Excessive subdomains ({subdomain_count} levels)")
        score += 20
    elif subdomain_count >= 3:
        flags.append(f"Multiple subdomains ({subdomain_count} levels)")
        score += 10

    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD (.{tld})")
        score += 20

    dash_count = hostname.count("-")
    if dash_count >= 4:
        flags.append(f"Excessive dashes in hostname ({dash_count})")
        score += 15
    elif dash_count >= 2:
        flags.append(f"Multiple dashes ({dash_count})")
        score += 8

    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if len(found_kw) >= 3:
        flags.append(f"Multiple suspicious keywords: {', '.join(found_kw[:3])}")
        score += 25
    elif found_kw:
        flags.append(f"Suspicious keyword: {found_kw[0]}")
        score += 10

    if len(hostname) > 50:
        flags.append(f"Very long hostname ({len(hostname)} chars)")
        score += 15
    elif len(hostname) > 30:
        flags.append(f"Long hostname ({len(hostname)} chars)")
        score += 5

    if re.search(r"https?://.*https?://", url):
        flags.append("URL inside URL (redirect trick)")
        score += 40

    if "xn--" in hostname:
        flags.append("Punycode/IDN domain (homoglyph attack risk)")
        score += 25

    digits_in_hostname = sum(c.isdigit() for c in hostname.replace(".", ""))
    if digits_in_hostname > 6 and not is_ip:
        flags.append("Digit-heavy hostname (unusual)")
        score += 10

    if parsed.port and parsed.port not in (80, 443):
        flags.append(f"Non-standard port ({parsed.port})")
        score += 10

    if parsed.scheme == "http":
        flags.append("Unencrypted HTTP (no TLS)")
        score += 15

    if url.startswith("data:"):
        flags.append("Data URI — potential credential harvester")
        score += 50

    return {
        "score": min(score, 100),
        "flags": flags,
        "is_ip": is_ip,
        "tld": tld,
        "subdomain_count": subdomain_count,
        "url_length": url_len,
        "dash_count": dash_count,
        "keyword_matches": found_kw,
        "has_at": "@" in url,
        "has_punycode": "xn--" in hostname,
    }

# ──────────────────────────────────────────────────────────────────
# STATIC — REDIRECT CHAIN
# ──────────────────────────────────────────────────────────────────

async def check_redirects(url: str, session: aiohttp.ClientSession) -> dict:
    chain   = []
    current = url
    try:
        for _ in range(10):
            async with session.head(
                current,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
            ) as r:
                chain.append({"url": current, "status": r.status})
                loc = r.headers.get("Location")
                if r.status in (301, 302, 303, 307, 308) and loc:
                    current = loc if loc.startswith("http") else urllib.parse.urljoin(current, loc)
                else:
                    break
    except Exception:
        pass
    return {
        "chain": chain,
        "hops": len(chain),
        "final_url": chain[-1]["url"] if chain else url,
        "suspicious": len(chain) > 3,
        "cross_domain": len({urllib.parse.urlparse(c["url"]).hostname for c in chain}) > 2,
    }

# ──────────────────────────────────────────────────────────────────
# DYNAMIC — PLAYWRIGHT BROWSER SANDBOX
# ──────────────────────────────────────────────────────────────────

async def dynamic_scan(url: str) -> dict:
    result = {
        "available": PLAYWRIGHT_AVAILABLE,
        "visited": False,
        "final_url": url,
        "redirected": False,
        "page_title": None,
        "screenshot_b64": None,
        "has_password_field": False,
        "has_login_form": False,
        "form_count": 0,
        "form_submit_urls": [],
        "external_scripts": [],
        "iframes": [],
        "popups_triggered": False,
        "network_requests": [],
        "suspicious_requests": [],
        "cookies_set": [],
        "js_obfuscation_detected": False,
        "urgency_language": [],
        "brand_impersonation": [],
        "risk_signals": [],
        "dom_size": None,
        "load_time_ms": None,
        "error": None,
    }

    if not PLAYWRIGHT_AVAILABLE:
        result["error"] = "Playwright not installed. Run: pip install playwright && playwright install chromium"
        return result

    SUSPICIOUS_EXFIL = [
        r"\.tk$", r"\.ml$", r"\.cf$", r"\.gq$",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    ]

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--js-flags=--max-old-space-size=256",
                ],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                java_script_enabled=True,
                accept_downloads=False,
            )
            page = await context.new_page()

            # Network request interception
            network_requests: list = []
            page.on("request", lambda req: network_requests.append({
                "url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
            }))

            # Popup detection
            popups: list = []
            context.on("page", lambda pg: popups.append(pg))

            # Navigate
            t0 = time.time()
            try:
                await page.goto(url, timeout=15000, wait_until="networkidle")
            except Exception:
                await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            result["load_time_ms"] = int((time.time() - t0) * 1000)

            result["visited"]          = True
            result["final_url"]        = page.url
            result["redirected"]       = page.url.rstrip("/") != url.rstrip("/")
            result["page_title"]       = await page.title()
            result["popups_triggered"] = len(popups) > 0
            result["network_requests"] = [r["url"] for r in network_requests[:30]]

            # Screenshot
            ss = await page.screenshot(full_page=False, type="jpeg", quality=55)
            result["screenshot_b64"] = base64.b64encode(ss).decode()

            # Forms / password fields
            pw_fields = await page.query_selector_all("input[type='password']")
            result["has_password_field"] = len(pw_fields) > 0
            forms = await page.query_selector_all("form")
            result["form_count"]    = len(forms)
            result["has_login_form"] = len(forms) > 0
            result["form_submit_urls"] = [
                a for a in [await f.get_attribute("action") for f in forms] if a
            ]

            # External scripts
            scripts = await page.query_selector_all("script[src]")
            result["external_scripts"] = [
                s for s in [await sc.get_attribute("src") for sc in scripts] if s
            ]

            # iframes
            iframes = await page.query_selector_all("iframe")
            result["iframes"] = [s for s in [await f.get_attribute("src") for f in iframes] if s]

            # DOM size
            result["dom_size"] = await page.evaluate("document.querySelectorAll('*').length")

            # JS obfuscation patterns
            content = await page.content()
            obf_patterns = [
                r"eval\(", r"atob\(", r"unescape\(",
                r"String\.fromCharCode", r"\\x[0-9a-fA-F]{2}",
                r"document\[.{1,20}\]\[.{1,20}\]",
            ]
            for pat in obf_patterns:
                if re.search(pat, content):
                    result["js_obfuscation_detected"] = True
                    result["risk_signals"].append(f"JS obfuscation pattern detected: {pat}")
                    break

            # Urgency language
            page_text = await page.evaluate("document.body ? document.body.innerText : ''")
            page_text_lower = page_text.lower()
            result["urgency_language"] = [p for p in URGENCY_PHRASES if p in page_text_lower]

            # Brand impersonation
            title_lower   = (result["page_title"] or "").lower()
            actual_domain = urllib.parse.urlparse(page.url).hostname or ""
            found_brands  = [b for b in BRANDS if b in page_text_lower or b in title_lower]
            result["brand_impersonation"] = [b for b in found_brands if b not in actual_domain]

            # Suspicious exfil requests
            susp_reqs = []
            for req in network_requests:
                netloc = urllib.parse.urlparse(req["url"]).netloc or ""
                if any(re.search(pat, netloc) for pat in SUSPICIOUS_EXFIL):
                    susp_reqs.append(req["url"])
            result["suspicious_requests"] = susp_reqs[:10]

            # Cookies
            cookies = await context.cookies()
            result["cookies_set"] = [
                {"name": c["name"], "domain": c["domain"],
                 "httpOnly": c.get("httpOnly", False), "secure": c.get("secure", False)}
                for c in cookies[:10]
            ]

            # Risk signals
            if result["has_password_field"] and result["redirected"]:
                result["risk_signals"].append("Password field found after redirect")
            if result["brand_impersonation"]:
                result["risk_signals"].append(f"Brand impersonation: {', '.join(result['brand_impersonation'])}")
            if result["urgency_language"]:
                result["risk_signals"].append(f"Urgency language detected ({len(result['urgency_language'])} phrases)")
            if susp_reqs:
                result["risk_signals"].append(f"Suspicious data requests: {susp_reqs[0][:60]}")
            if result["iframes"]:
                result["risk_signals"].append(f"{len(result['iframes'])} iframe(s) detected")
            if result["js_obfuscation_detected"]:
                result["risk_signals"].append("Obfuscated JavaScript in page source")
            if result["popups_triggered"]:
                result["risk_signals"].append("Popup / new tab triggered on load")
            if not result["cookies_set"] and result["has_login_form"]:
                result["risk_signals"].append("Login form but no session cookies — unusual")

            await browser.close()

    except asyncio.TimeoutError:
        result["error"] = "Page load timed out (15 s)"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result

# ──────────────────────────────────────────────────────────────────
# SCORING
# ──────────────────────────────────────────────────────────────────

def compute_risk_score(dns_data, whois_data, ssl_data, syntax_data,
                       blacklists, redirects, dynamic_data=None) -> tuple:
    score   = 0
    factors = []

    # DNS
    if not dns_data["resolved"]:
        score += 20
        factors.append({"factor": "DNS unresolvable", "weight": 20})
    if dns_data["is_ip"]:
        score += 25
        factors.append({"factor": "IP-based URL", "weight": 25})
    if dns_data.get("spf_found") is False and not dns_data.get("is_ip"):
        score += 5
        factors.append({"factor": "No SPF record", "weight": 5})

    # WHOIS
    age = whois_data.get("age_days")
    if age is not None:
        if age < 30:
            score += 35
            factors.append({"factor": "Newly registered domain (<30 days)", "weight": 35})
        elif age < 180:
            score += 15
            factors.append({"factor": "Young domain (<6 months)", "weight": 15})
        elif age < 365:
            score += 5
            factors.append({"factor": "Domain <1 year old", "weight": 5})
    elif whois_data.get("error"):
        score += 10
        factors.append({"factor": "WHOIS lookup failed", "weight": 10})
    if whois_data.get("privacy_protected"):
        score += 8
        factors.append({"factor": "WHOIS privacy protection", "weight": 8})

    # SSL
    if not ssl_data["present"]:
        score += 20
        factors.append({"factor": "No SSL certificate", "weight": 20})
    elif not ssl_data["valid"]:
        score += 15
        factors.append({"factor": "Invalid/expired SSL", "weight": 15})
    elif ssl_data["self_signed"]:
        score += 10
        factors.append({"factor": "Self-signed certificate", "weight": 10})
    days = ssl_data.get("days_until_expiry")
    if days is not None and 0 < days < 14:
        score += 5
        factors.append({"factor": f"SSL expiring in {days} days", "weight": 5})

    # Syntax
    s = syntax_data["score"]
    score += s // 2
    if s > 30:
        factors.append({"factor": f"High syntax risk ({s}/100)", "weight": s // 2})

    # Blacklists
    for bl in [b for b in blacklists if b.get("listed")]:
        score += 40
        factors.append({"factor": f"Listed on {bl['source']}", "weight": 40})

    # Redirects
    if redirects["suspicious"]:
        score += 15
        factors.append({"factor": f"Suspicious redirect chain ({redirects['hops']} hops)", "weight": 15})
    if redirects.get("cross_domain"):
        score += 10
        factors.append({"factor": "Cross-domain redirect", "weight": 10})

    # Dynamic
    if dynamic_data and dynamic_data.get("visited"):
        if dynamic_data.get("brand_impersonation"):
            score += 30
            factors.append({"factor": f"Brand impersonation: {', '.join(dynamic_data['brand_impersonation'])}", "weight": 30})
        if dynamic_data.get("js_obfuscation_detected"):
            score += 20
            factors.append({"factor": "Obfuscated JavaScript", "weight": 20})
        if dynamic_data.get("urgency_language"):
            n = len(dynamic_data["urgency_language"])
            w = min(n * 8, 24)
            score += w
            factors.append({"factor": f"Urgency language ({n} phrases)", "weight": w})
        if dynamic_data.get("has_password_field") and dynamic_data.get("redirected"):
            score += 25
            factors.append({"factor": "Password field after redirect", "weight": 25})
        if dynamic_data.get("suspicious_requests"):
            score += 15
            factors.append({"factor": "Suspicious exfiltration requests", "weight": 15})
        if dynamic_data.get("popups_triggered"):
            score += 10
            factors.append({"factor": "Popups triggered on load", "weight": 10})

    return min(100, max(0, score)), factors


def verdict_from_score(score: int) -> str:
    if score <= 15: return "SAFE"
    if score <= 35: return "LOW RISK"
    if score <= 55: return "SUSPICIOUS"
    if score <= 75: return "HIGH RISK"
    return "CRITICAL THREAT"


def build_threat_breakdown(dns_data, whois_data, ssl_data, syntax_data,
                           blacklists, redirects, dynamic_data=None) -> list:
    checks = []

    # SSL
    if ssl_data["valid"]:
        checks.append({"name": "SSL Certificate", "score": 5, "status": "PASS",
                        "detail": f"Valid — {ssl_data.get('issuer','?')}, {ssl_data.get('days_until_expiry','?')} days left", "type": "static"})
    elif ssl_data["present"]:
        checks.append({"name": "SSL Certificate", "score": 70, "status": "FAIL",
                        "detail": ssl_data.get("error", ssl_data["status"]), "type": "static"})
    else:
        checks.append({"name": "SSL Certificate", "score": 80, "status": "FAIL",
                        "detail": "No SSL/TLS certificate", "type": "static"})

    # DNS
    if dns_data["resolved"]:
        a_str = ", ".join(dns_data["a_records"][:3]) or "—"
        checks.append({"name": "DNS Resolution", "score": 5, "status": "PASS",
                        "detail": f"Resolved → {a_str}", "type": "static"})
    else:
        checks.append({"name": "DNS Resolution", "score": 85, "status": "FAIL",
                        "detail": f"Cannot resolve: {dns_data.get('error','')}", "type": "static"})

    # SPF
    if dns_data.get("spf_found"):
        checks.append({"name": "SPF Record", "score": 5, "status": "PASS",
                        "detail": "SPF record present", "type": "static"})
    elif dns_data.get("spf_found") is False:
        checks.append({"name": "SPF Record", "score": 20, "status": "WARN",
                        "detail": "No SPF record — spoofing risk", "type": "static"})
    else:
        checks.append({"name": "SPF Record", "score": 10, "status": "WARN",
                        "detail": "SPF check inconclusive", "type": "static"})

    # WHOIS domain age
    age = whois_data.get("age_days")
    if age is None:
        checks.append({"name": "Domain Age (WHOIS)", "score": 30, "status": "WARN",
                        "detail": "WHOIS data unavailable", "type": "static"})
    elif age < 30:
        checks.append({"name": "Domain Age (WHOIS)", "score": 90, "status": "FAIL",
                        "detail": f"Newly registered {age} days ago", "type": "static"})
    elif age < 180:
        checks.append({"name": "Domain Age (WHOIS)", "score": 50, "status": "WARN",
                        "detail": f"Young domain ({age} days)", "type": "static"})
    else:
        checks.append({"name": "Domain Age (WHOIS)", "score": 5, "status": "PASS",
                        "detail": f"Established — {age // 365}+ year(s) old", "type": "static"})

    # WHOIS privacy
    if whois_data.get("privacy_protected"):
        checks.append({"name": "WHOIS Privacy", "score": 30, "status": "WARN",
                        "detail": "Registrant identity hidden", "type": "static"})
    else:
        checks.append({"name": "WHOIS Privacy", "score": 5, "status": "PASS",
                        "detail": "Registrant info visible", "type": "static"})

    # Blacklists
    bl_count = sum(1 for b in blacklists if b.get("listed"))
    if bl_count == 0:
        checks.append({"name": "Blacklist Status", "score": 5, "status": "PASS",
                        "detail": f"Clean across {len(blacklists)} databases", "type": "static"})
    else:
        src = [b["source"] for b in blacklists if b.get("listed")]
        checks.append({"name": "Blacklist Status", "score": 95, "status": "FAIL",
                        "detail": f"Listed on: {', '.join(src)}", "type": "static"})

    # Syntax
    s  = syntax_data["score"]
    fl = syntax_data["flags"]
    if s <= 15:
        checks.append({"name": "URL Syntax", "score": s, "status": "PASS",
                        "detail": "No anomalies", "type": "static"})
    elif s <= 40:
        checks.append({"name": "URL Syntax", "score": s, "status": "WARN",
                        "detail": fl[0] if fl else "Minor anomalies", "type": "static"})
    else:
        checks.append({"name": "URL Syntax", "score": s, "status": "FAIL",
                        "detail": "; ".join(fl[:2]) if fl else "Multiple anomalies", "type": "static"})

    # IDN / Punycode
    if syntax_data.get("has_punycode"):
        checks.append({"name": "IDN / Homoglyph", "score": 75, "status": "WARN",
                        "detail": "Punycode domain — verify carefully", "type": "static"})
    else:
        checks.append({"name": "IDN / Homoglyph", "score": 5, "status": "PASS",
                        "detail": "No IDN patterns", "type": "static"})

    # Subdomain complexity
    sc = syntax_data.get("subdomain_count", 0)
    if sc >= 4:
        checks.append({"name": "Subdomain Complexity", "score": 65, "status": "FAIL",
                        "detail": f"{sc} nested levels", "type": "static"})
    elif sc >= 3:
        checks.append({"name": "Subdomain Complexity", "score": 40, "status": "WARN",
                        "detail": f"{sc} subdomain levels", "type": "static"})
    else:
        checks.append({"name": "Subdomain Complexity", "score": 5, "status": "PASS",
                        "detail": f"{sc} level(s)", "type": "static"})

    # Redirects
    hops = redirects.get("hops", 0)
    if hops > 3:
        checks.append({"name": "Redirect Chain", "score": 60, "status": "WARN",
                        "detail": f"{hops} redirects — possible cloaking", "type": "static"})
    else:
        checks.append({"name": "Redirect Chain", "score": 5 if hops == 0 else 10, "status": "PASS",
                        "detail": f"{hops} redirect(s) — normal", "type": "static"})

    # ── Dynamic checks ──────────────────────────────────────────
    if dynamic_data:
        if dynamic_data.get("error"):
            checks.append({"name": "Dynamic Browser Scan", "score": 0, "status": "WARN",
                            "detail": f"Error: {dynamic_data['error'][:80]}", "type": "dynamic"})
        elif dynamic_data.get("visited"):
            # Brand impersonation
            imp = dynamic_data.get("brand_impersonation", [])
            checks.append({"name": "Brand Impersonation", "score": 85 if imp else 5,
                            "status": "FAIL" if imp else "PASS",
                            "detail": f"Impersonates: {', '.join(imp)}" if imp else "None detected",
                            "type": "dynamic"})

            # JS obfuscation
            checks.append({"name": "JS Obfuscation", "score": 70 if dynamic_data.get("js_obfuscation_detected") else 5,
                            "status": "FAIL" if dynamic_data.get("js_obfuscation_detected") else "PASS",
                            "detail": "Obfuscated code in source" if dynamic_data.get("js_obfuscation_detected") else "None detected",
                            "type": "dynamic"})

            # Credential harvesting
            has_pw = dynamic_data.get("has_password_field")
            redir  = dynamic_data.get("redirected")
            checks.append({"name": "Credential Harvesting",
                            "score": 60 if (has_pw and redir) else (30 if has_pw else 5),
                            "status": "FAIL" if (has_pw and redir) else ("WARN" if has_pw else "PASS"),
                            "detail": ("Password field after redirect" if redir else "Password field present") if has_pw else "No credential fields",
                            "type": "dynamic"})

            # Social engineering / urgency
            urg = dynamic_data.get("urgency_language", [])
            checks.append({"name": "Social Engineering",
                            "score": min(len(urg) * 15, 60) if urg else 5,
                            "status": "WARN" if urg else "PASS",
                            "detail": f"Urgency phrases: {', '.join(urg[:2])}" if urg else "None detected",
                            "type": "dynamic"})

            # Popup behaviour
            checks.append({"name": "Popup Behaviour",
                            "score": 40 if dynamic_data.get("popups_triggered") else 5,
                            "status": "WARN" if dynamic_data.get("popups_triggered") else "PASS",
                            "detail": "Unsolicited popup triggered" if dynamic_data.get("popups_triggered") else "No popups",
                            "type": "dynamic"})

            # Data exfiltration
            sreqs = dynamic_data.get("suspicious_requests", [])
            checks.append({"name": "Data Exfiltration",
                            "score": 70 if sreqs else 5,
                            "status": "FAIL" if sreqs else "PASS",
                            "detail": f"Suspicious request: {sreqs[0][:50]}" if sreqs else "No suspicious requests",
                            "type": "dynamic"})

    return checks

# ──────────────────────────────────────────────────────────────────
# MAIN SCAN ENDPOINT  — HYBRID ONLY
# ──────────────────────────────────────────────────────────────────

@app.post("/scan")
async def scan_url(req: ScanRequest):
    raw_url = req.url.strip()

    if not raw_url.startswith(("http://", "https://", "data:")):
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Cannot extract hostname from URL")

    logger.info(f"[HYBRID SCAN] {raw_url}")

    # ── Run all static checks concurrently ───────────────────────
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False),
        headers={"User-Agent": "PhishGuard/3.0 Security Scanner"},
    ) as session:

        static_tasks = {
            "dns":       asyncio.create_task(dns_lookup(hostname)),
            "redirects": asyncio.create_task(check_redirects(raw_url, session)),
            "openphish": asyncio.create_task(check_openphish(raw_url, session)),
            "urlhaus":   asyncio.create_task(check_urlhaus(raw_url, session)),
            "gsb":       asyncio.create_task(check_google_safe_browsing(raw_url, session)),
            "urlscan":   asyncio.create_task(check_urlscan(raw_url, session)),
        }

        loop       = asyncio.get_event_loop()
        whois_task = loop.run_in_executor(None, whois_lookup, hostname)
        ssl_task   = loop.run_in_executor(None, ssl_lookup,   hostname)

        # Playwright dynamic scan (with 30 s cap so it never blocks forever)
        dynamic_task = asyncio.create_task(
            asyncio.wait_for(dynamic_scan(raw_url), timeout=30)
        )

        # Gather everything
        static_results = await asyncio.gather(
            *static_tasks.values(), whois_task, ssl_task, return_exceptions=True
        )
        static_keys = list(static_tasks.keys()) + ["whois", "ssl"]
        r = {}
        for k, v in zip(static_keys, static_results):
            r[k] = v if not isinstance(v, Exception) else {}

        try:
            dynamic_data = await dynamic_task
        except asyncio.TimeoutError:
            dynamic_data = {"error": "Dynamic scan timed out (30 s)", "visited": False}
        except Exception as e:
            dynamic_data = {"error": str(e)[:200], "visited": False}

    # ── Assemble ─────────────────────────────────────────────────
    blacklists  = [r["openphish"], r["urlhaus"], r["gsb"], r["urlscan"]]
    syntax_data = analyse_syntax(raw_url, parsed)

    risk_score, risk_factors = compute_risk_score(
        r["dns"], r["whois"], r["ssl"], syntax_data, blacklists, r["redirects"], dynamic_data
    )
    verdict = verdict_from_score(risk_score)
    threats = build_threat_breakdown(
        r["dns"], r["whois"], r["ssl"], syntax_data, blacklists, r["redirects"], dynamic_data
    )

    age_days = r["whois"].get("age_days")
    if age_days is None:
        age_str = "Unknown"
    elif age_days < 30:
        age_str = f"Newly registered ({age_days} days)"
    elif age_days < 365:
        age_str = f"{age_days // 30} month(s)"
    else:
        age_str = f"{age_days // 365} year(s)"

    labels    = hostname.split(".")
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""

    return {
        "url":         raw_url,
        "scanMode":    "hybrid",
        "riskScore":   risk_score,
        "verdict":     verdict,
        "riskFactors": risk_factors,
        "ssl":         r["ssl"],
        "dns":         r["dns"],
        "whois":       {**r["whois"], "age_string": age_str},
        "syntax":      syntax_data,
        "blacklists":  blacklists,
        "platformBlocks": [
            {"platform": "Google Safe Browsing", "blocked": r["gsb"].get("listed", False), "detail": r["gsb"].get("detail", "")},
            {"platform": "URLhaus / Abuse.ch",   "blocked": r["urlhaus"].get("listed", False), "detail": r["urlhaus"].get("detail", "")},
            {"platform": "OpenPhish Feed",        "blocked": r["openphish"].get("listed", False), "detail": r["openphish"].get("detail", "")},
            {"platform": "Urlscan.io",            "blocked": r["urlscan"].get("listed", False), "detail": r["urlscan"].get("detail", "")},
        ],
        "threats":   threats,
        "redirects": r["redirects"],
        "dynamic":   dynamic_data,
        "urlscan": {
            "screenshot": r["urlscan"].get("screenshot_url"),
            "report":     r["urlscan"].get("scan_url"),
            "score":      r["urlscan"].get("score"),
            "tags":       r["urlscan"].get("tags", []),
        },
        "urlInfo": {
            "protocol":       parsed.scheme,
            "hostname":       hostname,
            "tld":            labels[-1] if labels else "",
            "urlLength":      len(raw_url),
            "subdomain":      subdomain or "none",
            "pathDepth":      len([p for p in parsed.path.split("/") if p]),
            "hasSpecialChars": bool(re.search(r"[<>{}\\|^`]", raw_url)),
            "isIpBased":      r["dns"].get("is_ip", False),
            "port":           parsed.port,
        },
        "scannedAt": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health():
    return {
        "status":       "ok",
        "version":      "3.0.0",
        "playwright":   PLAYWRIGHT_AVAILABLE,
        "gsb_key":      bool(GSB_API_KEY),
        "urlscan_key":  bool(URLSCAN_API_KEY),
    }
