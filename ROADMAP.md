# STORM_VX — نقشه راه توسعه (v7.0)

## ساختار فایل‌های جدید

```
Storm-Vx/
├── finder/                        # ماژول‌های شناسایی
│   ├── VF_FINDER.py              # موتور اصلی (existing - خواندن ماژول‌ها)
│   ├── vf_subdomain.py           # 🆕 Subdomain Bruteforce
│   ├── vf_js_scanner.py          # 🆕 JS Secret Scanner
│   ├── vf_waf_probe.py           # 🆕 WAF Rule Fingerprinting
│   ├── vf_rate_probe.py          # 🆕 Rate Limit Probe
│   ├── vf_cache_analyzer.py      # 🆕 Cache Analyzer
│   └── vf_dir_fuzzer.py          # 🆕 Directory Fuzzer
│
├── tester/                        # ماژول‌های حمله
│   ├── VF_TESTER.py              # موتور اصلی (existing - خواندن ماژول‌ها)
│   ├── vf_h2c_smuggler.py        # 🆕 HTTP/2 Cleartext Smuggling
│   ├── vf_slow_read.py           # 🆕 Slow READ Attack
│   ├── vf_chunked_bomb.py        # 🆕 Chunked Transfer Bomb
│   ├── vf_ws_flood.py            # 🆕 WebSocket Flood
│   ├── vf_header_bomb.py         # 🆕 Header Bomb
│   ├── vf_h2_push.py             # 🆕 H2 Multiplex Push
│   ├── vf_graphql_flood.py       # 🆕 GraphQL Flood
│   └── vf_cookie_poison.py       # 🆕 Cookie Poisoning
│
├── evasion/                       # ماژول‌های دور زدن
│   ├── vf_fp_cloner.py           # 🆕 Browser Fingerprint Cloner
│   ├── vf_session_harvest.py     # 🆕 Session Harvesting
│   ├── vf_pipeline.py            # 🆕 Request Pipeline Orchestration
│   ├── vf_behavior.py            # 🆕 Behavioral Mimicry
│   └── vf_referrer.py            # 🆕 Referrer Chain Spoofing
│
├── infra/                         # زیرساخت و مدیریت
│   ├── vf_profile_manager.py     # 🆕 Attack Profile Save/Load
│   ├── vf_report.py              # 🆕 Post-Attack Report
│   ├── vf_telegram.py            # 🆕 Telegram Remote Control
│   ├── vf_updater.py             # 🆕 Auto-Update from GitHub
│   └── vf_multi_target.py        # 🆕 Multi-Target Queue
│
├── tracker/                       # جمع‌آوری credential
│   ├── VF_TRACKER.py             # (existing)
│   └── receive.php               # (existing)
│
├── run.bat                        # (existing - بروزرسانی)
├── run.sh                         # (existing - بروزرسانی)
└── ROADMAP.md                     # این فایل
```

## فازبندی پیاده‌سازی

### ── فاز ۱: تقویت شناسایی (Recon) ──────────────────────

| # | فایل | قابلیت | خطوط تخمینی | وابستگی |
|---|------|--------|-------------|---------|
| 1 | `vf_subdomain.py` | Subdomain Bruteforce — wordlist داخلی ۵۰۰+ کلمه، resolution همزمان | ~250 | aiohttp, dns.resolver |
| 2 | `vf_js_scanner.py` | JS Secret Scanner — دانلود JS، regex برای API key/token/IP/internal endpoint | ~300 | aiohttp, re |
| 3 | `vf_waf_probe.py` | WAF Rule Fingerprinting — ارسال ۳۰+ payload، ثبت کدوم بلاک میشه | ~350 | aiohttp |
| 4 | `vf_rate_probe.py` | Rate Limit Probe — افزایش تدریجی RPS تا آستانه block | ~200 | aiohttp |
| 5 | `vf_cache_analyzer.py` | Cache Analyzer — بررسی هدرهای کش + TTL + قابلیت Deception | ~250 | aiohttp |
| 6 | `vf_dir_fuzzer.py` | Directory Fuzzer — wordlist داخلی ۳۰۰+ مسیر حساس | ~250 | aiohttp |

### ── فاز ۲: حملات جدید (Attack) ──────────────────────

| # | فایل | قابلیت | خطوط تخمینی | وابستگی |
|---|------|--------|-------------|---------|
| 7 | `vf_h2c_smuggler.py` | h2c Smuggling — ارتقای H1 به H2C، bypass WAF | ~350 | aiohttp, h2 |
| 8 | `vf_slow_read.py` | Slow READ — اتصال باز + خواندن آهسته ۱ بایت/ثانیه | ~200 | aiohttp |
| 9 | `vf_chunked_bomb.py` | Chunked Transfer — چانک‌های ۱ بایتی با تاخیر | ~200 | aiohttp |
| 10 | `vf_ws_flood.py` | WebSocket Flood — اتصال WS + پیام انبوه | ~300 | websockets |
| 11 | `vf_header_bomb.py` | Header Bomb — هدرهای ۶۴KB+ | ~150 | aiohttp |
| 12 | `vf_h2_push.py` | H2 Multiplex Push — باز کردن streamهای یکطرفه | ~250 | httpx[h2] |
| 13 | `vf_graphql_flood.py` | GraphQL Flood — depth bomb + alias spam | ~250 | aiohttp |
| 14 | `vf_cookie_poison.py` | Cookie Poisoning — ساخت کوکی‌های مخرب | ~200 | aiohttp |

### ── فاز ۳: دور زدن پیشرفته (Evasion) ──────────────────────

| # | فایل | قابلیت | خطوط تخمینی | وابستگی |
|---|------|--------|-------------|---------|
| 15 | `vf_fp_cloner.py` | Browser FP Cloner — استخراج JA3 واقعی + تقلید | ~250 | ssl, aiohttp |
| 16 | `vf_session_harvest.py` | Session Harvesting — کوکی واقعی از مرورگر | ~300 | aiohttp, sqlite3 |
| 17 | `vf_pipeline.py` | Pipeline Orchestration — ترکیب حملات | ~350 | asyncio |
| 18 | `vf_behavior.py` | Behavioral Mimicry — شبیه‌سازی رفتار کاربر | ~300 | asyncio |
| 19 | `vf_referrer.py` | Referrer Chain Spoofing — Google/Site referrer | ~150 | - |

### ── فاز ۴: زیرساخت (Infrastructure) ──────────────────────

| # | فایل | قابلیت | خطوط تخمینی | وابستگی |
|---|------|--------|-------------|---------|
| 20 | `vf_profile_manager.py` | Profile Save/Load — ذخیره/بارگذاری پروفایل حمله | ~200 | json |
| 21 | `vf_report.py` | Post-Attack Report — گزارش HTML با نمودار | ~400 | jinja2/html |
| 22 | `vf_telegram.py` | Telegram Remote — کنترل از تلگرام | ~350 | aiohttp |
| 23 | `vf_updater.py` | Auto-Update — آپدیت از GitHub | ~150 | aiohttp, git |
| 24 | `vf_multi_target.py` | Multi-Target Queue — صف حمله چند تارگت | ~300 | asyncio |

## نحوه ادغام (Integration)

هر ماژول یک کلاس اصلی دارد که توسط VF_FINDER یا VF_TESTER فراخوانی می‌شود:

```python
# در VF_FINDER.py:
from finder.vf_subdomain import SubdomainBruteforcer
from finder.vf_js_scanner import JSSecretScanner
from finder.vf_waf_probe import WAFProber
# ...

# در VF_TESTER.py:
from tester.vf_h2c_smuggler import H2CSmuggler
from tester.vf_slow_read import SlowREADAttacker
from evasion.vf_behavior import BehavioralMimic
# ...
```

## کل خطوط تخمینی: ~5,500 خط جدید
## زمان تخمینی: تمام ۲۴ قابلیت
