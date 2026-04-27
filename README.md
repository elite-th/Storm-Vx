<h1 align="center">
  <br>
  <pre style="background:none;border:none;color:#00ff41;font-family:monospace;font-size:14px;">
███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗   ██╗   ██╗██╗  ██╗
██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║   ██║   ██║╚██╗██╔╝
███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║   ██║   ██║ ╚███╔╝ 
╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║   ╚██╗ ██╔╝ ██╔██╗ 
███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║    ╚████╔╝ ██╔╝ ██╗
╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═══╝  ╚═╝  ╚═╝
  </pre>
  <br>
  <strong>28-Vector Async Terminal Engine</strong>
  <br>
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/aiohttp-Async-2D5BB3?style=for-the-badge" alt="aiohttp">
  <img src="https://img.shields.io/badge/Vectors-28-brightgreen?style=for-the-badge" alt="28 Vectors">
  <img src="https://img.shields.io/badge/Mode-SAFE%20%7C%20NORMAL%20%7C%20UNLEASH-orange?style=for-the-badge" alt="Modes">
</h1>

<p align="center">
  <em>A professional-grade, multi-vector async load testing framework with real-time terminal dashboard, smart resource management, and adaptive auto-throttle. Built for performance engineers who need maximum insight and control.</em>
</p>

---

## Overview

**STORM VX** is a high-performance, asynchronous load testing engine written in pure Python. It combines **28 distinct attack vectors** across L4, L6, and L7 layers into a single unified terminal dashboard — inspired by tools like `htop` and `bpytop`. The engine features smart resource-aware scaling that protects your host machine while pushing the target to its limits.

> **Disclaimer**: This tool is intended for authorized load testing and security research only. Always obtain proper permission before testing any target. Misuse of this tool may violate laws in your jurisdiction.

---

## Key Features

### 28 Attack Vectors (3 Batches)

| Batch | Layer | Attacks |
|-------|-------|---------|
| **Batch 1** — Original (8) | L7 / L6 | HTTP Flood, Slowloris, Slow POST, Range Exploit, Login Flood, Resource Bomb, POST Bomb, SSL Flood |
| **Batch 2** — L7 Heavy (10) | L7 | H2 Rapid Reset, WebSocket Flood, WP XMLRPC, Cache Storm, API Fuzz, Multipart Upload, Header Bomb, Chunked Transfer, Session Flood, GraphQL Bomb |
| **Batch 3** — L4+L7 New (10) | L4/L7 | SYN Flood, UDP Flood, Cookie Bomb, HTTP HEAD Flood, XML Bomb (Billion Laughs), Slow Read, CONNECTION Flood, HTTP/1.0 Flood, URL Fuzzer, JSON Bomb |

### Smart Resource Manager

STORM VX automatically adapts to your system specs and prevents your machine from freezing:

| Mode | CPU Cap | RAM Cap | Worker Cap | How to Activate |
|------|---------|---------|------------|-----------------|
| **SAFE** (default) | 50% | 40% | 8,000 | Starts in SAFE |
| **NORMAL** | 75% | 60% | ~6,000 | Press `n` |
| **UNLEASH** | None | None | Unlimited | Press `x` (1000% power) |

The resource manager monitors CPU and RAM usage in real-time and automatically throttles worker creation when limits are approached. Press **X** at any time to remove all limits and unleash maximum power.

### Real-Time Terminal Dashboard

A `htop`-style alternate screen buffer dashboard showing:
- **Live RPS** (requests per second) with success/failure ratio
- **Response time** distribution (min / avg / P95 / max)
- **Bandwidth** tracking (uplink + downlink)
- **Attack vector status** — active/inactive per vector with per-mode counts
- **Server health indicator** — real-time success rate percentage
- **Security detection** — Rate Limit, CAPTCHA, Account Lockout alerts
- **Request log** — recent requests with status codes and response times
- **Resource monitor** — CPU/RAM usage with mode indicator

### Auto-Discovery Engine

STORM automatically probes the target to find:
- Heavy pages and slow endpoints
- Static resources (images, scripts, stylesheets)
- Login forms (ASP.NET, PHP, custom)
- API endpoints (GraphQL, REST, SOAP)
- Server technology stack (Nginx, Apache, IIS, ASP.NET, PHP, Node.js, Django)

### HeaderForge — Browser Fingerprint Engine

Every request is crafted with realistic, randomized browser fingerprints:
- 15 rotating User-Agents (Chrome, Firefox, Safari, Edge, Opera, Vivaldi)
- Randomized `Accept-Language` headers (including Persian/Farsi)
- `Sec-CH-UA` client hints rotation
- `Sec-Fetch-*` metadata per request type
- Cache-busting parameters on 30% of requests
- Session cookies with random session IDs

### Auto-Throttle

The server-side auto-throttle monitors target health in real-time:
- **Server healthy** — normal ramp-up continues
- **Server stressed** — ramp slows down
- **Server near death** — backs off to avoid premature kill
- **CRASH mode** (press `c`) — reverses logic: ramps harder when server is struggling

### Circuit Breaker

Per-mode circuit breakers prevent wasting resources on failing attack vectors:
- 5 consecutive failures → circuit opens (pauses that vector for 30s)
- After cooldown → half-open (allows 1 probe request)
- Success → circuit closes (resumes normal operation)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/storm-vx.git
cd storm-vx

# Install dependencies
pip install aiohttp psutil

# Optional (for better resource monitoring)
pip install psutil
```

### Requirements

- Python 3.9+
- `aiohttp` (required)
- `psutil` (optional — for accurate CPU/RAM monitoring; falls back to `/proc` on Linux)
- Root/Administrator privileges (required only for L4 attacks: SYN Flood, UDP Flood)

---

## Usage

```bash
# Basic — auto-discover and attack with all 28 vectors
python storm_vx.py https://example.com

# Custom step and phase duration
python storm_vx.py https://example.com --step 1000 --duration 3

# Custom timeout
python storm_vx.py https://example.com --timeout 15

# With root (enables L4 raw socket attacks: SYN Flood, UDP Flood)
sudo python storm_vx.py https://example.com
```

### Command-Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--step` | `-s` | 500 | Workers added per phase |
| `--duration` | `-d` | 5 | Phase duration in seconds |
| `--timeout` | `-t` | 10 | Request timeout in seconds |
| `--help` | `-h` | — | Show help and exit |

### Keyboard Controls (Live)

| Key | Action |
|-----|--------|
| `+` | Add 1,000 workers instantly |
| `-` | Reduce step size |
| `p` | Activate 5 more attack vectors |
| `a` | Enable ALL 28 attack vectors |
| `c` | Toggle CRASH mode (unlimited ramp) |
| `x` | **UNLEASH** — Remove ALL limits (1000% power) |
| `q` | Stop attack and show report |

---

## Architecture

```
storm_vx.py          # Main engine — Storm class, 28 workers, dashboard, keyboard handler
storm_core.py         # Core library — constants, headers, payloads, discovery, stats, throttle
```

### How It Works

1. **Discovery Phase** — STORM probes the target to find pages, resources, login forms, and APIs
2. **Initial Burst** — Launches workers across all active vectors (calculated from system resources)
3. **Ramp Phase** — Every N seconds, adds more workers distributed across active vectors
4. **Adaptive Throttle** — Monitors both host resources and server health to adjust intensity
5. **Report** — On exit, generates a detailed report with attack distribution, response times, and security analysis

### Worker Distribution Algorithm

Workers are distributed proportionally across all active attack vectors. Slow-type attacks (Slowloris, Slow Read, CONNECTION Flood) receive fewer workers per cycle since they hold connections open for extended periods, while fast-type attacks (HTTP Flood, HEAD Flood, Cache Storm) receive more to maximize throughput.

---

## Comparison with Known Tools

| Feature | STORM VX | MHDDoS | GoldenEye | Slowloris | HULK |
|---------|----------|--------|-----------|-----------|------|
| **Attack Vectors** | **28** | 15 | 4 | 1 | 1 |
| **L4 Attacks** | SYN, UDP | SYN, UDP, NTP, DNS | — | — | — |
| **L7 Attacks** | **26** | 13 | 4 | 1 | 1 |
| **Async Engine** | aiohttp | aiohttp | gevent | threaded | threaded |
| **Real-Time Dashboard** | htop-style | None | None | None | None |
| **Auto-Discovery** | Pages, APIs, Login | Basic | None | None | None |
| **Resource Management** | SAFE/NORMAL/UNLEASH | None | None | None | None |
| **Auto-Throttle** | Yes | None | None | None | None |
| **Circuit Breaker** | Per-vector | None | None | None | None |
| **Browser Fingerprint** | 15 UAs + full headers | 5 UAs | Basic | Basic | Basic |
| **Multi-Process** | Yes | Yes | No | No | No |
| **Terminal UI** | Full dashboard | Basic | Basic | Basic | Basic |

---

## Attack Vector Details

### Batch 1 — Original (8 Vectors)

| # | Name | Layer | Description |
|---|------|-------|-------------|
| 1 | HTTP Flood | L7 | High-volume GET requests with cache busting |
| 2 | Slowloris | L7 | Hold connections open with partial headers |
| 3 | Slow POST | L7 | Send large POST bodies very slowly |
| 4 | Range Exploit | L7 | Multiple overlapping Range headers to exhaust server memory |
| 5 | Login Flood | L7 | Brute-force login form with random credentials |
| 6 | Resource Bomb | L7 | Simultaneous requests for multiple heavy resources |
| 7 | POST Bomb | L7 | Large random POST payloads (512KB-2MB) |
| 8 | SSL Flood | L6 | Rapid TLS handshake + teardown cycles |

### Batch 2 — L7 Heavy (10 Vectors)

| # | Name | Layer | Description |
|---|------|-------|-------------|
| 9 | H2 Rapid Reset | L7 | HTTP/2 stream creation + immediate RST frames |
| 10 | WebSocket Flood | L7 | Open WebSocket connections and spam messages |
| 11 | WP XMLRPC | L7 | WordPress XML-RPC multicall with heavy methods |
| 12 | Cache Storm | L7 | Cache-busting with unique URL parameters |
| 13 | API Fuzz | L7 | Random JSON payloads against API endpoints |
| 14 | Multipart Upload | L7 | Large multipart form uploads with fake files |
| 15 | Header Bomb | L7 | Requests with 20-50 random X- headers |
| 16 | Chunked Transfer | L7 | Slow chunked transfer encoding to hold connections |
| 17 | Session Flood | L7 | Requests with many random session cookies |
| 18 | GraphQL Bomb | L7 | Deeply nested GraphQL queries with large limits |

### Batch 3 — L4 + L7 New (10 Vectors)

| # | Name | Layer | Description |
|---|------|-------|-------------|
| 19 | SYN Flood | L4 | Raw SYN packets with spoofed source IP (requires root) |
| 20 | UDP Flood | L4 | Random UDP packets to multiple ports (requires root) |
| 21 | Cookie Bomb | L7 | 8KB+ cookie headers to exhaust header parsing buffer |
| 22 | HTTP HEAD Flood | L7 | CPU-intensive HEAD-only requests |
| 23 | XML Bomb | L7 | Billion Laughs entity expansion OOM attack |
| 24 | Slow Read | L7 | Read response byte-by-byte to hold connections |
| 25 | CONNECTION Flood | L7 | Open TCP connections and keep them alive |
| 26 | HTTP/1.0 Flood | L7 | No keep-alive — forces new connection per request |
| 27 | URL Fuzzer | L7 | Random URL paths to trigger 404 error storms |
| 28 | JSON Bomb | L7 | Deeply nested or massively wide JSON payloads |

---

## Resource Mode Examples

### SAFE Mode (Default)
```
System: 24 CPUs | 32GB RAM
Resource mode: SAFE — CPU cap:50% RAM cap:40%
Worker cap: 8,000 | Press [x] to UNLEASH (1000%)
```
Your system stays smooth and responsive while STORM pushes the target.

### UNLEASH Mode (Press X)
```
🔥UNLEASH CPU:100%/100% RAM:100%/100%
Cap:999,999w — ALL LIMITS REMOVED — 1000% POWER
```
No CPU cap, no RAM cap, unlimited workers. Maximum devastation. Use with caution — your machine may become unresponsive.

---

## Final Report

When you stop STORM (press `q` or Ctrl+C), a detailed report is generated:

```
==============================================================================
  STORM VX — Final Report
==============================================================================
  Target: https://example.com
  Server: Nginx, PHP
  Attack Vectors: 28 (28 active)
  ----------------------------------------------------------------------

  +-- Summary ----------------------------------------------------------
  |
  |  Duration:        120.5s (2.0 min)
  |  Total Requests:  847,293
  |  Successful:      612,441 (72.2%)
  |  Failed:          234,852
  |  Avg RPS:         7,027.2
  |  Peak RPS:        12,445.8
  |  Max Workers:     15,500
  |  Max Phase:       31
  |  Timeouts:        45,231
  |  Conn Errors:     189,621
  |  Cache Busted:    34,219
  |
  +--------------------------------------------------------------------
```

---

## Tech Stack

- **Python 3.9+** — Core language
- **aiohttp** — Async HTTP client/server framework
- **ssl** — TLS/SSL connection handling
- **struct / socket** — Raw socket L4 attacks
- **asyncio** — Event loop and coroutine scheduling
- **multiprocessing** — Multi-process worker spawning (GIL bypass)
- **curses / msvcrt / termios** — Cross-platform terminal control

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**This tool is provided for educational and authorized testing purposes only.** The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission to test any target system. Unauthorized load testing may violate computer fraud and abuse laws in your jurisdiction.

---

<p align="center">
  <strong>STORM VX</strong> — When you need to know if your server can truly handle the storm.
</p>
