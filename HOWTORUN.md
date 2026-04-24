# ⚡ STORM VX


---

## 🚀 Quick Start

### 1. Requirements

- **Python 3.8+** (3.10+ recommended)
- **pip** (Python package manager)
- **Linux** or **Windows** (L4 raw-socket attacks require root on Linux)

### 2. Install Dependencies

```bash
pip install aiohttp
```

That's the only external dependency. Everything else uses Python's standard library.

### 3. Run STORM VX

```bash
python storm_vx.py https://example.com
```

> **Note:** Both `storm_vx.py` and `storm_core.py` must be in the same directory.

### 4. L4 Attacks (Optional — Requires Root)

If you want to use L4 raw-socket attacks (SYN Flood, UDP Flood), run as root:

```bash
sudo python storm_vx.py https://example.com
```

---

## ⌨️ Keyboard Controls

| Key | Action |
|-----|--------|
| `+` | Add 1000 workers instantly |
| `-` | Reduce step size |
| `p` | Activate 5 more attack vectors |
| `a` | Enable ALL 28 attack vectors |
| `c` | Toggle CRASH mode (unlimited ramp) |
| `x` | **UNLEASH!** Remove ALL limits (1000% power) |
| `n` | Switch to NORMAL mode (CPU 75%, RAM 60%) |
| `q` | Stop and show final report |

---
