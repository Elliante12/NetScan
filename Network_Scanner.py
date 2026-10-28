# network_scanner_terminal.py
import nmap
import socket
import subprocess
import json
import threading
import time
import concurrent.futures
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Set
import os
import re
import argparse
import sys
from tqdm import tqdm
import signal
import requests
from urllib.parse import urljoin
import ssl
import OpenSSL
import psutil
import scapy.all as scapy
from scapy.layers import http
import paramiko
import ldap3
from collections import defaultdict
import ftplib
import dns.resolver
import netifaces
import platform

# ================================================================
# COLOR CODES
# ================================================================
class Colors:
    HEADER = '\033[95m'
    WHITE = '\033[97m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[95m'

def print_colored(message, color=Colors.GREEN, end='\n'):
    print(f"{color}{message}{Colors.END}", end=end)

def banner():
    print("""
\033[95m
[+]       
                    
\033[91m|      ███▄    █   ██████   ▄████▄   ▄▄▄        ███▄    ██
\033[91m|      ██ ▀█   █  ▒██    ▒ ▒ ██▀ ▀█  ▒████▄     ██ ▀█   ██
\033[91m|      ▓██  ▀█ ██ ▒░ ▓██▄    ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
\033[91m|      ▓██▒  ▐▌██ ▒  ▒   ██▒ ▒▓▓▄ ▄██▒░██▄▄▄▄██  ▓██▒  ▐▌██▒
\033[91m|      ▒██░   ▓██ ░▒██████▒▒ ▒ ▓███▀ ░ ▓█   ▓██▒ ▒██░   ▓██░
\033[91m|      ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
\033[91m|      ░ ░░   ░ ▒ ░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
\033[91m|         ░   ░ ░ ░  ░  ░  ░          ░   ▒      ░   ░ ░
\033[91m|               ░       ░  ░ ░            ░  ░         ░ v.0.3.0\033[93m           
\033[91m|
\033[91m|                  [ Developed by ELLIANTE ]\033[95m               
[+]
* DISCLAIMER: THIS IS ONLY TO BE USED FOR EDUCATIONAL AND RESEARCH PURPOSES
          
\033[0m       
""")

def menu():
    print("""
\033[92m══════════════════════════════════════════════════════════════
\033[92m  BASIC SCANNING
\033[92m══════════════════════════════════════════════════════════════
\033[92m[1]  IP Ping
\033[92m[2]  Port Scan
\033[92m[3]  Device Recognition (Network Scan)
\033[92m[4]  Device Details
\033[92m[6]  Ping Sweep
\033[92m[8]  Route Trace (Traceroute)
\033[92m[9]  DNS Enumeration

\033[93m══════════════════════════════════════════════════════════════
\033[93m  ADVANCED SCANNING
\033[93m══════════════════════════════════════════════════════════════
\033[93m[10] Packet Sniffer
\033[93m[11] Bandwidth Monitor
\033[93m[12] Vulnerability Scanner
\033[93m[13] WiFi Scanner
\033[93m[14] Web Application Scanner
\033[93m[15] ARP Spoofing Detector
\033[93m[16] SSL Certificate Analyzer
\033[93m[17] Service Fingerprinter
\033[93m[18] SSH/Remote Access Scanner
\033[93m[19] WiFi Deauth Detector

\033[94m══════════════════════════════════════════════════════════════
\033[94m  ENTERPRISE FEATURES
\033[94m══════════════════════════════════════════════════════════════
\033[94m[20] Active Directory Scanner
\033[94m[21] Network Topology Mapper
\033[94m[22] Port Knock Scanner

\033[96m══════════════════════════════════════════════════════════════
\033[96m  UTILITIES
\033[96m══════════════════════════════════════════════════════════════
\033[96m[7]  Continuous Monitoring
\033[96m[5]  Export Results
\033[96m[23] Generate Report

\033[91m[0]  Exit
\033[0m
""")

# ================================================================
# PACKET SNIFFER
# ================================================================
class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.credentials = []
        self.dns_queries = []
        self.http_requests = []
        self.sniffing = False
    
    def sniff_packets(self, interface=None, count=100, timeout=30):
        """Sniff network packets and extract useful info"""
        self.packets = []
        self.credentials = []
        self.dns_queries = []
        self.http_requests = []
        self.sniffing = True
        
        def process_packet(packet):
            if not self.sniffing:
                return
            
            # HTTP Requests
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
                request = {
                    'method': http_layer.Method.decode() if hasattr(http_layer.Method, 'decode') else str(http_layer.Method),
                    'path': http_layer.Path.decode() if hasattr(http_layer.Path, 'decode') else str(http_layer.Path),
                    'host': http_layer.Host.decode() if hasattr(http_layer.Host, 'decode') else str(http_layer.Host),
                    'timestamp': datetime.now().isoformat()
                }
                self.http_requests.append(request)
                print_colored(f"[HTTP] {request['method']} {request['host']}{request['path']}", Colors.GREEN)
                
                # Extract credentials from POST
                if request['method'] == 'POST' and packet.haslayer(scapy.Raw):
                    try:
                        load = packet[scapy.Raw].load.decode()
                        self._extract_credentials(load)
                    except:
                        pass
            
            # DNS Queries
            if packet.haslayer(scapy.DNSQR):
                dns = packet.getlayer(scapy.DNSQR)
                query = dns.qname.decode() if hasattr(dns.qname, 'decode') else str(dns.qname)
                self.dns_queries.append(query)
                print_colored(f"[DNS] {query}", Colors.YELLOW)
            
            # ARP Requests/Responses
            if packet.haslayer(scapy.ARP):
                arp = packet[scapy.ARP]
                if arp.op == 1:
                    print_colored(f"[ARP Request] {arp.psrc} is looking for {arp.pdst}", Colors.WHITE)
                elif arp.op == 2:
                    print_colored(f"[ARP Response] {arp.psrc} is at {arp.hwsrc}", Colors.WHITE)
            
            self.packets.append(packet)
        
        try:
            print_colored("[*] Sniffing packets (Ctrl+C to stop)...", Colors.WHITE)
            scapy.sniff(iface=interface, prn=process_packet, count=count, timeout=timeout)
        except KeyboardInterrupt:
            print_colored("\n[*] Sniffing stopped", Colors.YELLOW)
        finally:
            self.sniffing = False
        
        return self.packets
    
    def _extract_credentials(self, data):
        """Extract credentials from packet data"""
        patterns = {
            'password': r'password[=:]\s*([^\s&]+)',
            'user': r'user(name)?[=:]\s*([^\s&]+)',
            'login': r'login[=:]\s*([^\s&]+)',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'session': r'session(id)?[=:]\s*([^\s&]+)',
            'token': r'token[=:]\s*([^\s&]+)',
            'api_key': r'api[_-]?key[=:]\s*([^\s&]+)'
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[-1]
                    self.credentials.append({key: match})
                    print_colored(f"[!] Found {key}: {match}", Colors.RED)
    
    def get_statistics(self):
        """Get packet statistics"""
        return {
            'total_packets': len(self.packets),
            'http_requests': len(self.http_requests),
            'dns_queries': len(self.dns_queries),
            'credentials_found': len(self.credentials)
        }

# ================================================================
# BANDWIDTH MONITOR
# ================================================================
class BandwidthMonitor:
    def __init__(self):
        self.baseline = None
        self.history = []
        self.monitoring = False
    
    def get_network_usage(self):
        """Get current network usage"""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    
    def monitor_bandwidth(self, interval=2, duration=None):
        """Monitor bandwidth usage in real-time"""
        print_colored(f"[*] Monitoring bandwidth (interval: {interval}s)", Colors.WHITE)
        print_colored("[*] Press Ctrl+C to stop", Colors.YELLOW)
        
        start_time = time.time()
        self.history = []
        self.monitoring = True
        
        try:
            while self.monitoring:
                if duration and (time.time() - start_time) > duration:
                    break
                
                current = self.get_network_usage()
                
                if self.baseline:
                    delta_sent = current['bytes_sent'] - self.baseline['bytes_sent']
                    delta_recv = current['bytes_recv'] - self.baseline['bytes_recv']
                    
                    sent_mbps = (delta_sent * 8) / (interval * 1024 * 1024)
                    recv_mbps = (delta_recv * 8) / (interval * 1024 * 1024)
                    
                    # Store history
                    self.history.append({
                        'timestamp': datetime.now().isoformat(),
                        'upload': sent_mbps,
                        'download': recv_mbps
                    })
                    
                    # Display
                    print(f"\r\033[KUpload: {sent_mbps:.2f} Mbps | Download: {recv_mbps:.2f} Mbps | Packets: {current['packets_sent']}/{current['packets_recv']}", end='')
                
                self.baseline = current
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped")
        finally:
            self.monitoring = False
        
        return self.history
    
    def stop_monitoring(self):
        self.monitoring = False
    
    def get_stats(self):
        """Get bandwidth statistics"""
        if not self.history:
            return None
        
        uploads = [h['upload'] for h in self.history]
        downloads = [h['download'] for h in self.history]
        
        return {
            'avg_upload': sum(uploads) / len(uploads),
            'max_upload': max(uploads),
            'avg_download': sum(downloads) / len(downloads),
            'max_download': max(downloads),
            'total_samples': len(self.history)
        }

# ================================================================
# VULNERABILITY SCANNER
# ================================================================
class VulnerabilityScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.vuln_db = self._load_vuln_db()
    
    def _load_vuln_db(self):
        """Load vulnerability database"""
        return {
            21: {
                'name': 'FTP',
                'vulns': [
                    'Anonymous login possible',
                    'CVE-2019-12815 (ProFTPD)',
                    'CVE-2015-3306 (vsftpd)'
                ],
                'severity': 'HIGH'
            },
            22: {
                'name': 'SSH',
                'vulns': [
                    'Weak ciphers allowed',
                    'CVE-2017-15906 (OpenSSH)',
                    'Default credentials check'
                ],
                'severity': 'MEDIUM'
            },
            23: {
                'name': 'Telnet',
                'vulns': [
                    'Unencrypted communication',
                    'CVE-2017-16894 (Linux)',
                    'Default credentials'
                ],
                'severity': 'CRITICAL'
            },
            25: {
                'name': 'SMTP',
                'vulns': [
                    'Open relay possible',
                    'CVE-2017-16530 (Exim)',
                    'CVE-2014-0166 (OpenSSL)'
                ],
                'severity': 'HIGH'
            },
            80: {
                'name': 'HTTP',
                'vulns': [
                    'Check for default credentials',
                    'Directory listing',
                    'CVE-2018-12858 (PHP)',
                    'CVE-2017-8917 (Joomla)'
                ],
                'severity': 'MEDIUM'
            },
            443: {
                'name': 'HTTPS',
                'vulns': [
                    'Weak SSL/TLS protocols',
                    'CVE-2014-0160 (Heartbleed)',
                    'CVE-2014-3566 (POODLE)'
                ],
                'severity': 'HIGH'
            },
            445: {
                'name': 'SMB',
                'vulns': [
                    'EternalBlue (MS17-010)',
                    'CVE-2019-0708 (BlueKeep)',
                    'CVE-2017-0143 (SMBv1)'
                ],
                'severity': 'CRITICAL'
            },
            3306: {
                'name': 'MySQL',
                'vulns': [
                    'Default root password',
                    'CVE-2012-2122 (Authentication Bypass)',
                    'CVE-2016-6662 (Privilege Escalation)'
                ],
                'severity': 'HIGH'
            },
            3389: {
                'name': 'RDP',
                'vulns': [
                    'BlueKeep (CVE-2019-0708)',
                    'CVE-2019-1181 (RDP RCE)',
                    'CVE-2020-0610 (RDP)'
                ],
                'severity': 'CRITICAL'
            },
            1433: {
                'name': 'MSSQL',
                'vulns': [
                    'SA default password',
                    'CVE-2019-1068 (SQL Injection)',
                    'CVE-2020-0618 (RCE)'
                ],
                'severity': 'HIGH'
            },
            5900: {
                'name': 'VNC',
                'vulns': [
                    'No authentication',
                    'CVE-2017-12191 (VNC)',
                    'CVE-2018-15133 (VNC)'
                ],
                'severity': 'HIGH'
            },
            6379: {
                'name': 'Redis',
                'vulns': [
                    'No authentication',
                    'CVE-2016-8339 (RCE)',
                    'CVE-2018-11218 (Lua Sandbox)'
                ],
                'severity': 'HIGH'
            },
            9200: {
                'name': 'Elasticsearch',
                'vulns': [
                    'CVE-2015-1427 (Groovy RCE)',
                    'CVE-2014-3120 (RCE)',
                    'CVE-2018-17246 (LFI)'
                ],
                'severity': 'CRITICAL'
            }
        }
    
    def check_vulnerabilities(self, ip, open_ports, timeout=2):
        """Check for vulnerabilities on open ports"""
        self.vulnerabilities = []
        
        for port in open_ports:
            if port in self.vuln_db:
                vuln_info = self.vuln_db[port]
                severity = vuln_info['severity']
                color = Colors.RED if severity == 'CRITICAL' else Colors.YELLOW if severity == 'HIGH' else Colors.WHITE
                
                print_colored(f"\n[!] Port {port} ({vuln_info['name']}) - {severity} Severity", color)
                for vuln in vuln_info['vulns']:
                    print_colored(f"    - {vuln}", Colors.END)
                    self.vulnerabilities.append({
                        'ip': ip,
                        'port': port,
                        'service': vuln_info['name'],
                        'vulnerability': vuln,
                        'severity': severity
                    })
                
                # Test for specific vulnerabilities
                if port == 21:
                    self._test_ftp_anonymous(ip, timeout)
                elif port == 22:
                    self._test_ssh(ip, timeout)
                elif port == 80 or port == 443:
                    self._test_web_vulnerabilities(ip, port, timeout)
                elif port == 3306:
                    self._test_mysql(ip, timeout)
                elif port == 445:
                    self._test_smb(ip, timeout)
        
        return self.vulnerabilities
    
    def _test_ftp_anonymous(self, ip, timeout):
        """Test FTP anonymous login"""
        try:
            ftp = ftplib.FTP(ip, timeout=timeout)
            ftp.login('anonymous', '')
            print_colored(f"    [!] FTP anonymous login SUCCESSFUL on {ip}", Colors.RED)
            self.vulnerabilities.append({
                'ip': ip,
                'port': 21,
                'service': 'FTP',
                'vulnerability': 'Anonymous login works',
                'severity': 'CRITICAL'
            })
            ftp.quit()
        except:
            pass
    
    def _test_ssh(self, ip, timeout):
        """Test SSH for weak ciphers"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, timeout=timeout, username='root', password='root')
            print_colored(f"    [!] SSH default credentials WORK on {ip}", Colors.RED)
            self.vulnerabilities.append({
                'ip': ip,
                'port': 22,
                'service': 'SSH',
                'vulnerability': 'Default credentials (root/root)',
                'severity': 'CRITICAL'
            })
        except:
            pass
    
    def _test_mysql(self, ip, timeout):
        """Test MySQL default credentials"""
        try:
            import pymysql
            conn = pymysql.connect(host=ip, user='root', password='', timeout=timeout)
            print_colored(f"    [!] MySQL root login with empty password on {ip}", Colors.RED)
            self.vulnerabilities.append({
                'ip': ip,
                'port': 3306,
                'service': 'MySQL',
                'vulnerability': 'Root with empty password',
                'severity': 'CRITICAL'
            })
            conn.close()
        except:
            pass
    
    def _test_smb(self, ip, timeout):
        """Test SMB vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, 445))
            sock.send(b'\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            data = sock.recv(1024)
            sock.close()
            
            if b'Windows' in data:
                print_colored(f"    [!] SMB (Windows) detected on {ip} - Possible EternalBlue", Colors.RED)
                self.vulnerabilities.append({
                    'ip': ip,
                    'port': 445,
                    'service': 'SMB',
                    'vulnerability': 'Windows SMB - Possible EternalBlue',
                    'severity': 'CRITICAL'
                })
        except:
            pass
    
    def _test_web_vulnerabilities(self, ip, port, timeout):
        """Test web vulnerabilities"""
        try:
            url = f"http{'s' if port == 443 else ''}://{ip}:{port}"
            
            # Check for common paths
            paths = ['/admin', '/phpmyadmin', '/wp-admin', '/backup', '/config', '/.env']
            for path in paths:
                try:
                    response = requests.get(f"{url}{path}", timeout=timeout)
                    if response.status_code == 200:
                        print_colored(f"    [!] Found accessible path: {path}", Colors.YELLOW)
                except:
                    pass
        except:
            pass
    
    def get_vulnerability_report(self):
        """Get vulnerability report"""
        if not self.vulnerabilities:
            return "No vulnerabilities found"
        
        report = []
        report.append("=" * 60)
        report.append("VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        
        by_severity = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                report.append(f"\n{severity} ({len(by_severity[severity])}):")
                for vuln in by_severity[severity]:
                    report.append(f"  - {vuln['ip']}:{vuln['port']} - {vuln['service']} - {vuln['vulnerability']}")
        
        return "\n".join(report)

# ================================================================
# WIFI SCANNER
# ================================================================
class WiFiScanner:
    def __init__(self):
        self.networks = []
        self.current_connection = None
    
    def scan_wifi(self):
        """Scan for available WiFi networks"""
        print_colored("[*] Scanning for WiFi networks...", Colors.WHITE)
        self.networks = []
        
        try:
            if os.name == 'nt':
                result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], 
                                      capture_output=True, text=True, timeout=10)
                self.networks = self._parse_windows_wifi(result.stdout)
            else:
                result = subprocess.run(['sudo', 'iwlist', 'scan'], 
                                      capture_output=True, text=True, timeout=30)
                self.networks = self._parse_linux_wifi(result.stdout)
            
            self._display_networks()
            return self.networks
        except Exception as e:
            print_colored(f"[-] WiFi scan failed: {e}", Colors.RED)
            return []
    
    def _parse_windows_wifi(self, output):
        """Parse Windows netsh output"""
        networks = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if 'SSID' in line and 'BSSID' not in line:
                if current and 'ssid' in current:
                    networks.append(current)
                ssid = line.split(':')[1].strip()
                current = {'ssid': ssid}
            elif 'Signal' in line:
                signal = line.split(':')[1].strip()
                current['signal'] = signal
            elif 'Authentication' in line:
                auth = line.split(':')[1].strip()
                current['auth'] = auth
            elif 'Radio type' in line:
                radio = line.split(':')[1].strip()
                current['radio'] = radio
        
        if current and 'ssid' in current:
            networks.append(current)
        
        return networks
    
    def _parse_linux_wifi(self, output):
        """Parse Linux iwlist output"""
        networks = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if 'ESSID' in line:
                if current and 'ssid' in current:
                    networks.append(current)
                ssid = line.split('"')[1] if '"' in line else line.split(':')[1].strip()
                current = {'ssid': ssid}
            elif 'Quality' in line:
                quality = re.search(r'Quality=(\d+)/(\d+)', line)
                if quality:
                    current['signal'] = f"{quality.group(1)}/{quality.group(2)}"
                    current['signal_percent'] = f"{int(quality.group(1)) / int(quality.group(2)) * 100:.0f}%"
            elif 'Encryption' in line:
                current['encrypted'] = 'Yes' if 'on' in line.lower() else 'No'
            elif 'Address' in line:
                mac = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
                if mac:
                    current['mac'] = mac.group()
        
        if current and 'ssid' in current:
            networks.append(current)
        
        return networks
    
    def _display_networks(self):
        """Display found networks"""
        print("\n" + "=" * 80)
        print_colored(f"{'#':<4} {'SSID':<35} {'Signal':<15} {'Auth':<15} {'Encrypted':<10}", Colors.WHITE)
        print("=" * 80)
        
        for idx, net in enumerate(self.networks, 1):
            signal = net.get('signal', 'N/A')
            if 'signal_percent' in net:
                signal = net['signal_percent']
            auth = net.get('auth', net.get('encrypted', 'N/A'))
            ssid = net.get('ssid', 'Unknown')[:35]
            encrypted = 'Yes' if 'Yes' in str(net.get('encrypted', '')) else 'No'
            
            print(f"{idx:<4} {ssid:<35} {signal:<15} {auth:<15} {encrypted:<10}")
        
        print("=" * 80)
        print_colored(f"[*] Total networks: {len(self.networks)}", Colors.WHITE)
    
    def connect_to_network(self, ssid, password=None):
        """Connect to a WiFi network"""
        print_colored(f"[*] Attempting to connect to {ssid}...", Colors.WHITE)
        
        try:
            if os.name == 'nt':
                # Windows
                if password:
                    cmd = f'netsh wlan connect name="{ssid}"'
                else:
                    cmd = f'netsh wlan connect name="{ssid}"'
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if 'successfully' in result.stdout.lower():
                    print_colored(f"[+] Connected to {ssid}", Colors.GREEN)
                    self.current_connection = ssid
                    return True
            else:
                # Linux
                if password:
                    cmd = f'sudo nmcli device wifi connect "{ssid}" password "{password}"'
                else:
                    cmd = f'sudo nmcli device wifi connect "{ssid}"'
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if 'successfully' in result.stdout.lower():
                    print_colored(f"[+] Connected to {ssid}", Colors.GREEN)
                    self.current_connection = ssid
                    return True
            
            print_colored(f"[-] Failed to connect to {ssid}", Colors.RED)
            return False
        except Exception as e:
            print_colored(f"[-] Connection error: {e}", Colors.RED)
            return False

# ================================================================
# WEB APPLICATION SCANNER
# ================================================================
class WebAppScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_web_app(self, base_url):
        """Scan web application for vulnerabilities"""
        print_colored(f"\n[*] Scanning web application: {base_url}", Colors.WHITE)
        print_colored("[*] This may take several minutes...", Colors.YELLOW)
        
        checks = {
            'Information Disclosure': self._check_info_disclosure,
            'Directory Listing': self._check_directory_listing,
            'Default Files': self._check_default_files,
            'SQL Injection': self._check_sql_injection,
            'XSS': self._check_xss,
            'Security Headers': self._check_headers,
            'Admin Panels': self._check_admin_panels,
            'Backup Files': self._check_backup_files,
            'Sensitive Files': self._check_sensitive_files,
            'Server Info': self._check_server_info
        }
        
        with tqdm(total=len(checks), desc="Scanning web app") as pbar:
            for name, check in checks.items():
                result = check(base_url)
                if result:
                    self.vulnerabilities.append(result)
                pbar.update(1)
        
        self._display_results()
        return self.vulnerabilities
    
    def _check_info_disclosure(self, url):
        """Check for information disclosure"""
        try:
            response = self.session.get(url, timeout=5)
            disclosures = []
            
            # Check for server info in headers
            server = response.headers.get('Server', '')
            if server:
                disclosures.append(f"Server: {server}")
            
            # Check for PHP info
            if 'PHP' in response.text:
                disclosures.append("PHP version disclosed")
            
            # Check for framework info
            frameworks = ['WordPress', 'Drupal', 'Joomla', 'Laravel', 'Django', 'Rails']
            for framework in frameworks:
                if framework in response.text:
                    disclosures.append(f"Framework: {framework}")
            
            if disclosures:
                print_colored(f"[!] Information disclosure found: {', '.join(disclosures)}", Colors.YELLOW)
                return {'type': 'Information Disclosure', 'details': disclosures}
        except:
            pass
    
    def _check_directory_listing(self, url):
        """Check for directory listing"""
        test_dirs = ['/images/', '/css/', '/js/', '/backup/', '/logs/', '/temp/']
        
        for dir_path in test_dirs:
            test_url = urljoin(url, dir_path)
            try:
                response = self.session.get(test_url, timeout=5)
                if 'Index of' in response.text or 'Directory listing' in response.text:
                    print_colored(f"[!] Directory listing: {test_url}", Colors.RED)
                    return {'type': 'Directory Listing', 'details': test_url}
            except:
                pass
    
    def _check_default_files(self, url):
        """Check for default installation files"""
        default_files = [
            'wp-admin/', 'wp-login.php', 'phpmyadmin/', 'adminer.php', 
            'info.php', 'phpinfo.php', 'config.php', 'setup.php',
            'install.php', 'README.md', 'CHANGELOG.md', 'composer.json',
            'package.json', 'web.config', '.htaccess'
        ]
        
        for file_path in default_files:
            test_url = urljoin(url, file_path)
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
                    print_colored(f"[!] Default file found: {test_url}", Colors.RED)
                    return {'type': 'Default File', 'details': test_url}
            except:
                pass
    
    def _check_sql_injection(self, url):
        """Check for SQL injection"""
        payloads = [
            "' OR '1'='1",
            "' AND 1=0--",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' OR 'x'='x",
            "'; DROP TABLE users--"
        ]
        
        params = ['id', 'page', 'cat', 'product', 'user', 'search', 'q', 'query']
        
        for param in params:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=3)
                    if 'sql' in response.text.lower() or 'mysql' in response.text.lower() or 'syntax' in response.text.lower():
                        print_colored(f"[!] Possible SQL injection: {test_url}", Colors.RED)
                        return {'type': 'SQL Injection', 'details': test_url}
                except:
                    pass
    
    def _check_xss(self, url):
        """Check for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert('XSS')",
            "<svg/onload=alert(1)>"
        ]
        
        params = ['q', 'search', 's', 'query', 'term']
        
        for param in params:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                try:
                    response = self.session.get(test_url, timeout=3)
                    if payload in response.text:
                        print_colored(f"[!] Possible XSS: {test_url}", Colors.RED)
                        return {'type': 'XSS', 'details': test_url}
                except:
                    pass
    
    def _check_headers(self, url):
        """Check security headers"""
        try:
            response = self.session.get(url, timeout=5)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking',
                'X-XSS-Protection': 'XSS Protection',
                'X-Content-Type-Options': 'MIME Sniffing',
                'Referrer-Policy': 'Referrer Policy',
                'Feature-Policy': 'Feature Policy'
            }
            
            missing = []
            for header, name in security_headers.items():
                if header not in headers:
                    missing.append(name)
            
            if missing:
                print_colored(f"[!] Missing security headers: {', '.join(missing)}", Colors.YELLOW)
                return {'type': 'Missing Headers', 'details': missing}
        except:
            pass
    
    def _check_admin_panels(self, url):
        """Check for admin panels"""
        admin_paths = [
            'admin', 'administrator', 'wp-admin', 'login', 'cpanel',
            'admincp', 'admin.php', 'manage', 'system', 'dashboard'
        ]
        
        for path in admin_paths:
            test_url = urljoin(url, f'/{path}/')
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200 and ('login' in response.text.lower() or 'admin' in response.text.lower()):
                    print_colored(f"[!] Admin panel found: {test_url}", Colors.RED)
                    return {'type': 'Admin Panel', 'details': test_url}
            except:
                pass
    
    def _check_backup_files(self, url):
        """Check for backup files"""
        extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp']
        common_files = ['config', 'wp-config', 'database', 'backup', 'dump']
        
        for file_base in common_files:
            for ext in extensions:
                test_url = urljoin(url, f'/{file_base}{ext}')
                try:
                    response = self.session.get(test_url, timeout=3)
                    if response.status_code == 200:
                        print_colored(f"[!] Backup file found: {test_url}", Colors.RED)
                        return {'type': 'Backup File', 'details': test_url}
                except:
                    pass
    
    def _check_sensitive_files(self, url):
        """Check for sensitive files"""
        sensitive = [
            '.env', '.git/config', '.htpasswd', '.aws/credentials',
            'config.yml', 'settings.php', 'database.yml', 'secrets.yml'
        ]
        
        for file_path in sensitive:
            test_url = urljoin(url, f'/{file_path}')
            try:
                response = self.session.get(test_url, timeout=3)
                if response.status_code == 200:
                    print_colored(f"[!] Sensitive file found: {test_url}", Colors.RED)
                    return {'type': 'Sensitive File', 'details': test_url}
            except:
                pass
    
    def _check_server_info(self, url):
        """Check server information"""
        try:
            response = self.session.get(url, timeout=5)
            info = []
            
            # Server header
            server = response.headers.get('Server', '')
            if server:
                info.append(f"Server: {server}")
            
            # X-Powered-By
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                info.append(f"Powered by: {powered_by}")
            
            # PHP Version
            php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', response.text)
            if php_match:
                info.append(f"PHP Version: {php_match.group(1)}")
            
            if info:
                print_colored(f"[i] Server info: {', '.join(info)}", Colors.WHITE)
                return {'type': 'Server Info', 'details': info}
        except:
            pass
    
    def _display_results(self):
        """Display scan results"""
        if not self.vulnerabilities:
            print_colored("\n[+] No vulnerabilities found!", Colors.GREEN)
            return
        
        print("\n" + "=" * 80)
        print_colored("WEB APPLICATION SCAN RESULTS", Colors.WHITE)
        print("=" * 80)
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            color = Colors.RED if 'CRITICAL' in str(severity).upper() or 'HIGH' in str(severity).upper() else Colors.YELLOW
            print_colored(f"\n[!] {vuln['type']}", color)
            print_colored(f"    Details: {vuln['details']}", Colors.END)

# ================================================================
# ARP SPOOFING DETECTOR
# ================================================================
class ARPMonitor:
    def __init__(self):
        self.arp_table = {}
        self.attack_detected = False
        self.attacks = []
    
    def monitor_arp(self, interface=None, duration=None):
        """Monitor for ARP spoofing attacks"""
        print_colored("[*] Monitoring for ARP spoofing...", Colors.WHITE)
        print_colored("[*] Press Ctrl+C to stop", Colors.YELLOW)
        
        def process_packet(packet):
            if packet.haslayer(scapy.ARP):
                arp = packet[scapy.ARP]
                if arp.op == 2:  # ARP response
                    ip = arp.psrc
                    mac = arp.hwsrc
                    
                    # Check if IP already has a different MAC
                    if ip in self.arp_table:
                        if self.arp_table[ip] != mac:
                            attack = {
                                'timestamp': datetime.now().isoformat(),
                                'ip': ip,
                                'old_mac': self.arp_table[ip],
                                'new_mac': mac
                            }
                            self.attacks.append(attack)
                            self.attack_detected = True
                            
                            print_colored(f"\n[!] ARP SPOOFING DETECTED!", Colors.RED)
                            print_colored(f"    IP: {ip}", Colors.YELLOW)
                            print_colored(f"    Old MAC: {self.arp_table[ip]}", Colors.YELLOW)
                            print_colored(f"    New MAC: {mac}", Colors.YELLOW)
                            print_colored(f"    Time: {attack['timestamp']}", Colors.YELLOW)
                    else:
                        self.arp_table[ip] = mac
        
        try:
            if duration:
                scapy.sniff(iface=interface, prn=process_packet, filter="arp", store=0, timeout=duration)
            else:
                scapy.sniff(iface=interface, prn=process_packet, filter="arp", store=0)
        except KeyboardInterrupt:
            print_colored("\n[*] Monitoring stopped", Colors.YELLOW)
        
        return self.attacks
    
    def get_statistics(self):
        """Get ARP monitoring statistics"""
        return {
            'devices_monitored': len(self.arp_table),
            'attacks_detected': len(self.attacks),
            'attack_detected': self.attack_detected
        }

# ================================================================
# SSL CERTIFICATE ANALYZER
# ================================================================
class CertificateAnalyzer:
    def __init__(self):
        self.certs = []
        self.issues = []
    
    def analyze_certificate(self, hostname, port=443):
        """Analyze SSL certificate"""
        print_colored(f"\n[*] Analyzing certificate for {hostname}:{port}", Colors.WHITE)
        
        try:
            # Get certificate
            cert = ssl.get_server_certificate((hostname, port))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            # Extract info
            info = {
                'hostname': hostname,
                'issuer': x509.get_issuer().CN,
                'subject': x509.get_subject().CN,
                'not_before': x509.get_notBefore().decode(),
                'not_after': x509.get_notAfter().decode(),
                'version': x509.get_version(),
                'serial': hex(x509.get_serial_number()),
                'fingerprint': self._get_fingerprint(cert)
            }
            
            # Check for SAN
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if ext.get_short_name() == b'subjectAltName':
                    info['san'] = str(ext)
            
            self.certs.append(info)
            self._analyze_security(info)
            self._display_certificate(info)
            
            return info
        except Exception as e:
            print_colored(f"[-] Failed to analyze certificate: {e}", Colors.RED)
            return None
    
    def _get_fingerprint(self, cert):
        """Get certificate fingerprint"""
        try:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            digest = OpenSSL.crypto.digest(x509, 'sha256')
            return ':'.join(digest[i:i+2].upper() for i in range(0, len(digest), 2))
        except:
            return 'Unknown'
    
    def _analyze_security(self, info):
        """Analyze certificate security"""
        issues = []
        
        # Check expiry
        expiry = datetime.strptime(info['not_after'], '%Y%m%d%H%M%SZ')
        days_left = (expiry - datetime.now()).days
        
        if days_left < 30:
            issues.append(f"Certificate expires in {days_left} days!")
        if days_left < 0:
            issues.append("Certificate has EXPIRED!")
        
        # Check issuer
        if 'Let\'s Encrypt' not in info['issuer'] and 'DigiCert' not in info['issuer']:
            issues.append(f"Unknown issuer: {info['issuer']}")
        
        # Check subject/CN match
        if info['subject'] != info['hostname']:
            issues.append(f"Subject CN ({info['subject']}) doesn't match hostname ({info['hostname']})")
        
        if issues:
            self.issues.append({'hostname': info['hostname'], 'issues': issues})
        
        return issues
    
    def _display_certificate(self, info):
        """Display certificate information"""
        print("\n" + "=" * 60)
        print_colored("CERTIFICATE INFORMATION", Colors.WHITE)
        print("=" * 60)
        print(f"  Hostname    : {info['hostname']}")
        print(f"  Issuer      : {info['issuer']}")
        print(f"  Subject     : {info['subject']}")
        print(f"  Valid From  : {info['not_before']}")
        print(f"  Valid Until : {info['not_after']}")
        print(f"  Version     : {info['version']}")
        print(f"  Serial      : {info['serial']}")
        print(f"  Fingerprint : {info['fingerprint']}")
        
        if 'san' in info:
            print(f"  SAN         : {info['san']}")
        
        # Check expiry
        expiry = datetime.strptime(info['not_after'], '%Y%m%d%H%M%SZ')
        days_left = (expiry - datetime.now()).days
        color = Colors.GREEN if days_left > 30 else Colors.RED if days_left < 7 else Colors.YELLOW
        print_colored(f"  Days Left   : {days_left} days", color)

# ================================================================
# DNS ENUMERATOR
# ================================================================
class DNSEnumerator:
    def __init__(self):
        self.records = {}
        self.subdomains = []
    
    def enumerate(self, domain):
        """Enumerate DNS records for a domain"""
        print_colored(f"\n[*] Enumerating DNS for {domain}", Colors.WHITE)
        self.records = {}
        self.subdomains = []
        
        # Common record types
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                records = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if records:
                    self.records[record_type] = []
                    for rec in records:
                        ip = rec[4][0]
                        self.records[record_type].append(ip)
                    print_colored(f"  [+] {record_type}: {len(records)} record(s)", Colors.GREEN)
            except:
                pass
        
        # Try MX records specifically
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                self.records['MX'] = []
                for mx in mx_records:
                    self.records['MX'].append(str(mx.exchange))
                print_colored(f"  [+] MX: {len(mx_records)} record(s)", Colors.GREEN)
        except:
            pass
        
        # Enumerate subdomains
        self._enumerate_subdomains(domain)
        
        return self.records
    
    def _enumerate_subdomains(self, domain):
        """Enumerate common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api', 'internal',
            'secure', 'vpn', 'remote', 'portal', 'dashboard', 'cpanel',
            'webmail', 'smtp', 'pop3', 'imap', 'dns', 'ns1', 'ns2',
            'git', 'jenkins', 'jira', 'confluence', 'bitbucket', 'grafana',
            'monitoring', 'stats', 'status', 'cdn', 'static', 'assets'
        ]
        
        print_colored(f"\n[*] Enumerating subdomains", Colors.WHITE)
        
        for sub in common_subdomains:
            target = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                self.subdomains.append({'subdomain': target, 'ip': ip})
                print_colored(f"  [+] Found: {target} -> {ip}", Colors.GREEN)
            except:
                pass
        
        return self.subdomains
    
    def get_report(self):
        """Get DNS enumeration report"""
        report = []
        report.append("=" * 60)
        report.append("DNS ENUMERATION REPORT")
        report.append("=" * 60)
        
        for record_type, records in self.records.items():
            report.append(f"\n{record_type} Records:")
            for rec in records:
                report.append(f"  - {rec}")
        
        if self.subdomains:
            report.append(f"\nFound Subdomains ({len(self.subdomains)}):")
            for sub in self.subdomains:
                report.append(f"  - {sub['subdomain']} -> {sub['ip']}")
        
        return "\n".join(report)

# ================================================================
# SERVICE FINGERPRINTER
# ================================================================
class ServiceFingerprinter:
    def __init__(self):
        self.services = {}
        self.banners = {}
        self.fingerprints = {}
    
    def fingerprint_service(self, ip, port, timeout=3):
        """Fingerprint a service by grabbing its banner"""
        print_colored(f"\n[*] Fingerprinting service on {ip}:{port}", Colors.WHITE)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect and send probe
            sock.connect((ip, port))
            probe = self._get_probe(port)
            if probe:
                sock.send(probe.encode())
            
            # Get banner
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            
            if banner:
                self.banners[f"{ip}:{port}"] = banner
                service = self._identify_service(ip, port, banner)
                self.services[f"{ip}:{port}"] = service
                
                print_colored(f"  [+] Service identified: {service}", Colors.GREEN)
                print_colored(f"  [+] Banner: {banner[:100]}...", Colors.YELLOW)
                return service
            
        except Exception as e:
            pass
        
        return None
    
    def _get_probe(self, port):
        """Get appropriate probe for service detection"""
        probes = {
            80: "HEAD / HTTP/1.0\r\n\r\n",
            443: "HEAD / HTTP/1.0\r\n\r\n",
            21: "HELP\r\n",
            25: "HELO test\r\n",
            22: "",
            23: "",
            3306: "",
            1433: "",
            3389: "",
            5900: "",
            6379: "INFO\r\n",
            9200: "",
            8080: "HEAD / HTTP/1.0\r\n\r\n",
            8443: "HEAD / HTTP/1.0\r\n\r\n"
        }
        return probes.get(port, "")
    
    def _identify_service(self, ip, port, banner):
        """Identify service based on banner"""
        banner_lower = banner.lower()
        
        # Web servers
        if 'apache' in banner_lower:
            return 'Apache HTTP Server'
        if 'nginx' in banner_lower:
            return 'nginx'
        if 'iis' in banner_lower or 'microsoft-iis' in banner_lower:
            return 'Microsoft IIS'
        if 'lighttpd' in banner_lower:
            return 'Lighttpd'
        
        # FTP
        if 'vsftpd' in banner_lower:
            return 'vsftpd'
        if 'proftpd' in banner_lower:
            return 'ProFTPD'
        if 'filezilla' in banner_lower:
            return 'FileZilla FTP'
        if 'pure-ftpd' in banner_lower:
            return 'Pure-FTPd'
        
        # SSH
        if 'openssh' in banner_lower:
            return 'OpenSSH'
        if 'dropbear' in banner_lower:
            return 'Dropbear SSH'
        
        # Mail servers
        if 'postfix' in banner_lower:
            return 'Postfix'
        if 'sendmail' in banner_lower:
            return 'Sendmail'
        if 'exim' in banner_lower:
            return 'Exim'
        if 'microsoft' in banner_lower and 'exchange' in banner_lower:
            return 'Microsoft Exchange'
        
        # Databases
        if 'mysql' in banner_lower:
            return 'MySQL'
        if 'mariadb' in banner_lower:
            return 'MariaDB'
        if 'postgresql' in banner_lower or 'postgres' in banner_lower:
            return 'PostgreSQL'
        if 'mongodb' in banner_lower:
            return 'MongoDB'
        if 'redis' in banner_lower:
            return 'Redis'
        if 'elasticsearch' in banner_lower:
            return 'Elasticsearch'
        
        # Windows services
        if 'microsoft' in banner_lower and 'rdp' in banner_lower:
            return 'RDP (Windows)'
        if 'microsoft' in banner_lower and 'smb' in banner_lower:
            return 'SMB (Windows)'
        
        # Remote access
        if 'vnc' in banner_lower:
            return 'VNC'
        if 'rdp' in banner_lower:
            return 'RDP'
        if 'teamviewer' in banner_lower:
            return 'TeamViewer'
        
        # Misc
        if 'telnet' in banner_lower:
            return 'Telnet'
        if 'smtp' in banner_lower:
            return 'SMTP'
        if 'pop3' in banner_lower:
            return 'POP3'
        if 'imap' in banner_lower:
            return 'IMAP'
        
        return 'Unknown Service'

# ================================================================
# REMOTE ACCESS SCANNER
# ================================================================
class RemoteAccessScanner:
    def __init__(self):
        self.access_points = []
        self.successful_logins = []
    
    def scan_remote_access(self, ip, ports=None):
        """Scan for remote access services"""
        if ports is None:
            ports = {
                21: 'FTP',
                22: 'SSH', 
                23: 'Telnet',
                3389: 'RDP',
                5900: 'VNC',
                5800: 'VNC-HTTP',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                1433: 'MSSQL'
            }
        
        print_colored(f"\n[*] Scanning remote access on {ip}", Colors.WHITE)
        
        for port, service in ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    print_colored(f"  [+] {service} accessible on port {port}", Colors.GREEN)
                    self.access_points.append({
                        'ip': ip,
                        'port': port,
                        'service': service
                    })
                    
                    # Try default credentials for some services
                    if service == 'SSH':
                        self._test_ssh_login(ip, port)
                    elif service == 'FTP':
                        self._test_ftp_login(ip, port)
                    elif service == 'RDP':
                        self._test_rdp_login(ip, port)
            except:
                pass
        
        return self.access_points
    
    def _test_ssh_login(self, ip, port):
        """Test SSH default credentials"""
        credentials = [
            ('root', 'root'), ('root', ''), ('admin', 'admin'),
            ('administrator', 'password'), ('root', 'toor'),
            ('user', 'user'), ('test', 'test')
        ]
        
        for username, password in credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=username, password=password, timeout=3)
                client.close()
                
                print_colored(f"    [!] SSH LOGIN SUCCESS: {username}:{password}", Colors.RED)
                self.successful_logins.append({
                    'ip': ip,
                    'port': port,
                    'service': 'SSH',
                    'username': username,
                    'password': password
                })
                return
            except:
                pass
    
    def _test_ftp_login(self, ip, port):
        """Test FTP default credentials"""
        import ftplib
        credentials = [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')]
        
        for username, password in credentials:
            try:
                ftp = ftplib.FTP(ip, timeout=3)
                ftp.login(username, password)
                ftp.quit()
                
                print_colored(f"    [!] FTP LOGIN SUCCESS: {username}:{password}", Colors.RED)
                self.successful_logins.append({
                    'ip': ip,
                    'port': port,
                    'service': 'FTP',
                    'username': username,
                    'password': password
                })
                return
            except:
                pass
    
    def _test_rdp_login(self, ip, port):
        """Test RDP default credentials (basic check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            print_colored(f"    [i] RDP service is accessible (auto-login not tested)", Colors.YELLOW)
        except:
            pass

# ================================================================
# NETWORK TOPOLOGY MAPPER
# ================================================================
class NetworkTopologyMapper:
    def __init__(self):
        self.routes = []
        self.hops = []
        self.devices = {}
        self.latency_data = {}
    
    def trace_route(self, target, max_hops=30):
        """Trace route to target"""
        print_colored(f"\n[*] Tracing route to {target}", Colors.WHITE)
        self.hops = []
        
        for ttl in range(1, max_hops + 1):
            try:
                packet = scapy.IP(dst=target, ttl=ttl) / scapy.ICMP()
                reply = scapy.sr1(packet, timeout=2, verbose=0)
                
                if reply is None:
                    print(f"  {ttl}: *")
                    continue
                elif reply.src == target:
                    print_colored(f"  {ttl}: {reply.src} (Destination reached)", Colors.GREEN)
                    self.hops.append(reply.src)
                    break
                else:
                    print(f"  {ttl}: {reply.src}")
                    self.hops.append(reply.src)
            except:
                print(f"  {ttl}: *")
        
        return self.hops
    
    def discover_network(self, network_range=None, scan_devices=None):
        """Discover network topology"""
        if network_range is None:
            network_range = "192.168.1.0/24"
        
        print_colored(f"\n[*] Discovering network topology: {network_range}", Colors.WHITE)
        
        # Get all devices
        scanner = NetworkScanner()
        devices = scanner.scan_devices()
        
        # Map network structure
        router_ip = None
        
        # Find router/gateway
        for device in devices:
            if 'router' in device.get('hostname', '').lower() or 'gateway' in device.get('hostname', '').lower():
                router_ip = device['ip']
                break
        
        if not router_ip and devices:
            # Assume first device is gateway
            router_ip = devices[0]['ip']
        
        self.devices = devices
        return {
            'total_devices': len(devices),
            'router_ip': router_ip,
            'devices': devices,
            'hops': self.hops
        }

# ================================================================
# ACTIVE DIRECTORY SCANNER
# ================================================================
class ActiveDirectoryScanner:
    def __init__(self, domain_controller=None, username=None, password=None):
        self.dc = domain_controller
        self.username = username
        self.password = password
        self.connection = None
        self.users = []
        self.computers = []
        self.groups = []
    
    def connect(self):
        """Connect to Active Directory"""
        print_colored(f"\n[*] Connecting to AD: {self.dc}", Colors.WHITE)
        
        try:
            server = ldap3.Server(self.dc, get_info=ldap3.ALL)
            self.connection = ldap3.Connection(server, self.username, self.password, auto_bind=True)
            print_colored("[+] Connected to AD", Colors.GREEN)
            return True
        except Exception as e:
            print_colored(f"[-] AD connection failed: {e}", Colors.RED)
            return False
    
    def enumerate_users(self):
        """Enumerate AD users"""
        if not self.connection:
            return []
        
        print_colored("\n[*] Enumerating AD users...", Colors.WHITE)
        self.users = []
        
        try:
            self.connection.search(
                search_base='dc=local,dc=com',
                search_filter='(objectClass=user)',
                attributes=['cn', 'sAMAccountName', 'userPrincipalName', 'memberOf', 'title', 'department']
            )
            
            for entry in self.connection.entries:
                user = {
                    'name': entry.cn.value if hasattr(entry, 'cn') else 'Unknown',
                    'username': entry.sAMAccountName.value,
                    'upn': entry.userPrincipalName.value if hasattr(entry, 'userPrincipalName') else None,
                    'title': entry.title.value if hasattr(entry, 'title') else None,
                    'department': entry.department.value if hasattr(entry, 'department') else None
                }
                self.users.append(user)
                print_colored(f"  [+] User: {user['name']} ({user['username']})", Colors.GREEN)
            
            return self.users
        except Exception as e:
            print_colored(f"[-] User enumeration failed: {e}", Colors.RED)
            return []
    
    def enumerate_computers(self):
        """Enumerate AD computers"""
        if not self.connection:
            return []
        
        print_colored("\n[*] Enumerating AD computers...", Colors.WHITE)
        self.computers = []
        
        try:
            self.connection.search(
                search_base='dc=local,dc=com',
                search_filter='(objectClass=computer)',
                attributes=['cn', 'operatingSystem', 'dNSHostName', 'lastLogon']
            )
            
            for entry in self.connection.entries:
                computer = {
                    'name': entry.cn.value,
                    'os': entry.operatingSystem.value if hasattr(entry, 'operatingSystem') else 'Unknown',
                    'dns': entry.dNSHostName.value if hasattr(entry, 'dNSHostName') else None
                }
                self.computers.append(computer)
                print_colored(f"  [+] Computer: {computer['name']} ({computer['os']})", Colors.GREEN)
            
            return self.computers
        except Exception as e:
            print_colored(f"[-] Computer enumeration failed: {e}", Colors.RED)
            return []
    
    def enumerate_groups(self):
        """Enumerate AD groups"""
        if not self.connection:
            return []
        
        print_colored("\n[*] Enumerating AD groups...", Colors.WHITE)
        self.groups = []
        
        try:
            self.connection.search(
                search_base='dc=local,dc=com',
                search_filter='(objectClass=group)',
                attributes=['cn', 'description', 'member']
            )
            
            for entry in self.connection.entries:
                group = {
                    'name': entry.cn.value,
                    'description': entry.description.value if hasattr(entry, 'description') else None,
                    'members': len(entry.member.value) if hasattr(entry, 'member') else 0
                }
                self.groups.append(group)
                print_colored(f"  [+] Group: {group['name']} ({group['members']} members)", Colors.GREEN)
            
            return self.groups
        except Exception as e:
            print_colored(f"[-] Group enumeration failed: {e}", Colors.RED)
            return []
    
    def get_domain_info(self):
        """Get domain information"""
        if not self.connection:
            return None
        
        info = {
            'domain': self.connection.server.info.domain_dns_name,
            'forest': self.connection.server.info.forest_dns_name,
            'domain_controllers': self.connection.server.info.domain_controllers,
            'schema_version': self.connection.server.info.schema_version
        }
        
        return info

# ================================================================
# WIFI DEAUTH DETECTOR
# ================================================================
class DeauthDetector:
    """
    Sniffs 802.11 management frames to detect deauthentication /
    disassociation attacks. Requires monitor mode + root.
    """
    
    # 802.11 management frame subtypes we care about
    SUBTYPE_DEAUTH   = 12
    SUBTYPE_DISASSOC = 10
    
    # Reason codes that are suspicious when seen en masse
    SUSPICIOUS_REASONS = {
        1: "Unspecified",
        2: "Prev auth no longer valid",
        3: "Station leaving",
        4: "Inactivity",
        5: "AP unable to handle stations",
        6: "Class 2 frame from unauth station",
        7: "Class 3 frame from unassoc station",
    }
    
    def __init__(self):
        self.frames        = []          # all deauth/disassoc frames seen
        self.alerts        = []          # triggered alerts
        self.oui_hits      = defaultdict(int)   # attacker OUI -> count
        self.target_hits   = defaultdict(int)   # dst MAC -> count
        self.my_mac        = None
        self.my_bssid      = None
        self.running       = False
        self.start_time    = None
        self.threshold     = 5           # frames/sec from one src = attack
        self._rate_window  = defaultdict(list)  # src -> [timestamps]
    
    # ------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------
    def _get_my_mac(self):
        """Return the MAC of the first wireless interface we can find."""
        try:
            for iface, addrs in netifaces.interfaces() and {
                i: netifaces.ifaddresses(i) for i in netifaces.interfaces()
            }.items():
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get('addr')
                    if mac and mac != '00:00:00:00:00:00':
                        return mac.upper()
        except Exception:
            pass
        return None
    
    def _oui(self, mac):
        """First 3 octets of a MAC = vendor OUI."""
        return mac[:8].upper() if mac else "??:??:??"
    
    def _classify_attacker(self, oui):
        """Best-effort guess at what tool is being used."""
        vendor = self._oui_lookup(oui)
        guesses = {
            "Alfa":        "Alfa adapter (likely aireplay-ng / mdk4)",
            "TP-LINK":     "TP-Link adapter (likely aireplay-ng / mdk4)",
            "Ralink":      "Ralink chipset (common in mdk4 setups)",
            "Atheros":     "Atheros chipset (common in aireplay-ng)",
            "Realtek":     "Realtek adapter",
            "Intel":       "Intel adapter",
        }
        return guesses.get(vendor, f"Unknown OUI ({oui})")
    
    def _oui_lookup(self, oui):
        """Reuse your scanner's OUI DB if you have one handy."""
        # fall back to a tiny hard-coded map
        table = {
            "00:C0:CA": "Alfa",
            "00:0C:43": "Ralink",
            "00:15:6D": "Ubiquiti",
            "F8:1A:67": "TP-LINK",
            "00:1C:DF": "Belkin",
        }
        return table.get(oui, "Unknown")
    
    def _is_broadcast(self, mac):
        return mac in ("FF:FF:FF:FF:FF:FF", "ff:ff:ff:ff:ff:ff")
    
    # ------------------------------------------------------------
    # frame handler
    # ------------------------------------------------------------
    def _handle_frame(self, pkt):
        if not pkt.haslayer(scapy.Dot11):
            return
        
        dot11 = pkt[scapy.Dot11]
        if dot11.type != 0:          # 0 = management
            return
        
        subtype = dot11.subtype
        if subtype not in (self.SUBTYPE_DEAUTH, self.SUBTYPE_DISASSOC):
            return
        
        # Reason code lives in the Dot11Deauth / Dot11Disas layer
        reason = None
        for layer in (scapy.Dot11Deauth, scapy.Dot11Disas):
            if pkt.haslayer(layer):
                try:
                    reason = int(pkt[layer].reason)
                except Exception:
                    reason = None
                break
        
        src = (dot11.addr2 or "").upper()
        dst = (dot11.addr1 or "").upper()
        bssid = (dot11.addr3 or "").upper()
        now = time.time()
        
        frame = {
            "timestamp": datetime.now().isoformat(),
            "type":      "deauth" if subtype == self.SUBTYPE_DEAUTH else "disassoc",
            "src":       src,
            "dst":       dst,
            "bssid":     bssid,
            "reason":    reason,
            "reason_txt": self.SUSPICIOUS_REASONS.get(reason, "Unknown"),
            "broadcast": self._is_broadcast(dst),
        }
        self.frames.append(frame)
        
        # rate tracking per source MAC
        self._rate_window[src].append(now)
        cutoff = now - 1.0
        self._rate_window[src] = [t for t in self._rate_window[src] if t >= cutoff]
        rate = len(self._rate_window[src])
        
        # is this aimed at us?
        targeting_me = self.my_mac and dst == self.my_mac
        targeting_bcast = frame["broadcast"]
        
        # ---- alert logic -------------------------------------
        severity = None
        if targeting_me:
            severity = "CRITICAL"
        elif targeting_bcast and rate >= self.threshold:
            severity = "HIGH"
        elif rate >= self.threshold * 2:
            severity = "HIGH"
        elif rate >= self.threshold:
            severity = "MEDIUM"
        
        if severity:
            oui = self._oui(src)
            self.oui_hits[oui] += 1
            self.target_hits[dst] += 1
            
            alert = {
                "timestamp":  frame["timestamp"],
                "severity":   severity,
                "src":        src,
                "dst":        dst,
                "bssid":      bssid,
                "reason":     frame["reason_txt"],
                "rate":       f"{rate} frames/sec",
                "broadcast":  targeting_bcast,
                "targeting_me": targeting_me,
                "attacker_guess": self._classify_attacker(oui),
            }
            self.alerts.append(alert)
            
            color = Colors.RED if severity == "CRITICAL" else (
                    Colors.YELLOW if severity == "HIGH" else Colors.WHITE)
            
            print_colored(f"\n[!] {severity} — {frame['type'].upper()} ATTACK DETECTED", color)
            print_colored(f"    From    : {src}", Colors.END)
            print_colored(f"    To      : {dst}" + (" (BROADCAST)" if targeting_bcast else ""),
                          Colors.END)
            print_colored(f"    BSSID   : {bssid}", Colors.END)
            print_colored(f"    Reason  : {frame['reason_txt']}", Colors.END)
            print_colored(f"    Rate    : {rate} frames/sec", Colors.END)
            print_colored(f"    Attacker: {alert['attacker_guess']}", Colors.END)
            if targeting_me:
                print_colored("    >>> THIS IS AIMED AT YOUR MACHINE <<<", Colors.RED)
    
    # ------------------------------------------------------------
    # public API
    # ------------------------------------------------------------
    def detect(self, interface=None, duration=None, my_mac=None, threshold=5):
        """
        Sniff for deauth/disassoc frames.
        
        interface : wireless iface in monitor mode (e.g. wlan0mon)
                    If None, we try to auto-detect one.
        duration  : seconds to run (None = until Ctrl+C)
        my_mac    : your MAC so we can flag targeted attacks
        threshold : frames/sec from one src before we call it an attack
        """
        self.running    = True
        self.start_time = time.time()
        self.threshold  = threshold
        self.my_mac     = (my_mac or self._get_my_mac() or "").upper() or None
        
        if not interface:
            interface = self._auto_monitor_iface()
        
        if not interface:
            print_colored("[-] No wireless interface found. Put a card into "
                          "monitor mode first (e.g. `airmon-ng start wlan0`).", Colors.RED)
            return []
        
        print_colored(f"[*] Deauth detector listening on {interface}", Colors.WHITE)
        if self.my_mac:
            print_colored(f"[*] Your MAC: {self.my_mac}", Colors.WHITE)
        print_colored(f"[*] Alert threshold: {threshold} frames/sec", Colors.WHITE)
        print_colored("[*] Press Ctrl+C to stop\n", Colors.YELLOW)
        
        try:
            if duration:
                scapy.sniff(iface=interface, prn=self._handle_frame,
                            store=0, timeout=duration, monitor=True)
            else:
                scapy.sniff(iface=interface, prn=self._handle_frame,
                            store=0, monitor=True)
        except KeyboardInterrupt:
            print_colored("\n[*] Detector stopped", Colors.YELLOW)
        except Exception as e:
            print_colored(f"[-] Sniff error: {e}", Colors.RED)
            print_colored("    (monitor mode + root usually required)", Colors.YELLOW)
        finally:
            self.running = False
        
        return self.alerts
    
    def _auto_monitor_iface(self):
        """Look for a *mon interface, else first wireless iface."""
        try:
            ifaces = netifaces.interfaces()
        except Exception:
            return None
        for i in ifaces:
            if "mon" in i.lower():
                return i
        for i in ifaces:
            if i.lower().startswith(("wl", "wlan", "wlp")):
                return i
        return None
    
    def get_statistics(self):
        return {
            "total_frames":      len(self.frames),
            "alerts":            len(self.alerts),
            "critical":          sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
            "high":              sum(1 for a in self.alerts if a["severity"] == "HIGH"),
            "medium":            sum(1 for a in self.alerts if a["severity"] == "MEDIUM"),
            "unique_attackers":  len(self.oui_hits),
            "top_attackers":     sorted(self.oui_hits.items(),
                                        key=lambda x: -x[1])[:5],
            "top_targets":       sorted(self.target_hits.items(),
                                        key=lambda x: -x[1])[:5],
            "duration_sec":      round(time.time() - self.start_time, 1)
                                 if self.start_time else 0,
        }
    
    def get_report(self):
        stats = self.get_statistics()
        lines = [
            "=" * 60,
            "DEAUTH ATTACK REPORT",
            "=" * 60,
            f"Duration        : {stats['duration_sec']}s",
            f"Frames captured : {stats['total_frames']}",
            f"Alerts          : {stats['alerts']}",
            f"  CRITICAL      : {stats['critical']}",
            f"  HIGH          : {stats['high']}",
            f"  MEDIUM        : {stats['medium']}",
            f"Unique attackers: {stats['unique_attackers']}",
        ]
        if stats["top_attackers"]:
            lines.append("\nTop attacker OUIs:")
            for oui, cnt in stats["top_attackers"]:
                lines.append(f"  {oui}  x{cnt}  ({self._oui_lookup(oui)})")
        if stats["top_targets"]:
            lines.append("\nTop targets:")
            for mac, cnt in stats["top_targets"]:
                tag = " <-- YOU" if self.my_mac and mac == self.my_mac else ""
                lines.append(f"  {mac}  x{cnt}{tag}")
        return "\n".join(lines)

# ================================================================
# PORT KNOCK SCANNER
# ================================================================
class PortKnockScanner:
    def __init__(self):
        self.knock_sequence = []
        self.responses = []
    
    def scan_port_knock(self, target, ports, timeout=1):
        """Scan for port knock sequences"""
        print_colored(f"\n[*] Scanning port knock on {target}", Colors.WHITE)
        print_colored(f"[*] Testing sequence: {ports}", Colors.YELLOW)
        
        self.responses = []
        self.knock_sequence = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                # Send SYN packet (port knock)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    print_colored(f"  [+] Port {port} responded (open)", Colors.GREEN)
                    self.responses.append({'port': port, 'status': 'open'})
                else:
                    print_colored(f"  [-] Port {port} did not respond", Colors.END)
                    self.responses.append({'port': port, 'status': 'closed'})
            except:
                pass
        
        # Analyze results
        open_ports = [r for r in self.responses if r['status'] == 'open']
        if open_ports:
            print_colored(f"\n[!] Port knock sequence detected!", Colors.RED)
            print_colored(f"    Open ports: {', '.join(str(p['port']) for p in open_ports)}", Colors.YELLOW)
            
            # Try to detect service
            for port in open_ports:
                if port['port'] == 22:
                    print_colored("    [i] Likely SSH knock sequence", Colors.WHITE)
                elif port['port'] == 80 or port['port'] == 443:
                    print_colored("    [i] Likely Web knock sequence", Colors.WHITE)
        
        return self.responses

# ================================================================
# MAIN NETWORK SCANNER
# ================================================================
class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.nmap_available = False
        self.nm = None
        self.oui_cache = {}
        self.monitoring_active = False
        self.monitoring_thread = None
        self.known_devices = set()
        self.scan_history = []
        self.output_file = None
        self._oui_lock = threading.Lock()
        self.oui_db = self._get_default_oui_db()
        
        # Initialize Nmap
        nmap_dir = r'C:\Program Files (x86)\Nmap'
        if os.path.exists(nmap_dir):
            if nmap_dir not in os.environ['PATH']:
                os.environ['PATH'] = nmap_dir + os.pathsep + os.environ['PATH']
        
        try:
            self.nm = nmap.PortScanner()
            self.nm.nmap_search_path = [r'C:\Program Files (x86)\Nmap\nmap.exe']
            print_colored("[+] Nmap initialized", Colors.GREEN)
            self.nmap_available = True
        except Exception as e:
            print_colored(f"[-] Nmap error: {e}", Colors.RED)
            self.nmap_available = False
        
        # Initialize components
        self.packet_sniffer = PacketSniffer()
        self.bandwidth_monitor = BandwidthMonitor()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.wifi_scanner = WiFiScanner()
        self.cert_analyzer = CertificateAnalyzer()
        self.dns_enum = DNSEnumerator()
        self.service_fingerprinter = ServiceFingerprinter()
        self.remote_scanner = RemoteAccessScanner()
        self.topology_mapper = NetworkTopologyMapper()
        self.ad_scanner = None
        self.port_knocker = PortKnockScanner()
        self.web_scanner = WebAppScanner()
        self.arp_monitor = ARPMonitor()
        self.deauth_detector = DeauthDetector()
    
    def _get_default_oui_db(self):
        """Default OUI database for MAC address lookup"""
        return {
            '000A95': 'Apple Inc.',
            '000D93': 'Apple Inc.',
            '001B63': 'Apple Inc.',
            '001EC2': 'Apple Inc.',
            '0017F2': 'Apple Inc.',
            '002590': 'Apple Inc.',
            '00256B': 'Apple Inc.',
            '0024AB': 'Apple Inc.',
            '001FF3': 'Apple Inc.',
            '001451': 'Apple Inc.',
            '001124': 'Apple Inc.',
            '0010FA': 'Apple Inc.',
            '0050F2': 'Microsoft Corporation',
            '0018F3': 'Microsoft Corporation',
            '001C42': 'Microsoft Corporation',
            '0021CC': 'Microsoft Corporation',
            '0022B0': 'Microsoft Corporation',
            '002558': 'Microsoft Corporation',
            '0015C5': 'Microsoft Corporation',
            '0013D4': 'Microsoft Corporation',
            '001A4B': 'Hewlett Packard',
            '0018FE': 'Hewlett Packard',
            '001B78': 'Hewlett Packard',
            '002197': 'Hewlett Packard',
            '0011D8': 'Cisco Systems',
            '0012D8': 'Cisco Systems',
            '0013C3': 'Cisco Systems',
            '0015C6': 'Cisco Systems',
            '001849': 'Cisco Systems',
            '0021D7': 'Cisco Systems',
            '0022BD': 'Cisco Systems',
            '001460': 'Dell Inc.',
            '001B78': 'Dell Inc.',
            '0023AE': 'Dell Inc.',
            '001A4B': 'Dell Inc.',
            '001E4F': 'Dell Inc.',
            '001E8C': 'Dell Inc.',
            '000C6E': 'Intel Corporation',
            '0013C3': 'Intel Corporation',
            '001B43': 'Intel Corporation',
            '001D09': 'Intel Corporation',
            '001D7E': 'Intel Corporation',
            '001E6B': 'Intel Corporation',
            '0012F0': 'Samsung Electronics',
            '0014A5': 'Samsung Electronics',
            '001A2B': 'Samsung Electronics',
            '002157': 'Samsung Electronics',
            '0022B0': 'Samsung Electronics',
            '0023CD': 'Samsung Electronics',
            '00022D': 'Google Inc.',
            '00E04C': 'Google Inc.',
            '001DDD': 'Google Inc.',
            '0020E0': 'Google Inc.',
        }
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '192.168.1.1'
    
    def get_network_range(self):
        ip = self.get_local_ip()
        base = '.'.join(ip.split('.')[:-1])
        return f"{base}.0/24"
    
    def get_hostname_dns(self, ip):
        try:
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    def get_hostname_nbns(self, ip):
        try:
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        return parts[0].strip()
        except:
            pass
        return None
    
    
    def get_vendor_from_mac(self, mac):
        if not mac or mac == 'Unknown':
            return 'Unknown'
    
        with self._oui_lock:
            if mac in self.oui_cache:
                return self.oui_cache[mac]
    
        oui = mac[:8].upper().replace(':', '').replace('-', '')
        vendor = self.oui_db.get(oui, 'Unknown')
    
        with self._oui_lock:
            self.oui_cache[mac] = vendor
    
        return vendor
    
    def scan_devices(self, show_progress=True, max_workers=50):
        """Scan network for devices (threaded enrichment)."""
        if not self.nmap_available:
            print_colored("[-] Nmap not available", Colors.RED)
            return []
    
        network = self.get_network_range()
        print_colored(f"[*] Scanning {network}...", Colors.WHITE)
    
        try:
            # Phase 1: Fast nmap host discovery (single call, already parallel internally)
            start = time.time()
            self.nm.scan(hosts=network, arguments='-sn -PR -T4 -R')
            nmap_time = time.time() - start
            print_colored(f"[+] Nmap discovery completed in {nmap_time:.2f}s", Colors.GREEN)
        
            live_hosts = [h for h in self.nm.all_hosts() 
                          if self.nm[h].state() == 'up']
        
            if not live_hosts:
                print_colored("[-] No live hosts found", Colors.YELLOW)
                return []
        
            print_colored(f"[*] Enriching {len(live_hosts)} hosts with "
                          f"{max_workers} threads...", Colors.WHITE)

            # Phase 2: Threaded per-host enrichment (hostname + vendor)
            devices = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self._enrich_host, host): host 
                           for host in live_hosts}

                if show_progress:
                    with tqdm(total=len(futures), desc="Enriching hosts", 
                              unit="host") as pbar:
                        for future in as_completed(futures):
                            try:
                                device = future.result()
                                devices.append(device)
                                pbar.update(1)
                            except Exception as e:
                                pbar.update(1)
                else:
                    for future in as_completed(futures):
                        try:
                            devices.append(future.result())
                        except:
                            pass
                            
            # Sort by IP for consistent output
            devices.sort(key=lambda d: tuple(int(x) for x in d['ip'].split('.')))

            # Print results
            for d in devices:
                print_colored(
                    f"  [+] {d['ip']:15} | {d['hostname'][:25]:25} | "
                    f"{d['vendor'][:15]:15} | {d['mac']}",
                    Colors.WHITE
                )

            self.devices = devices
            return devices

        except Exception as e:
            print_colored(f"[-] Scan failed: {e}", Colors.RED)
            return []
    
    def port_scan(self, target, start_port=1, end_port=1024, timeout=1, 
              max_workers=200, show_progress=True, batch_size=1000):
        """Scan ports with batched threading (faster for large ranges)."""
        open_ports = []
        total_ports = end_port - start_port + 1
    
        if show_progress:
            print_colored(f"[*] Scanning ports {start_port}-{end_port} "
                          f"on {target} ({max_workers} workers)", Colors.WHITE)
    
        all_ports = list(range(start_port, end_port + 1))
        completed = 0
    
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._scan_port, target, port, timeout): port
                       for port in all_ports}

            for future in as_completed(futures):
                completed += 1
                if show_progress and completed % 200 == 0:
                    print(f"\r  Progress: {completed}/{total_ports} ports "
                          f"({completed*100//total_ports}%)", end='')

                result = future.result()
                if result:
                    open_ports.append(result)
    
        if show_progress:
            print(f"\n  Found {len(open_ports)} open ports")
    
        return sorted(open_ports)
    
    def _scan_port(self, target, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    def ping_sweep(self, network=None, show_progress=True):
        """Perform ping sweep on a network"""
        if network is None:
            network = self.get_network_range()
        
        print_colored(f"[*] Ping sweeping {network}...", Colors.WHITE)
        base_ip = network.rsplit('.', 1)[0]
        online = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._ping_host, f"{base_ip}.{i}"): i for i in range(1, 255)}
            
            for idx, future in enumerate(as_completed(futures), 1):
                if show_progress and idx % 25 == 0:
                    print(f"\r  Progress: {idx}/254 hosts", end='')
                
                result = future.result()
                if result:
                    online.append(result)
        
        if show_progress:
            print(f"\n  Found {len(online)} hosts online")
        
        return online
    
    def _ping_host(self, ip):
        try:
            param = '-n' if os.name == 'nt' else '-c'
            result = subprocess.run(['ping', param, '1', '-w', '1000', ip], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return ip
        except:
            pass
        return None
    
    def get_device_details(self, ip):
        """Get detailed device information"""
        print_colored(f"\n[*] Fetching details for {ip}...", Colors.WHITE)
        
        try:
            self.nm.scan(hosts=ip, arguments='-sS -T4 -R -O -sV -p 1-1000')
            
            if ip in self.nm.all_hosts() and self.nm[ip].state() == 'up':
                host = self.nm[ip]
                
                details = {
                    'ip': ip,
                    'hostname': host.hostname() if host.hostname() else 'Unknown',
                    'state': host.state(),
                    'mac': host.get('mac', 'Unknown'),
                    'vendor': 'Unknown',
                    'os': 'Unknown',
                    'os_accuracy': 0,
                    'open_ports': [],
                    'services': {},
                    'last_seen': datetime.now().isoformat(),
                    'device_type': 'Unknown'
                }
                
                if 'vendor' in host:
                    vendor_data = host['vendor']
                    if isinstance(vendor_data, dict):
                        details['vendor'] = list(vendor_data.values())[0] if vendor_data else 'Unknown'
                    else:
                        details['vendor'] = str(vendor_data)
                else:
                    details['vendor'] = self.get_vendor_from_mac(details['mac'])
                
                if 'osmatch' in host and host['osmatch']:
                    details['os'] = host['osmatch'][0]['name']
                    try:
                        details['os_accuracy'] = int(host['osmatch'][0].get('accuracy', '0'))
                    except:
                        pass
                
                if 'tcp' in host:
                    for port, data in host['tcp'].items():
                        if data['state'] == 'open':
                            details['open_ports'].append(port)
                            details['services'][port] = {
                                'service': data.get('name', 'unknown'),
                                'product': data.get('product', ''),
                                'version': data.get('version', ''),
                                'extra': data.get('extrainfo', '')
                            }
                
                details['device_type'] = self._identify_device_type(details)
                return details
        except Exception as e:
            print_colored(f"[-] Could not get detailed info: {e}", Colors.RED)
            return None
    
    def _identify_device_type(self, details):
        """Identify device type based on information"""
        vendor = details.get('vendor', '').lower()
        hostname = details.get('hostname', '').lower()
        services = details.get('services', {})
        open_ports = details.get('open_ports', [])
        os_name = details.get('os', '').lower()
        
        if 'windows' in os_name:
            return 'Windows Computer'
        if 'linux' in os_name:
            return 'Linux Computer'
        if 'mac' in os_name or 'apple' in os_name:
            return 'Mac Computer'
        if 'android' in os_name:
            return 'Android Device'
        if 'ios' in os_name or 'iphone' in os_name:
            return 'iOS Device'
        if 'apple' in vendor:
            return 'Apple Device'
        if 'samsung' in vendor:
            return 'Samsung Device'
        if 'google' in vendor:
            return 'Google Device'
        if 'cisco' in vendor:
            return 'Network Equipment (Cisco)'
        if 'tplink' in vendor or 'tp-link' in vendor:
            return 'Router/Network Equipment'
        if 80 in open_ports or 443 in open_ports:
            return 'Web Server'
        if 22 in open_ports:
            return 'SSH Server'
        if 3389 in open_ports:
            return 'Windows Machine (RDP)'
        if 445 in open_ports:
            return 'Windows Machine (SMB)'
        if 'raspberry' in hostname or 'pi' in hostname:
            return 'Raspberry Pi'
        if 'printer' in hostname or 'print' in hostname:
            return 'Printer'
        if 'camera' in hostname or 'cam' in hostname:
            return 'IP Camera'
        return 'Unknown Device'
    
    def print_table(self, devices):
        """Print devices in a table format"""
        if not devices:
            print_colored("[-] No devices found", Colors.RED)
            return
        
        print("\n" + "=" * 100)
        print_colored(f"{'#':<4} {'IP Address':<18} {'Hostname':<30} {'Vendor':<25}", Colors.WHITE)
        print("=" * 100)
        
        for idx, d in enumerate(devices, 1):
            print(f"{idx:<4} {d['ip']:<18} {d['hostname'][:30]:<30} {d['vendor'][:25]}")
        
        print("=" * 100)
        print_colored(f"[*] Total: {len(devices)} devices", Colors.WHITE)
    
    def print_device_details(self, ip=None):
        """Print detailed device information"""
        if ip is None:
            ip = input("Enter the IP address to get details for: ")
        
        details = self.get_device_details(ip)
        
        if not details:
            print_colored(f"[-] Could not get details for {ip}", Colors.RED)
            return
        
        print("\n" + "=" * 80)
        print_colored(f"DEVICE DETAILS: {ip}", Colors.WHITE)
        print("=" * 80)
        
        print("\n[Basic Info]")
        print(f"  IP Address    : {details['ip']}")
        print(f"  Hostname      : {details['hostname']}")
        print(f"  Status        : {details['state']}")
        print(f"  MAC Address   : {details['mac']}")
        print(f"  Vendor        : {details['vendor']}")
        print(f"  Device Type   : {details['device_type']}")
        
        print("\n[OS Information]")
        print(f"  OS            : {details['os']}")
        if details['os_accuracy'] > 0:
            print(f"  Accuracy      : {details['os_accuracy']}%")
        
        print("\n[Open Ports]")
        if details['open_ports']:
            print(f"  Total open ports: {len(details['open_ports'])}")
            print(f"  Ports: {', '.join(map(str, sorted(details['open_ports'])))}")
            
            print("\n  Service Details:")
            for port in sorted(details['open_ports']):
                if port in details['services']:
                    svc = details['services'][port]
                    product_info = ""
                    if svc['product']:
                        product_info += f" (Product: {svc['product']}"
                        if svc['version']:
                            product_info += f" {svc['version']}"
                        product_info += ")"
                    print(f"    Port {port}: {svc['service']}{product_info}")
        else:
            print("  No open ports found")
        
        print("\n" + "=" * 80)
    
    def continuous_monitoring(self, interval=60, output_file=None):
        """Continuously monitor network for changes"""
        self.monitoring_active = True
        known_devices = set()
        
        print_colored(f"[*] Starting continuous monitoring (interval: {interval}s)", Colors.WHITE)
        print_colored("[*] Press Ctrl+C to stop", Colors.YELLOW)
        
        try:
            while self.monitoring_active:
                devices = self.scan_devices(show_progress=False)
                current_ips = {d['ip'] for d in devices}
                
                # Check for new devices
                new_devices = current_ips - known_devices
                for ip in new_devices:
                    device = next(d for d in devices if d['ip'] == ip)
                    print_colored(f"[!] NEW DEVICE DETECTED: {ip} ({device['hostname']})", Colors.RED)
                
                # Check for missing devices
                missing_devices = known_devices - current_ips
                for ip in missing_devices:
                    print_colored(f"[-] Device left: {ip}", Colors.YELLOW)
                
                known_devices = current_ips
                
                # Save to file if specified
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(devices, f, indent=2)
                
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        self.monitoring_active = False
        print_colored("[*] Monitoring stopped", Colors.YELLOW)
    
    def export_results(self, devices, filename=None):
        """Export scan results to JSON"""
        if not filename:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(devices),
            'devices': devices
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print_colored(f"[+] Results exported to {filename}", Colors.GREEN)
        return filename

    def _enrich_host(self, host, mac_lookup_timeout=1):
        """Enrich a single host with hostname/vendor info (thread-safe)."""
        try:
            # Run hostname lookups in parallel within this thread
            hostname = None
        
            # Try DNS first (fast fail)
            try:
                socket.setdefaulttimeout(mac_lookup_timeout)
                hostname = socket.gethostbyaddr(host)[0]
            except:
                pass
            finally:
                socket.setdefaulttimeout(None)
        
            # Fall back to NBNS on Windows
            if not hostname and os.name == 'nt':
                try:
                    result = subprocess.run(
                        ['nbtstat', '-A', host],
                        capture_output=True, text=True, timeout=2
                    )
                    for line in result.stdout.split('\n'):
                        if '<00>' in line and 'UNIQUE' in line:
                            parts = line.split()
                            if len(parts) >= 1:
                                hostname = parts[0].strip()
                                break
                except:
                    pass
        
            # Get MAC/vendor from already-collected nmap data
            mac = 'Unknown'
            vendor = 'Unknown'
            if host in self.nm.all_hosts():
                host_data = self.nm[host]
                if 'mac' in host_data:
                    mac = host_data['mac']
                if 'vendor' in host_data:
                    vendor_data = host_data['vendor']
                    if isinstance(vendor_data, dict):
                        vendor = list(vendor_data.values())[0] if vendor_data else 'Unknown'
                    else:
                        vendor = str(vendor_data)
                else:
                    vendor = self.get_vendor_from_mac(mac)
        
            return {
                'ip': host,
                'hostname': hostname or 'Unknown',
                'mac': mac,
                'vendor': vendor,
                'status': 'online',
                'last_seen': datetime.now().isoformat()
            }
        except Exception:
            return {
                'ip': host,
                'hostname': 'Unknown',
                'mac': 'Unknown',
                'vendor': 'Unknown',
                'status': 'online',
                'last_seen': datetime.now().isoformat()
            }

# ================================================================
# MAIN INTERACTIVE MODE
# ================================================================
def main_interactive():
    scanner = NetworkScanner()
    devices = []
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        menu()
        
        try:
            choice = int(input("Selection: "))
        except ValueError:
            print_colored("Please enter a valid whole number.", Colors.RED)
            input("\nPress Enter...")
            continue
        
        # Basic Scanning
        if choice == 1:
            ip = input("Enter IP address to ping: ")
            os.system('cls' if os.name == 'nt' else 'clear')
            os.system('ping ' + ip)
        
        elif choice == 2:
            os.system('cls' if os.name == 'nt' else 'clear')
            target = input("Enter the target IP address or hostname: ")
            start_port = int(input("Start port (default 1): ") or 1)
            end_port = int(input("End port (default 1024): ") or 1024)
            open_ports = scanner.port_scan(target, start_port, end_port)
            print_colored(f"\nFound {len(open_ports)} open ports:", Colors.WHITE)
            for port in sorted(open_ports):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                print(f"  Port {port}: {service}")
        
        elif choice == 3:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Network Scanner - Device Discovery", Colors.WHITE)
            print("=" * 60)
            devices = scanner.scan_devices()
            scanner.print_table(devices)
        
        elif choice == 4:
            if not devices:
                print_colored("\n[-] Please run a network scan first (Option 3)", Colors.RED)
                input("\nPress Enter...")
                continue
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n" + "=" * 60)
            print_colored("Device Details - Select an IP", Colors.WHITE)
            print("=" * 60)
            scanner.print_table(devices)
            print("\nOptions:")
            print("  - Enter an IP address")
            print("  - Enter a number from the list above")
            choice_input = input("\nSelect device: ").strip()
            try:
                idx = int(choice_input)
                if 1 <= idx <= len(devices):
                    ip = devices[idx-1]['ip']
                else:
                    print_colored("Invalid selection", Colors.RED)
                    input("\nPress Enter...")
                    continue
            except ValueError:
                ip = choice_input
            scanner.print_device_details(ip)
        
        elif choice == 6:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Ping Sweep - Quick Network Scan", Colors.WHITE)
            print("=" * 60)
            network = input(f"Enter network range (default {scanner.get_network_range()}): ")
            if not network:
                network = scanner.get_network_range()
            results = scanner.ping_sweep(network)
            if results:
                print_colored(f"\n[*] {len(results)} host(s) online:", Colors.WHITE)
                for ip in sorted(results):
                    print(f"  {ip}")
        
        elif choice == 8:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Route Trace (Traceroute)", Colors.WHITE)
            print("=" * 60)
            target = input("Enter target IP or domain: ")
            scanner.topology_mapper.trace_route(target)
        
        elif choice == 9:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("DNS Enumeration", Colors.WHITE)
            print("=" * 60)
            domain = input("Enter domain to enumerate: ")
            scanner.dns_enum.enumerate(domain)
            print("\n" + scanner.dns_enum.get_report())
        
        # Advanced Scanning
        elif choice == 10:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Packet Sniffer", Colors.WHITE)
            print("=" * 60)
            count = int(input("Number of packets to capture (default 100): ") or 100)
            scanner.packet_sniffer.sniff_packets(count=count)
            stats = scanner.packet_sniffer.get_statistics()
            print_colored(f"\n[Statistics]", Colors.WHITE)
            print(f"  Total packets: {stats['total_packets']}")
            print(f"  HTTP requests: {stats['http_requests']}")
            print(f"  DNS queries: {stats['dns_queries']}")
            print(f"  Credentials found: {stats['credentials_found']}")
        
        elif choice == 11:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Bandwidth Monitor", Colors.WHITE)
            print("=" * 60)
            interval = int(input("Monitoring interval in seconds (default 2): ") or 2)
            duration = input("Duration in seconds (0 for infinite): ")
            duration = int(duration) if duration and int(duration) > 0 else None
            scanner.bandwidth_monitor.monitor_bandwidth(interval=interval, duration=duration)
            stats = scanner.bandwidth_monitor.get_stats()
            if stats:
                print(f"\nAverage Upload: {stats['avg_upload']:.2f} Mbps")
                print(f"Max Upload: {stats['max_upload']:.2f} Mbps")
                print(f"Average Download: {stats['avg_download']:.2f} Mbps")
                print(f"Max Download: {stats['max_download']:.2f} Mbps")
        
        elif choice == 12:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Vulnerability Scanner", Colors.WHITE)
            print("=" * 60)
            target = input("Enter IP to scan for vulnerabilities: ")
            print_colored("[*] First, scanning for open ports...", Colors.WHITE)
            open_ports = scanner.port_scan(target, show_progress=True)
            if open_ports:
                scanner.vulnerability_scanner.check_vulnerabilities(target, open_ports)
                print("\n" + scanner.vulnerability_scanner.get_vulnerability_report())
            else:
                print_colored("[-] No open ports found", Colors.RED)
        
        elif choice == 13:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("WiFi Scanner", Colors.WHITE)
            print("=" * 60)
            scanner.wifi_scanner.scan_wifi()
            connect = input("\nConnect to a network? (y/n): ")
            if connect.lower() == 'y':
                idx = int(input("Enter network number: ")) - 1
                if 0 <= idx < len(scanner.wifi_scanner.networks):
                    net = scanner.wifi_scanner.networks[idx]
                    password = input("Enter password (press Enter for open network): ")
                    scanner.wifi_scanner.connect_to_network(net['ssid'], password if password else None)
        
        elif choice == 14:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Web Application Scanner", Colors.WHITE)
            print("=" * 60)
            url = input("Enter URL to scan (e.g., http://example.com): ")
            scanner.web_scanner.scan_web_app(url)
        
        elif choice == 15:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("ARP Spoofing Detector", Colors.WHITE)
            print("=" * 60)
            print_colored("[!] WARNING: This requires admin/root privileges", Colors.RED)
            interface = input("Network interface (leave blank for default): ")
            duration = int(input("Monitoring duration in seconds (0 for infinite): ") or 0)
            scanner.arp_monitor.monitor_arp(interface=interface if interface else None, 
                                           duration=duration if duration > 0 else None)
            stats = scanner.arp_monitor.get_statistics()
            print(f"\n[Statistics]")
            print(f"  Devices monitored: {stats['devices_monitored']}")
            print(f"  Attacks detected: {stats['attacks_detected']}")
        
        elif choice == 16:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("SSL Certificate Analyzer", Colors.WHITE)
            print("=" * 60)
            hostname = input("Enter hostname: ")
            port = int(input("Port (default 443): ") or 443)
            scanner.cert_analyzer.analyze_certificate(hostname, port)
        
        elif choice == 17:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Service Fingerprinter", Colors.WHITE)
            print("=" * 60)
            ip = input("Enter IP address: ")
            port = int(input("Enter port: "))
            scanner.service_fingerprinter.fingerprint_service(ip, port)
        
        elif choice == 18:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Remote Access Scanner", Colors.WHITE)
            print("=" * 60)
            ip = input("Enter IP address to scan: ")
            scanner.remote_scanner.scan_remote_access(ip)
            if scanner.remote_scanner.successful_logins:
                print_colored("\n[!] Successful logins found!", Colors.RED)
                for login in scanner.remote_scanner.successful_logins:
                    print(f"  {login['service']} - {login['username']}:{login['password']}")
        
        # Enterprise Features
        elif choice == 19:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Active Directory Scanner", Colors.WHITE)
            print("=" * 60)
            dc = input("Enter Domain Controller IP: ")
            username = input("Enter username (optional): ")
            password = input("Enter password (optional): ")
            scanner.ad_scanner = ActiveDirectoryScanner(dc, username if username else None, 
                                                       password if password else None)
            if scanner.ad_scanner.connect():
                scanner.ad_scanner.enumerate_users()
                scanner.ad_scanner.enumerate_computers()
                scanner.ad_scanner.enumerate_groups()
                info = scanner.ad_scanner.get_domain_info()
                if info:
                    print(f"\n[Domain Info]")
                    print(f"  Domain: {info['domain']}")
                    print(f"  Forest: {info['forest']}")
        
        elif choice == 20:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Network Topology Mapper", Colors.WHITE)
            print("=" * 60)
            target = input("Enter target IP for traceroute (optional): ")
            if target:
                scanner.topology_mapper.trace_route(target)
            network = input("Enter network range (default auto): ")
            if network:
                topology = scanner.topology_mapper.discover_network(network)
            else:
                topology = scanner.topology_mapper.discover_network()
            print(f"\n[Network Topology]")
            print(f"  Total devices: {topology['total_devices']}")
            if topology.get('router_ip'):
                print(f"  Router/Gateway: {topology['router_ip']}")
            if topology.get('hops'):
                print(f"  Hops: {len(topology['hops'])}")
        
        elif choice == 21:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Port Knock Scanner", Colors.WHITE)
            print("=" * 60)
            ip = input("Enter IP address: ")
            ports_input = input("Enter ports to test (comma-separated, e.g., 22,80,443): ")
            ports = [int(p.strip()) for p in ports_input.split(',') if p.strip()]
            scanner.port_knocker.scan_port_knock(ip, ports)
        
        # Utilities
        elif choice == 7:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Continuous Network Monitoring", Colors.WHITE)
            print("=" * 60)
            interval = int(input("Monitoring interval in seconds (default 60): ") or 60)
            output_file = input("Output file (optional): ") or None
            print_colored("\n[*] Starting continuous monitoring...", Colors.WHITE)
            print_colored("[*] Press Ctrl+C in the terminal to stop", Colors.YELLOW)
            try:
                scanner.continuous_monitoring(interval=interval, output_file=output_file)
            except KeyboardInterrupt:
                scanner.stop_monitoring()
        
        elif choice == 5:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Export Results", Colors.WHITE)
            print("=" * 60)
            if not devices and not scanner.devices:
                print_colored("[-] No devices to export. Please scan first.", Colors.RED)
                input("\nPress Enter...")
                continue
            export_devices = devices if devices else scanner.devices
            filename = input("Filename (default: scan_results_TIMESTAMP.json): ")
            scanner.export_results(export_devices, filename if filename.strip() else None)

        elif choice == 23:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("WiFi Deauth Detector", Colors.WHITE)
            print("=" * 60)
            print_colored("[!] Requires: root + wireless NIC in monitor mode", Colors.RED)
            print_colored("[!] Quick setup: sudo airmon-ng start wlan0", Colors.YELLOW)
            print_colored("[!] Then use the resulting wlan0mon interface\n", Colors.YELLOW)

            iface = input("Monitor interface (blank = auto-detect): ").strip() or None
            dur_in = input("Duration in seconds (0 = until Ctrl+C): ").strip()
            duration = int(dur_in) if dur_in and int(dur_in) > 0 else None
            my_mac = input("Your MAC (blank = auto-detect): ").strip() or None
            thr_in = input("Alert threshold frames/sec (default 5): ").strip()
            threshold = int(thr_in) if thr_in else 5

            scanner.deauth_detector.detect(
                interface=iface,
                duration=duration,
                my_mac=my_mac,
                threshold=threshold,
            )
            print("\n" + scanner.deauth_detector.get_report())
        
        elif choice == 22:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("=" * 60)
            print_colored("Generate Report", Colors.WHITE)
            print("=" * 60)
            if not devices and not scanner.devices:
                print_colored("[-] No devices found. Please scan first.", Colors.RED)
                input("\nPress Enter...")
                continue
            report = []
            report.append("=" * 60)
            report.append("NETWORK SECURITY REPORT")
            report.append("=" * 60)
            report.append(f"Generated: {datetime.now().isoformat()}")
            report.append(f"Total Devices: {len(devices or scanner.devices)}")
            
            # Device info
            report.append("\n[DEVICES]")
            for d in (devices or scanner.devices):
                report.append(f"  {d['ip']} - {d['hostname']} ({d['vendor']})")
            
            # Vulnerabilities
            if scanner.vulnerability_scanner.vulnerabilities:
                report.append("\n[VULNERABILITIES]")
                for v in scanner.vulnerability_scanner.vulnerabilities:
                    report.append(f"  {v['ip']}:{v['port']} - {v['service']} - {v['vulnerability']} ({v['severity']})")
            
            # Web vulnerabilities
            if scanner.web_scanner.vulnerabilities:
                report.append("\n[WEB VULNERABILITIES]")
                for v in scanner.web_scanner.vulnerabilities:
                    report.append(f"  {v['type']} - {v['details']}")
            
            # Certificate issues
            if scanner.cert_analyzer.issues:
                report.append("\n[CERTIFICATE ISSUES]")
                for issue in scanner.cert_analyzer.issues:
                    report.append(f"  {issue['hostname']}: {', '.join(issue['issues'])}")
            
            # Save report
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("\n".join(report))
            print_colored(f"[+] Report saved to {filename}", Colors.GREEN)
            print("\n" + "\n".join(report))
        
        elif choice == 0:
            if scanner.monitoring_active:
                scanner.stop_monitoring()
            print_colored("Exiting...", Colors.YELLOW)
            break
        else:
            print_colored("Invalid option", Colors.RED)
        
        input("\nPress Enter to continue...")

# ================================================================
# MAIN CLI MODE
# ================================================================
def main_cli():
    parser = argparse.ArgumentParser(description='Network Security Scanner v0.3.0')
    parser.add_argument('-t', '--target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--scan-type', choices=['quick', 'full', 'stealth'], default='quick')
    parser.add_argument('--monitor', action='store_true', help='Enable continuous monitoring')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval')
    parser.add_argument('--ping-sweep', action='store_true', help='Perform ping sweep')
    parser.add_argument('--sniff', action='store_true', help='Start packet sniffer')
    parser.add_argument('--sniff-count', type=int, default=100, help='Packets to capture')
    parser.add_argument('--bandwidth', action='store_true', help='Monitor bandwidth')
    parser.add_argument('--vulnerability-scan', action='store_true', help='Scan for vulnerabilities')
    parser.add_argument('--web-scan', help='Scan web application')
    parser.add_argument('--wifi-scan', action='store_true', help='Scan WiFi networks')
    parser.add_argument('--arp-monitor', action='store_true', help='Monitor ARP spoofing')
    parser.add_argument('--cert-check', help='Check SSL certificate')
    parser.add_argument('--dns-enum', help='Enumerate DNS records')
    parser.add_argument('--trace', help='Trace route to target')
    parser.add_argument('--export', action='store_true', help='Export results')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bars')
    
    args = parser.parse_args()
    scanner = NetworkScanner()
    
    # Handle each feature
    if args.ping_sweep:
        results = scanner.ping_sweep(show_progress=not args.no_progress)
        if args.output:
            scanner.export_results(results, args.output)
        return
    
    if args.sniff:
        scanner.packet_sniffer.sniff_packets(count=args.sniff_count)
        stats = scanner.packet_sniffer.get_statistics()
        print(f"\n[Sniffer Stats]")
        print(f"  Packets: {stats['total_packets']}")
        print(f"  HTTP: {stats['http_requests']}")
        print(f"  Credentials: {stats['credentials_found']}")
        return
    
    if args.bandwidth:
        scanner.bandwidth_monitor.monitor_bandwidth()
        stats = scanner.bandwidth_monitor.get_stats()
        if stats:
            print(f"\nAvg Upload: {stats['avg_upload']:.2f} Mbps")
            print(f"Avg Download: {stats['avg_download']:.2f} Mbps")
        return
    
    if args.wifi_scan:
        scanner.wifi_scanner.scan_wifi()
        return
    
    if args.arp_monitor:
        scanner.arp_monitor.monitor_arp()
        stats = scanner.arp_monitor.get_statistics()
        print(f"\nAttacks detected: {stats['attacks_detected']}")
        return
    
    if args.cert_check:
        hostname = args.cert_check
        scanner.cert_analyzer.analyze_certificate(hostname)
        return
    
    if args.dns_enum:
        scanner.dns_enum.enumerate(args.dns_enum)
        print(scanner.dns_enum.get_report())
        return
    
    if args.trace:
        scanner.topology_mapper.trace_route(args.trace)
        return
    
    if args.web_scan:
        scanner.web_scanner.scan_web_app(args.web_scan)
        return
    
    if args.vulnerability_scan and args.target:
        open_ports = scanner.port_scan(args.target, show_progress=not args.no_progress)
        if open_ports:
            scanner.vulnerability_scanner.check_vulnerabilities(args.target, open_ports)
            print(scanner.vulnerability_scanner.get_vulnerability_report())
        return
    
    # Default: target scan
    if args.target:
        if args.scan_type == 'quick':
            scanner.port_scan(args.target, show_progress=not args.no_progress)
        elif args.scan_type == 'full':
            devices = scanner.scan_devices(show_progress=not args.no_progress)
            scanner.print_table(devices)
            if args.export or args.output:
                scanner.export_results(devices, args.output)
        elif args.scan_type == 'stealth':
            scanner.port_scan(args.target, start_port=1, end_port=1024, 
                            timeout=0.5, max_workers=50, show_progress=not args.no_progress)
        return
    
    # If no arguments, run interactive
    main_interactive()

# ================================================================
# MAIN ENTRY POINT
# ================================================================
def signal_handler(sig, frame):
    print_colored("\n\n[*] Interrupted by user", Colors.YELLOW)
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    # Install required packages if missing
    try:
        import scapy
        import paramiko
        import ldap3
        import requests
        import psutil
        import OpenSSL
        from tqdm import tqdm
    except ImportError as e:
        print_colored("[!] Missing required packages. Installing...", Colors.YELLOW)
        packages = ['scapy', 'paramiko', 'ldap3', 'requests', 'psutil', 'pyOpenSSL', 'tqdm', 'dnspython']
        for pkg in packages:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg])
        print_colored("[+] Packages installed. Please restart the script.", Colors.GREEN)
        sys.exit(0)
    
    if len(sys.argv) > 1:
        main_cli()
    else:
        main_interactive()

if __name__ == "__main__":
    main()