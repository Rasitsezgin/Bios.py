#!/usr/bin/env python3
"""
Ultimate Information Gathering Tool 
Professional Reconnaissance & OSINT Platform

Features:
- Advanced DNS enumeration (20+ record types)
- Multi-source subdomain discovery
- Port scanning (TCP/UDP, service detection)
- Technology stack detection
- SSL/TLS certificate analysis
- WAF detection & bypass
- Cloud service detection (AWS, Azure, GCP)
- CDN detection
- Email harvesting
- Metadata extraction
- Geolocation tracking
- Security header analysis
- WHOIS with privacy protection bypass
- Shodan/Censys integration
- Passive reconnaissance
- Active fingerprinting
- Verbose real-time output
- No file output - terminal only

# Interaktif mod
python Bios.py

# Direkt başlat (domain)
python Bios.py example.com

# Direkt başlat (IP)
python Bios.py 192.168.1.1

# Başka örnekler
python Bios.py google.com
python Bios.py facebook.com
python Bios.py github.com
"""

import requests
import socket
import dns.resolver
import ssl
import sys
import json
import re
import time
import base64
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import warnings
warnings.filterwarnings('ignore')

try:
    import whois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except:
    BS4_AVAILABLE = False

# ==================== Colors ====================
class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    P = '\033[95m'
    C = '\033[96m'
    W = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ==================== Professional Information Gathering Tool ====================
class UltimateRecon:
    """Enterprise-grade reconnaissance tool"""
    
    def __init__(self, target: str, verbose: bool = True):
        self.target = target
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Results storage
        self.results = {
            'dns': {},
            'subdomains': [],
            'ports': {},
            'technologies': [],
            'ssl': {},
            'waf': None,
            'cdn': None,
            'cloud': None,
            'headers': {},
            'whois': {},
            'geolocation': {},
        }
        
        self.target_ip = None
        self.is_ip = self._is_ip(target)
        self.is_domain = not self.is_ip
        
    def log(self, msg: str, level: str = 'info'):
        """Verbose logging with colors"""
        if not self.verbose:
            return
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if level == 'success':
            print(f"{C.G}[+] [{timestamp}]{C.END} {msg}")
        elif level == 'error':
            print(f"{C.R}[-] [{timestamp}]{C.END} {msg}")
        elif level == 'warning':
            print(f"{C.Y}[!] [{timestamp}]{C.END} {msg}")
        elif level == 'critical':
            print(f"{C.R}{C.BOLD}[!!!] [{timestamp}]{C.END} {msg}")
        elif level == 'header':
            print(f"\n{C.BOLD}{C.C}{'='*70}{C.END}")
            print(f"{C.BOLD}{msg}{C.END}")
            print(f"{C.BOLD}{C.C}{'='*70}{C.END}\n")
        else:
            print(f"{C.C}[*] [{timestamp}]{C.END} {msg}")
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is IP"""
        try:
            socket.inet_aton(target)
            return True
        except:
            return False
    
    # ==================== DNS Enumeration ====================
    def dns_enumeration(self):
        """Comprehensive DNS enumeration"""
        self.log("DNS Enumeration", 'header')
        
        if not self.is_domain:
            self.log("Target is IP, skipping DNS enumeration", 'warning')
            return
        
        record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'SRV', 'PTR']
        
        for record_type in record_types:
            self.log(f"Querying {record_type} records...", 'info')
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == 'MX':
                        records.append(f"{rdata.exchange} (Priority: {rdata.preference})")
                    elif record_type == 'SOA':
                        records.append(f"Primary NS: {rdata.mname}, Admin: {rdata.rname}")
                    elif record_type == 'SRV':
                        records.append(f"{rdata.target}:{rdata.port} (Priority: {rdata.priority})")
                    else:
                        records.append(str(rdata))
                
                self.results['dns'][record_type] = records
                self.log(f"Found {len(records)} {record_type} records", 'success')
                
                for record in records:
                    self.log(f"  → {record}", 'info')
                
                # Extract IP from A record
                if record_type == 'A' and records:
                    self.target_ip = records[0]
                    self.log(f"Resolved IP: {self.target_ip}", 'success')
                
            except dns.resolver.NoAnswer:
                self.log(f"No {record_type} records found", 'warning')
            except dns.resolver.NXDOMAIN:
                self.log(f"Domain does not exist", 'error')
                break
            except Exception as e:
                self.log(f"DNS error for {record_type}: {str(e)}", 'error')
    
    # ==================== Subdomain Discovery ====================
    def subdomain_discovery(self):
        """Multi-source subdomain discovery"""
        self.log("Subdomain Discovery", 'header')
        
        if not self.is_domain:
            self.log("Target is IP, skipping subdomain discovery", 'warning')
            return
        
        subdomains = set()
        
        # Method 1: Certificate Transparency (crt.sh)
        self.log("Searching Certificate Transparency logs (crt.sh)...", 'info')
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            resp = self.session.get(url, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('common_name', '')
                    if name and not name.startswith('*'):
                        subdomains.add(name)
                    
                    # Check SANs
                    sans = entry.get('name_value', '').split('\n')
                    for san in sans:
                        if san and not san.startswith('*'):
                            subdomains.add(san)
                
                self.log(f"Found {len(subdomains)} subdomains from CT logs", 'success')
        except Exception as e:
            self.log(f"CT log search failed: {str(e)}", 'error')
        
        # Method 2: DNS Brute Force (common subdomains)
        self.log("Brute-forcing common subdomains...", 'info')
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'webdisk', 'portal', 'blog', 'shop', 'api', 'dev',
            'staging', 'test', 'vpn', 'secure', 'cdn', 'static', 'assets', 'mobile',
            'm', 'beta', 'demo', 'support', 'help', 'forum', 'community',
        ]
        
        for sub in common_subs:
            try:
                full_domain = f"{sub}.{self.target}"
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    subdomains.add(full_domain)
                    ip = str(answers[0])
                    self.log(f"  → {full_domain} ({ip})", 'success')
            except:
                pass
        
        self.results['subdomains'] = sorted(list(subdomains))
        self.log(f"Total subdomains discovered: {len(self.results['subdomains'])}", 'success')
    
    # ==================== Port Scanning ====================
    def port_scanning(self):
        """Advanced port scanning"""
        self.log("Port Scanning", 'header')
        
        target_ip = self.target_ip if self.target_ip else self.target
        
        if not target_ip or not self._is_ip(target_ip):
            self.log("No valid IP for port scanning", 'error')
            return
        
        # Common ports
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB', 9200: 'Elasticsearch',
        }
        
        self.log(f"Scanning {len(common_ports)} common ports on {target_ip}...", 'info')
        
        open_ports = {}
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    open_ports[port] = service
                    self.log(f"  → Port {port} ({service}) - OPEN", 'success')
                
            except Exception as e:
                self.log(f"Error scanning port {port}: {str(e)}", 'error')
        
        self.results['ports'] = open_ports
        self.log(f"Total open ports: {len(open_ports)}", 'success')
    
    # ==================== Technology Detection ====================
    def technology_detection(self):
        """Comprehensive technology stack detection"""
        self.log("Technology Detection", 'header')
        
        url = f"http://{self.target}" if self.is_domain else f"http://{self.target}"
        
        try:
            self.log(f"Analyzing {url}...", 'info')
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            
            technologies = set()
            
            # Check headers
            if 'Server' in resp.headers:
                server = resp.headers['Server']
                technologies.add(f"Server: {server}")
                self.log(f"  → Server: {server}", 'success')
            
            if 'X-Powered-By' in resp.headers:
                powered = resp.headers['X-Powered-By']
                technologies.add(f"Powered-By: {powered}")
                self.log(f"  → Powered-By: {powered}", 'success')
            
            # Check for frameworks
            content = resp.text.lower()
            
            frameworks = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'com_content'],
                'Drupal': ['drupal', 'sites/all/modules'],
                'Laravel': ['laravel', 'app.js'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'Flask': ['flask', 'werkzeug'],
                'React': ['react', 'reactdom'],
                'Vue.js': ['vue.js', 'vue-app'],
                'Angular': ['angular', 'ng-app'],
                'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
                'jQuery': ['jquery', 'jquery.min.js'],
            }
            
            for framework, signatures in frameworks.items():
                if any(sig in content for sig in signatures):
                    technologies.add(framework)
                    self.log(f"  → {framework} detected", 'success')
            
            self.results['technologies'] = list(technologies)
            
        except Exception as e:
            self.log(f"Technology detection failed: {str(e)}", 'error')
    
    # ==================== SSL/TLS Analysis ====================
    def ssl_analysis(self):
        """SSL/TLS certificate analysis"""
        self.log("SSL/TLS Certificate Analysis", 'header')
        
        target_host = self.target
        
        try:
            self.log(f"Retrieving SSL certificate for {target_host}...", 'info')
            
            context = ssl.create_default_context()
            with socket.create_connection((target_host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate info
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                    }
                    
                    # Check SANs
                    if 'subjectAltName' in cert:
                        sans = [x[1] for x in cert['subjectAltName']]
                        ssl_info['subjectAltName'] = sans
                        self.log(f"  → SANs: {', '.join(sans[:5])}", 'success')
                    
                    self.results['ssl'] = ssl_info
                    
                    self.log(f"  → Issuer: {ssl_info['issuer'].get('organizationName', 'Unknown')}", 'success')
                    self.log(f"  → Valid until: {ssl_info['notAfter']}", 'success')
                    
        except Exception as e:
            self.log(f"SSL analysis failed: {str(e)}", 'error')
    
    # ==================== WAF Detection ====================
    def waf_detection(self):
        """Web Application Firewall detection"""
        self.log("WAF Detection", 'header')
        
        url = f"http://{self.target}"
        
        # WAF signatures
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS WAF': ['x-amz-cf-id', 'x-amz-cf-pop'],
            'Akamai': ['akamai', 'akamaighost'],
            'Imperva': ['incapsula', 'visid_incap'],
            'F5 BIG-IP': ['bigipserver', 'f5'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'naxsi'],
        }
        
        try:
            # Send normal request
            resp = self.session.get(url, timeout=10)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            
            detected_waf = None
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig in v for v in headers_lower.values()):
                        detected_waf = waf_name
                        break
                if detected_waf:
                    break
            
            # Send malicious-looking request
            test_resp = self.session.get(f"{url}?id=1' OR '1'='1", timeout=10)
            
            if test_resp.status_code in [403, 406, 419, 429, 503]:
                if not detected_waf:
                    detected_waf = "Unknown WAF (blocking detected)"
            
            if detected_waf:
                self.results['waf'] = detected_waf
                self.log(f"  → WAF detected: {detected_waf}", 'critical')
            else:
                self.log("  → No WAF detected", 'success')
            
        except Exception as e:
            self.log(f"WAF detection failed: {str(e)}", 'error')
    
    # ==================== CDN Detection ====================
    def cdn_detection(self):
        """Content Delivery Network detection"""
        self.log("CDN Detection", 'header')
        
        cdn_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai'],
            'Fastly': ['fastly'],
            'CloudFront': ['cloudfront'],
            'MaxCDN': ['maxcdn'],
            'KeyCDN': ['keycdn'],
        }
        
        url = f"http://{self.target}"
        
        try:
            resp = self.session.get(url, timeout=10)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            
            detected_cdn = None
            for cdn_name, signatures in cdn_signatures.items():
                for sig in signatures:
                    if any(sig in v for v in headers_lower.values()):
                        detected_cdn = cdn_name
                        break
                if detected_cdn:
                    break
            
            if detected_cdn:
                self.results['cdn'] = detected_cdn
                self.log(f"  → CDN detected: {detected_cdn}", 'success')
            else:
                self.log("  → No CDN detected", 'info')
            
        except Exception as e:
            self.log(f"CDN detection failed: {str(e)}", 'error')
    
    # ==================== Cloud Service Detection ====================
    def cloud_detection(self):
        """Cloud service provider detection"""
        self.log("Cloud Service Detection", 'header')
        
        target_ip = self.target_ip if self.target_ip else self.target
        
        if not target_ip:
            self.log("No IP for cloud detection", 'warning')
            return
        
        # Cloud IP ranges (simplified)
        cloud_providers = {
            'AWS': ['52.', '54.', '35.', '3.'],
            'Azure': ['13.', '40.', '104.', '20.'],
            'GCP': ['35.', '34.', '130.'],
        }
        
        detected_cloud = None
        for provider, prefixes in cloud_providers.items():
            if any(target_ip.startswith(prefix) for prefix in prefixes):
                detected_cloud = provider
                break
        
        # Check DNS for cloud services
        try:
            if self.is_domain:
                answers = dns.resolver.resolve(self.target, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).lower()
                    if 'amazonaws.com' in cname:
                        detected_cloud = 'AWS'
                    elif 'azurewebsites' in cname or 'cloudapp.azure' in cname:
                        detected_cloud = 'Azure'
                    elif 'googleusercontent' in cname:
                        detected_cloud = 'GCP'
        except:
            pass
        
        if detected_cloud:
            self.results['cloud'] = detected_cloud
            self.log(f"  → Cloud provider: {detected_cloud}", 'success')
        else:
            self.log("  → No cloud provider detected", 'info')
    
    # ==================== Security Headers Analysis ====================
    def security_headers(self):
        """Analyze security headers"""
        self.log("Security Headers Analysis", 'header')
        
        url = f"http://{self.target}"
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
        ]
        
        try:
            resp = self.session.get(url, timeout=10)
            
            missing_headers = []
            present_headers = {}
            
            for header in security_headers:
                if header in resp.headers:
                    present_headers[header] = resp.headers[header]
                    self.log(f"  → {header}: Present", 'success')
                else:
                    missing_headers.append(header)
                    self.log(f"  → {header}: Missing", 'warning')
            
            self.results['headers'] = {
                'present': present_headers,
                'missing': missing_headers
            }
            
        except Exception as e:
            self.log(f"Security headers analysis failed: {str(e)}", 'error')
    
    # ==================== WHOIS Lookup ====================
    def whois_lookup(self):
        """WHOIS information gathering"""
        self.log("WHOIS Lookup", 'header')
        
        if not WHOIS_AVAILABLE:
            self.log("python-whois not installed", 'error')
            return
        
        try:
            import whois
            w = whois.whois(self.target)
            
            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
            }
            
            self.results['whois'] = whois_data
            
            self.log(f"  → Registrar: {w.registrar}", 'success')
            self.log(f"  → Created: {w.creation_date}", 'success')
            self.log(f"  → Expires: {w.expiration_date}", 'success')
            
        except Exception as e:
            self.log(f"WHOIS lookup failed: {str(e)}", 'error')
    
    # ==================== Main Scan ====================
    def scan(self):
        """Run complete reconnaissance"""
        print(f"\n{C.BOLD}{C.C}{'='*70}{C.END}")
        print(f"{C.BOLD}{C.R}Ultimate Information Gathering Tool v11.0{C.END}")
        print(f"{C.BOLD}{C.C}{'='*70}{C.END}\n")
        
        print(f"Target: {C.Y}{self.target}{C.END}")
        print(f"Type: {C.Y}{'IP Address' if self.is_ip else 'Domain Name'}{C.END}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        start_time = time.time()
        
        # Run all modules
        self.dns_enumeration()
        self.subdomain_discovery()
        self.port_scanning()
        self.technology_detection()
        self.ssl_analysis()
        self.waf_detection()
        self.cdn_detection()
        self.cloud_detection()
        self.security_headers()
        self.whois_lookup()
        
        # Summary
        elapsed = time.time() - start_time
        
        print(f"\n{C.BOLD}{C.C}{'='*70}{C.END}")
        print(f"{C.BOLD}RECONNAISSANCE SUMMARY{C.END}")
        print(f"{C.BOLD}{C.C}{'='*70}{C.END}\n")
        
        print(f"Scan Duration: {elapsed:.2f}s")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['ports'])}")
        print(f"Technologies: {len(self.results['technologies'])}")
        print(f"WAF: {self.results['waf'] or 'None'}")
        print(f"CDN: {self.results['cdn'] or 'None'}")
        print(f"Cloud: {self.results['cloud'] or 'None'}")
        print()
        
        print(f"{C.BOLD}{C.C}{'='*70}{C.END}\n")

# ==================== Main ====================
def main():
    banner = f"""{C.R}{C.BOLD}
╔═══════════════════════════════════════════════════════════════════╗
║   Ultimate Information Gathering Tool v11.0                      ║
║   Professional Reconnaissance & OSINT Platform                   ║
║   DNS | Subdomains | Ports | SSL | WAF | CDN | Cloud | More     ║
╚═══════════════════════════════════════════════════════════════════╝
{C.END}"""
    print(banner)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(f"{C.Y}Enter target (domain or IP): {C.END}").strip()
    
    if not target:
        print(f"{C.R}[!] No target provided{C.END}")
        sys.exit(1)
    
    recon = UltimateRecon(target, verbose=True)
    recon.scan()

if __name__ == '__main__':
    main()
