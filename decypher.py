#!/usr/bin/env python3
"""
Decypher - Advanced Penetration Testing Framework v2.0
Professional Security Assessment Tool
For AUTHORIZED testing only
"""

import socket
import argparse
import sys
import json
import requests
import threading
import time
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, quote
import ssl
from collections import defaultdict
import warnings
import subprocess
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings
warnings.filterwarnings('ignore')
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class InteractiveGuide:
    """Interactive step-by-step pentesting guide"""
    
    def __init__(self):
        self.steps_completed = []
        self.findings = []
    
    def print_step(self, step_num, title, description):
        """Print a guided step"""
        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.YELLOW}STEP {step_num}: {title}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(f"\n{description}\n")
    
    def wait_for_user(self, prompt="Press Enter to continue..."):
        """Wait for user input"""
        input(f"{Colors.GREEN}{prompt}{Colors.END}")
    
    def explain_phase(self, phase_name, what_it_does, why_important):
        """Explain what a phase does"""
        print(f"\n{Colors.BOLD}📚 What is {phase_name}?{Colors.END}")
        print(f"   {what_it_does}")
        print(f"\n{Colors.BOLD}💡 Why is this important?{Colors.END}")
        print(f"   {why_important}\n")
    
    def show_tip(self, tip):
        """Show a pentesting tip"""
        print(f"\n{Colors.YELLOW}💡 TIP: {tip}{Colors.END}\n")
    
    def show_warning(self, warning):
        """Show a warning"""
        print(f"\n{Colors.RED}⚠️  WARNING: {warning}{Colors.END}\n")
    
    def next_steps_suggestion(self, suggestions):
        """Suggest next steps based on findings"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}📋 Suggested Next Steps:{Colors.END}")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"   {i}. {suggestion}")
        print()

class AdvancedFeatures:
    """Advanced pentesting features"""
    
    @staticmethod
    def whois_lookup(domain):
        """Perform WHOIS lookup"""
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
            return result.stdout
        except:
            return None
    
    @staticmethod
    def dns_records(domain):
        """Get DNS records"""
        records = {'A': [], 'MX': [], 'NS': [], 'TXT': []}
        
        try:
            # A records
            import socket
            ip = socket.gethostbyname(domain)
            records['A'].append(ip)
        except:
            pass
        
        return records
    
    @staticmethod
    def check_waf(url):
        """Detect Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'Akamai': ['akamai', 'akamaihd'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'F5 BIG-IP': ['BigIP', 'F5', 'TS01'],
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            detected_wafs = []
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in str(response.headers).lower() or sig.lower() in response.text.lower():
                        detected_wafs.append(waf_name)
                        break
            
            return detected_wafs
        except:
            return []
    
    @staticmethod
    def robots_txt_analysis(base_url):
        """Analyze robots.txt for hidden directories"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = requests.get(robots_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                disallowed = re.findall(r'Disallow: (.+)', response.text)
                return [d.strip() for d in disallowed]
        except:
            pass
        return []
    
    @staticmethod
    def sitemap_analysis(base_url):
        """Analyze sitemap.xml"""
        sitemaps = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap-index.xml']
        found_urls = []
        
        for sitemap in sitemaps:
            try:
                sitemap_url = urljoin(base_url, sitemap)
                response = requests.get(sitemap_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    urls = re.findall(r'<loc>(.+?)</loc>', response.text)
                    found_urls.extend(urls)
            except:
                continue
        
        return found_urls
    
    @staticmethod
    def check_security_txt(base_url):
        """Check for security.txt"""
        locations = ['/.well-known/security.txt', '/security.txt']
        
        for loc in locations:
            try:
                url = urljoin(base_url, loc)
                response = requests.get(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    return {'found': True, 'location': loc, 'content': response.text}
            except:
                continue
        
        return {'found': False}
    
    @staticmethod
    def detect_cms_version(url, cms_type):
        """Detect specific CMS version"""
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            if cms_type == 'WordPress':
                # Check generator meta tag
                version = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', response.text)
                if version:
                    return version.group(1)
                
                # Check readme
                readme_url = urljoin(url, '/readme.html')
                readme_resp = requests.get(readme_url, timeout=5, verify=False)
                version = re.search(r'Version ([0-9.]+)', readme_resp.text)
                if version:
                    return version.group(1)
            
            elif cms_type == 'Joomla':
                version = re.search(r'Joomla! ([0-9.]+)', response.text)
                if version:
                    return version.group(1)
            
        except:
            pass
        
        return None
    
    @staticmethod
    def cloud_detection(ip):
        """Detect if hosted on cloud platform"""
        cloud_ranges = {
            'AWS': ['18.', '52.', '54.', '3.'],
            'Google Cloud': ['35.', '34.'],
            'Azure': ['13.', '20.', '40.', '52.', '104.'],
            'DigitalOcean': ['104.', '134.', '137.', '138.', '142.', '143.', '147.', '159.', '161.', '162.', '164.', '165.', '167.', '178.', '188.', '206.', '207.'],
        }
        
        for cloud, prefixes in cloud_ranges.items():
            if any(ip.startswith(prefix) for prefix in prefixes):
                return cloud
        
        return 'Unknown/On-Premise'
    
    @staticmethod
    def check_http_trace(url):
        """Check if HTTP TRACE method is enabled"""
        try:
            parsed = urlparse(url)
            response = requests.request('TRACE', url, timeout=5, verify=False)
            
            if response.status_code == 200 and 'TRACE' in response.text:
                return True
        except:
            pass
        return False

class PenTestFramework:
    def __init__(self, target, aggressive=False, output_file=None, threads=10, timeout=10, guided=False):
        self.target = target
        self.aggressive = aggressive
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.guided = guided
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'technologies': {},
            'urls_discovered': 0,
            'parameters_found': 0,
            'open_ports': [],
            'subdomains': [],
            'email_addresses': [],
            'sensitive_files': [],
            'waf_detected': [],
            'cloud_provider': None,
            'cms_version': None
        }
        self.discovered_urls = set()
        self.parameters = defaultdict(list)
        self.vuln_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        self.start_time = time.time()
        self.guide = InteractiveGuide() if guided else None
        self.advanced = AdvancedFeatures()
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{'=' * 80}
  ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ 
  ██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗
  ██║  ██║█████╗  ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝
  ██║  ██║██╔══╝  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
  ██████╔╝███████╗╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║
  ╚═════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  Advanced Penetration Testing Framework v2.0                    
{'=' * 80}{Colors.END}

  {Colors.BOLD}Target:{Colors.END} {Colors.YELLOW}{self.target}{Colors.END}
  {Colors.BOLD}Mode:{Colors.END} {Colors.YELLOW}{'AGGRESSIVE' if self.aggressive else 'STANDARD'}{Colors.END}
  {Colors.BOLD}Threads:{Colors.END} {self.threads}
  {Colors.BOLD}Date:{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{Colors.RED}  ⚠️  ENSURE YOU HAVE WRITTEN AUTHORIZATION ⚠️{Colors.END}

{Colors.CYAN}{'=' * 80}{Colors.END}
"""
        print(banner)
    
    def print_phase(self, number, name):
        """Print phase header"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}╔{'═' * 78}╗{Colors.END}")
        print(f"{Colors.BOLD}{Colors.HEADER}║  PHASE {number}: {name.upper()}{' ' * (67 - len(name))}║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.HEADER}╚{'═' * 78}╝{Colors.END}\n")
    
    def print_section(self, name):
        """Print section header"""
        print(f"\n{Colors.CYAN}┌─ {name}{Colors.END}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Colors.GREEN}  ✓ {message}{Colors.END}")
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Colors.CYAN}  ℹ {message}{Colors.END}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Colors.YELLOW}  ⚠ {message}{Colors.END}")
    
    def print_vuln(self, severity, vuln_type, description):
        """Print vulnerability finding"""
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': '🔵'
        }
        colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MEDIUM': Colors.CYAN,
            'LOW': Colors.GREEN,
            'INFO': Colors.BLUE
        }
        
        icon = icons.get(severity, '•')
        color = colors.get(severity, Colors.END)
        
        print(f"\n{color}  {icon} [{severity}] {vuln_type}{Colors.END}")
        print(f"{color}     └─ {description}{Colors.END}")
        
        self.vuln_count[severity] += 1
    
    def log_vulnerability(self, severity, vuln_type, description, details=None):
        """Log vulnerability to results"""
        vuln = {
            'severity': severity,
            'type': vuln_type,
            'description': description,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results['vulnerabilities'].append(vuln)
        self.print_vuln(severity, vuln_type, description)
        
        if details:
            if details.get('cve'):
                print(f"{Colors.BLUE}     └─ CVE: {details['cve']}{Colors.END}")
            if details.get('remediation'):
                print(f"{Colors.GREEN}     └─ Fix: {details['remediation']}{Colors.END}")
            if details.get('tool_command'):
                print(f"{Colors.CYAN}     └─ Command: {details['tool_command']}{Colors.END}")
    
    def port_scan(self, start_port=1, end_port=1000):
        """Fast multi-threaded port scanner"""
        self.print_section("Port Scanning")
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        self.print_info(f"Scanning ports {start_port}-{end_port}...")
        
        with ThreadPoolExecutor(max_workers=self.threads * 10) as executor:
            futures = [executor.submit(scan_port, port) for port in range(start_port, end_port + 1)]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    
                    # Identify common services
                    services = {
                        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
                    }
                    service = services.get(result, 'Unknown')
                    
                    severity = 'HIGH' if result in [21, 23, 445, 3389] else 'MEDIUM' if result in [22, 3306, 5432] else 'INFO'
                    
                    self.print_info(f"Port {Colors.BOLD}{result}{Colors.END} open - {Colors.YELLOW}{service}{Colors.END}")
                    
                    if severity in ['HIGH', 'MEDIUM']:
                        self.log_vulnerability(
                            severity,
                            f'Open Port: {result}',
                            f'{service} service exposed',
                            {'remediation': f'Review if port {result} needs to be publicly accessible'}
                        )
        
        open_ports.sort()
        self.results['open_ports'] = open_ports
        self.print_success(f"Found {len(open_ports)} open ports")
        return open_ports
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        self.print_section("Subdomain Enumeration")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'dev', 'test', 'staging',
            'api', 'portal', 'vpn', 'remote', 'support', 'help', 'cdn', 'static',
            'assets', 'app', 'mobile', 'webmail', 'cpanel', 'cloud', 'secure'
        ]
        
        found_subdomains = []
        
        def check_subdomain(sub):
            try:
                subdomain = f"{sub}.{self.target}"
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        self.print_info(f"Testing common subdomains...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    self.print_info(f"Found: {Colors.BOLD}{Colors.GREEN}{result}{Colors.END}")
        
        self.results['subdomains'] = found_subdomains
        self.print_success(f"Found {len(found_subdomains)} subdomains")
        return found_subdomains
    
    def email_harvesting(self, url):
        """Harvest email addresses from website"""
        self.print_section("Email Harvesting")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Email regex pattern
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = set(re.findall(email_pattern, response.text))
            
            # Filter out common false positives
            emails = {e for e in emails if not any(x in e.lower() for x in ['example.com', 'test.com', 'domain.com'])}
            
            self.results['email_addresses'] = list(emails)
            
            for email in emails:
                self.print_info(f"Found: {Colors.BOLD}{email}{Colors.END}")
                
                if len(emails) > 5:
                    self.log_vulnerability(
                        'LOW',
                        'Email Exposure',
                        f'Multiple email addresses exposed ({len(emails)} found)',
                        {'remediation': 'Consider obfuscating email addresses to prevent spam'}
                    )
                    break
            
            self.print_success(f"Found {len(emails)} email addresses")
            
        except Exception as e:
            self.print_warning(f"Email harvesting failed: {str(e)}")
    
    def sensitive_file_detection(self, base_url):
        """Detect sensitive files and directories"""
        self.print_section("Sensitive File Detection")
        
        sensitive_paths = [
            '/.git/config', '/.env', '/.env.local', '/.env.production',
            '/backup.zip', '/backup.sql', '/database.sql', '/db_backup.sql',
            '/.htaccess', '/.htpasswd', '/web.config', '/robots.txt',
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/config.php', '/configuration.php', '/settings.php',
            '/.git/HEAD', '/.svn/entries', '/.DS_Store',
            '/composer.json', '/package.json', '/yarn.lock',
            '/phpinfo.php', '/info.php', '/test.php',
            '/.well-known/security.txt', '/security.txt',
            '/sitemap.xml', '/crossdomain.xml',
            '/server-status', '/server-info',
            '/.gitlab-ci.yml', '/.travis.yml', '/Dockerfile'
        ]
        
        found_files = []
        
        def check_path(path):
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return (path, response.status_code)
            except:
                pass
            return None
        
        self.print_info(f"Checking {len(sensitive_paths)} common paths...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_path, path) for path in sensitive_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status_code = result
                    found_files.append({'path': path, 'status': status_code})
                    
                    severity = 'HIGH' if status_code == 200 else 'MEDIUM'
                    color = Colors.RED if status_code == 200 else Colors.YELLOW
                    
                    self.print_info(f"{color}{path}{Colors.END} - Status: {status_code}")
                    
                    if status_code == 200:
                        self.log_vulnerability(
                            severity,
                            'Sensitive File Exposed',
                            f'{path} is publicly accessible',
                            {'remediation': f'Restrict access to {path} or remove if not needed'}
                        )
        
        self.results['sensitive_files'] = found_files
        self.print_success(f"Found {len(found_files)} accessible sensitive paths")
    
    def directory_bruteforce(self, base_url):
        """Brute force common directories"""
        self.print_section("Directory Discovery")
        
        common_dirs = [
            '/admin', '/administrator', '/api', '/app', '/assets', '/backup',
            '/bin', '/cache', '/config', '/css', '/data', '/database', '/db',
            '/dev', '/docs', '/download', '/files', '/images', '/img', '/include',
            '/includes', '/js', '/lib', '/library', '/logs', '/media', '/old',
            '/private', '/public', '/scripts', '/source', '/src', '/static',
            '/temp', '/test', '/tmp', '/upload', '/uploads', '/user', '/users',
            '/var', '/vendor', '/wp-content', '/wp-includes'
        ]
        
        found_dirs = []
        
        def check_dir(directory):
            try:
                url = urljoin(base_url, directory)
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return (directory, response.status_code)
            except:
                pass
            return None
        
        self.print_info(f"Checking {len(common_dirs)} common directories...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_dir, d) for d in common_dirs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    directory, status_code = result
                    found_dirs.append({'directory': directory, 'status': status_code})
                    
                    if status_code == 200:
                        self.print_info(f"{Colors.GREEN}{directory}{Colors.END} - Status: {status_code}")
        
        self.print_success(f"Found {len(found_dirs)} accessible directories")
        return found_dirs
    
    def technology_detection(self, url):
        """Detect web technologies with version detection"""
        self.print_section("Technology Detection")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            # Server detection with version
            server = response.headers.get('Server', 'Unknown')
            self.results['technologies']['server'] = server
            self.print_info(f"Server: {Colors.BOLD}{server}{Colors.END}")
            
            # Check for outdated versions
            if 'Apache/2.4.49' in server or 'Apache/2.4.50' in server:
                self.log_vulnerability(
                    'CRITICAL',
                    'Vulnerable Apache Version',
                    'Apache version vulnerable to CVE-2021-41773 (Path Traversal)',
                    {'cve': 'CVE-2021-41773', 'remediation': 'Update Apache to latest version'}
                )
            
            # Powered by
            powered = response.headers.get('X-Powered-By')
            if powered:
                self.results['technologies']['powered_by'] = powered
                self.print_info(f"Powered by: {Colors.BOLD}{powered}{Colors.END}")
                self.log_vulnerability(
                    'LOW',
                    'Information Disclosure',
                    f'X-Powered-By header reveals: {powered}',
                    {'remediation': 'Remove X-Powered-By header'}
                )
            
            # Framework detection
            frameworks = {
                'Laravel': ['laravel_session', '_token'],
                'Django': ['csrfmiddlewaretoken', 'Django'],
                'Ruby on Rails': ['_session_id', 'csrf-token'],
                'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION'],
                'Spring': ['JSESSIONID', 'Spring Framework'],
                'Express.js': ['express', 'X-Powered-By: Express']
            }
            
            for framework, patterns in frameworks.items():
                if any(pattern in response.text or pattern in str(response.headers) for pattern in patterns):
                    self.results['technologies']['framework'] = framework
                    self.print_info(f"Framework: {Colors.BOLD}{Colors.CYAN}{framework}{Colors.END}")
                    break
            
            # CMS Detection with version
            if '/wp-content/' in response.text or '/wp-includes/' in response.text:
                self.results['technologies']['cms'] = 'WordPress'
                self.print_info(f"CMS: {Colors.BOLD}{Colors.YELLOW}WordPress{Colors.END}")
                
                # Try to get WordPress version
                version_match = re.search(r'wp-includes.*?ver=([\d.]+)', response.text)
                if version_match:
                    wp_version = version_match.group(1)
                    self.print_info(f"WordPress Version: {Colors.BOLD}{wp_version}{Colors.END}")
                
                self.log_vulnerability(
                    'MEDIUM',
                    'WordPress Detected',
                    'WordPress installation found - verify plugins and themes',
                    {'tool_command': f'wpscan --url {url} --enumerate vp,vt,u --api-token YOUR_TOKEN'}
                )
            
            # JavaScript libraries with versions
            js_libs = {
                'jQuery': r'jquery[.-](\d+\.\d+\.\d+)',
                'React': r'react[.-](\d+\.\d+\.\d+)',
                'Angular': r'angular[.-](\d+\.\d+\.\d+)',
                'Vue.js': r'vue[.-](\d+\.\d+\.\d+)',
                'Bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
            }
            
            for lib, pattern in js_libs.items():
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    self.print_info(f"Library: {lib} v{version}")
                    
                    # Check for known vulnerable versions
                    if lib == 'jQuery' and version.startswith('1.'):
                        self.log_vulnerability(
                            'MEDIUM',
                            'Outdated jQuery',
                            f'jQuery {version} contains known XSS vulnerabilities',
                            {'remediation': 'Update jQuery to version 3.x or later'}
                        )
            
            self.print_success("Technology detection complete")
            
        except Exception as e:
            self.print_warning(f"Technology detection failed: {str(e)}")
    
    def cors_misconfiguration_check(self, url):
        """Check for CORS misconfigurations"""
        self.print_section("CORS Configuration Check")
        
        try:
            # Test with various origins
            test_origins = [
                'https://evil.com',
                'null',
                f'https://evil.{self.target}'
            ]
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao == origin or acao == '*':
                    severity = 'HIGH' if acac == 'true' else 'MEDIUM'
                    self.log_vulnerability(
                        severity,
                        'CORS Misconfiguration',
                        f'CORS allows origin: {origin}' + (' with credentials' if acac == 'true' else ''),
                        {'remediation': 'Implement strict CORS policy with whitelist of allowed origins'}
                    )
                    break
            else:
                self.print_success("CORS properly configured")
                
        except Exception as e:
            self.print_warning(f"CORS check failed: {str(e)}")
    
    def http_methods_check(self, url):
        """Check for dangerous HTTP methods"""
        self.print_section("HTTP Methods Check")
        
        try:
            response = self.session.options(url, timeout=self.timeout, verify=False)
            allowed_methods = response.headers.get('Allow', '')
            
            self.print_info(f"Allowed methods: {allowed_methods}")
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            found_dangerous = [m for m in dangerous_methods if m in allowed_methods.upper()]
            
            if found_dangerous:
                self.log_vulnerability(
                    'HIGH',
                    'Dangerous HTTP Methods',
                    f'Dangerous methods enabled: {", ".join(found_dangerous)}',
                    {'remediation': 'Disable unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT)'}
                )
            else:
                self.print_success("No dangerous HTTP methods enabled")
                
        except Exception as e:
            self.print_warning(f"HTTP methods check failed: {str(e)}")
    
    def ssl_tls_analysis(self, hostname):
        """Analyze SSL/TLS configuration"""
        self.print_section("SSL/TLS Analysis")
        
        try:
            # Test SSL/TLS protocols
            protocols = [
                ('SSLv2', ssl.PROTOCOL_SSLv23),
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('TLSv1.0', ssl.PROTOCOL_TLSv1),
                ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ]
            
            for protocol_name, protocol_constant in protocols:
                try:
                    context = ssl.SSLContext(protocol_constant)
                    with socket.create_connection((hostname, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            self.log_vulnerability(
                                'HIGH',
                                f'Weak Protocol: {protocol_name}',
                                f'{protocol_name} is enabled (deprecated and insecure)',
                                {'remediation': f'Disable {protocol_name}, use TLS 1.2 or higher'}
                            )
                except:
                    self.print_info(f"{protocol_name}: Disabled (good)")
            
            # Check certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        self.log_vulnerability(
                            'CRITICAL',
                            'Expired Certificate',
                            f'SSL certificate expired {abs(days_until_expiry)} days ago',
                            {'remediation': 'Renew SSL certificate immediately'}
                        )
                    elif days_until_expiry < 30:
                        self.log_vulnerability(
                            'MEDIUM',
                            'Certificate Expiring Soon',
                            f'SSL certificate expires in {days_until_expiry} days',
                            {'remediation': 'Renew SSL certificate'}
                        )
                    else:
                        self.print_success(f"Certificate valid until {not_after.strftime('%Y-%m-%d')}")
                    
        except ssl.SSLError as e:
            self.log_vulnerability(
                'HIGH',
                'SSL/TLS Error',
                f'SSL/TLS configuration error: {str(e)}',
                {'remediation': 'Fix SSL/TLS configuration'}
            )
        except Exception as e:
            self.print_warning(f"SSL/TLS analysis failed: {str(e)}")
    
    def network_mapping(self):
        """Advanced network mapping and host discovery"""
        self.print_section("Network Mapping & Host Discovery")
        
        # Try to resolve target
        try:
            target_ip = socket.gethostbyname(self.target)
            self.print_info(f"Target IP: {Colors.BOLD}{target_ip}{Colors.END}")
            self.results['target_ip'] = target_ip
            
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(target_ip)[0]
                if hostname != self.target:
                    self.print_info(f"Reverse DNS: {Colors.BOLD}{hostname}{Colors.END}")
                    self.results['reverse_dns'] = hostname
            except:
                pass
            
            # Check if target is in private IP range
            octets = target_ip.split('.')
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            is_private = False
            network_class = "Unknown"
            
            if first_octet == 10:
                is_private = True
                network_class = "Class A Private (10.0.0.0/8)"
            elif first_octet == 172 and 16 <= second_octet <= 31:
                is_private = True
                network_class = "Class B Private (172.16.0.0/12)"
            elif first_octet == 192 and second_octet == 168:
                is_private = True
                network_class = "Class C Private (192.168.0.0/16)"
            
            if is_private:
                self.print_info(f"Network Class: {Colors.YELLOW}{network_class}{Colors.END}")
                self.results['network_class'] = network_class
                
                # Scan local network if private
                if self.aggressive:
                    self.print_info("Scanning local network range...")
                    self.scan_local_network(target_ip)
            else:
                self.print_info(f"Public IP detected")
                self.results['network_class'] = "Public Internet"
            
        except Exception as e:
            self.print_warning(f"Network mapping failed: {str(e)}")
    
    def scan_local_network(self, base_ip):
        """Scan local network for active hosts"""
        self.print_section("Local Network Host Discovery")
        
        # Get network prefix
        octets = base_ip.split('.')
        network_prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
        
        active_hosts = []
        
        def ping_host(host_ip):
            try:
                # Try to connect to port 80 or 443 (faster than ICMP)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host_ip, 80))
                sock.close()
                if result == 0:
                    return host_ip
                
                # Try port 443
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host_ip, 443))
                sock.close()
                if result == 0:
                    return host_ip
            except:
                pass
            return None
        
        self.print_info(f"Scanning network range {network_prefix}.1-254...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_host, f"{network_prefix}.{i}") for i in range(1, 255)]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    self.print_info(f"{Colors.GREEN}Active host found: {result}{Colors.END}")
        
        self.results['active_hosts'] = active_hosts
        self.print_success(f"Found {len(active_hosts)} active hosts on local network")
    
    def os_fingerprinting(self, target_ip):
        """Basic OS fingerprinting based on TTL and open ports"""
        self.print_section("OS Fingerprinting")
        
        try:
            # TTL-based detection
            import platform
            if platform.system().lower() == 'windows':
                ping_cmd = ['ping', '-n', '1', target_ip]
            else:
                ping_cmd = ['ping', '-c', '1', target_ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
            
            # Extract TTL
            ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                self.print_info(f"TTL: {ttl}")
                
                # OS detection based on TTL
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                elif ttl <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Network Device/Router"
                
                self.print_info(f"Likely OS: {Colors.BOLD}{Colors.YELLOW}{os_guess}{Colors.END}")
                self.results['os_fingerprint'] = {'ttl': ttl, 'guess': os_guess}
            
            # Port-based OS detection
            open_ports = self.results.get('open_ports', [])
            if 3389 in open_ports:
                self.print_info("RDP detected - Likely Windows Server")
            if 22 in open_ports and 80 in open_ports:
                self.print_info("SSH + Web - Likely Linux Server")
            if 445 in open_ports:
                self.print_info("SMB detected - Windows/Samba")
                
        except Exception as e:
            self.print_warning(f"OS fingerprinting failed: {str(e)}")
    
    def service_version_detection(self):
        """Detect service versions on open ports"""
        self.print_section("Service Version Detection")
        
        open_ports = self.results.get('open_ports', [])
        
        for port in open_ports[:10]:  # Check first 10 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.results.get('target_ip', self.target), port))
                
                # Send generic probe
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if banner:
                    # Extract version info
                    version_match = re.search(r'Server: (.+)', banner)
                    if version_match:
                        version = version_match.group(1).strip()
                        self.print_info(f"Port {port}: {Colors.BOLD}{version}{Colors.END}")
                        
            except:
                continue
        
        self.print_success("Service version detection complete")
    
    def spider_urls(self, base_url, max_depth=2):
        """Spider and discover URLs"""
        self.print_section("Web Spidering")
        
        visited = set()
        to_visit = [(base_url, 0)]
        
        self.print_info("Crawling website...")
        
        while to_visit and len(visited) < 100:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                self.discovered_urls.add(url)
                
                # Extract parameters
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        self.parameters[param_name].append(url)
                
                # Find links
                links = re.findall(r'href=["\'](.*?)["\']', response.text)
                for link in links:
                    absolute_url = urljoin(url, link)
                    if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                        if absolute_url not in visited and len(to_visit) < 50:
                            to_visit.append((absolute_url, depth + 1))
                
            except:
                continue
        
        self.results['urls_discovered'] = len(self.discovered_urls)
        self.results['parameters_found'] = len(self.parameters)
        self.results['discovered_urls'] = sorted(list(self.discovered_urls))
        
        self.print_info(f"URLs discovered: {Colors.BOLD}{len(self.discovered_urls)}{Colors.END}")
        self.print_info(f"Parameters found: {Colors.BOLD}{len(self.parameters)}{Colors.END}")
        
        # Print discovered URLs
        print(f"\n{Colors.CYAN}  Discovered URLs:{Colors.END}")
        for idx, url in enumerate(sorted(self.discovered_urls)[:20], 1):
            # Highlight URLs with parameters
            if '?' in url:
                print(f"    {Colors.YELLOW}[{idx}] {url}{Colors.END}")
            else:
                print(f"    {Colors.BLUE}[{idx}] {url}{Colors.END}")
        
        if len(self.discovered_urls) > 20:
            print(f"    {Colors.CYAN}... and {len(self.discovered_urls) - 20} more URLs{Colors.END}")
        
        self.print_success("Spidering complete")
    
    def advanced_reconnaissance(self, url):
        """Advanced reconnaissance with additional checks"""
        self.print_section("Advanced Reconnaissance")
        
        if self.guided:
            self.guide.explain_phase(
                "Advanced Reconnaissance",
                "This phase goes beyond basic scanning to gather deep intelligence about the target.",
                "Understanding the target's infrastructure, protections, and configuration helps you plan more effective tests and avoid detection."
            )
            self.guide.wait_for_user()
        
        # WAF Detection
        if self.guided:
            self.guide.show_tip("Detecting Web Application Firewalls (WAFs) helps you understand what security measures are in place and adjust your testing approach.")
        
        wafs = self.advanced.check_waf(url)
        if wafs:
            self.results['waf_detected'] = wafs
            for waf in wafs:
                self.print_warning(f"WAF Detected: {Colors.BOLD}{waf}{Colors.END}")
                self.log_vulnerability(
                    'INFO',
                    f'WAF Detected: {waf}',
                    'Web Application Firewall is protecting this site',
                    {'remediation': f'Use evasion techniques or test from different IPs. WAF: {waf}'}
                )
        else:
            self.print_info("No WAF detected")
        
        # Cloud Detection
        target_ip = self.results.get('target_ip', self.target)
        cloud = self.advanced.cloud_detection(target_ip)
        self.results['cloud_provider'] = cloud
        self.print_info(f"Cloud/Hosting: {Colors.BOLD}{cloud}{Colors.END}")
        
        # Robots.txt Analysis
        if self.guided:
            self.guide.show_tip("robots.txt often reveals hidden directories and admin panels that developers don't want search engines to index.")
        
        robots_paths = self.advanced.robots_txt_analysis(url)
        if robots_paths:
            self.print_info(f"Found {len(robots_paths)} paths in robots.txt")
            for path in robots_paths[:10]:
                self.print_info(f"  Hidden path: {Colors.YELLOW}{path}{Colors.END}")
        
        # Sitemap Analysis
        sitemap_urls = self.advanced.sitemap_analysis(url)
        if sitemap_urls:
            self.print_info(f"Found {len(sitemap_urls)} URLs in sitemap.xml")
            for surl in sitemap_urls[:5]:
                self.discovered_urls.add(surl)
        
        # Security.txt Check
        security_txt = self.advanced.check_security_txt(url)
        if security_txt['found']:
            self.print_success(f"security.txt found at {security_txt['location']}")
            self.log_vulnerability(
                'INFO',
                'Security Contact Information',
                f'security.txt found - organization follows responsible disclosure',
                {'details': security_txt['content'][:200]}
            )
        
        # HTTP TRACE Check
        if self.advanced.check_http_trace(url):
            self.log_vulnerability(
                'MEDIUM',
                'HTTP TRACE Method Enabled',
                'TRACE method is enabled - potential XST vulnerability',
                {'remediation': 'Disable HTTP TRACE method in web server configuration'}
            )
        
        # CMS Version Detection
        if self.results['technologies'].get('cms'):
            cms_type = self.results['technologies']['cms']
            version = self.advanced.detect_cms_version(url, cms_type)
            if version:
                self.results['cms_version'] = version
                self.print_info(f"{cms_type} Version: {Colors.BOLD}{Colors.YELLOW}{version}{Colors.END}")
        
        if self.guided:
            self.guide.show_tip(f"WAFs detected: {len(wafs)}. Hosting: {cloud}. Use this info to plan your approach.")
            self.guide.wait_for_user("Ready to continue to next phase")
        
        self.print_success("Advanced reconnaissance complete")
    
    def web_fuzzing(self, base_url):
        """Advanced web fuzzing for parameters and endpoints"""
        self.print_section("Advanced Web Fuzzing")
        
        if self.guided:
            self.guide.explain_phase(
                "Web Fuzzing",
                "Fuzzing sends various inputs to discover hidden parameters, endpoints, and potential injection points.",
                "Finding hidden functionality and parameters is crucial - these are often less tested and more vulnerable."
            )
            self.guide.wait_for_user()
        
        # Parameter fuzzing
        common_params = [
            'id', 'user', 'account', 'page', 'edit', 'search', 'query',
            'debug', 'admin', 'test', 'file', 'path', 'url', 'redirect',
            'return', 'next', 'callback', 'data', 'action'
        ]
        
        self.print_info("Testing for hidden parameters...")
        
        found_params = []
        for param in common_params[:10]:  # Test first 10
            test_url = f"{base_url}?{param}=test"
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check if parameter affects response
                base_response = self.session.get(base_url, timeout=5, verify=False)
                if len(response.text) != len(base_response.text):
                    found_params.append(param)
                    self.print_info(f"Found parameter: {Colors.YELLOW}{param}{Colors.END}")
                    
            except:
                continue
        
        if found_params:
            self.log_vulnerability(
                'INFO',
                'Hidden Parameters Discovered',
                f'Found {len(found_params)} potentially interesting parameters',
                {'parameters': found_params}
            )
        
        if self.guided:
            self.guide.show_tip(f"Found {len(found_params)} parameters. These should all be tested for injection vulnerabilities.")
            self.guide.wait_for_user()
        
        self.print_success(f"Fuzzing complete - found {len(found_params)} parameters")
    
    def backup_file_scanner(self, base_url):
        """Scan for backup files"""
        self.print_section("Backup File Scanner")
        
        if self.guided:
            self.guide.explain_phase(
                "Backup File Scanner",
                "Searches for backup files that developers often forget to remove from production.",
                "Backup files can contain source code, credentials, and database dumps - critical security issues."
            )
        
        parsed = urlparse(base_url)
        base_path = parsed.path.rstrip('/') if parsed.path != '/' else ''
        
        backup_extensions = [
            '.bak', '.backup', '.old', '.save', '.copy', '_backup',
            '.tar.gz', '.zip', '.rar', '.7z', '~', '.swp'
        ]
        
        common_files = ['index', 'config', 'database', 'db', 'admin', 'backup', 'data']
        
        found_backups = []
        
        for filename in common_files[:5]:
            for ext in backup_extensions[:6]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/{filename}{ext}"
                try:
                    response = self.session.head(test_url, timeout=3, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        found_backups.append(test_url)
                        self.print_warning(f"Backup file found: {test_url}")
                        self.log_vulnerability(
                            'HIGH',
                            'Backup File Exposed',
                            f'Backup file accessible: {test_url}',
                            {'remediation': 'Remove all backup files from production'}
                        )
                except:
                    continue
        
        if not found_backups:
            self.print_success("No backup files found")
        
        if self.guided:
            self.guide.wait_for_user()
    
    def api_testing(self, base_url):
        """Advanced API security testing"""
        self.print_section("API Security Testing")
        
        if self.guided:
            self.guide.explain_phase(
                "API Security Testing",
                "Tests API endpoints for common security issues like broken authentication, excessive data exposure, and rate limiting.",
                "APIs often have different security controls than web interfaces and are frequent attack targets."
            )
        
        api_paths = ['/api', '/api/v1', '/api/v2', '/graphql', '/rest']
        
        for api_path in api_paths:
            api_url = urljoin(base_url, api_path)
            try:
                # Test unauthenticated access
                response = self.session.get(api_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    self.print_info(f"API endpoint accessible: {api_url}")
                    
                    # Check for excessive data exposure
                    try:
                        data = response.json()
                        if isinstance(data, (list, dict)):
                            if len(str(data)) > 5000:
                                self.log_vulnerability(
                                    'MEDIUM',
                                    'API Excessive Data Exposure',
                                    f'API returns large amount of data without authentication: {api_url}',
                                    {'remediation': 'Implement proper authentication and data filtering'}
                                )
                    except:
                        pass
                    
                    # Test rate limiting
                    rate_limit_hit = False
                    for i in range(15):
                        r = self.session.get(api_url, timeout=2, verify=False)
                        if r.status_code == 429:
                            rate_limit_hit = True
                            break
                    
                    if not rate_limit_hit:
                        self.log_vulnerability(
                            'MEDIUM',
                            'No API Rate Limiting',
                            f'API endpoint has no rate limiting: {api_url}',
                            {'remediation': 'Implement rate limiting to prevent abuse'}
                        )
                    else:
                        self.print_success(f"Rate limiting detected on {api_url}")
                        
            except:
                continue
        
        if self.guided:
            self.guide.wait_for_user()
        
        self.print_success("API testing complete")
    
    def generate_tool_commands(self):
        """Generate specific tool commands based on findings"""
        commands = {
            'nmap': [],
            'nuclei': [],
            'sqlmap': [],
            'nikto': [],
            'wpscan': [],
            'metasploit': [],
            'gobuster': [],
            'ffuf': [],
            'burpsuite': []
        }
        
        target = self.results.get('target_ip', self.target)
        
        # Nmap commands
        if self.results.get('open_ports'):
            ports = ','.join(map(str, self.results['open_ports']))
            commands['nmap'].append(f"nmap -sV -sC -p {ports} {target}")
            commands['nmap'].append(f"nmap -sV --script=vuln -p {ports} {target}")
            commands['nmap'].append(f"nmap -O {target}  # OS detection")
        else:
            commands['nmap'].append(f"nmap -sV -sC -p- {target}")
        
        # Nuclei commands
        if self.results.get('discovered_urls'):
            base_url = self.results['discovered_urls'][0] if self.results['discovered_urls'] else f"http://{self.target}"
            commands['nuclei'].append(f"nuclei -u {base_url} -severity critical,high,medium")
            commands['nuclei'].append(f"nuclei -u {base_url} -t cves/ -t vulnerabilities/")
            commands['nuclei'].append(f"nuclei -u {base_url} -t exposures/ -t misconfigurations/")
        
        # SQLMap commands for URLs with parameters
        param_urls = [url for url in self.results.get('discovered_urls', []) if '?' in url]
        for url in param_urls[:3]:
            commands['sqlmap'].append(f"sqlmap -u '{url}' --batch --risk=3 --level=5")
            commands['sqlmap'].append(f"sqlmap -u '{url}' --batch --dbs")
        
        # Nikto
        if 80 in self.results.get('open_ports', []) or 443 in self.results.get('open_ports', []):
            commands['nikto'].append(f"nikto -h {self.target}")
            commands['nikto'].append(f"nikto -h {self.target} -Tuning 123bde")
        
        # WPScan for WordPress
        if self.results['technologies'].get('cms') == 'WordPress':
            base_url = f"http://{self.target}"
            commands['wpscan'].append(f"wpscan --url {base_url} --enumerate vp,vt,u")
            commands['wpscan'].append(f"wpscan --url {base_url} --enumerate u --passwords /path/to/wordlist.txt")
        
        # Gobuster/FFuF for directory bruteforce
        commands['gobuster'].append(f"gobuster dir -u http://{self.target} -w /usr/share/wordlists/dirb/common.txt")
        commands['gobuster'].append(f"gobuster dir -u http://{self.target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        commands['ffuf'].append(f"ffuf -u http://{self.target}/FUZZ -w /usr/share/wordlists/dirb/common.txt")
        commands['ffuf'].append(f"ffuf -u http://{self.target}/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt")
        
        # Metasploit modules based on findings
        if 21 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/ftp/ftp_version")
            commands['metasploit'].append("use auxiliary/scanner/ftp/anonymous")
        if 22 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/ssh/ssh_version")
            commands['metasploit'].append("use auxiliary/scanner/ssh/ssh_login")
        if 445 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/smb/smb_version")
            commands['metasploit'].append("use exploit/windows/smb/ms17_010_eternalblue")
        if 3389 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/rdp/rdp_scanner")
            commands['metasploit'].append("use exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
        
        # Burp Suite guidance
        if param_urls:
            commands['burpsuite'].append(f"1. Import discovered URLs to Burp Suite")
            commands['burpsuite'].append(f"2. Run active scanner on: {param_urls[0]}")
            commands['burpsuite'].append(f"3. Use Intruder for parameter fuzzing")
        
        return commands
    
    def generate_attack_scenarios(self):
        """Generate security improvement scenarios based on findings"""
        self.print_section("Security Risk Assessment")
        
        scenarios = []
        
        # Based on open ports
        if 22 in self.results.get('open_ports', []):
            scenarios.append({
                'risk': 'SSH Brute Force Vulnerability',
                'description': 'SSH is exposed and may be vulnerable to credential attacks',
                'fix': 'Use key-based authentication, implement fail2ban, change default port',
                'severity': 'HIGH'
            })
        
        if 3306 in self.results.get('open_ports', []):
            scenarios.append({
                'risk': 'MySQL Database Exposed',
                'description': 'Database port accessible from internet',
                'fix': 'Restrict MySQL to localhost only, use firewall rules',
                'severity': 'HIGH'
            })
        
        # Based on vulnerabilities
        sqli_found = any('SQL' in v['type'] for v in self.results['vulnerabilities'])
        if sqli_found:
            scenarios.append({
                'risk': 'SQL Injection Vulnerability',
                'description': 'Application vulnerable to database attacks',
                'fix': 'Use parameterized queries, input validation, prepared statements',
                'severity': 'CRITICAL'
            })
        
        xss_found = any('XSS' in v['type'] for v in self.results['vulnerabilities'])
        if xss_found:
            scenarios.append({
                'risk': 'Cross-Site Scripting (XSS)',
                'description': 'Application vulnerable to script injection',
                'fix': 'Implement output encoding, Content Security Policy (CSP)',
                'severity': 'HIGH'
            })
        
        # Based on WAF
        if not self.results.get('waf_detected'):
            scenarios.append({
                'risk': 'No Web Application Firewall',
                'description': 'No WAF detected - application is directly exposed',
                'fix': 'Consider implementing Cloudflare, AWS WAF, or ModSecurity',
                'severity': 'MEDIUM'
            })
        
        # Based on missing headers
        header_issues = sum(1 for v in self.results['vulnerabilities'] if 'Header' in v['type'])
        if header_issues > 3:
            scenarios.append({
                'risk': 'Missing Security Headers',
                'description': f'{header_issues} critical security headers missing',
                'fix': 'Add HSTS, CSP, X-Frame-Options to web server config',
                'severity': 'MEDIUM'
            })
        
        if scenarios:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}🛡️  Security Risks Identified:{Colors.END}\n")
            for i, scenario in enumerate(scenarios, 1):
                severity_colors = {
                    'CRITICAL': Colors.RED,
                    'HIGH': Colors.YELLOW,
                    'MEDIUM': Colors.CYAN,
                    'LOW': Colors.GREEN
                }
                color = severity_colors.get(scenario['severity'], Colors.END)
                
                print(f"{color}{i}. {scenario['risk']} [{scenario['severity']}]{Colors.END}")
                print(f"   Issue: {scenario['description']}")
                print(f"   {Colors.GREEN}Fix: {scenario['fix']}{Colors.END}\n")
            
            self.results['security_risks'] = scenarios
        
        return scenarios
        """Generate specific tool commands based on findings"""
        commands = {
            'nmap': [],
            'nuclei': [],
            'sqlmap': [],
            'nikto': [],
            'wpscan': [],
            'metasploit': [],
            'gobuster': [],
            'ffuf': [],
            'burpsuite': []
        }
        
        target = self.results.get('target_ip', self.target)
        
        # Nmap commands
        if self.results.get('open_ports'):
            ports = ','.join(map(str, self.results['open_ports']))
            commands['nmap'].append(f"nmap -sV -sC -p {ports} {target}")
            commands['nmap'].append(f"nmap -sV --script=vuln -p {ports} {target}")
            commands['nmap'].append(f"nmap -O {target}  # OS detection")
        else:
            commands['nmap'].append(f"nmap -sV -sC -p- {target}")
        
        # Nuclei commands
        if self.results.get('discovered_urls'):
            base_url = self.results['discovered_urls'][0] if self.results['discovered_urls'] else f"http://{self.target}"
            commands['nuclei'].append(f"nuclei -u {base_url} -severity critical,high,medium")
            commands['nuclei'].append(f"nuclei -u {base_url} -t cves/ -t vulnerabilities/")
            commands['nuclei'].append(f"nuclei -u {base_url} -t exposures/ -t misconfigurations/")
        
        # SQLMap commands for URLs with parameters
        param_urls = [url for url in self.results.get('discovered_urls', []) if '?' in url]
        for url in param_urls[:3]:
            commands['sqlmap'].append(f"sqlmap -u '{url}' --batch --risk=3 --level=5")
            commands['sqlmap'].append(f"sqlmap -u '{url}' --batch --dbs")
        
        # Nikto
        if 80 in self.results.get('open_ports', []) or 443 in self.results.get('open_ports', []):
            commands['nikto'].append(f"nikto -h {self.target}")
            commands['nikto'].append(f"nikto -h {self.target} -Tuning 123bde")
        
        # WPScan for WordPress
        if self.results['technologies'].get('cms') == 'WordPress':
            base_url = f"http://{self.target}"
            commands['wpscan'].append(f"wpscan --url {base_url} --enumerate vp,vt,u")
            commands['wpscan'].append(f"wpscan --url {base_url} --enumerate u --passwords /path/to/wordlist.txt")
        
        # Gobuster/FFuF for directory bruteforce
        commands['gobuster'].append(f"gobuster dir -u http://{self.target} -w /usr/share/wordlists/dirb/common.txt")
        commands['gobuster'].append(f"gobuster dir -u http://{self.target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        commands['ffuf'].append(f"ffuf -u http://{self.target}/FUZZ -w /usr/share/wordlists/dirb/common.txt")
        commands['ffuf'].append(f"ffuf -u http://{self.target}/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt")
        
        # Metasploit modules based on findings
        if 21 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/ftp/ftp_version")
            commands['metasploit'].append("use auxiliary/scanner/ftp/anonymous")
        if 22 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/ssh/ssh_version")
            commands['metasploit'].append("use auxiliary/scanner/ssh/ssh_login")
        if 445 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/smb/smb_version")
            commands['metasploit'].append("use exploit/windows/smb/ms17_010_eternalblue")
        if 3389 in self.results.get('open_ports', []):
            commands['metasploit'].append("use auxiliary/scanner/rdp/rdp_scanner")
            commands['metasploit'].append("use exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
        
        # Burp Suite guidance
        if param_urls:
            commands['burpsuite'].append(f"1. Import discovered URLs to Burp Suite")
            commands['burpsuite'].append(f"2. Run active scanner on: {param_urls[0]}")
            commands['burpsuite'].append(f"3. Use Intruder for parameter fuzzing")
        
        return commands
        """Spider and discover URLs"""
        self.print_section("Web Spidering")
        
        visited = set()
        to_visit = [(base_url, 0)]
        
        self.print_info("Crawling website...")
        
        while to_visit and len(visited) < 100:
            url, depth = to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=True)
                self.discovered_urls.add(url)
                
                # Extract parameters
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        self.parameters[param_name].append(url)
                
                # Find links
                links = re.findall(r'href=["\'](.*?)["\']', response.text)
                for link in links:
                    absolute_url = urljoin(url, link)
                    if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                        if absolute_url not in visited and len(to_visit) < 50:
                            to_visit.append((absolute_url, depth + 1))
                
            except:
                continue
        
        self.results['urls_discovered'] = len(self.discovered_urls)
        self.results['parameters_found'] = len(self.parameters)
        self.results['discovered_urls'] = sorted(list(self.discovered_urls))
        
        self.print_info(f"URLs discovered: {Colors.BOLD}{len(self.discovered_urls)}{Colors.END}")
        self.print_info(f"Parameters found: {Colors.BOLD}{len(self.parameters)}{Colors.END}")
        
        # Print discovered URLs
        print(f"\n{Colors.CYAN}  Discovered URLs:{Colors.END}")
        for idx, url in enumerate(sorted(self.discovered_urls)[:20], 1):
            # Highlight URLs with parameters
            if '?' in url:
                print(f"    {Colors.YELLOW}[{idx}] {url}{Colors.END}")
            else:
                print(f"    {Colors.BLUE}[{idx}] {url}{Colors.END}")
        
        if len(self.discovered_urls) > 20:
            print(f"    {Colors.CYAN}... and {len(self.discovered_urls) - 20} more URLs{Colors.END}")
        
        self.print_success("Spidering complete")
    
    def security_headers_check(self, url):
        """Check for security headers"""
        self.print_section("Security Headers Analysis")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            critical_headers = {
                'Strict-Transport-Security': ('HIGH', 'HSTS not configured - vulnerable to SSL stripping'),
                'Content-Security-Policy': ('HIGH', 'CSP not configured - vulnerable to XSS'),
                'X-Frame-Options': ('MEDIUM', 'Clickjacking protection missing'),
                'X-Content-Type-Options': ('MEDIUM', 'MIME-sniffing protection missing'),
                'Referrer-Policy': ('LOW', 'Referrer policy not set'),
                'Permissions-Policy': ('LOW', 'Permissions policy not configured'),
            }
            
            missing_count = 0
            for header, (severity, desc) in critical_headers.items():
                if header not in response.headers:
                    missing_count += 1
                    self.log_vulnerability(
                        severity,
                        f'Missing: {header}',
                        desc,
                        {'remediation': f'Add {header} header'}
                    )
                else:
                    self.print_success(f"{header} present")
            
            if missing_count == 0:
                self.print_success("All critical security headers present")
            
        except Exception as e:
            self.print_warning(f"Header check failed: {str(e)}")
    
    def test_sql_injection(self, url):
        """Test for SQL injection"""
        self.print_section("SQL Injection Testing")
        
        parsed = urlparse(url)
        if not parsed.query:
            self.print_info("No parameters to test")
            return
        
        params = parse_qs(parsed.query)
        tested = 0
        
        for param_name in list(params.keys())[:5]:
            tested += 1
            self.print_info(f"Testing parameter: {Colors.BOLD}{param_name}{Colors.END}")
            
            payloads = ["'", "' OR '1'='1", "' AND 1=1--", "' WAITFOR DELAY '0:0:5'--"]
            
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    start = time.time()
                    response = self.session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start
                    
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 
                                  'Microsoft SQL', 'Warning: mysql']
                    
                    for error in sql_errors:
                        if error in response.text:
                            self.log_vulnerability(
                                'CRITICAL',
                                'SQL Injection',
                                f'Error-based SQLi in parameter "{param_name}"',
                                {
                                    'cve': 'CWE-89',
                                    'tool_command': f'sqlmap -u "{url}" -p {param_name} --batch',
                                    'remediation': 'Use parameterized queries'
                                }
                            )
                            return
                    
                    if elapsed > 4 and 'WAITFOR' in payload:
                        self.log_vulnerability(
                            'CRITICAL',
                            'Time-Based SQL Injection',
                            f'Time-based blind SQLi in parameter "{param_name}"',
                            {
                                'cve': 'CWE-89',
                                'tool_command': f'sqlmap -u "{url}" -p {param_name} --technique=T',
                                'remediation': 'Use parameterized queries'
                            }
                        )
                        return
                        
                except:
                    continue
        
        self.print_success(f"Tested {tested} parameters - No SQL injection found")
    
    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        self.print_section("XSS Testing")
        
        parsed = urlparse(url)
        if not parsed.query:
            self.print_info("No parameters to test")
            return
        
        params = parse_qs(parsed.query)
        tested = 0
        
        for param_name in list(params.keys())[:5]:
            tested += 1
            self.print_info(f"Testing parameter: {Colors.BOLD}{param_name}{Colors.END}")
            
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>"
            ]
            
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if payload in response.text:
                        self.log_vulnerability(
                            'HIGH',
                            'Reflected XSS',
                            f'XSS vulnerability in parameter "{param_name}"',
                            {
                                'cve': 'CWE-79',
                                'remediation': 'Implement output encoding and CSP',
                                'tool_command': 'Manual verification required'
                            }
                        )
                        return
                        
                except:
                    continue
        
        self.print_success(f"Tested {tested} parameters - No XSS found")
    
    def test_command_injection(self, url):
        """Test for command injection"""
        self.print_section("Command Injection Testing")
        
        parsed = urlparse(url)
        if not parsed.query:
            self.print_info("No parameters to test")
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in list(params.keys())[:3]:
            self.print_info(f"Testing parameter: {Colors.BOLD}{param_name}{Colors.END}")
            
            payloads = ["; whoami", "| id", "& hostname", "`uname -a`"]
            
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    indicators = ['uid=', 'gid=', 'groups=', 'root:']
                    for indicator in indicators:
                        if indicator in response.text:
                            self.log_vulnerability(
                                'CRITICAL',
                                'Command Injection',
                                f'OS command injection in parameter "{param_name}"',
                                {
                                    'cve': 'CWE-78',
                                    'remediation': 'Never pass user input directly to system commands'
                                }
                            )
                            return
                except:
                    continue
        
        self.print_success("No command injection found")
    
    def test_ssrf(self, url):
        """Test for SSRF vulnerabilities"""
        self.print_section("SSRF Testing")
        
        parsed = urlparse(url)
        if not parsed.query:
            self.print_info("No parameters to test")
            return
        
        params = parse_qs(parsed.query)
        
        for param_name in list(params.keys())[:3]:
            self.print_info(f"Testing parameter: {Colors.BOLD}{param_name}{Colors.END}")
            
            payloads = [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/'
            ]
            
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    ssrf_indicators = ['root:', 'ami-id', 'instance-id']
                    for indicator in ssrf_indicators:
                        if indicator in response.text:
                            self.log_vulnerability(
                                'CRITICAL',
                                'SSRF Vulnerability',
                                f'SSRF in parameter "{param_name}"',
                                {
                                    'cve': 'CWE-918',
                                    'remediation': 'Implement URL whitelist'
                                }
                            )
                            return
                            
                except:
                    continue
        
        self.print_success("No SSRF vulnerabilities found")
    
    def test_lfi(self, url):
        """Test for Local File Inclusion"""
        self.print_section("LFI/Path Traversal Testing")
        
        parsed = urlparse(url)
        if not parsed.query:
            self.print_info("No parameters to test")
            return
        
        params = parse_qs(parsed.query)
        
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        for param_name in list(params.keys())[:3]:
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_query = '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    indicators = ['root:', '[extensions]', 'daemon:']
                    for indicator in indicators:
                        if indicator in response.text:
                            self.log_vulnerability(
                                'CRITICAL',
                                'Local File Inclusion',
                                f'LFI vulnerability in parameter "{param_name}"',
                                {
                                    'cve': 'CWE-22',
                                    'remediation': 'Validate and sanitize file paths'
                                }
                            )
                            return
                except:
                    continue
        
        self.print_success("No LFI vulnerabilities found")
    
    def generate_report(self):
        """Generate final report"""
        self.print_phase(6, "Report Generation")
        
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Colors.BOLD}{'─' * 80}{Colors.END}")
        print(f"{Colors.BOLD}EXECUTIVE SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'─' * 80}{Colors.END}\n")
        
        print(f"  Target: {Colors.YELLOW}{self.target}{Colors.END}")
        print(f"  Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration: {elapsed_time:.2f} seconds")
        print(f"  Total Vulnerabilities: {Colors.BOLD}{len(self.results['vulnerabilities'])}{Colors.END}\n")
        
        print(f"{Colors.BOLD}SEVERITY BREAKDOWN{Colors.END}")
        print(f"{'─' * 80}\n")
        
        print(f"  {Colors.RED}🔴 CRITICAL: {self.vuln_count['CRITICAL']}{Colors.END}  (Immediate action required)")
        print(f"  {Colors.YELLOW}🟠 HIGH:     {self.vuln_count['HIGH']}{Colors.END}  (Urgent remediation needed)")
        print(f"  {Colors.CYAN}🟡 MEDIUM:   {self.vuln_count['MEDIUM']}{Colors.END}  (Should be addressed)")
        print(f"  {Colors.GREEN}🟢 LOW:      {self.vuln_count['LOW']}{Colors.END}  (Minor issues)")
        print(f"  {Colors.BLUE}🔵 INFO:     {self.vuln_count['INFO']}{Colors.END}  (Informational)\n")
        
        # Risk level
        risk_level = "LOW"
        risk_color = Colors.GREEN
        
        if self.vuln_count['CRITICAL'] > 0:
            risk_level = "CRITICAL"
            risk_color = Colors.RED
        elif self.vuln_count['HIGH'] > 0:
            risk_level = "HIGH"
            risk_color = Colors.YELLOW
        elif self.vuln_count['MEDIUM'] > 0:
            risk_level = "MEDIUM"
            risk_color = Colors.CYAN
        
        print(f"{Colors.BOLD}OVERALL RISK LEVEL{Colors.END}")
        print(f"{'─' * 80}\n")
        print(f"  {risk_color}{Colors.BOLD}{risk_level}{Colors.END}\n")
        
        # Statistics
        print(f"{Colors.BOLD}SCAN STATISTICS{Colors.END}")
        print(f"{'─' * 80}\n")
        print(f"  URLs Discovered: {self.results['urls_discovered']}")
        print(f"  Parameters Found: {self.results['parameters_found']}")
        print(f"  Open Ports: {len(self.results['open_ports'])}")
        print(f"  Subdomains Found: {len(self.results['subdomains'])}")
        print(f"  Email Addresses: {len(self.results['email_addresses'])}")
        print(f"  Sensitive Files: {len(self.results['sensitive_files'])}\n")
        
        # Recommended actions
        if self.vuln_count['CRITICAL'] > 0 or self.vuln_count['HIGH'] > 0:
            print(f"{Colors.BOLD}RECOMMENDED ACTIONS{Colors.END}")
            print(f"{'─' * 80}\n")
            print(f"  {Colors.RED}⚠  IMMEDIATE ATTENTION REQUIRED{Colors.END}")
            print(f"  Critical and high-severity vulnerabilities detected!")
            print(f"  Review findings and implement remediation steps immediately.\n")
        
        # Tool recommendations with specific commands
        print(f"{Colors.BOLD}RECOMMENDED TOOLS FOR DEEPER TESTING{Colors.END}")
        print(f"{'─' * 80}\n")
        
        tool_commands = self.generate_tool_commands()
        
        # Nmap
        if tool_commands['nmap']:
            print(f"{Colors.CYAN}┌─ Nmap (Network Scanner){Colors.END}")
            for cmd in tool_commands['nmap']:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # Nuclei
        if tool_commands['nuclei']:
            print(f"{Colors.CYAN}┌─ Nuclei (Vulnerability Scanner){Colors.END}")
            for cmd in tool_commands['nuclei']:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # SQLMap
        if tool_commands['sqlmap']:
            print(f"{Colors.CYAN}┌─ SQLMap (SQL Injection){Colors.END}")
            for cmd in tool_commands['sqlmap'][:2]:  # Show first 2
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            if len(tool_commands['sqlmap']) > 2:
                print(f"{Colors.YELLOW}  ... and {len(tool_commands['sqlmap']) - 2} more commands{Colors.END}")
            print()
        
        # Nikto
        if tool_commands['nikto']:
            print(f"{Colors.CYAN}┌─ Nikto (Web Server Scanner){Colors.END}")
            for cmd in tool_commands['nikto']:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # WPScan
        if tool_commands['wpscan']:
            print(f"{Colors.CYAN}┌─ WPScan (WordPress Scanner){Colors.END}")
            for cmd in tool_commands['wpscan']:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # Gobuster
        if tool_commands['gobuster']:
            print(f"{Colors.CYAN}┌─ Gobuster (Directory Bruteforce){Colors.END}")
            for cmd in tool_commands['gobuster']:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # FFuF
        if tool_commands['ffuf']:
            print(f"{Colors.CYAN}┌─ FFuF (Web Fuzzer){Colors.END}")
            for cmd in tool_commands['ffuf'][:2]:
                print(f"{Colors.GREEN}  $ {cmd}{Colors.END}")
            print()
        
        # Metasploit
        if tool_commands['metasploit']:
            print(f"{Colors.CYAN}┌─ Metasploit Framework{Colors.END}")
            print(f"{Colors.GREEN}  $ msfconsole{Colors.END}")
            for cmd in tool_commands['metasploit'][:3]:
                print(f"{Colors.YELLOW}  msf6 > {cmd}{Colors.END}")
            if len(tool_commands['metasploit']) > 3:
                print(f"{Colors.YELLOW}  ... and {len(tool_commands['metasploit']) - 3} more modules{Colors.END}")
            print()
        
        # Burp Suite
        if tool_commands['burpsuite']:
            print(f"{Colors.CYAN}┌─ Burp Suite (Manual Testing){Colors.END}")
            for cmd in tool_commands['burpsuite']:
                print(f"{Colors.YELLOW}  • {cmd}{Colors.END}")
            print()
        
        # Save JSON report
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.print_success(f"Detailed JSON report saved: {Colors.BOLD}{self.output_file}{Colors.END}")
        
        # Save HTML report
        if self.output_file:
            html_file = self.output_file.replace('.json', '.html')
            self.generate_html_report(html_file)
            self.print_success(f"HTML report saved: {Colors.BOLD}{html_file}{Colors.END}")
        
        # Save commands to file
        if self.output_file:
            commands_file = self.output_file.replace('.json', '_commands.txt')
            with open(commands_file, 'w') as f:
                f.write(f"Penetration Testing Commands for {self.target}\n")
                f.write(f"{'=' * 80}\n\n")
                
                for tool, cmds in tool_commands.items():
                    if cmds:
                        f.write(f"\n{'─' * 80}\n")
                        f.write(f"{tool.upper()}\n")
                        f.write(f"{'─' * 80}\n")
                        for cmd in cmds:
                            f.write(f"{cmd}\n")
                
            self.print_success(f"Commands saved to: {Colors.BOLD}{commands_file}{Colors.END}")
        
        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}  ✓ ASSESSMENT COMPLETE{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.END}\n")
        
        # Save JSON report
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.print_success(f"Detailed JSON report saved: {Colors.BOLD}{self.output_file}{Colors.END}")
        
        # Save HTML report
        if self.output_file:
            html_file = self.output_file.replace('.json', '.html')
            self.generate_html_report(html_file)
            self.print_success(f"HTML report saved: {Colors.BOLD}{html_file}{Colors.END}")
        
        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}  ✓ ASSESSMENT COMPLETE{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.END}\n")
    
    def generate_html_report(self, filename):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 10px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #f39c12; font-weight: bold; }}
        .medium {{ color: #3498db; font-weight: bold; }}
        .low {{ color: #2ecc71; font-weight: bold; }}
        .vuln {{ margin: 15px 0; padding: 15px; border-left: 4px solid #3498db; background: #ecf0f1; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .url-list {{ max-height: 400px; overflow-y: auto; background: #ecf0f1; padding: 15px; border-radius: 5px; }}
        .url-item {{ padding: 8px; margin: 5px 0; background: white; border-radius: 3px; word-break: break-all; }}
        .url-param {{ background: #fff3cd; border-left: 3px solid #ffc107; }}
        .collapsible {{ background-color: #34495e; color: white; cursor: pointer; padding: 18px; width: 100%; border: none; text-align: left; outline: none; font-size: 15px; margin-top: 10px; }}
        .collapsible:hover {{ background-color: #2c3e50; }}
        .content {{ padding: 0 18px; max-height: 0; overflow: hidden; transition: max-height 0.2s ease-out; background-color: #f1f1f1; }}
    </style>
    <script>
        function toggleSection(id) {{
            var content = document.getElementById(id);
            if (content.style.maxHeight) {{
                content.style.maxHeight = null;
            }} else {{
                content.style.maxHeight = content.scrollHeight + "px";
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>🔒 Penetration Test Report</h1>
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>Total Vulnerabilities Found: <strong>{len(self.results['vulnerabilities'])}</strong></p>
        <ul>
            <li class="critical">🔴 CRITICAL: {self.vuln_count['CRITICAL']}</li>
            <li class="high">🟠 HIGH: {self.vuln_count['HIGH']}</li>
            <li class="medium">🟡 MEDIUM: {self.vuln_count['MEDIUM']}</li>
            <li class="low">🟢 LOW: {self.vuln_count['LOW']}</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Scan Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>URLs Discovered</td><td>{self.results['urls_discovered']}</td></tr>
            <tr><td>Parameters Found</td><td>{self.results['parameters_found']}</td></tr>
            <tr><td>Open Ports</td><td>{len(self.results['open_ports'])}</td></tr>
            <tr><td>Subdomains Found</td><td>{len(self.results['subdomains'])}</td></tr>
            <tr><td>Email Addresses</td><td>{len(self.results['email_addresses'])}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Discovered URLs ({len(self.results.get('discovered_urls', []))})</h2>
        <button class="collapsible" onclick="toggleSection('urls-content')">Show/Hide All URLs</button>
        <div id="urls-content" class="content">
            <div class="url-list">
"""
        
        # Add all discovered URLs
        for url in self.results.get('discovered_urls', []):
            url_class = 'url-param' if '?' in url else ''
            param_badge = ' <strong>[HAS PARAMS]</strong>' if '?' in url else ''
            html += f'                <div class="url-item {url_class}">{url}{param_badge}</div>\n'
        
        html += """            </div>
        </div>
    </div>
"""
        
        # Add subdomains section if found
        if self.results['subdomains']:
            html += """
    <div class="section">
        <h2>Discovered Subdomains</h2>
        <div class="url-list">
"""
            for subdomain in self.results['subdomains']:
                html += f'            <div class="url-item">{subdomain}</div>\n'
            html += """        </div>
    </div>
"""
        
        # Add email addresses section if found
        if self.results['email_addresses']:
            html += """
    <div class="section">
        <h2>Harvested Email Addresses</h2>
        <div class="url-list">
"""
            for email in self.results['email_addresses']:
                html += f'            <div class="url-item">📧 {email}</div>\n'
            html += """        </div>
    </div>
"""
        
        # Add open ports section if found
        if self.results['open_ports']:
            html += """
    <div class="section">
        <h2>Open Ports</h2>
        <table>
            <tr><th>Port</th><th>Service</th></tr>
"""
            services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
            }
            for port in self.results['open_ports']:
                service = services.get(port, 'Unknown')
                html += f'            <tr><td>{port}</td><td>{service}</td></tr>\n'
            html += """        </table>
    </div>
"""
        
        html += """
    <div class="section">
        <h2>Vulnerabilities</h2>
"""
        
        for vuln in self.results['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}
            icon = icons.get(vuln['severity'], '•')
            html += f"""
        <div class="vuln">
            <h3 class="{severity_class}">{icon} [{vuln['severity']}] {vuln['type']}</h3>
            <p>{vuln['description']}</p>
"""
            if vuln.get('details'):
                if vuln['details'].get('remediation'):
                    html += f"<p><strong>🔧 Remediation:</strong> {vuln['details']['remediation']}</p>"
                if vuln['details'].get('cve'):
                    html += f"<p><strong>🔖 CVE:</strong> {vuln['details']['cve']}</p>"
                if vuln['details'].get('tool_command'):
                    html += f"<p><strong>💻 Command:</strong> <code>{vuln['details']['tool_command']}</code></p>"
            html += "        </div>\n"
        
        html += """
    </div>
</body>
</html>"""
        
        with open(filename, 'w') as f:
            f.write(html)
    
    def run_assessment(self, url=None):
        """Run comprehensive security assessment"""
        self.print_banner()
        
        if self.guided:
            self.guide.print_step(
                0,
                "Welcome to Comprehensive Security Assessment",
                "This guided assessment will walk you through each security testing phase,\n" +
                "providing detailed explanations, educational insights, and actionable recommendations.\n\n" +
                "Whether you're a website owner protecting your business, an IT professional\n" +
                "securing infrastructure, or a security enthusiast learning the craft,\n" +
                "you'll gain valuable insights into your security posture.\n\n" +
                "Each phase tests different aspects of security - from network configuration\n" +
                "to application vulnerabilities. You'll understand not just WHAT was found,\n" +
                "but WHY it matters and HOW to fix it."
            )
            self.guide.wait_for_user("Press Enter to begin the assessment...")
        
        if not url:
            url = f"https://{self.target}"
        
        try:
            # Phase 0: Network Mapping
            self.print_phase(0, "Network Mapping & Intelligence")
            if self.guided:
                self.guide.explain_phase(
                    "Network Mapping & Intelligence Gathering",
                    "We begin by understanding the basic network infrastructure - IP addresses, \n" +
                    "    DNS configuration, network classification, and hosting environment.\n" +
                    "    This is like creating a map of your digital property.",
                    "IMPORTANCE: Knowing your infrastructure helps identify:\n" +
                    "    • What's publicly visible vs what should be private\n" +
                    "    • Potential misconfigurations in network setup\n" +
                    "    • Whether you're properly leveraging cloud security features\n" +
                    "    • Attack surface exposure to the internet"
                )
                self.guide.wait_for_user()
            
            self.network_mapping()
            target_ip = self.results.get('target_ip', self.target)
            
            # Phase 1: Network Reconnaissance
            self.print_phase(1, "Network Reconnaissance")
            if self.guided:
                self.guide.explain_phase(
                    "Network Reconnaissance - Port & Service Discovery",
                    "Now scanning for open network ports and identifying running services.\n" +
                    "    Think of ports as doors to your system - we're checking which ones are open\n" +
                    "    and what's behind them.",
                    "IMPORTANCE: Every open port represents:\n" +
                    "    • A potential entry point into your system\n" +
                    "    • A service that needs to be kept secure and updated\n" +
                    "    • Something that might be unnecessarily exposed to the internet\n" +
                    "    • A component that could have known vulnerabilities\n\n" +
                    "    Common findings: SSH (port 22), HTTP (80), HTTPS (443), MySQL (3306)"
                )
                self.guide.show_tip("This scan may trigger security monitoring systems - that's actually a GOOD sign! \n        It means your monitoring is working. In production, you want to know when \n        someone is scanning your systems.")
                self.guide.wait_for_user()
            
            open_ports = self.port_scan(1, 1000)
            self.subdomain_enumeration()
            self.os_fingerprinting(target_ip)
            self.service_version_detection()
            
            if self.guided:
                self.guide.show_tip(f"Discovery Results: Found {len(open_ports)} open ports and {len(self.results.get('subdomains', []))} subdomains.\n\n" +
                    "        WHAT THIS MEANS:\n" +
                    "        • More open ports = larger attack surface\n" +
                    "        • Each service needs security attention\n" +
                    "        • Unused ports should be closed\n" +
                    "        • Services should be on latest versions\n\n" +
                    "        Next, we'll identify what software is running on these ports.")
                self.guide.wait_for_user("Press Enter to continue to Information Gathering...")
            
            # Phase 2: Information Gathering
            self.print_phase(2, "Information Gathering")
            if self.guided:
                self.guide.explain_phase(
                    "Information Gathering - Technology Stack Identification",
                    "Identifying the software, frameworks, and content management systems powering your site.\n" +
                    "    We're looking for: Web servers, programming languages, CMS platforms,\n" +
                    "    JavaScript libraries, and security measures like firewalls.",
                    "IMPORTANCE: Understanding your tech stack helps:\n" +
                    "    • Identify software that needs updates or patching\n" +
                    "    • Find known vulnerabilities in specific versions\n" +
                    "    • Understand what security features are (or aren't) in place\n" +
                    "    • Prioritize security investments\n\n" +
                    "    Examples: 'WordPress 5.8' has different risks than 'WordPress 6.4'\n" +
                    "              'nginx with WAF' is more secure than 'nginx alone'"
                )
                self.guide.wait_for_user()
            
            self.technology_detection(url)
            self.advanced_reconnaissance(url)  # NEW: Advanced recon
            self.spider_urls(url, max_depth=2)
            self.email_harvesting(url)
            
            if self.guided:
                self.guide.show_tip(f"Technology Discovery: Identified {len(self.results['technologies'])} technology components.\n\n" +
                    f"        URLs Discovered: {self.results['urls_discovered']}\n" +
                    f"        Parameters Found: {self.results['parameters_found']}\n" +
                    f"        WAF Detected: {'Yes - ' + ', '.join(self.results.get('waf_detected', [])) if self.results.get('waf_detected') else 'No'}\n\n" +
                    "        WHAT TO DO NEXT:\n" +
                    "        • Check if all software is on latest versions\n" +
                    "        • Review CVE databases for your specific versions\n" +
                    "        • Consider implementing a WAF if none detected\n" +
                    "        • Document your tech stack for security planning")
                self.guide.wait_for_user("Press Enter to continue to Active Enumeration...")
            
            # Phase 3: Active Enumeration
            self.print_phase(3, "Active Enumeration")
            if self.guided:
                self.guide.explain_phase(
                    "Active Enumeration - Finding Hidden Content",
                    "Actively searching for files and directories that might be unintentionally exposed.\n" +
                    "    Looking for: Backup files, config files, development resources, admin panels,\n" +
                    "    API endpoints, and sensitive documentation.",
                    "IMPORTANCE: Hidden/forgotten files are a TOP security risk:\n" +
                    "    • .env files often contain database passwords and API keys\n" +
                    "    • Backup files (.bak, .old) may expose source code\n" +
                    "    • robots.txt reveals paths developers want hidden\n" +
                    "    • Old admin panels might lack security updates\n\n" +
                    "    REAL EXAMPLE: A .git folder exposure can leak entire codebase\n" +
                    "    including credentials, business logic, and vulnerabilities."
                )
                self.guide.show_warning("This phase generates more HTTP requests and will appear in your server logs.\n" +
                    "        That's normal - you WANT to see this activity in your logs to verify\n" +
                    "        your monitoring is working.")
                self.guide.wait_for_user()
            
            self.sensitive_file_detection(url)
            self.directory_bruteforce(url)
            self.backup_file_scanner(url)  # NEW: Backup files
            self.web_fuzzing(url)  # NEW: Web fuzzing
            self.api_testing(url)  # NEW: API testing
            
            if self.guided:
                sensitive_count = len(self.results.get('sensitive_files', []))
                if sensitive_count > 0:
                    self.guide.show_warning(f"⚠️  CRITICAL FINDING: {sensitive_count} sensitive files are publicly accessible!\n\n" +
                        "        This is a HIGH priority security issue. These files could contain:\n" +
                        "        • Database credentials and connection strings\n" +
                        "        • API keys and authentication tokens\n" +
                        "        • Source code revealing business logic\n" +
                        "        • User data or configuration details\n\n" +
                        "        IMMEDIATE ACTION: Review each file and either:\n" +
                        "        1. Remove it from the server entirely (best option)\n" +
                        "        2. Move it outside web root directory\n" +
                        "        3. Add access restrictions via .htaccess or web.config")
                else:
                    self.guide.show_tip("✓ Good news! No obvious sensitive files found.\n" +
                        "        However, continue to:\n" +
                        "        • Regularly audit your web directory\n" +
                        "        • Use .gitignore to prevent committing sensitive files\n" +
                        "        • Implement automated scanning in your CI/CD pipeline")
                self.guide.wait_for_user("Press Enter to continue to Security Configuration...")
            
            # Phase 4: Security Configuration
            self.print_phase(4, "Security Configuration Analysis")
            if self.guided:
                self.guide.explain_phase(
                    "Security Configuration Analysis",
                    "Examining HTTP security headers, SSL/TLS configuration, CORS policies,\n" +
                    "    and other defensive security measures that should be in place.",
                    "IMPORTANCE: Security headers are your first line of defense:\n\n" +
                    "    • HSTS - Forces HTTPS, prevents SSL stripping attacks\n" +
                    "    • CSP - Prevents XSS attacks by controlling script sources\n" +
                    "    • X-Frame-Options - Stops clickjacking attacks\n" +
                    "    • X-Content-Type-Options - Prevents MIME-type attacks\n\n" +
                    "    These are EASY to implement (often just server config changes)\n" +
                    "    but provide SIGNIFICANT security improvements.\n\n" +
                    "    Think of them as locks on your doors - simple but essential."
                )
                self.guide.wait_for_user()
            
            self.security_headers_check(url)
            self.cors_misconfiguration_check(url)
            self.http_methods_check(url)
            
            if 443 in open_ports:
                self.ssl_tls_analysis(self.target)
            
            if self.guided:
                header_issues = sum(1 for v in self.results['vulnerabilities'] if 'Header' in v['type'])
                if header_issues > 0:
                    self.guide.show_tip(f"Found {header_issues} missing security headers.\n\n" +
                        "        THE GOOD NEWS: These are usually EASY fixes!\n" +
                        "        Most can be added with simple web server configuration.\n\n" +
                        "        FOR NGINX: Add to your nginx.conf\n" +
                        "        FOR APACHE: Add to your .htaccess or httpd.conf\n" +
                        "        FOR CLOUD: Most cloud platforms have GUI options\n\n" +
                        "        EFFORT: Low (minutes to implement)\n" +
                        "        SECURITY IMPACT: High (blocks entire attack categories)")
                else:
                    self.guide.show_tip("✓ Excellent! All major security headers are present.\n" +
                        "        This shows good security awareness and implementation.")
                self.guide.wait_for_user("Press Enter to continue to Vulnerability Testing...")
            
            # Phase 5: Vulnerability Testing
            self.print_phase(5, "Vulnerability Testing")
            if self.guided:
                self.guide.explain_phase(
                    "Vulnerability Testing - The Critical Phase",
                    "Testing for actual vulnerabilities that could be exploited:\n" +
                    "    • SQL Injection - Database manipulation/data theft\n" +
                    "    • Cross-Site Scripting (XSS) - Script injection attacks\n" +
                    "    • Command Injection - Server command execution\n" +
                    "    • SSRF - Internal network access\n" +
                    "    • Path Traversal - Unauthorized file access",
                    "IMPORTANCE: These are the vulnerabilities that make headlines:\n\n" +
                    "    SQL INJECTION → Data breaches, stolen customer data\n" +
                    "    XSS → Account takeover, malware distribution\n" +
                    "    COMMAND INJECTION → Complete server compromise\n\n" +
                    "    Finding these BEFORE attackers do is critical.\n" +
                    "    Each finding comes with specific fix recommendations.\n\n" +
                    "    THE PROCESS: We send test payloads to see if input is properly sanitized.\n" +
                    "    If an error message appears or unexpected behavior occurs, it indicates\n" +
                    "    a potential vulnerability that needs immediate attention."
                )
                self.guide.show_warning("These tests send special characters and test strings to your application.\n" +
                    "        • This is safe and won't damage your system\n" +
                    "        • May trigger security monitoring (that's good!)\n" +
                    "        • Some test queries might appear in your logs\n" +
                    "        • All tests are read-only, not destructive")
                self.guide.wait_for_user()
            
            test_urls = [u for u in self.discovered_urls if '?' in u][:5]
            
            if test_urls:
                if self.guided:
                    self.guide.show_tip(f"Testing {len(test_urls)} URLs with parameters. Each parameter will be tested with multiple payloads.")
                    self.guide.wait_for_user()
                
                for test_url in test_urls:
                    self.test_sql_injection(test_url)
                    self.test_xss(test_url)
                    self.test_command_injection(test_url)
                    self.test_ssrf(test_url)
                    self.test_lfi(test_url)
            else:
                self.print_info("No parameterized URLs found for vulnerability testing")
                if self.guided:
                    self.guide.show_tip("No parameters found. Try manual testing or use fuzzing to find hidden parameters.")
            
            if self.guided:
                self.guide.print_step(
                    5.5,
                    "Security Improvement Recommendations",
                    "Based on findings, here are potential security issues and how to address them..."
                )
            
            scenarios = self.generate_attack_scenarios()  # NEW: Attack scenarios
            
            if self.guided and scenarios:
                self.guide.show_warning(f"Found {len(scenarios)} potential security concerns. Review each and implement fixes as needed.")
                self.guide.wait_for_user()
            
            # Phase 6: Report
            self.generate_report()
            
            if self.guided:
                self.guide.print_step(
                    "FINAL",
                    "Security Assessment Complete - Results & Recommendations",
                    f"{'='*76}\n" +
                    f"Assessment Duration: {time.time() - self.start_time:.2f} seconds\n" +
                    f"Total Security Findings: {len(self.results['vulnerabilities'])}\n" +
                    f"{'='*76}\n\n" +
                    f"WHAT WE TESTED:\n" +
                    f"✓ Network configuration and exposed services\n" +
                    f"✓ Technology stack and version identification\n" +
                    f"✓ Sensitive file exposure\n" +
                    f"✓ Security header configuration\n" +
                    f"✓ Common web vulnerabilities\n" +
                    f"✓ SSL/TLS security\n" +
                    f"✓ API security posture\n\n" +
                    f"THREE DETAILED REPORTS HAVE BEEN GENERATED:\n" +
                    f"1. JSON Report - Machine-readable, complete data\n" +
                    f"2. HTML Report - Visual, shareable, professional format\n" +
                    f"3. Commands File - Ready-to-use security tools commands"
                )
                
                # Generate next steps
                next_steps = []
                
                if self.vuln_count['CRITICAL'] > 0:
                    next_steps.append("🔴 CRITICAL: Address critical vulnerabilities immediately to prevent exploitation")
                
                if any('SQL' in v['type'] for v in self.results['vulnerabilities']):
                    next_steps.append("Fix SQL injection issues - use parameterized queries")
                
                if any('XSS' in v['type'] for v in self.results['vulnerabilities']):
                    next_steps.append("Implement output encoding and Content Security Policy (CSP)")
                
                if any('Header' in v['type'] for v in self.results['vulnerabilities']):
                    next_steps.append("Add missing security headers to your web server configuration")
                
                if self.results.get('waf_detected'):
                    next_steps.append("✅ Good: WAF detected, but ensure it's properly configured")
                
                if len(self.results.get('sensitive_files', [])) > 0:
                    next_steps.append("⚠️  Remove or protect sensitive files found during scan")
                
                next_steps.extend([
                    "Run deeper scans with tools like Nuclei for comprehensive coverage",
                    "Review all generated commands in the _commands.txt file",
                    "Consider professional security audit for complex findings",
                    "Implement security monitoring and logging",
                    "Keep all software and dependencies updated"
                ])
                
                self.guide.next_steps_suggestion(next_steps)
                
                print(f"\n{Colors.GREEN}{Colors.BOLD}📚 Security Best Practices:{Colors.END}")
                print("  • Regularly scan your systems for vulnerabilities")
                print("  • Keep all software updated and patched")
                print("  • Implement the principle of least privilege")
                print("  • Use strong authentication and encryption")
                print("  • Monitor logs for suspicious activity")
                print("  • Have an incident response plan ready")
                print()
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
            self.generate_report()
        except Exception as e:
            print(f"\n\n{Colors.RED}Error during scan: {str(e)}{Colors.END}")
            import traceback
            traceback.print_exc()
            self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='Decypher - Advanced Penetration Testing Framework v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 decypher.py example.com
  python3 decypher.py example.com -u https://example.com
  python3 decypher.py example.com -a -t 20 -o report.json
  python3 decypher.py 192.168.1.1 --timeout 5
        '''
    )
    
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-u', '--url', help='Specific URL to test')
    parser.add_argument('-a', '--aggressive', action='store_true',
                       help='Enable aggressive testing')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', default='decypher_report.json',
                       help='Output report file (default: decypher_report.json)')
    
    args = parser.parse_args()
    
    # Welcome banner
    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("=" * 80)
    print("  DECYPHER - ADVANCED SECURITY ASSESSMENT FRAMEWORK")
    print("=" * 80)
    print(f"{Colors.END}")
    
    # Legal disclaimer
    print(f"\n{Colors.YELLOW}{Colors.BOLD}LEGAL DISCLAIMER{Colors.END}")
    print("─" * 80)
    print("This tool performs comprehensive security assessments.")
    print(f"{Colors.BOLD}Use only on:{Colors.END}")
    print("  • Your own systems and infrastructure")
    print("  • Systems where you have explicit written permission")
    print("  • Authorized practice/lab environments")
    print()
    print(f"{Colors.RED}Unauthorized testing is illegal and punishable by law.{Colors.END}")
    print("User assumes all legal responsibility for tool usage.")
    print("─" * 80)
    
    # Authorization confirmation
    print(f"\n{Colors.BOLD}Authorization Confirmation{Colors.END}")
    confirm = input(f"\n{Colors.YELLOW}I confirm I have authorization to test this target (yes/no): {Colors.END}")
    
    if confirm.lower() != 'yes':
        print(f"\n{Colors.RED}❌ Authorization not confirmed. Exiting for your safety.{Colors.END}\n")
        sys.exit(1)
    
    print(f"{Colors.GREEN}✓ Authorization confirmed{Colors.END}")
    
    # Ask for guided mode
    print(f"\n{Colors.CYAN}{Colors.BOLD}Assessment Mode Selection{Colors.END}")
    print("─" * 80)
    print(f"\n{Colors.BOLD}Choose your assessment mode:{Colors.END}\n")
    
    print(f"{Colors.GREEN}1. Guided Mode (Recommended){Colors.END}")
    print("   • Step-by-step explanations of each phase")
    print("   • Educational tips and security insights")
    print("   • Learn what each test does and why it matters")
    print("   • Perfect for learning or understanding findings")
    print("   • Interactive - pauses between phases")
    
    print(f"\n{Colors.CYAN}2. Standard Mode{Colors.END}")
    print("   • Fast, automated assessment")
    print("   • No explanations or pauses")
    print("   • Complete scan without interruption")
    print("   • Best for experienced users or quick scans")
    print("   • Focus on results, not process")
    
    print()
    mode_choice = input(f"{Colors.YELLOW}Select mode (1 for Guided, 2 for Standard) [1]: {Colors.END}").strip()
    
    # Default to guided if empty or invalid
    if mode_choice == "2":
        guided_mode = False
        print(f"\n{Colors.CYAN}📊 Standard Mode selected - Running automated assessment...{Colors.END}")
    else:
        guided_mode = True
        print(f"\n{Colors.GREEN}🎓 Guided Mode enabled - You'll learn as we assess!{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 80}")
        print("  GUIDED MODE FEATURES")
        print("=" * 80)
        print("✓ Detailed explanations of each security test")
        print("✓ Learn professional security assessment methodology")
        print("✓ Understand your security posture step-by-step")
        print("✓ Get actionable recommendations throughout")
        print("✓ Perfect for website owners, IT staff, and learners")
        print(f"{'=' * 80}{Colors.END}\n")
    
    time.sleep(1)
    print(f"\n{Colors.GREEN}{Colors.BOLD}🚀 Starting security assessment of {args.target}...{Colors.END}\n")
    time.sleep(1)
    
    # Run assessment with chosen mode
    pentest = PenTestFramework(
        args.target, 
        args.aggressive, 
        args.output,
        args.threads,
        args.timeout,
        guided_mode  # Use the mode chosen by user
    )
    pentest.run_assessment(args.url)

if __name__ == '__main__':
    main()