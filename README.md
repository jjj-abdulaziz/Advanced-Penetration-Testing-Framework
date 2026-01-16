# 🔓 Decypher - Advanced Penetration Testing Framework

<div align="center">

```
  ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ 
  ██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗
  ██║  ██║█████╗  ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝
  ██║  ██║██╔══╝  ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
  ██████╔╝███████╗╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║
  ╚═════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**Unveil Hidden Vulnerabilities | Map Complete Networks | Generate Actionable Reports**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/yourusername/Advanced-Penetration-Testing-Framework)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen.svg)](https://github.com/yourusername/Advanced-Penetration-Testing-Framework/graphs/commit-activity)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

Decypher is designed exclusively for security professionals and authorized penetration testers. Unauthorized access to computer systems is **illegal** under various laws including the Computer Fraud and Abuse Act (CFAA) and similar legislation worldwide.

**You must obtain explicit written permission before testing any target.**

Users assume all legal responsibility for the use of this tool.

---

## 🎯 What is Decypher?

Decypher is a professional-grade, comprehensive penetration testing framework that automates the reconnaissance, vulnerability scanning, and network mapping phases of security assessments. Built for efficiency and thoroughness, it combines multiple testing methodologies into a single, powerful tool.

### Why Decypher?

- 🚀 **Fast** - Multi-threaded scanning with configurable performance
- 🎯 **Comprehensive** - Tests for 10+ vulnerability categories
- 📊 **Professional Reports** - HTML, JSON, and command outputs
- 🛠️ **Tool Integration** - Generates commands for Nmap, SQLMap, Nuclei, and more
- 🌐 **Network Mapping** - Complete network intelligence gathering
- 💻 **Cross-Platform** - Works on Linux, Windows, and macOS

---

## ✨ Features

### 🌐 Network Intelligence & Mapping
- **IP Resolution & Analysis** - Resolves hostnames to IPs with network classification
- **Reverse DNS Lookup** - Discovers associated hostnames and records
- **Network Class Detection** - Identifies private vs public networks automatically
- **Local Network Discovery** - Maps active hosts on local subnets
- **OS Fingerprinting** - TTL-based operating system detection
- **Banner Grabbing** - Service version identification

### 🔍 Comprehensive Reconnaissance
- **Fast Port Scanning** - Multi-threaded scanning of 1-1000 ports
- **Service Detection** - Identifies services running on open ports
- **Subdomain Enumeration** - Discovers subdomains automatically (25+ common patterns)
- **Web Application Spidering** - Crawls and maps complete website structure
- **Email Harvesting** - Extracts email addresses from web content
- **Technology Stack Detection** - Identifies CMS, frameworks, JavaScript libraries with versions

### 🔎 Active Enumeration
- **Sensitive File Detection** - Scans for 40+ common sensitive files:
  - Configuration files (.env, .git, web.config)
  - Backup files (.sql, .zip, database dumps)
  - Hidden directories (.git, .svn, .DS_Store)
  - Development files (composer.json, package.json, Dockerfile)
- **Directory Bruteforcing** - Discovers 40+ common hidden directories
- **API Endpoint Discovery** - Finds REST APIs, GraphQL, Swagger docs
- **Parameter Extraction** - Tracks all URL parameters for testing

### 🛡️ Security Configuration Analysis
- **Security Headers** - Comprehensive analysis of 6+ critical headers:
  - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - Referrer-Policy, Permissions-Policy
- **CORS Misconfiguration Detection** - Tests for insecure CORS policies
- **HTTP Methods Testing** - Checks for dangerous methods (PUT, DELETE, TRACE)
- **SSL/TLS Analysis** - Protocol version testing and certificate validation
- **Information Disclosure** - Detects revealing headers and responses

### 🎯 Vulnerability Testing
- **SQL Injection** 
  - Error-based detection with 10+ payloads
  - Time-based blind SQLi testing
  - Automatic SQLMap command generation
- **Cross-Site Scripting (XSS)**
  - Reflected XSS with multiple payload types
  - Encoding bypass techniques
  - DOM-based XSS detection
- **Command Injection** - OS command execution testing
- **Server-Side Request Forgery (SSRF)** - Internal network access testing
- **Local File Inclusion (LFI)** - Path traversal vulnerability detection
- **Authentication Bypass** - Common authentication vulnerability testing

### 📊 Professional Reporting
- **Real-Time Console Output** - Color-coded, organized results with progress indicators
- **JSON Reports** - Complete machine-readable data export
- **Interactive HTML Reports** - Beautiful reports featuring:
  - Executive summary with risk scoring
  - Complete URL listing (collapsible sections)
  - Subdomain discovery results
  - Harvested email addresses
  - Open ports and services table
  - Vulnerability details with remediation steps
- **Command Generation** - Ready-to-use commands for:
  - Nmap, Nuclei, SQLMap, Nikto
  - WPScan, Gobuster, FFuF
  - Metasploit modules
  - Burp Suite testing guidance

### ⚡ Performance & Reliability
- **Multi-threaded Architecture** - Configurable thread count (default: 10)
- **Smart Rate Limiting** - Configurable timeouts to respect target systems
- **Graceful Error Handling** - Continues scanning even if individual tests fail
- **Interrupt Handling** - Generates reports even if scan is interrupted (Ctrl+C)
- **Progress Tracking** - Real-time progress indicators and timing

---

## 🚀 Installation

### Prerequisites

- **Python 3.7+** 
- **pip** (Python package installer)
- **Internet connection** (for target scanning)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework.git
cd Advanced-Penetration-Testing-Framework

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 decypher.py --help
```

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Platform-Specific Installation

<details>
<summary><b>🐧 Linux (Ubuntu/Debian)</b></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip git -y
git clone https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework.git
cd Advanced-Penetration-Testing-Framework
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Using Homebrew
brew install python3 git
git clone https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework.git
cd Advanced-Penetration-Testing-Framework
pip3 install -r requirements.txt
```
</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# Install Python from python.org, then:
git clone https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework.git
cd Advanced-Penetration-Testing-Framework
pip install -r requirements.txt
```
</details>

<details>
<summary><b>🔪 Kali Linux</b></summary>

```bash
# Python 3 pre-installed
git clone https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework.git
cd Advanced-Penetration-Testing-Framework
pip3 install -r requirements.txt
```
</details>

---

## 📖 Usage

### Basic Scan

```bash
python3 decypher.py example.com
```

### Common Use Cases

```bash
# Scan specific URL
python3 decypher.py example.com -u https://example.com/app

# Aggressive mode with more threads
python3 decypher.py example.com -a -t 20

# Custom timeout and output file
python3 decypher.py example.com --timeout 5 -o myscan.json

# Scan IP address with aggressive mode
python3 decypher.py 192.168.1.1 -a

# Fast scan (high threads, low timeout)
python3 decypher.py example.com -t 50 --timeout 3
```

### Command-Line Arguments

```
positional arguments:
  target                    Target hostname or IP address

optional arguments:
  -h, --help                Show help message and exit
  -u URL, --url URL         Specific URL to test
  -a, --aggressive          Enable aggressive testing mode
  -t THREADS                Number of threads (default: 10)
  --timeout TIMEOUT         Request timeout in seconds (default: 10)
  -o OUTPUT, --output FILE  Output report file (default: decypher_report.json)
```

### Advanced Examples

```bash
# Full subnet scan (use with caution and authorization)
python3 decypher.py 192.168.1.0/24 -a -t 30

# Target specific ports range (modify code for custom ports)
python3 decypher.py example.com -t 20

# Generate only reports without aggressive testing
python3 decypher.py example.com -o report.json

# Test specific web application
python3 decypher.py example.com -u https://example.com/admin/ -a
```

---

## 📂 Output Files

After each scan, Decypher generates three files:

### 1. JSON Report (`decypher_report.json`)
Complete scan data in machine-readable format:
```json
{
  "target": "example.com",
  "vulnerabilities": [...],
  "discovered_urls": [...],
  "open_ports": [...],
  "subdomains": [...],
  "technologies": {...}
}
```

### 2. HTML Report (`decypher_report.html`)
Interactive web report with:
- Executive summary
- Risk assessment
- Complete findings
- Visual vulnerability breakdown
- Collapsible sections for URLs and data

### 3. Commands File (`decypher_report_commands.txt`)
Ready-to-execute commands for deeper testing with tools like:
- Nmap
- Nuclei
- SQLMap
- Nikto
- WPScan
- Gobuster
- Metasploit

---

## 🎬 Example Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║  PHASE 0: NETWORK MAPPING & INTELLIGENCE                                ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─ Network Mapping & Host Discovery
  ℹ Target IP: 93.184.216.34
  ℹ Reverse DNS: example.com
  ✓ Network mapping complete

╔══════════════════════════════════════════════════════════════════════════╗
║  PHASE 1: NETWORK RECONNAISSANCE                                        ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─ Port Scanning
  ℹ Scanning ports 1-1000...
  ℹ Port 80 open - HTTP
  ℹ Port 443 open - HTTPS
  ✓ Found 2 open ports

SEVERITY BREAKDOWN
────────────────────────────────────────────────────────────────────────────

  🔴 CRITICAL: 0  (Immediate action required)
  🟠 HIGH:     2  (Urgent remediation needed)
  🟡 MEDIUM:   5  (Should be addressed)
  🟢 LOW:      3  (Minor issues)

RECOMMENDED TOOLS FOR DEEPER TESTING
────────────────────────────────────────────────────────────────────────────

┌─ Nmap (Network Scanner)
  $ nmap -sV -sC -p 80,443 example.com
  $ nmap -sV --script=vuln -p 80,443 example.com

┌─ Nuclei (Vulnerability Scanner)
  $ nuclei -u https://example.com -severity critical,high,medium
```

---

## 📚 Documentation

### Scanning Phases

Decypher executes a comprehensive 6-phase assessment:

**Phase 0: Network Mapping**
- IP resolution and classification
- Reverse DNS lookup
- Network class detection
- OS fingerprinting

**Phase 1: Network Reconnaissance**
- Port scanning (1-1000)
- Service detection
- Subdomain enumeration
- Banner grabbing

**Phase 2: Information Gathering**
- Technology stack detection
- Web application spidering
- Email harvesting
- CMS/Framework identification

**Phase 3: Active Enumeration**
- Sensitive file detection
- Directory bruteforcing
- API endpoint discovery
- Parameter extraction

**Phase 4: Security Configuration**
- Security headers analysis
- CORS configuration testing
- SSL/TLS analysis
- HTTP methods testing

**Phase 5: Vulnerability Testing**
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- SSRF
- LFI/Path Traversal

**Phase 6: Report Generation**
- Executive summary
- Risk assessment
- Tool command generation
- Multi-format exports

### Performance Tuning

**Threads** (`-t` flag)
- **Low (5-10)**: Stealthy, less likely to trigger IDS/IPS
- **Medium (10-20)**: Balanced speed and stealth
- **High (20-50)**: Fast scanning, may trigger alarms

**Timeout** (`--timeout` flag)
- **Low (3-5s)**: Fast but may miss slow servers
- **Medium (10s)**: Default, balanced
- **High (15-30s)**: Thorough but slower

**Mode**
- **Standard**: Balanced reconnaissance and testing
- **Aggressive** (`-a`): Includes auth bypass attempts and deeper testing

---

## 🛠️ Tool Integration

Decypher automatically generates commands for industry-standard tools:

### Nmap
```bash
nmap -sV -sC -p 80,443,8080 example.com
nmap -sV --script=vuln -p 80,443 example.com
nmap -O example.com  # OS detection
```

### Nuclei
```bash
nuclei -u https://example.com -severity critical,high,medium
nuclei -u https://example.com -t cves/ -t vulnerabilities/
```

### SQLMap
```bash
sqlmap -u 'https://example.com/page?id=1' --batch --risk=3 --level=5
sqlmap -u 'https://example.com/page?id=1' --dbs
```

### Metasploit
```bash
use auxiliary/scanner/http/http_version
use auxiliary/scanner/smb/smb_version
use exploit/windows/smb/ms17_010_eternalblue
```

---

## 🤝 Contributing

We welcome contributions from the security community!

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Contribution Guidelines

- Follow PEP 8 style guide
- Add comments for complex logic
- Test on multiple targets
- Update documentation
- Ensure ethical use cases only

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 🔐 Security Best Practices

When using Decypher:

1. ✅ **Always obtain written authorization**
2. ✅ **Test in isolated environments** when possible
3. ✅ **Respect rate limits** - use appropriate thread counts
4. ✅ **Document all findings** professionally
5. ✅ **Follow responsible disclosure** for vulnerabilities
6. ✅ **Keep the tool updated**
7. ❌ **Never test without permission**
8. ❌ **Don't use for malicious purposes**

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Additional Terms for Security Tools

This tool is provided for **AUTHORIZED SECURITY TESTING ONLY**. Users must:
- Obtain explicit written authorization before testing
- Ensure legal compliance in their jurisdiction
- Use only for lawful purposes
- Accept all liability for misuse

---

## 🙏 Acknowledgments

- OWASP for web security methodology
- The security research community
- All contributors and testers
- Open-source security tool developers

---

## 📞 Support & Contact

- **Issues**: [Open an issue](https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework/discussions)
- **Documentation**: Check the [Wiki](https://github.com/jjj-abdulaziz/Advanced-Penetration-Testing-Framework/wiki)

---

## 🔖 Version History

### v2.0.0 (Current)
- 🌐 Complete network mapping and intelligence
- 🔍 OS fingerprinting and banner grabbing
- 🗺️ Local network scanning capabilities
- 📊 Enhanced HTML reporting with interactive elements
- 🛠️ Automatic tool command generation
- ⚡ Improved multi-threading performance
- 🎯 Extended vulnerability testing suite

### v1.0.0
- Initial release
- Basic reconnaissance and vulnerability scanning

---

## ⭐ Star History

If you find Decypher useful, please consider starring the repository!

---

<div align="center">

**Made with ❤️ for the security community**

**Use responsibly. Stay legal. Keep learning.**

[⬆ Back to Top](#-decypher---advanced-penetration-testing-framework)

</div>
