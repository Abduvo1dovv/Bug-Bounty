<![CDATA[<div align="center">

```
  __  __  ___  _  _ ___ _____ ___ ___
 |  \/  |/ _ \| \| / __|_   _| __| _ \
 | |\/| | (_) | .` \__ \ | | | _||   /
 |_|  |_|\___/|_|\_|___/ |_| |___|_|_\
```

# Monster v2.0.0

### Bug Bounty Reconnaissance & Vulnerability Assessment Toolkit

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Lines of Code](https://img.shields.io/badge/Lines-23%2C075-orange.svg)]()
[![Modules](https://img.shields.io/badge/Modules-5-purple.svg)]()

</div>

---

**[<< Back to Main README](../README.md)**

---

## Table of Contents

- [Overview](#overview)
- [Modules](#modules)
- [Installation](#installation)
- [CLI Options](#cli-options)
- [Scan Profiles](#scan-profiles)
- [Usage Examples](#usage-examples)
- [Output Structure](#output-structure)
- [Cookie Management](#cookie-management)
- [Configuration File](#configuration-file)
- [Report Formats](#report-formats)

---

## Overview

Monster is a comprehensive passive/semi-passive web security assessment toolkit designed for bug bounty hunters. It integrates reconnaissance, JavaScript analysis, vulnerability scanning, parameter discovery, and cookie security analysis into a single workflow with professional report generation.

**Design philosophy:**
- Passive-first approach (safe for authorized testing)
- Modular architecture (run only what you need)
- Zero external tool dependencies (pure Python + colorama)
- Professional output (HackerOne/Bugcrowd/Intigriti report templates)
- Configurable rate limiting and proxy support

---

## Modules

### 1. Reconnaissance (`recon.py`)

Subdomain enumeration, DNS resolution, technology fingerprinting, and target mapping.

| Feature | Description |
|---------|-------------|
| Subdomain Enumeration | Wordlist-based + pattern generation |
| DNS Resolution | A, AAAA, CNAME, MX, TXT, NS records |
| Technology Detection | Server headers, meta tags, response patterns |
| Port Scanning | Common web ports (80, 443, 8080, 8443, etc.) |
| WAF Detection | Identify web application firewalls |
| CMS Fingerprinting | WordPress, Joomla, Drupal, etc. |
| SSL/TLS Analysis | Certificate info, protocol versions |
| HTTP Method Discovery | OPTIONS-based method enumeration |

### 2. JavaScript Analysis (`js_analyzer.py`)

Deep analysis of JavaScript files for sensitive data, API endpoints, and security issues.

| Feature | Description |
|---------|-------------|
| Endpoint Extraction | API routes, internal URLs, admin paths |
| Secret Detection | API keys, tokens, passwords, AWS keys |
| Source Map Analysis | Check for exposed .map files |
| Framework Detection | React, Angular, Vue, jQuery versions |
| DOM Sink Analysis | Potential DOM-XSS sink identification |
| Dependency Extraction | Third-party library detection |
| Webpack Chunk Analysis | Parse webpack manifests for routes |
| Inline Config Extraction | JSON configs embedded in JS |

### 3. Vulnerability Scanner (`vuln_scanner.py`)

Active and passive vulnerability detection with CVE/CWE mapping.

| Feature | Description |
|---------|-------------|
| Security Headers | Missing/misconfigured headers (CSP, HSTS, X-Frame) |
| CORS Misconfiguration | Origin reflection, null origin, wildcard |
| Open Redirect | Parameter-based and path-based redirects |
| SSRF Indicators | Internal URL patterns, cloud metadata |
| Information Disclosure | Error pages, stack traces, version exposure |
| Subdomain Takeover | Dangling CNAME detection |
| HTTP Verb Tampering | PUT, DELETE, PATCH, TRACE checks |
| Cookie Security | Missing Secure/HttpOnly/SameSite flags |
| CRLF Injection | Header injection via response splitting |
| Host Header Injection | Virtual host routing abuse |

### 4. Parameter Miner (`param_miner.py`)

Hidden parameter discovery and input analysis.

| Feature | Description |
|---------|-------------|
| Parameter Bruteforce | Wordlist-based hidden parameter discovery |
| Reflection Detection | Input reflected in response (XSS candidates) |
| Parameter Pollution | HPP vulnerability testing |
| Content-Type Switching | JSON/XML/form-data parameter testing |
| Rate Limit Detection | Identify rate-limited endpoints |
| Cache Key Discovery | Cache-based parameter deduction |
| Mass Assignment | Object property injection testing |
| IDOR Patterns | Sequential/predictable ID detection |

### 5. Cookie Manager (`cookie_manager.py`)

Cookie security analysis and session management testing.

| Feature | Description |
|---------|-------------|
| Attribute Analysis | Secure, HttpOnly, SameSite, Path, Domain |
| Session Fixation | Pre/post-auth cookie rotation checks |
| Cookie Scope | Overly broad domain/path scoping |
| Entropy Analysis | Session token randomness assessment |
| Expiration Policy | Long-lived session detection |
| Third-Party Cookies | Tracking cookie identification |
| Cookie Jar Management | Load/save cookies between scan runs |
| Authentication Flow | Maintain authenticated sessions |

---

## Installation

```bash
# From the repository root
cd Bug-Bounty
pip install -r requirements.txt

# Verify
python -m monster --version
python -m monster --help
```

**Dependencies:** Only `colorama>=0.4.6` (for colored terminal output).

---

## CLI Options

```
usage: monster [-h] [--target URL] [--scope FILE] [--apk FILE]
               [--module MODULE] [--profile PROFILE]
               [--output DIR] [--format FORMAT] [--verbose] [--no-color]
               [--delay SECONDS] [--threads N] [--timeout SECONDS]
               [--proxy URL] [--cookies FILE] [--cookie-jar FILE]
               [--dry-run] [--resume] [--exclude PATTERNS]
               [--webhook URL] [--config FILE] [--interactive]
               [--version]
```

### Target Options

| Flag | Description |
|------|-------------|
| `--target, -t URL` | Single target domain or URL |
| `--scope, -s FILE` | File containing list of targets (one per line) |
| `--apk FILE` | APK file path for mobile app analysis |

### Module Options

| Flag | Description |
|------|-------------|
| `--module, -m MODULE` | Modules to run: `all`, `recon`, `js`, `vuln`, `param`, `cookie`, `report` |
| `--profile PROFILE` | Scan profile: `quick`, `normal`, `deep`, `aggressive` |

### Output Options

| Flag | Description |
|------|-------------|
| `--output, -o DIR` | Output directory (default: `./monster_output`) |
| `--format FORMAT` | Report format: `json`, `md`, `html`, `all` |
| `--verbose, -v` | Enable verbose output |
| `--no-color` | Disable colored terminal output |

### Performance Options

| Flag | Description |
|------|-------------|
| `--delay SECONDS` | Rate limit delay between requests |
| `--threads N` | Maximum concurrent threads |
| `--timeout SECONDS` | HTTP request timeout |

### Network Options

| Flag | Description |
|------|-------------|
| `--proxy URL` | HTTP/SOCKS proxy (e.g., `http://127.0.0.1:8080`) |
| `--cookies FILE` | Load cookies from file (Netscape or JSON format) |
| `--cookie-jar FILE` | Save and load cookies between scan runs |

### Scan Behavior

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate scan without making network requests |
| `--resume` | Skip already-scanned targets from previous runs |
| `--exclude PATTERNS` | Comma-separated patterns to exclude |

### Notifications

| Flag | Description |
|------|-------------|
| `--webhook URL` | Webhook URL for real-time finding notifications (POST) |

### Configuration

| Flag | Description |
|------|-------------|
| `--config FILE` | Path to config file (default: `.monsterrc`) |
| `--interactive` | Run in interactive mode with guided prompts |
| `--version` | Show version and exit |

---

## Scan Profiles

| Profile | Modules | Threads | Delay | Description |
|---------|---------|---------|-------|-------------|
| `quick` | recon | 5 | 0.5s | Fast initial assessment |
| `normal` | recon, js, vuln | 10 | 1.0s | Balanced scan (default) |
| `deep` | recon, js, vuln, param, cookie | 5 | 2.0s | Thorough analysis, slower |
| `aggressive` | recon, js, vuln, param, cookie | 20 | 0.2s | Fast full scan, noisy |

---

## Usage Examples

### Basic Scanning

```bash
# Single target with default profile
python -m monster --target example.com

# Quick recon only
python -m monster --target example.com --profile quick

# Deep scan with verbose output
python -m monster --target example.com --profile deep --verbose

# Specific modules only
python -m monster --target example.com --module recon,js
```

### Multiple Targets

```bash
# Create a scope file
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "target3.com" >> targets.txt

# Scan all targets
python -m monster --scope targets.txt --output ./results
```

### Authenticated Scanning

```bash
# With cookie file
python -m monster --target example.com --cookies cookies.txt

# With cookie jar (persists between runs)
python -m monster --target example.com --cookie-jar session.json
```

### Through a Proxy

```bash
# Burp Suite proxy
python -m monster --target example.com --proxy http://127.0.0.1:8080

# SOCKS proxy (Tor)
python -m monster --target example.com --proxy socks5://127.0.0.1:9050
```

### Report Generation

```bash
# JSON only
python -m monster --target example.com --format json

# HTML only (interactive report)
python -m monster --target example.com --format html

# All formats
python -m monster --target example.com --format all
```

### Advanced Options

```bash
# Custom rate limiting
python -m monster --target example.com --delay 2.0 --threads 3

# Exclude specific patterns
python -m monster --target example.com --exclude "*.staging.*,admin.*"

# Resume a previous scan
python -m monster --target example.com --resume

# Dry run (test configuration without network)
python -m monster --target example.com --dry-run

# Webhook notifications for critical findings
python -m monster --target example.com --webhook https://hooks.slack.com/xxx
```

---

## Output Structure

```
monster_output/
+-- reports/
    |-- monster_report_example.com_20260531_120000.json   # Full JSON data
    |-- monster_report_example.com_20260531_120000.md     # Markdown report
    +-- monster_report_example.com_20260531_120000.html   # Interactive HTML
```

### JSON Report Contents

```json
{
  "metadata": {
    "target": "example.com",
    "scan_date": "2026-05-31T12:00:00",
    "version": "2.0.0",
    "profile": "deep",
    "modules_run": ["recon", "js", "vuln", "param", "cookie"]
  },
  "summary": {
    "total_findings": 7,
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 2
  },
  "findings": [
    {
      "title": "Missing Content-Security-Policy Header",
      "severity": "MEDIUM",
      "category": "Security Headers",
      "cwe": "CWE-693",
      "url": "https://example.com",
      "description": "...",
      "remediation": "...",
      "evidence": "..."
    }
  ],
  "recon_data": { ... },
  "js_analysis": { ... }
}
```

### HTML Report Features

- Interactive finding table with sort/filter
- Severity badges with color coding
- Collapsible sections for each module
- Executive summary with statistics
- Dark theme professional styling

---

## Cookie Management

### Loading Cookies

Monster supports two cookie file formats:

**Netscape format (cookies.txt):**
```
# Netscape HTTP Cookie File
.example.com	TRUE	/	TRUE	0	session_id	abc123def456
.example.com	TRUE	/	FALSE	0	csrf_token	xyz789
```

**JSON format:**
```json
[
  {
    "name": "session_id",
    "value": "abc123def456",
    "domain": ".example.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  }
]
```

### Cookie Jar (Persistent Sessions)

Use `--cookie-jar` to maintain session state across multiple scan runs:

```bash
# First run - cookies are saved
python -m monster --target example.com --cookies login_cookies.txt --cookie-jar session.json

# Subsequent runs - cookies are loaded automatically
python -m monster --target example.com --cookie-jar session.json
```

---

## Configuration File

Create a `.monsterrc` file in your working directory or home directory:

```json
{
  "module": "all",
  "profile": "normal",
  "output": "./monster_output",
  "delay": 1.0,
  "threads": 10,
  "timeout": 15,
  "verbose": false,
  "format": "all",
  "proxy": null,
  "exclude": "",
  "webhook": null
}
```

**Priority order:** CLI flags > config file > scan profile > defaults

---

## Report Formats

Monster generates reports compatible with major bug bounty platforms:

| Format | Description |
|--------|-------------|
| JSON | Machine-readable, full scan data |
| Markdown | Human-readable with tables and sections |
| HTML | Interactive web report with filtering |
| HackerOne Template | Formatted for HackerOne submissions |
| Bugcrowd Template | Formatted for Bugcrowd submissions |
| Intigriti Template | Formatted for Intigriti submissions |

---

## Tips for Bug Bounty

1. **Start with `quick` profile** to map the attack surface
2. **Use `deep` profile** on interesting targets identified in recon
3. **Always use `--cookies`** for authenticated testing (more findings behind auth)
4. **Route through Burp** with `--proxy` to capture traffic for manual testing
5. **Check the HTML report** for an overview, then drill into JSON for details
6. **Use `--exclude`** to stay within program scope
7. **Run `--resume`** when re-scanning after fixes are deployed

---

**[<< Back to Main README](../README.md)**
]]>