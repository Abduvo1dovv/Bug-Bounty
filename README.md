<![CDATA[<div align="center">

```
 ____                   ____                    _
| __ ) _   _  __ _    | __ )  ___  _   _ _ __ | |_ _   _
|  _ \| | | |/ _` |   |  _ \ / _ \| | | | '_ \| __| | | |
| |_) | |_| | (_| |   | |_) | (_) | |_| | | | | |_| |_| |
|____/ \__,_|\__, |   |____/ \___/ \__,_|_| |_|\__|\__, |
             |___/                                  |___/
    _                                _
   / \   _ __ ___  ___ _ __   __ _ | |
  / _ \ | '__/ __|/ _ \ '_ \ / _` || |
 / ___ \| |  \__ \  __/ | | | (_| || |
/_/   \_\_|  |___/\___|_| |_|\__,_||_|
```

# Bug Bounty Arsenal

### Complete Toolkit for Security Researchers

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)]()

*A curated collection of purpose-built security assessment tools for authorized bug bounty hunting and penetration testing.*

---

</div>

## Table of Contents

- [Overview](#overview)
- [Tools](#tools)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Output Example](#output-example)
- [Project Structure](#project-structure)
- [Author](#author)
- [Legal Disclaimer](#legal-disclaimer)

---

## Overview

Bug Bounty Arsenal is a modular collection of security research tools built in pure Python. Each tool is designed for a specific phase of the bug bounty workflow - from mobile app analysis to web reconnaissance and vulnerability discovery.

**Key Principles:**
- Minimal dependencies (only `colorama` for colored output)
- No external tool requirements (no apktool, no jadx, no nuclei)
- Professional report generation (JSON, Markdown, HTML)
- Passive/semi-passive by design - safe for authorized testing
- Built by hunters, for hunters

---

## Tools

| # | Tool | Description | Status |
|---|------|-------------|--------|
| 1 | [APK Analyzer](apk_analyzer/README.md) | Mobile app static analysis with DEX binary parsing | :white_check_mark: Ready |
| 2 | [Monster](monster/README.md) | Web reconnaissance & vulnerability scanner | :white_check_mark: Ready |
| 3 | [Super Monster](super_monster/README.md) | Elite mode - multi-target orchestration & advanced correlation | :white_check_mark: Ready |

---

### 1. APK Analyzer - Mobile App Static Analysis

> **[Full Documentation](apk_analyzer/README.md)**

Advanced APK security scanner with DEX binary parsing, vulnerability detection, CVE/CWE mapping, and known vulnerable library detection. No decompilation tools required.

**Highlights:**
- Pure Python DEX format parsing (no apktool/jadx needed)
- 19+ vulnerability categories with CVE/CWE references
- Known vulnerable library detection (OkHttp, Jackson, BouncyCastle, etc.)
- 30+ secret pattern detection (API keys, tokens, credentials)
- Multi-format reports (JSON, TXT, HTML)

```bash
python apk_analyzer/analyze.py target.apk
```

---

### 2. Monster - Web Reconnaissance & Vulnerability Scanner

> **[Full Documentation](monster/README.md)**

Comprehensive web reconnaissance and vulnerability assessment toolkit. Performs subdomain enumeration, JavaScript analysis, vulnerability scanning, parameter mining, and cookie security analysis.

**Highlights:**
- 5 integrated modules: Recon, JS Analysis, Vuln Scanner, Param Miner, Cookie Analyzer
- Scan profiles: quick, normal, deep, aggressive
- Cookie and proxy support for authenticated scanning
- Report templates for HackerOne, Bugcrowd, and Intigriti
- 23,000+ lines of assessment logic

```bash
python -m monster --target example.com --profile deep
```

---

### 3. Super Monster v2.0 - Elite Adaptive Bug Bounty Scanner

Next-generation adaptive scanner with inline verification. Classifies targets by domain type, applies targeted test methodology, and verifies every finding before reporting. Zero false positives, fast execution.

**Highlights:**
- Adaptive per-domain-type scanning (payment, auth, API, admin, CDN, web)
- Inline verification - every finding confirmed before reporting
- Real attack chain correlation (not noise)
- Fast execution (30-60 min for 47 domains vs 6 hours in v1)
- Honest reporting with three categories (Report, Investigate, Informational)
- No fake bounty estimates
- HackerOne-ready markdown reports

```bash
# Scan a single domain
python -m super_monster scan --target payment.tw.coupang.com

# Scan multiple targets from file
python -m super_monster scan --scope targets.txt -o ./results

# Dry run (show test plan without scanning)
python -m super_monster scan --target example.com --dry-run

# Re-analyze Monster output through v2 pipeline
python -m super_monster analyze --input ./monster_output/reports -o ./results
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/Bug-Bounty.git
cd Bug-Bounty

# Install dependencies
pip install -r requirements.txt

# Scan a web target
python -m monster --target example.com

# Analyze an APK
python apk_analyzer/analyze.py app.apk
```

---

## Installation

**Requirements:**
- Python 3.11 or higher
- pip (Python package manager)

```bash
# 1. Clone
git clone https://github.com/yourusername/Bug-Bounty.git
cd Bug-Bounty

# 2. Install dependencies (just colorama)
pip install -r requirements.txt

# 3. Verify installation
python -m monster --version
python -m monster --help
```

No additional system dependencies, external tools, or API keys required.

---

## Usage Examples

### Web Target Assessment

```bash
# Quick recon scan
python -m monster --target example.com --profile quick

# Full deep assessment
python -m monster --target example.com --profile deep --verbose

# Scan with authentication cookies
python -m monster --target example.com --cookies cookies.txt

# Through a proxy (Burp Suite)
python -m monster --target example.com --proxy http://127.0.0.1:8080

# Multiple targets from file
python -m monster --scope targets.txt --output ./results

# Dry run (no network, test config)
python -m monster --target example.com --dry-run
```

### Mobile App Analysis

```bash
# Full APK analysis
python apk_analyzer/analyze.py target.apk

# HTML report only
python apk_analyzer/analyze.py target.apk --format html

# Custom output name
python apk_analyzer/analyze.py target.apk -o my_report
```

---

## Output Example

```
  __  __  ___  _  _ ___ _____ ___ ___
 |  \/  |/ _ \| \| / __|_   _| __| _ \
 | |\/| | (_) | .` \__ \ | | | _||   /
 |_|  |_|\___/|_|\_|___/ |_| |___|_|_\

  Bug Bounty Recon & Vulnerability Assessment Toolkit
  Version 2.0.0

[*] Target: example.com
[*] Profile: deep
[*] Modules: recon, js, vuln, param, cookie

[=== RECONNAISSANCE ===]
[+] Subdomain enumeration...
[+] Found: api.example.com
[+] Found: staging.example.com
[+] DNS records collected
[+] Technology fingerprinting complete

[=== JAVASCRIPT ANALYSIS ===]
[+] Analyzing 12 JavaScript files...
[+] Found 3 API endpoints
[+] Found 1 potential secret

[=== VULNERABILITY SCANNING ===]
[!] [HIGH] Missing security headers on api.example.com
[!] [MEDIUM] CORS misconfiguration detected
[+] XSS checks complete

[=== RESULTS ===]
[+] Total findings: 7
[+] Critical: 0 | High: 2 | Medium: 3 | Low: 2
[+] Reports saved to ./monster_output/reports/
```

---

## Project Structure

```
Bug-Bounty/
|-- README.md                  # This file
|-- requirements.txt           # Python dependencies
|-- .gitignore                 # Git ignore rules
|
|-- apk_analyzer/              # Tool 1: Mobile APK Analysis
|   |-- README.md
|   |-- analyze.py             # Main analyzer (4,492 lines)
|   +-- requirements.txt
|
|-- monster/                   # Tool 2: Web Recon & Vuln Scanner
|   |-- README.md
|   |-- __init__.py            # Package init + version
|   |-- __main__.py            # Entry point (python -m monster)
|   |-- main.py                # CLI orchestration
|   |-- config.py              # Configuration constants
|   |-- utils.py               # Shared utilities
|   |-- recon.py               # Reconnaissance module
|   |-- js_analyzer.py         # JavaScript analysis
|   |-- vuln_scanner.py        # Vulnerability scanning
|   |-- param_miner.py         # Parameter discovery
|   |-- cookie_manager.py      # Cookie security analysis
|   |-- report_generator.py    # Report generation (JSON/MD/HTML)
|   +-- wordlists/
|       +-- subdomains.txt     # Subdomain wordlist
|
|-- super_monster/             # Tool 3: Elite Adaptive Bug Bounty Scanner v2.0
|   |-- __init__.py            # Package init + VERSION
|   |-- __main__.py            # Entry point (python -m super_monster)
|   |-- main.py                # CLI orchestrator
|   |-- config.py              # Domain types, scan rules, colors
|   |-- domain_classifier.py   # Smart domain classification
|   |-- smart_scanner.py       # Adaptive scanner with inline verification
|   |-- verifier.py            # Finding verification engine
|   |-- correlator.py          # Real attack chain correlation
|   +-- reporter.py            # Clean, honest reporting (JSON/MD)
|
+-- monster_output/            # Default output directory
    +-- reports/               # Generated reports
```

---

## Author

**Monster Security Team**

Built with purpose for the bug bounty community. Contributions welcome.

---

## Legal Disclaimer

> **This toolkit is intended for authorized security testing only.**

- Only use these tools against systems you have explicit written permission to test
- Comply with all applicable bug bounty program rules and scope definitions
- Follow responsible disclosure practices
- The authors are not responsible for misuse or damage caused by this toolkit
- Unauthorized access to computer systems is illegal in most jurisdictions

**Supported platforms for authorized testing:**
- HackerOne programs
- Bugcrowd programs
- Intigriti programs
- Private bug bounty programs with written authorization
- Your own infrastructure

---

<div align="center">

*Happy hunting. Stay ethical. Get bounties.*

</div>
]]>