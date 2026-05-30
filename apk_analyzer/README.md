# APK Deep Analyzer v2.0

Advanced APK security scanner with **DEX binary parsing**, **vulnerability detection**,
**CVE/CWE mapping**, and **known vulnerable library detection**.

No decompilation tools required (`apktool`, `jadx`, `dex2jar` NOT needed).
Pure Python binary parsing of DEX format structures.

## Features

### 1. DEX Deep Parser (no decompilation)
- Parses DEX file format headers (magic, checksum, signature)
- Extracts all string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs
- Resolves full class names, method references, field references
- Detects obfuscated vs non-obfuscated classes (obfuscation score)
- Cross-references which classes call which methods

### 2. Vulnerability Detection with CVE/CWE Mapping

| Category | Detection | Reference |
|----------|-----------|-----------|
| Insecure Crypto | DES, 3DES, RC4, MD5, ECB mode, static IV/key | CWE-327, CWE-321 |
| Weak SSL/TLS | TrustAll, AllowAllHostname, no verification | CVE-2014-3566, CWE-295 |
| SQL Injection | rawQuery, execSQL with concat | CWE-89 |
| Path Traversal | Unsanitized file ops, "../" | CWE-22 |
| Insecure WebView | JS+Interface, file access | CVE-2012-6636, CWE-749 |
| Data Storage | MODE_WORLD_READABLE, plaintext creds | CWE-312 |
| Intent Injection | Implicit intents, exported | CWE-927 |
| Clipboard Leak | ClipboardManager sensitive data | CWE-200 |
| Insecure Random | java.util.Random for crypto | CWE-330 |
| Hardcoded Keys | Static keys near Cipher/SecretKeySpec | CWE-321 |
| Logging | Log.d/v/i with sensitive data | CWE-532 |
| Backup Vuln | allowBackup=true | CWE-921 |
| Debuggable | debuggable=true in production | CWE-489 |
| Tapjacking | No filterTouchesWhenObscured | CWE-1021 |
| Deep Link Abuse | Unvalidated deep links | CWE-939 |
| Fragment Injection | Exported PreferenceActivity | CVE-2013-6271 |
| Zip Slip | ZipEntry without path validation | CWE-22 |
| Deserialization | ObjectInputStream no validation | CWE-502 |
| Command Injection | Runtime.exec / ProcessBuilder | CWE-78 |

### 3. Known Vulnerable Library Detection
- OkHttp < 3.12.1 (CVE-2018-20200)
- Apache HttpClient (CVE-2014-3577)
- BouncyCastle old versions (CVE-2018-1000613)
- Jackson-databind (CVE-2020-36518)
- Gson < 2.8.9 (CVE-2022-25647)
- Facebook SDK, Firebase, Glide, Picasso, Retrofit, Volley
- Butterknife, EventBus, Dagger

### 4. Additional Analysis
- Certificate/signing info extraction (META-INF/)
- 30+ secret pattern detection (API keys, tokens, credentials)
- Analytics/tracking SDK detection (Firebase, Facebook, Mixpanel, Amplitude, etc.)
- Anti-debugging/anti-root check detection
- Obfuscation level scoring (0-100%)
- Network security analysis
- Exported component analysis

### 5. Reporting
- **JSON** - Machine-readable, full details
- **TXT** - Human-readable with executive summary for bug bounty reports
- **HTML** - Visual report with colored severity badges, dark theme

Each finding includes:
- Severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- CVE/CWE identifier
- CVSS score estimate
- Affected class/method
- Description, remediation, confidence level

## Installation

```bash
pip install -r requirements.txt
```

Only `colorama` is used (optional, for colored terminal output).
No other dependencies needed - pure Python standard library.

## Usage

```bash
# Basic scan (generates all report formats)
python analyze.py app.apk

# Custom output prefix
python analyze.py app.apk -o my_report

# Specific format only
python analyze.py app.apk --format html
python analyze.py app.apk --format json
python analyze.py app.apk --format txt

# Quiet mode (no terminal output)
python analyze.py app.apk --quiet

# Adjust string extraction sensitivity
python analyze.py app.apk --min-len 8
```

Output files:
- `<name>.report.json` - Full JSON report
- `<name>.report.txt` - Text report with executive summary
- `<name>.report.html` - Visual HTML report

## Report Structure

```
[RISK SCORE] 75/100

[DEX ANALYSIS]
  classes.dex: 5420 classes, 48210 methods, 22105 fields
  Obfuscation: 34.2%

[VULNERABLE LIBRARIES]
  - OkHttp (< 3.12.1)
  - Jackson Databind

[TRACKING SDKs]
  - Firebase Analytics
  - Facebook Analytics

[FINDINGS]
  [CRITICAL] Trust All Certificates [CWE-295] CVSS:9.1
  [HIGH] Hardcoded Cryptographic Key [CWE-321] CVSS:9.1
  ...
```

## How It Works

1. Opens APK as ZIP archive
2. Parses DEX binary format (header, string pool, type/proto/field/method/class tables)
3. Extracts binary AndroidManifest.xml string pool
4. Runs vulnerability patterns against DEX structures
5. Matches class paths against known vulnerable library signatures
6. Scans string data for hardcoded secrets/credentials
7. Generates multi-format reports

## Bug Bounty Tips

Priority findings for reports:
1. **CRITICAL/HIGH vulnerabilities** with CVE references (strongest impact)
2. **Hardcoded API keys/secrets** - if production keys, high severity
3. **Trust All Certificates / No hostname verification** - MITM possible
4. **Cleartext HTTP endpoints** - traffic interception
5. **Debuggable=true** in release build - debugger attachment
6. **Known vulnerable libraries** - reference specific CVEs
7. **Exported components without permissions** - unauthorized access

## Ethics

Use this tool only on applications you have authorization to test
(HackerOne, Bugcrowd, etc.). Report findings responsibly according
to the program's scope and disclosure policy.
