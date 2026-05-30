"""
Monster - Passive Vulnerability Scanner.

Performs intelligent passive and semi-passive vulnerability detection including
CORS misconfiguration, security header analysis, cookie auditing, subdomain
takeover detection, SSL/TLS analysis, CSP bypass analysis, and more.
NO active exploitation.
"""

import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

from monster.config import (
    CORS_TEST_ORIGINS,
    INFO_DISCLOSURE_PATHS,
    REDIRECT_PARAMS,
    SECURITY_HEADERS,
    TAKEOVER_FINGERPRINTS,
)
from monster.utils import (
    ColorOutput,
    DNSResolver,
    FileManager,
    HTTPClient,
    RateLimiter,
    domain_from_url,
    normalize_url,
)


# ---------------------------------------------------------------------------
# Finding Data Structure
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    url: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# VulnScanner Class
# ---------------------------------------------------------------------------

class VulnScanner:
    """Passive vulnerability scanner for web targets."""

    def __init__(self, targets, subdomains_data=None, output_dir="./output",
                 rate_limit=1.0, timeout=10, dry_run=False):
        self.targets = targets if targets else []
        self.subdomains_data = subdomains_data or {}
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.findings: List[Finding] = []
        self.http = HTTPClient(timeout=timeout, rate_limit=rate_limit,
                               verify_ssl=False)
        self.file_mgr = FileManager(output_dir)

    def run(self):
        """Execute all vulnerability checks against all targets."""
        ColorOutput.info("Starting passive vulnerability scan...")

        if self.dry_run:
            ColorOutput.warning("DRY-RUN mode: no network calls will be made")
            for target in self.targets:
                ColorOutput.info(f"Would scan: {target}")
            return self.findings

        for i, target in enumerate(self.targets, 1):
            url = normalize_url(target)
            domain = domain_from_url(url)
            ColorOutput.info(f"[{i}/{len(self.targets)}] Scanning: {domain}")

            self.check_security_headers(url)
            self.check_cors(url)
            self.check_cookie_security(url)
            self.check_clickjacking(url)
            self.check_information_disclosure(url)
            self.check_http_methods(url)
            self.check_host_header(url)
            self.check_ssl_tls(domain)
            self.check_email_security(domain)
            self.check_csp_weaknesses(url)
            self.check_open_redirect_params(url)

        # Check subdomain takeover for all subdomains
        if self.subdomains_data:
            self._check_all_subdomain_takeovers()

        self._save_results()
        self._print_summary()
        return self.findings

    def _add_finding(self, finding):
        """Add a finding to the results list."""
        self.findings.append(finding)
        ColorOutput.finding(finding.severity, f"{finding.title} - {finding.url}")

    # -------------------------------------------------------------------
    # CORS Misconfiguration Analysis
    # -------------------------------------------------------------------

    def check_cors(self, url):
        """Test for CORS misconfigurations with various Origin headers."""
        domain = domain_from_url(url)
        test_origins = [
            "https://evil.com",
            "null",
            f"https://{domain}.evil.com",
            f"https://evil-{domain}",
            f"https://sub.{domain}",
        ]

        for origin in test_origins:
            resp = self.http.get(url, headers={"Origin": origin})
            if resp is None:
                continue

            status, headers, body = resp
            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "")

            if acao and origin != "null" and acao == origin:
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                cwe = "CWE-346"
                desc = (
                    f"The server reflects the Origin header '{origin}' in "
                    f"Access-Control-Allow-Origin."
                )
                if acac.lower() == "true":
                    desc += " Credentials are also allowed (critical combination)."
                evidence = (
                    f"Origin: {origin}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac}"
                )
                self._add_finding(Finding(
                    finding_type="CORS Misconfiguration",
                    severity=severity,
                    title=f"CORS reflects {'arbitrary' if 'evil.com' in origin else 'related'} origin",
                    description=desc,
                    url=url,
                    evidence=evidence,
                    remediation="Implement a strict allowlist of trusted origins. Do not reflect arbitrary Origin headers.",
                    cvss_score=7.5 if severity == "HIGH" else 5.3,
                    cwe_id=cwe,
                ))
                break  # One finding per URL is enough

            elif acao == "null" and origin == "null":
                self._add_finding(Finding(
                    finding_type="CORS Misconfiguration",
                    severity="MEDIUM",
                    title="CORS allows null origin",
                    description="The server allows the 'null' origin which can be exploited via sandboxed iframes.",
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: null",
                    remediation="Do not allow the null origin in CORS policies.",
                    cvss_score=5.3,
                    cwe_id="CWE-346",
                ))
                break

    # -------------------------------------------------------------------
    # Security Headers Analysis
    # -------------------------------------------------------------------

    def check_security_headers(self, url):
        """Check for missing or misconfigured security headers."""
        resp = self.http.get(url)
        if resp is None:
            return

        status, headers, body = resp
        headers_lower = {k.lower(): v for k, v in headers.items()}

        missing = []
        for header in SECURITY_HEADERS:
            if header.lower() not in headers_lower:
                missing.append(header)

        if missing:
            # Group into severity levels
            critical_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
            medium_headers = ["X-Frame-Options", "X-Content-Type-Options"]

            for h in missing:
                if h in critical_headers:
                    severity = "MEDIUM"
                    cvss = 5.3
                elif h in medium_headers:
                    severity = "LOW"
                    cvss = 3.7
                else:
                    severity = "INFO"
                    cvss = 0.0

                self._add_finding(Finding(
                    finding_type="Missing Security Header",
                    severity=severity,
                    title=f"Missing {h} header",
                    description=f"The response is missing the {h} security header.",
                    url=url,
                    evidence=f"Header '{h}' not found in response.",
                    remediation=f"Add the {h} header with an appropriate value.",
                    cvss_score=cvss,
                    cwe_id="CWE-693",
                ))

    # -------------------------------------------------------------------
    # Cookie Security Audit
    # -------------------------------------------------------------------

    def check_cookie_security(self, url):
        """Analyze Set-Cookie headers for security flags."""
        resp = self.http.get(url)
        if resp is None:
            return

        status, headers, body = resp

        # Collect all Set-Cookie headers
        cookies_raw = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                cookies_raw.append(value)

        if not cookies_raw:
            return

        for cookie_str in cookies_raw:
            parts = cookie_str.split(";")
            cookie_name = parts[0].split("=")[0].strip() if parts else "unknown"
            flags_lower = " ".join(p.strip().lower() for p in parts[1:])

            issues = []
            if "secure" not in flags_lower:
                issues.append("missing Secure flag")
            if "httponly" not in flags_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in flags_lower:
                issues.append("missing SameSite attribute")

            if issues:
                self._add_finding(Finding(
                    finding_type="Cookie Security",
                    severity="LOW",
                    title=f"Cookie '{cookie_name}' has insecure configuration",
                    description=f"Cookie issues: {', '.join(issues)}.",
                    url=url,
                    evidence=f"Set-Cookie: {cookie_str}",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax on all sensitive cookies.",
                    cvss_score=3.1,
                    cwe_id="CWE-614",
                ))

    # -------------------------------------------------------------------
    # Subdomain Takeover Detection
    # -------------------------------------------------------------------

    def check_subdomain_takeover(self, subdomain, cname):
        """Check if a subdomain CNAME points to an unclaimed service."""
        if not cname:
            return

        cname_lower = cname.lower().rstrip(".")

        for service, data in TAKEOVER_FINGERPRINTS.items():
            cname_match = any(
                c in cname_lower for c in data.get("cnames", [])
            )
            if not cname_match:
                continue

            # Try to fetch the subdomain and check for fingerprint
            url = f"https://{subdomain}"
            resp = self.http.get(url)
            if resp is None:
                url = f"http://{subdomain}"
                resp = self.http.get(url)
            if resp is None:
                continue

            status, headers, body = resp
            for fingerprint in data.get("fingerprints", []):
                if fingerprint.lower() in body.lower():
                    self._add_finding(Finding(
                        finding_type="Subdomain Takeover",
                        severity="HIGH",
                        title=f"Potential subdomain takeover via {service}",
                        description=(
                            f"The subdomain {subdomain} has a CNAME pointing to "
                            f"{cname} ({service}) which appears to be unclaimed."
                        ),
                        url=url,
                        evidence=f"CNAME: {cname}\nFingerprint: {fingerprint}",
                        remediation=f"Remove the DNS record or claim the resource on {service}.",
                        cvss_score=8.6,
                        cwe_id="CWE-284",
                    ))
                    return

    def _check_all_subdomain_takeovers(self):
        """Check all discovered subdomains for takeover potential."""
        ColorOutput.info("Checking subdomain takeover potential...")
        for subdomain, data in self.subdomains_data.items():
            cnames = data if isinstance(data, list) else data.get("cname", [])
            if isinstance(cnames, str):
                cnames = [cnames]
            for cname in cnames:
                self.check_subdomain_takeover(subdomain, cname)

    # -------------------------------------------------------------------
    # Open Redirect Parameter Detection
    # -------------------------------------------------------------------

    def check_open_redirect_params(self, url):
        """Identify URL parameters that may be used for open redirects."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        redirect_found = []
        for param_name in params:
            if param_name.lower() in REDIRECT_PARAMS:
                redirect_found.append(param_name)

        # Also check discovered URLs in subdomains_data
        if redirect_found:
            self._add_finding(Finding(
                finding_type="Open Redirect",
                severity="MEDIUM",
                title="Potential open redirect parameter detected",
                description=f"URL contains redirect-like parameters: {', '.join(redirect_found)}",
                url=url,
                evidence=f"Parameters: {', '.join(redirect_found)}",
                remediation="Validate and whitelist redirect destinations. Use relative paths only.",
                cvss_score=4.7,
                cwe_id="CWE-601",
            ))

    # -------------------------------------------------------------------
    # Information Disclosure
    # -------------------------------------------------------------------

    def check_information_disclosure(self, url):
        """Check for server version info and sensitive files."""
        resp = self.http.get(url)
        if resp is None:
            return

        status, headers, body = resp

        # Server header version disclosure
        server = headers.get("Server", "")
        if server and re.search(r"[0-9]+\.[0-9]+", server):
            self._add_finding(Finding(
                finding_type="Information Disclosure",
                severity="LOW",
                title="Server version disclosed",
                description=f"The Server header reveals version information: {server}",
                url=url,
                evidence=f"Server: {server}",
                remediation="Remove or genericize the Server header to hide version information.",
                cvss_score=2.6,
                cwe_id="CWE-200",
            ))

        # X-Powered-By disclosure
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            self._add_finding(Finding(
                finding_type="Information Disclosure",
                severity="LOW",
                title="Technology stack disclosed via X-Powered-By",
                description=f"X-Powered-By header reveals: {powered_by}",
                url=url,
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Remove the X-Powered-By header from responses.",
                cvss_score=2.6,
                cwe_id="CWE-200",
            ))

    # -------------------------------------------------------------------
    # Email Security (SPF/DKIM/DMARC)
    # -------------------------------------------------------------------

    def check_email_security(self, domain):
        """Check SPF, DKIM, and DMARC records for the domain."""
        txt_records = DNSResolver.resolve(domain, "TXT")

        has_spf = False
        has_dmarc = False

        for record in txt_records:
            if "v=spf1" in record.lower():
                has_spf = True
                # Check for weak SPF
                if "+all" in record.lower():
                    self._add_finding(Finding(
                        finding_type="Email Security",
                        severity="HIGH",
                        title="SPF record uses +all (allows all senders)",
                        description="The SPF record ends with +all which allows any server to send mail for this domain.",
                        url=f"dns://{domain}",
                        evidence=f"SPF: {record}",
                        remediation="Change +all to -all or ~all to restrict email senders.",
                        cvss_score=7.4,
                        cwe_id="CWE-290",
                    ))

        # Check DMARC
        dmarc_records = DNSResolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in dmarc_records:
            if "v=dmarc1" in record.lower():
                has_dmarc = True
                if "p=none" in record.lower():
                    self._add_finding(Finding(
                        finding_type="Email Security",
                        severity="LOW",
                        title="DMARC policy set to none (monitoring only)",
                        description="The DMARC policy is set to 'none' which does not enforce email authentication.",
                        url=f"dns://{domain}",
                        evidence=f"DMARC: {record}",
                        remediation="Consider upgrading DMARC policy to 'quarantine' or 'reject'.",
                        cvss_score=2.6,
                        cwe_id="CWE-290",
                    ))

        if not has_spf:
            self._add_finding(Finding(
                finding_type="Email Security",
                severity="MEDIUM",
                title="No SPF record found",
                description="The domain does not have an SPF record, making it vulnerable to email spoofing.",
                url=f"dns://{domain}",
                evidence="No TXT record with v=spf1 found.",
                remediation="Add an SPF TXT record to specify authorized email senders.",
                cvss_score=5.3,
                cwe_id="CWE-290",
            ))

        if not has_dmarc:
            self._add_finding(Finding(
                finding_type="Email Security",
                severity="MEDIUM",
                title="No DMARC record found",
                description="The domain does not have a DMARC record for email authentication policy.",
                url=f"dns://{domain}",
                evidence="No TXT record at _dmarc.{domain} with v=DMARC1 found.",
                remediation="Add a DMARC TXT record at _dmarc.{domain}.",
                cvss_score=5.3,
                cwe_id="CWE-290",
            ))

    # -------------------------------------------------------------------
    # SSL/TLS Analysis
    # -------------------------------------------------------------------

    def check_ssl_tls(self, domain):
        """Analyze SSL/TLS certificate and configuration."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                return

            # Check expiry
            import datetime
            not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
            now = time.time()
            days_left = (not_after - now) / 86400

            if days_left < 0:
                self._add_finding(Finding(
                    finding_type="SSL/TLS",
                    severity="CRITICAL",
                    title="SSL certificate expired",
                    description=f"The SSL certificate expired {abs(int(days_left))} days ago.",
                    url=f"https://{domain}",
                    evidence=f"Expiry: {cert.get('notAfter')}",
                    remediation="Renew the SSL certificate immediately.",
                    cvss_score=9.1,
                    cwe_id="CWE-295",
                ))
            elif days_left < 30:
                self._add_finding(Finding(
                    finding_type="SSL/TLS",
                    severity="LOW",
                    title="SSL certificate expiring soon",
                    description=f"The SSL certificate expires in {int(days_left)} days.",
                    url=f"https://{domain}",
                    evidence=f"Expiry: {cert.get('notAfter')}",
                    remediation="Renew the SSL certificate before expiry.",
                    cvss_score=2.6,
                    cwe_id="CWE-295",
                ))

            # Check for wildcard cert
            sans = []
            for type_name, value in cert.get("subjectAltName", []):
                if type_name == "DNS":
                    sans.append(value)

            # Check issuer
            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_org = issuer.get("organizationName", "Unknown")

        except ssl.SSLCertVerificationError as e:
            self._add_finding(Finding(
                finding_type="SSL/TLS",
                severity="HIGH",
                title="SSL certificate verification failed",
                description=f"SSL verification error: {e}",
                url=f"https://{domain}",
                evidence=str(e),
                remediation="Fix the SSL certificate configuration.",
                cvss_score=7.4,
                cwe_id="CWE-295",
            ))
        except (socket.timeout, socket.error, OSError):
            pass

    # -------------------------------------------------------------------
    # CSP Weakness Analysis
    # -------------------------------------------------------------------

    def check_csp_weaknesses(self, url):
        """Analyze Content-Security-Policy for bypass potential."""
        resp = self.http.get(url)
        if resp is None:
            return

        status, headers, body = resp
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return  # Already flagged as missing header

        weaknesses = []

        if "'unsafe-inline'" in csp:
            weaknesses.append("unsafe-inline allows inline script execution")
        if "'unsafe-eval'" in csp:
            weaknesses.append("unsafe-eval allows eval() and similar functions")
        if "data:" in csp and "script-src" in csp.split("data:")[0].rsplit(";", 1)[-1]:
            weaknesses.append("data: URI in script-src allows script injection")

        # Check for wildcard in script-src
        directives = csp.split(";")
        for directive in directives:
            directive = directive.strip()
            if directive.startswith("script-src"):
                if "*" in directive:
                    weaknesses.append("wildcard (*) in script-src is overly permissive")
                if "http:" in directive:
                    weaknesses.append("http: in script-src allows loading scripts over HTTP")

        if weaknesses:
            self._add_finding(Finding(
                finding_type="CSP Weakness",
                severity="MEDIUM",
                title="Content-Security-Policy has weaknesses",
                description="The CSP contains directives that reduce its effectiveness: " + "; ".join(weaknesses),
                url=url,
                evidence=f"CSP: {csp[:200]}",
                remediation="Remove unsafe-inline, unsafe-eval, wildcards, and data: from script-src.",
                cvss_score=5.3,
                cwe_id="CWE-693",
            ))

    # -------------------------------------------------------------------
    # Clickjacking (X-Frame-Options)
    # -------------------------------------------------------------------

    def check_clickjacking(self, url):
        """Check X-Frame-Options and frame-ancestors for clickjacking protection."""
        resp = self.http.get(url)
        if resp is None:
            return

        status, headers, body = resp
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")

        has_frame_protection = False
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            has_frame_protection = True
        if "frame-ancestors" in csp:
            has_frame_protection = True

        if not has_frame_protection:
            self._add_finding(Finding(
                finding_type="Clickjacking",
                severity="LOW",
                title="Missing clickjacking protection",
                description="No X-Frame-Options or CSP frame-ancestors directive found.",
                url=url,
                evidence="X-Frame-Options: (not set), CSP frame-ancestors: (not set)",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.",
                cvss_score=4.3,
                cwe_id="CWE-1021",
            ))

    # -------------------------------------------------------------------
    # HTTP Methods Testing
    # -------------------------------------------------------------------

    def check_http_methods(self, url):
        """Send OPTIONS request to discover allowed HTTP methods."""
        resp = self.http.get(url, headers={"Access-Control-Request-Method": "OPTIONS"})
        if resp is None:
            return

        status, headers, body = resp
        allow = headers.get("Allow", "")
        if not allow:
            return

        dangerous_methods = ["PUT", "DELETE", "TRACE", "PATCH"]
        found_dangerous = [m for m in dangerous_methods if m in allow.upper()]

        if found_dangerous:
            self._add_finding(Finding(
                finding_type="HTTP Methods",
                severity="LOW",
                title=f"Potentially dangerous HTTP methods enabled",
                description=f"The server allows: {', '.join(found_dangerous)}",
                url=url,
                evidence=f"Allow: {allow}",
                remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE).",
                cvss_score=3.7,
                cwe_id="CWE-749",
            ))

    # -------------------------------------------------------------------
    # Host Header Injection
    # -------------------------------------------------------------------

    def check_host_header(self, url):
        """Check if Host header value is reflected in the response."""
        evil_host = "evil-host-injection-test.com"
        resp = self.http.get(url, headers={"Host": evil_host})
        if resp is None:
            return

        status, headers, body = resp

        # Check if evil host appears in response body or Location header
        location = headers.get("Location", "")
        if evil_host in body or evil_host in location:
            self._add_finding(Finding(
                finding_type="Host Header Injection",
                severity="MEDIUM",
                title="Host header reflected in response",
                description="The server reflects the Host header in its response, which may enable cache poisoning or password reset attacks.",
                url=url,
                evidence=f"Injected Host: {evil_host}, found in {'Location header' if evil_host in location else 'response body'}",
                remediation="Validate the Host header against a whitelist of expected values.",
                cvss_score=5.3,
                cwe_id="CWE-644",
            ))

    # -------------------------------------------------------------------
    # Results Management
    # -------------------------------------------------------------------

    def _save_results(self):
        """Save all findings to JSON file."""
        results = {
            "total_findings": len(self.findings),
            "by_severity": self._count_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
        self.file_mgr.save_json(results, "vulnerabilities.json")
        ColorOutput.success(
            f"Results saved to {os.path.join(self.output_dir, 'vulnerabilities.json')}"
        )

    def _count_by_severity(self):
        """Count findings grouped by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _print_summary(self):
        """Print a summary of all findings."""
        counts = self._count_by_severity()
        total = len(self.findings)
        ColorOutput.info(
            f"Scan complete: {total} findings "
            f"(C:{counts['CRITICAL']} H:{counts['HIGH']} "
            f"M:{counts['MEDIUM']} L:{counts['LOW']} I:{counts['INFO']})"
        )
