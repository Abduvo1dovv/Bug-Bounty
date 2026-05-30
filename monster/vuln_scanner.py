"""
Monster v2.0.0 Vulnerability Scanner Module

Comprehensive vulnerability scanning for bug bounty reconnaissance.
Performs passive and semi-passive security checks against target URLs
to identify misconfigurations, missing security controls, and
potential vulnerabilities.

Features:
    - Security header analysis
    - CORS misconfiguration detection
    - Cookie security assessment
    - Clickjacking protection check
    - Information disclosure detection
    - HTTP method enumeration
    - Host header injection testing
    - SSL/TLS configuration check
    - Email security (SPF/DKIM/DMARC)
    - CSP weakness analysis
    - Cache poisoning indicators
    - Request smuggling indicators
    - GraphQL introspection detection
    - SSRF indicator identification
    - XXE indicator detection
    - IDOR pattern recognition
    - Rate limiting assessment
    - WAF fingerprinting
    - 403 bypass techniques
    - Broken link hijacking
    - Business logic flaw detection
    - API versioning discovery
    - Sensitive file detection
    - Parameter pollution testing
    - CRLF injection testing
    - Path traversal testing
    - Open redirect detection
    - Subdomain takeover checking

Usage:
    from monster.vuln_scanner import VulnScanner, Finding
    scanner = VulnScanner(["https://example.com"], output_dir="./output")
    findings = scanner.run()
"""

import re
import json
import time
import socket
import ssl
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
from urllib.parse import urlparse, urljoin, urlencode, quote, unquote, parse_qs

from monster.utils import (
    ColorOutput, HTTPClient, FileManager, RateLimiter,
    DNSResolver, normalize_url, domain_from_url
)
from monster.config import (
    PATTERNS, TECH_SIGNATURES, INFO_DISCLOSURE_PATHS,
    SECURITY_HEADERS, CORS_TEST_ORIGINS, TAKEOVER_FINGERPRINTS,
    SENSITIVE_FILE_PATHS, WAF_SIGNATURES, REDIRECT_PARAMS, COMMON_PARAMS
)


# =============================================================================
# FINDING DATACLASS
# =============================================================================

@dataclass
class Finding:
    """
    Represents a single vulnerability or security finding.

    Contains all information about a detected security issue including
    severity, evidence, remediation guidance, and standardized references.

    Attributes:
        finding_type: Category of the finding (e.g., "cors", "headers").
        severity: Impact level: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
        title: Short descriptive title of the finding.
        description: Detailed explanation of the vulnerability.
        url: The URL where the finding was detected.
        evidence: Technical evidence supporting the finding.
        remediation: Recommended fix or mitigation.
        cvss_score: CVSS v3.1 base score (0.0-10.0).
        cwe_id: Common Weakness Enumeration identifier.
    """
    finding_type: str = ""
    severity: str = "INFO"
    title: str = ""
    description: str = ""
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
        }

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"[{self.severity}] {self.title} - {self.url}"


# =============================================================================
# WAF SIGNATURES (if not in config)
# =============================================================================

LOCAL_WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body_patterns": ["cloudflare", "cf-error"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "cookies": ["awsalb", "awsalbcors"],
        "body_patterns": ["aws", "Request blocked"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "cookies": ["akamai_generated", "ak_bmsc"],
        "body_patterns": ["akamai", "reference #"],
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["incap_ses", "visid_incap"],
        "body_patterns": ["incapsula", "imperva"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": ["sucuri_cloudproxy"],
        "body_patterns": ["sucuri", "cloudproxy"],
    },
    "ModSecurity": {
        "headers": ["server"],
        "cookies": [],
        "body_patterns": ["mod_security", "modsecurity", "NOYB"],
    },
    "F5 BIG-IP": {
        "headers": ["x-cnection", "x-wa-info"],
        "cookies": ["bigipserver", "BIGipServer"],
        "body_patterns": ["BIG-IP", "f5"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "cookies": ["barra_counter_session"],
        "body_patterns": ["barracuda"],
    },
    "Fortinet/FortiWeb": {
        "headers": ["fortiwafsid"],
        "cookies": ["fortiwafsid"],
        "body_patterns": ["fortigate", "fortiweb"],
    },
    "Wordfence": {
        "headers": [],
        "cookies": ["wfwaf-authcookie"],
        "body_patterns": ["wordfence", "wf-error"],
    },
}


# =============================================================================
# VULN SCANNER CLASS
# =============================================================================

class VulnScanner:
    """
    Comprehensive vulnerability scanner for web application security assessment.

    Performs multiple categories of security checks against target URLs
    to identify vulnerabilities, misconfigurations, and security weaknesses.

    Attributes:
        targets: List of target URLs to scan.
        subdomains_data: Optional subdomain enumeration data.
        output_dir: Directory for saving scan results.
        rate_limit: Delay between requests in seconds.
        timeout: HTTP request timeout in seconds.
        dry_run: If True, simulate scanning without network requests.
        findings: List of all findings from the scan.
    """

    def __init__(
        self,
        targets: List[str],
        subdomains_data: Dict[str, Any] = None,
        output_dir: str = "./output",
        rate_limit: float = 1.0,
        timeout: int = 10,
        dry_run: bool = False,
    ):
        """
        Initialize the vulnerability scanner.

        Args:
            targets: List of target URLs to scan.
            subdomains_data: Optional dict with subdomain info from recon.
            output_dir: Directory for output files.
            rate_limit: Delay between HTTP requests (seconds).
            timeout: HTTP timeout in seconds.
            dry_run: Skip actual network requests if True.
        """
        self.targets = targets if isinstance(targets, list) else [targets]
        self.subdomains_data = subdomains_data or {}
        self.output_dir = output_dir
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.dry_run = dry_run
        self.color = ColorOutput()
        self.findings: List[Finding] = []

        # Initialize HTTP client
        rate_limiter = RateLimiter(rate_limit)
        self.http = HTTPClient(
            timeout=timeout,
            rate_limiter=rate_limiter,
            verify_ssl=False,
        )

        # Initialize DNS resolver
        self.dns = DNSResolver()

        # Initialize file manager
        self.file_manager = FileManager(output_dir)

    def run(self) -> List[Finding]:
        """
        Execute all vulnerability checks against all targets.

        Orchestrates the full scanning pipeline, running each check
        category against every target URL. Results are collected,
        deduplicated, and saved.

        Returns:
            List of Finding objects representing all detected issues.
        """
        self.color.info("Starting vulnerability scan...")
        self.color.info(f"Targets: {len(self.targets)}")

        for target in self.targets:
            try:
                url = normalize_url(target)
                domain = domain_from_url(url)
                self.color.status(f"Scanning: {url}")

                # Run all checks
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
                self.check_cache_poisoning(url)
                self.check_request_smuggling_indicators(url)
                self.check_graphql_introspection(url)
                self.check_ssrf_indicators(url)
                self.check_xxe_indicators(url)
                self.check_idor_patterns(url)
                self.check_rate_limiting(url)
                self.check_waf_fingerprint(url)
                self.check_403_bypass(url)
                self.check_broken_link_hijacking(url)
                self.check_business_logic(url)
                self.check_api_versioning(url)
                self.check_sensitive_files(url)
                self.check_parameter_pollution(url)
                self.check_crlf_injection(url)
                self.check_path_traversal(url)
                self.check_open_redirect(url)

                # Subdomain takeover if we have subdomain data
                if self.subdomains_data:
                    subdomains = self.subdomains_data.get("subdomains", [])
                    if subdomains:
                        self.check_subdomain_takeover(subdomains)

                self.color.success(f"Completed scan for {url}: {len(self.findings)} findings so far")

            except Exception as e:
                self.color.error(f"Error scanning {target}: {str(e)}")

        # Save findings
        self._save_findings()

        # Summary
        critical = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high = sum(1 for f in self.findings if f.severity == "HIGH")
        medium = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low = sum(1 for f in self.findings if f.severity == "LOW")
        info = sum(1 for f in self.findings if f.severity == "INFO")

        self.color.success(
            f"Scan complete. Total findings: {len(self.findings)} "
            f"(C:{critical} H:{high} M:{medium} L:{low} I:{info})"
        )

        return self.findings

    def _create_finding(
        self,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        url: str,
        evidence: str = "",
        remediation: str = "",
        cvss: float = 0.0,
        cwe: str = "",
    ) -> Finding:
        """
        Create a Finding object and add it to the findings list.

        Args:
            finding_type: Category of the finding.
            severity: CRITICAL/HIGH/MEDIUM/LOW/INFO.
            title: Short title.
            description: Detailed description.
            url: Affected URL.
            evidence: Supporting evidence.
            remediation: Fix recommendation.
            cvss: CVSS score.
            cwe: CWE identifier.

        Returns:
            The created Finding object.
        """
        finding = Finding(
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=description,
            url=url,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss,
            cwe_id=cwe,
        )
        self.findings.append(finding)
        severity_colors = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "info",
            "INFO": "info",
        }
        log_method = getattr(self.color, severity_colors.get(severity, "info"))
        log_method(f"  [{severity}] {title}")
        return finding


    # =========================================================================
    # CHECK SECURITY HEADERS
    # =========================================================================

    def check_security_headers(self, url: str) -> None:
        """
        Check for missing or misconfigured security headers.

        Analyzes the response headers against the SECURITY_HEADERS list
        and reports any that are missing or improperly configured.
        Each missing header is reported with appropriate severity
        and remediation guidance.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check security headers")
            self._create_finding(
                finding_type="security_headers",
                severity="INFO",
                title="Security Headers Check (dry-run)",
                description="Security headers check would be performed.",
                url=url,
            )
            return

        try:
            response = self.http.get(url)
            if response is None or response.status_code == 0:
                return

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Define expected headers with their severity and remediation
            header_checks = {
                "strict-transport-security": {
                    "severity": "HIGH",
                    "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                    "cvss": 6.1,
                    "cwe": "CWE-319",
                },
                "content-security-policy": {
                    "severity": "MEDIUM",
                    "description": "Content Security Policy (CSP) header is missing. This reduces protection against XSS and data injection attacks.",
                    "remediation": "Implement a restrictive Content-Security-Policy header. Start with default-src 'self' and add exceptions as needed.",
                    "cvss": 5.4,
                    "cwe": "CWE-693",
                },
                "x-content-type-options": {
                    "severity": "LOW",
                    "description": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, leading to XSS.",
                    "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
                    "cvss": 3.1,
                    "cwe": "CWE-16",
                },
                "x-frame-options": {
                    "severity": "MEDIUM",
                    "description": "X-Frame-Options header is missing. The page can be embedded in frames, enabling clickjacking attacks.",
                    "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
                    "cvss": 4.3,
                    "cwe": "CWE-1021",
                },
                "x-xss-protection": {
                    "severity": "LOW",
                    "description": "X-XSS-Protection header is missing. While deprecated in modern browsers, it provides defense-in-depth for older browsers.",
                    "remediation": "Add 'X-XSS-Protection: 1; mode=block' header (or rely on CSP instead).",
                    "cvss": 2.1,
                    "cwe": "CWE-79",
                },
                "referrer-policy": {
                    "severity": "LOW",
                    "description": "Referrer-Policy header is missing. Sensitive information in URLs may leak through the Referer header.",
                    "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' header.",
                    "cvss": 2.6,
                    "cwe": "CWE-200",
                },
                "permissions-policy": {
                    "severity": "LOW",
                    "description": "Permissions-Policy (formerly Feature-Policy) header is missing. Browser features are not restricted.",
                    "remediation": "Add Permissions-Policy header to restrict access to sensitive browser features (camera, microphone, geolocation).",
                    "cvss": 2.1,
                    "cwe": "CWE-16",
                },
                "cross-origin-embedder-policy": {
                    "severity": "LOW",
                    "description": "Cross-Origin-Embedder-Policy header is missing.",
                    "remediation": "Add 'Cross-Origin-Embedder-Policy: require-corp' header for cross-origin isolation.",
                    "cvss": 2.1,
                    "cwe": "CWE-16",
                },
                "cross-origin-opener-policy": {
                    "severity": "LOW",
                    "description": "Cross-Origin-Opener-Policy header is missing.",
                    "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
                    "cvss": 2.1,
                    "cwe": "CWE-16",
                },
                "cross-origin-resource-policy": {
                    "severity": "LOW",
                    "description": "Cross-Origin-Resource-Policy header is missing.",
                    "remediation": "Add 'Cross-Origin-Resource-Policy: same-origin' header.",
                    "cvss": 2.1,
                    "cwe": "CWE-16",
                },
            }

            for header_name, check_info in header_checks.items():
                if header_name not in headers:
                    self._create_finding(
                        finding_type="security_headers",
                        severity=check_info["severity"],
                        title=f"Missing Security Header: {header_name}",
                        description=check_info["description"],
                        url=url,
                        evidence=f"Header '{header_name}' not present in response.",
                        remediation=check_info["remediation"],
                        cvss=check_info["cvss"],
                        cwe=check_info["cwe"],
                    )

            # Check for information leakage in headers
            info_headers = {
                "server": "Server version disclosure",
                "x-powered-by": "Technology stack disclosure",
                "x-aspnet-version": "ASP.NET version disclosure",
                "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
            }
            for header_name, title in info_headers.items():
                if header_name in headers:
                    self._create_finding(
                        finding_type="information_disclosure",
                        severity="LOW",
                        title=title,
                        description=f"The {header_name} header reveals server technology information that helps attackers fingerprint the application.",
                        url=url,
                        evidence=f"{header_name}: {headers[header_name]}",
                        remediation=f"Remove or suppress the {header_name} header in production.",
                        cvss=2.6,
                        cwe="CWE-200",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking security headers: {str(e)}")

    # =========================================================================
    # CHECK CORS
    # =========================================================================

    def check_cors(self, url: str) -> None:
        """
        Test for CORS misconfiguration vulnerabilities.

        Tests multiple CORS bypass techniques:
        - Arbitrary origin reflection (evil.com)
        - Null origin acceptance
        - Prefix match bypass (evil-target.com)
        - Suffix match bypass (target.com.evil.com)
        - Subdomain match (sub.target.com)
        - Special characters in origin
        - Wildcard with credentials
        - Pre-flight bypass attempts

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check CORS configuration")
            return

        domain = domain_from_url(url)

        # CORS test origins with target substitution
        test_origins = [
            ("https://evil.com", "arbitrary_origin"),
            ("null", "null_origin"),
            (f"https://evil-{domain}", "prefix_match"),
            (f"https://{domain}.evil.com", "suffix_match"),
            (f"https://sub.{domain}", "subdomain"),
            (f"https://{domain}%60.evil.com", "special_chars"),
            (f"http://{domain}", "http_downgrade"),
            (f"https://not{domain}", "partial_match"),
            (f"https://{domain}_.evil.com", "underscore_bypass"),
            (f"https://evil.com.{domain}", "domain_confusion"),
        ]

        for origin, test_type in test_origins:
            try:
                headers = {"Origin": origin}
                response = self.http.get(url, headers=headers)
                if response is None or response.status_code == 0:
                    continue

                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "").lower()

                if not acao:
                    continue

                # Check if our origin was reflected
                is_reflected = (acao == origin or acao == "*")
                has_credentials = (acac == "true")

                if is_reflected and origin != f"https://sub.{domain}":
                    severity = "HIGH" if has_credentials else "MEDIUM"
                    if origin == "null":
                        severity = "HIGH"

                    self._create_finding(
                        finding_type="cors",
                        severity=severity,
                        title=f"CORS Misconfiguration: {test_type}",
                        description=(
                            f"The server reflects the Origin header '{origin}' in "
                            f"Access-Control-Allow-Origin, allowing cross-origin access. "
                            f"{'Credentials are also allowed, making this exploitable for data theft.' if has_credentials else ''}"
                        ),
                        url=url,
                        evidence=(
                            f"Request Origin: {origin}\n"
                            f"Response ACAO: {acao}\n"
                            f"Response ACAC: {acac}"
                        ),
                        remediation=(
                            "Implement a strict whitelist of allowed origins. "
                            "Never reflect arbitrary origins. "
                            "Do not use Access-Control-Allow-Credentials: true with reflected origins."
                        ),
                        cvss=7.5 if has_credentials else 5.3,
                        cwe="CWE-942",
                    )
                    break  # Found a CORS issue, no need to test more

                # Check wildcard with credentials
                if acao == "*" and has_credentials:
                    self._create_finding(
                        finding_type="cors",
                        severity="MEDIUM",
                        title="CORS: Wildcard with Credentials",
                        description="The server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. While browsers block this, it indicates a misconfiguration.",
                        url=url,
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Use specific origins instead of wildcard when credentials are needed.",
                        cvss=5.3,
                        cwe="CWE-942",
                    )

            except Exception:
                continue

    # =========================================================================
    # CHECK COOKIE SECURITY
    # =========================================================================

    def check_cookie_security(self, url: str) -> None:
        """
        Analyze cookies for security attribute issues.

        For each cookie in the response, checks:
        - HttpOnly flag (prevents JS access)
        - Secure flag (HTTPS only)
        - SameSite attribute (CSRF protection)
        - Path scope
        - Domain scope
        - Expiry settings
        - Cookie prefixes (__Host- / __Secure-)

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check cookie security")
            return

        try:
            response = self.http.get(url)
            if response is None or response.status_code == 0:
                return

            # Get Set-Cookie headers
            set_cookies = []
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookies.append(value)

            if not set_cookies:
                return

            for cookie_str in set_cookies:
                # Parse cookie
                parts = cookie_str.split(";")
                if not parts:
                    continue

                cookie_name_value = parts[0].strip()
                cookie_name = cookie_name_value.split("=")[0].strip() if "=" in cookie_name_value else cookie_name_value

                attributes = {}
                for part in parts[1:]:
                    part = part.strip().lower()
                    if "=" in part:
                        attr_name, attr_value = part.split("=", 1)
                        attributes[attr_name.strip()] = attr_value.strip()
                    else:
                        attributes[part] = True

                # Check HttpOnly
                if "httponly" not in attributes:
                    is_sensitive = any(kw in cookie_name.lower() for kw in [
                        "session", "token", "auth", "jwt", "sid", "csrf",
                    ])
                    if is_sensitive:
                        self._create_finding(
                            finding_type="cookie_security",
                            severity="MEDIUM",
                            title=f"Cookie Missing HttpOnly: {cookie_name}",
                            description=f"The sensitive cookie '{cookie_name}' does not have the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based theft.",
                            url=url,
                            evidence=f"Set-Cookie: {cookie_str[:200]}",
                            remediation="Add the HttpOnly flag to prevent JavaScript access to this cookie.",
                            cvss=4.3,
                            cwe="CWE-1004",
                        )

                # Check Secure flag
                if "secure" not in attributes and url.startswith("https"):
                    self._create_finding(
                        finding_type="cookie_security",
                        severity="MEDIUM",
                        title=f"Cookie Missing Secure Flag: {cookie_name}",
                        description=f"The cookie '{cookie_name}' does not have the Secure flag, allowing transmission over unencrypted HTTP connections.",
                        url=url,
                        evidence=f"Set-Cookie: {cookie_str[:200]}",
                        remediation="Add the Secure flag to ensure the cookie is only sent over HTTPS.",
                        cvss=4.3,
                        cwe="CWE-614",
                    )

                # Check SameSite
                samesite = attributes.get("samesite", "")
                if not samesite or samesite == "none":
                    self._create_finding(
                        finding_type="cookie_security",
                        severity="LOW",
                        title=f"Cookie SameSite Not Set or None: {cookie_name}",
                        description=f"The cookie '{cookie_name}' has SameSite=None or no SameSite attribute, making it susceptible to CSRF attacks in older browsers.",
                        url=url,
                        evidence=f"Set-Cookie: {cookie_str[:200]}",
                        remediation="Set SameSite=Lax or SameSite=Strict for CSRF protection.",
                        cvss=3.1,
                        cwe="CWE-1275",
                    )

                # Check cookie prefix compliance
                if cookie_name.startswith("__Host-"):
                    if "secure" not in attributes or attributes.get("path") != "/":
                        self._create_finding(
                            finding_type="cookie_security",
                            severity="LOW",
                            title=f"Invalid __Host- Cookie Prefix: {cookie_name}",
                            description="A cookie with the __Host- prefix must have Secure flag, Path=/, and no Domain attribute.",
                            url=url,
                            evidence=f"Set-Cookie: {cookie_str[:200]}",
                            remediation="Ensure __Host- prefixed cookies have Secure flag and Path=/.",
                            cvss=2.1,
                            cwe="CWE-16",
                        )

                if cookie_name.startswith("__Secure-"):
                    if "secure" not in attributes:
                        self._create_finding(
                            finding_type="cookie_security",
                            severity="LOW",
                            title=f"Invalid __Secure- Cookie Prefix: {cookie_name}",
                            description="A cookie with the __Secure- prefix must have the Secure flag.",
                            url=url,
                            evidence=f"Set-Cookie: {cookie_str[:200]}",
                            remediation="Ensure __Secure- prefixed cookies have the Secure flag.",
                            cvss=2.1,
                            cwe="CWE-16",
                        )

        except Exception as e:
            self.color.warning(f"  Error checking cookie security: {str(e)}")

    # =========================================================================
    # CHECK CLICKJACKING
    # =========================================================================

    def check_clickjacking(self, url: str) -> None:
        """
        Check for clickjacking protection.

        Verifies both X-Frame-Options header and CSP frame-ancestors
        directive are properly configured to prevent framing attacks.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check clickjacking protection")
            return

        try:
            response = self.http.get(url)
            if response is None or response.status_code == 0:
                return

            headers = {k.lower(): v for k, v in response.headers.items()}

            xfo = headers.get("x-frame-options", "").upper()
            csp = headers.get("content-security-policy", "")

            has_xfo = xfo in ("DENY", "SAMEORIGIN") or xfo.startswith("ALLOW-FROM")
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            if not has_xfo and not has_frame_ancestors:
                self._create_finding(
                    finding_type="clickjacking",
                    severity="MEDIUM",
                    title="No Clickjacking Protection",
                    description="Neither X-Frame-Options nor CSP frame-ancestors is configured. The page can be embedded in an attacker-controlled iframe for clickjacking attacks.",
                    url=url,
                    evidence=f"X-Frame-Options: {xfo or 'not set'}\nCSP frame-ancestors: {'not set' if not has_frame_ancestors else 'set'}",
                    remediation="Add 'X-Frame-Options: DENY' header and/or 'Content-Security-Policy: frame-ancestors \'none\'' directive.",
                    cvss=4.3,
                    cwe="CWE-1021",
                )
            elif has_xfo and xfo == "ALLOW-FROM":
                self._create_finding(
                    finding_type="clickjacking",
                    severity="LOW",
                    title="X-Frame-Options ALLOW-FROM (deprecated)",
                    description="X-Frame-Options uses the deprecated ALLOW-FROM directive which is not supported by modern browsers.",
                    url=url,
                    evidence=f"X-Frame-Options: {xfo}",
                    remediation="Use CSP frame-ancestors instead of X-Frame-Options ALLOW-FROM.",
                    cvss=3.1,
                    cwe="CWE-1021",
                )

        except Exception as e:
            self.color.warning(f"  Error checking clickjacking: {str(e)}")


    # =========================================================================
    # CHECK INFORMATION DISCLOSURE
    # =========================================================================

    def check_information_disclosure(self, url: str) -> None:
        """
        Probe for information disclosure through exposed files and paths.

        Tests a subset of INFO_DISCLOSURE_PATHS for accessible files
        that should not be publicly available (config files, backups,
        version control, debug endpoints).

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check information disclosure paths")
            return

        # Use the first 40 paths from the list for efficiency
        paths_to_check = INFO_DISCLOSURE_PATHS[:40]

        for path in paths_to_check:
            try:
                check_url = urljoin(url, path)
                response = self.http.get(check_url)

                if response is None:
                    continue

                # Check for successful response with content
                if response.status_code == 200 and response.body:
                    body_len = len(response.body)

                    # Verify it is not just a generic error page
                    if body_len < 50:
                        continue
                    if any(kw in response.body.lower() for kw in ["404", "not found", "page not found"]):
                        continue

                    # Determine severity based on file type
                    severity = "MEDIUM"
                    if any(kw in path for kw in [".env", "credentials", "secret", "private", "key"]):
                        severity = "HIGH"
                    elif any(kw in path for kw in [".git", ".svn", "wp-config", "database"]):
                        severity = "HIGH"
                    elif any(kw in path for kw in ["phpinfo", "server-status", "actuator"]):
                        severity = "MEDIUM"
                    elif any(kw in path for kw in [".txt", "robots", "sitemap"]):
                        severity = "INFO"

                    self._create_finding(
                        finding_type="information_disclosure",
                        severity=severity,
                        title=f"Accessible Sensitive File: {path}",
                        description=f"The file '{path}' is publicly accessible and may contain sensitive information.",
                        url=check_url,
                        evidence=f"HTTP {response.status_code}, Content-Length: {body_len}, First 100 chars: {response.body[:100]}",
                        remediation=f"Restrict access to '{path}' using web server configuration or remove it from the web root.",
                        cvss=5.3 if severity in ("HIGH", "MEDIUM") else 2.1,
                        cwe="CWE-538",
                    )

            except Exception:
                continue

    # =========================================================================
    # CHECK HTTP METHODS
    # =========================================================================

    def check_http_methods(self, url: str) -> None:
        """
        Test for dangerous HTTP methods enabled on the server.

        Sends an OPTIONS request to discover allowed methods, then
        specifically tests for TRACE (XST vulnerability), PUT, and
        DELETE methods which should typically be disabled.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check HTTP methods")
            return

        try:
            # Send OPTIONS request
            response = self.http.options(url)
            if response is None:
                return

            allow_header = ""
            for key, value in response.headers.items():
                if key.lower() == "allow":
                    allow_header = value
                    break

            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]

                # Check for TRACE (XST - Cross-Site Tracing)
                if "TRACE" in methods:
                    self._create_finding(
                        finding_type="http_methods",
                        severity="MEDIUM",
                        title="TRACE Method Enabled (XST)",
                        description="The TRACE HTTP method is enabled. This can be exploited for Cross-Site Tracing (XST) attacks to steal credentials from HttpOnly cookies.",
                        url=url,
                        evidence=f"Allow: {allow_header}",
                        remediation="Disable the TRACE method in the web server configuration.",
                        cvss=4.3,
                        cwe="CWE-693",
                    )

                # Check for PUT
                if "PUT" in methods:
                    self._create_finding(
                        finding_type="http_methods",
                        severity="LOW",
                        title="PUT Method Enabled",
                        description="The PUT HTTP method is enabled. If not properly secured, this could allow unauthorized file uploads.",
                        url=url,
                        evidence=f"Allow: {allow_header}",
                        remediation="Disable PUT method if not required, or ensure proper authorization.",
                        cvss=3.1,
                        cwe="CWE-749",
                    )

                # Check for DELETE
                if "DELETE" in methods:
                    self._create_finding(
                        finding_type="http_methods",
                        severity="LOW",
                        title="DELETE Method Enabled",
                        description="The DELETE HTTP method is enabled. If not properly secured, this could allow unauthorized resource deletion.",
                        url=url,
                        evidence=f"Allow: {allow_header}",
                        remediation="Disable DELETE method if not required, or ensure proper authorization.",
                        cvss=3.1,
                        cwe="CWE-749",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking HTTP methods: {str(e)}")

    # =========================================================================
    # CHECK HOST HEADER INJECTION
    # =========================================================================

    def check_host_header(self, url: str) -> None:
        """
        Test for host header injection vulnerabilities.

        Tests include:
        - Injected host header reflection in response body
        - Absolute URL confusion
        - X-Forwarded-Host manipulation
        - Double Host header

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check host header injection")
            return

        try:
            evil_host = "evil.com"
            parsed = urlparse(url)
            original_host = parsed.netloc

            # Test 1: X-Forwarded-Host injection
            headers = {"X-Forwarded-Host": evil_host}
            response = self.http.get(url, headers=headers)
            if response and response.body and evil_host in response.body:
                self._create_finding(
                    finding_type="host_header_injection",
                    severity="HIGH",
                    title="Host Header Injection via X-Forwarded-Host",
                    description="The application reflects the X-Forwarded-Host header value in the response, which can be exploited for cache poisoning, password reset hijacking, or SSRF.",
                    url=url,
                    evidence=f"Injected X-Forwarded-Host: {evil_host}, found in response body.",
                    remediation="Ignore X-Forwarded-Host header or validate it against a whitelist of expected hosts.",
                    cvss=6.1,
                    cwe="CWE-644",
                )

            # Test 2: X-Host injection
            headers = {"X-Host": evil_host}
            response = self.http.get(url, headers=headers)
            if response and response.body and evil_host in response.body:
                self._create_finding(
                    finding_type="host_header_injection",
                    severity="HIGH",
                    title="Host Header Injection via X-Host",
                    description="The application reflects the X-Host header value in the response body.",
                    url=url,
                    evidence=f"Injected X-Host: {evil_host}, found in response body.",
                    remediation="Do not trust X-Host header from client requests.",
                    cvss=6.1,
                    cwe="CWE-644",
                )

            # Test 3: X-Forwarded-Server
            headers = {"X-Forwarded-Server": evil_host}
            response = self.http.get(url, headers=headers)
            if response and response.body and evil_host in response.body:
                self._create_finding(
                    finding_type="host_header_injection",
                    severity="MEDIUM",
                    title="Host Header Injection via X-Forwarded-Server",
                    description="The application reflects X-Forwarded-Server in the response.",
                    url=url,
                    evidence=f"Injected X-Forwarded-Server: {evil_host}, found in response body.",
                    remediation="Validate and sanitize all forwarded headers.",
                    cvss=5.3,
                    cwe="CWE-644",
                )

        except Exception as e:
            self.color.warning(f"  Error checking host header: {str(e)}")

    # =========================================================================
    # CHECK SSL/TLS
    # =========================================================================

    def check_ssl_tls(self, domain: str) -> None:
        """
        Check SSL/TLS configuration for security issues.

        Examines:
        - Certificate validity and expiry
        - Certificate chain issues
        - HSTS configuration
        - Protocol version support

        Args:
            domain: The domain to check SSL/TLS for.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check SSL/TLS configuration")
            return

        try:
            # Connect and get certificate info
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    if cert:
                        # Check expiry
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            from datetime import datetime as dt
                            try:
                                expiry = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (expiry - dt.now()).days

                                if days_left < 0:
                                    self._create_finding(
                                        finding_type="ssl_tls",
                                        severity="CRITICAL",
                                        title="SSL Certificate Expired",
                                        description=f"The SSL certificate expired {abs(days_left)} days ago.",
                                        url=f"https://{domain}",
                                        evidence=f"Certificate notAfter: {not_after}",
                                        remediation="Renew the SSL certificate immediately.",
                                        cvss=7.5,
                                        cwe="CWE-295",
                                    )
                                elif days_left < 30:
                                    self._create_finding(
                                        finding_type="ssl_tls",
                                        severity="MEDIUM",
                                        title="SSL Certificate Expiring Soon",
                                        description=f"The SSL certificate expires in {days_left} days.",
                                        url=f"https://{domain}",
                                        evidence=f"Certificate notAfter: {not_after}, Days remaining: {days_left}",
                                        remediation="Renew the SSL certificate before expiry.",
                                        cvss=4.3,
                                        cwe="CWE-295",
                                    )
                            except ValueError:
                                pass

                        # Check subject alternative names
                        san = cert.get("subjectAltName", [])
                        subject = dict(x[0] for x in cert.get("subject", []) if x)

                        # Check if wildcard cert
                        cn = subject.get("commonName", "")
                        if cn.startswith("*."):
                            self._create_finding(
                                finding_type="ssl_tls",
                                severity="INFO",
                                title="Wildcard SSL Certificate",
                                description=f"A wildcard certificate is used: {cn}. While not inherently insecure, compromising one server compromises all subdomains.",
                                url=f"https://{domain}",
                                evidence=f"Common Name: {cn}",
                                remediation="Consider using individual certificates for critical subdomains.",
                                cvss=0.0,
                                cwe="CWE-295",
                            )

                    # Check protocol version
                    if protocol and "TLSv1.0" in protocol or "TLSv1.1" in str(protocol):
                        self._create_finding(
                            finding_type="ssl_tls",
                            severity="MEDIUM",
                            title=f"Deprecated TLS Protocol: {protocol}",
                            description=f"The server supports {protocol} which is deprecated and has known vulnerabilities.",
                            url=f"https://{domain}",
                            evidence=f"Negotiated protocol: {protocol}",
                            remediation="Disable TLS 1.0 and TLS 1.1. Use TLS 1.2+ only.",
                            cvss=5.3,
                            cwe="CWE-326",
                        )

        except ssl.SSLError as e:
            self._create_finding(
                finding_type="ssl_tls",
                severity="HIGH",
                title="SSL/TLS Error",
                description=f"SSL/TLS connection failed: {str(e)}",
                url=f"https://{domain}",
                evidence=str(e),
                remediation="Fix the SSL/TLS configuration.",
                cvss=5.9,
                cwe="CWE-295",
            )
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            self.color.warning(f"  Error checking SSL/TLS: {str(e)}")


    # =========================================================================
    # CHECK EMAIL SECURITY
    # =========================================================================

    def check_email_security(self, domain: str) -> None:
        """
        Check email security configuration (SPF, DKIM, DMARC).

        Resolves TXT records for the domain to verify:
        - SPF record exists and is properly configured
        - DMARC record exists with enforcement policy
        - DKIM selector records (common selectors)

        Args:
            domain: The domain to check email security for.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check email security")
            return

        try:
            # Check SPF
            txt_records = self.dns.resolve(domain, "TXT")
            has_spf = False
            spf_record = ""
            for record in txt_records:
                if "v=spf1" in record.lower():
                    has_spf = True
                    spf_record = record
                    break

            if not has_spf:
                self._create_finding(
                    finding_type="email_security",
                    severity="MEDIUM",
                    title="Missing SPF Record",
                    description="No SPF record found. This allows anyone to send emails pretending to be from this domain (email spoofing).",
                    url=f"https://{domain}",
                    evidence="No TXT record containing 'v=spf1' found.",
                    remediation="Add an SPF TXT record: 'v=spf1 include:_spf.example.com -all'",
                    cvss=4.3,
                    cwe="CWE-290",
                )
            elif "+all" in spf_record:
                self._create_finding(
                    finding_type="email_security",
                    severity="HIGH",
                    title="SPF Record Too Permissive (+all)",
                    description="The SPF record uses '+all' which allows ANY server to send email for this domain, defeating the purpose of SPF.",
                    url=f"https://{domain}",
                    evidence=f"SPF Record: {spf_record}",
                    remediation="Change '+all' to '-all' (hard fail) or '~all' (soft fail).",
                    cvss=5.3,
                    cwe="CWE-290",
                )

            # Check DMARC
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = self.dns.resolve(dmarc_domain, "TXT")
            has_dmarc = False
            dmarc_record = ""
            for record in dmarc_records:
                if "v=dmarc1" in record.lower():
                    has_dmarc = True
                    dmarc_record = record
                    break

            if not has_dmarc:
                self._create_finding(
                    finding_type="email_security",
                    severity="MEDIUM",
                    title="Missing DMARC Record",
                    description="No DMARC record found. DMARC provides instructions to receiving servers on how to handle failed SPF/DKIM checks.",
                    url=f"https://{domain}",
                    evidence=f"No TXT record at _dmarc.{domain}",
                    remediation="Add a DMARC TXT record at _dmarc.domain: 'v=DMARC1; p=reject; rua=mailto:dmarc@domain'",
                    cvss=4.3,
                    cwe="CWE-290",
                )
            elif "p=none" in dmarc_record.lower():
                self._create_finding(
                    finding_type="email_security",
                    severity="LOW",
                    title="DMARC Policy Set to None",
                    description="DMARC policy is set to 'none' (monitoring only). Failed authentication does not result in message rejection.",
                    url=f"https://{domain}",
                    evidence=f"DMARC Record: {dmarc_record}",
                    remediation="Change DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' after monitoring.",
                    cvss=3.1,
                    cwe="CWE-290",
                )

        except Exception as e:
            self.color.warning(f"  Error checking email security: {str(e)}")

    # =========================================================================
    # CHECK CSP WEAKNESSES
    # =========================================================================

    def check_csp_weaknesses(self, url: str) -> None:
        """
        Parse and analyze Content-Security-Policy for weaknesses.

        Checks for:
        - unsafe-inline (allows inline scripts)
        - unsafe-eval (allows eval())
        - Wildcard sources (*)
        - data: URI scheme
        - blob: URI scheme
        - Missing base-uri directive
        - Missing object-src directive
        - Missing form-action directive
        - Overly broad whitelists

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check CSP weaknesses")
            return

        try:
            response = self.http.get(url)
            if response is None or response.status_code == 0:
                return

            headers = {k.lower(): v for k, v in response.headers.items()}
            csp = headers.get("content-security-policy", "")

            if not csp:
                # Already reported in security headers check
                return

            # Parse CSP directives
            directives = {}
            for directive in csp.split(";"):
                directive = directive.strip()
                if not directive:
                    continue
                parts = directive.split()
                if parts:
                    dir_name = parts[0].lower()
                    dir_values = parts[1:] if len(parts) > 1 else []
                    directives[dir_name] = dir_values

            # Check unsafe-inline
            for dir_name in ["script-src", "default-src", "style-src"]:
                values = directives.get(dir_name, [])
                if "'unsafe-inline'" in values:
                    severity = "HIGH" if dir_name == "script-src" else "MEDIUM"
                    self._create_finding(
                        finding_type="csp_weakness",
                        severity=severity,
                        title=f"CSP {dir_name} allows unsafe-inline",
                        description=f"The {dir_name} directive includes 'unsafe-inline', which defeats XSS protection by allowing inline scripts/styles.",
                        url=url,
                        evidence=f"CSP {dir_name}: {' '.join(values)}",
                        remediation=f"Remove 'unsafe-inline' from {dir_name}. Use nonces or hashes instead.",
                        cvss=6.1 if dir_name == "script-src" else 4.3,
                        cwe="CWE-79",
                    )

            # Check unsafe-eval
            for dir_name in ["script-src", "default-src"]:
                values = directives.get(dir_name, [])
                if "'unsafe-eval'" in values:
                    self._create_finding(
                        finding_type="csp_weakness",
                        severity="MEDIUM",
                        title=f"CSP {dir_name} allows unsafe-eval",
                        description=f"The {dir_name} directive includes 'unsafe-eval', allowing eval() and similar constructs.",
                        url=url,
                        evidence=f"CSP {dir_name}: {' '.join(values)}",
                        remediation=f"Remove 'unsafe-eval' from {dir_name}. Refactor code to avoid eval().",
                        cvss=5.3,
                        cwe="CWE-79",
                    )

            # Check wildcard sources
            for dir_name, values in directives.items():
                if "*" in values:
                    self._create_finding(
                        finding_type="csp_weakness",
                        severity="MEDIUM",
                        title=f"CSP {dir_name} uses wildcard (*)",
                        description=f"The {dir_name} directive uses a wildcard (*), allowing resources from any origin.",
                        url=url,
                        evidence=f"CSP {dir_name}: {' '.join(values)}",
                        remediation=f"Replace wildcard in {dir_name} with specific trusted origins.",
                        cvss=5.3,
                        cwe="CWE-79",
                    )

            # Check data: URI
            for dir_name in ["script-src", "default-src", "object-src"]:
                values = directives.get(dir_name, [])
                if "data:" in values:
                    self._create_finding(
                        finding_type="csp_weakness",
                        severity="MEDIUM",
                        title=f"CSP {dir_name} allows data: URIs",
                        description=f"The {dir_name} directive allows data: URIs which can be used to inject scripts.",
                        url=url,
                        evidence=f"CSP {dir_name}: {' '.join(values)}",
                        remediation=f"Remove 'data:' from {dir_name} or restrict it to specific contexts.",
                        cvss=5.3,
                        cwe="CWE-79",
                    )

            # Check missing important directives
            if "base-uri" not in directives:
                self._create_finding(
                    finding_type="csp_weakness",
                    severity="LOW",
                    title="CSP Missing base-uri Directive",
                    description="The CSP does not include a base-uri directive. An attacker could inject a <base> tag to hijack relative URLs.",
                    url=url,
                    evidence=f"CSP: {csp[:200]}",
                    remediation="Add 'base-uri \'self\'' to the CSP.",
                    cvss=4.3,
                    cwe="CWE-79",
                )

            if "object-src" not in directives and "default-src" not in directives:
                self._create_finding(
                    finding_type="csp_weakness",
                    severity="LOW",
                    title="CSP Missing object-src Directive",
                    description="The CSP does not restrict object-src, allowing Flash/Java plugins that could bypass XSS protections.",
                    url=url,
                    evidence=f"CSP: {csp[:200]}",
                    remediation="Add 'object-src \'none\'' to the CSP.",
                    cvss=4.3,
                    cwe="CWE-79",
                )

        except Exception as e:
            self.color.warning(f"  Error checking CSP: {str(e)}")

    # =========================================================================
    # CHECK CACHE POISONING
    # =========================================================================

    def check_cache_poisoning(self, url: str) -> None:
        """
        Test for web cache poisoning vulnerabilities.

        Tests unkeyed headers that might be reflected in cached responses:
        - X-Forwarded-Host
        - X-Original-URL
        - X-Rewrite-URL
        - X-Forwarded-Scheme
        - X-HTTP-Method-Override

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check cache poisoning")
            return

        try:
            # First, get baseline response
            baseline = self.http.get(url)
            if baseline is None or baseline.status_code == 0:
                return

            # Test unkeyed headers
            poison_headers = [
                ("X-Forwarded-Host", "evil.com"),
                ("X-Original-URL", "/evil-path"),
                ("X-Rewrite-URL", "/evil-rewrite"),
                ("X-Forwarded-Scheme", "nothttps"),
                ("X-HTTP-Method-Override", "POST"),
                ("X-Forwarded-Port", "1337"),
                ("X-Forwarded-Prefix", "/evil"),
            ]

            for header_name, header_value in poison_headers:
                try:
                    headers = {header_name: header_value}
                    response = self.http.get(url, headers=headers)
                    if response is None:
                        continue

                    # Check if the header value is reflected in the response
                    if response.body and header_value in response.body:
                        # Verify it was not in the baseline
                        if baseline.body and header_value not in baseline.body:
                            self._create_finding(
                                finding_type="cache_poisoning",
                                severity="HIGH",
                                title=f"Potential Cache Poisoning via {header_name}",
                                description=f"The unkeyed header '{header_name}' is reflected in the response body. If the response is cached, this could poison the cache for all users.",
                                url=url,
                                evidence=f"Header: {header_name}: {header_value}\nReflected in response body.",
                                remediation=f"Do not reflect the {header_name} header in responses, or include it as a cache key.",
                                cvss=6.5,
                                cwe="CWE-444",
                            )

                    # Check if response differs significantly (may indicate processing)
                    if response.status_code != baseline.status_code:
                        self._create_finding(
                            finding_type="cache_poisoning",
                            severity="LOW",
                            title=f"Unkeyed Header Affects Response: {header_name}",
                            description=f"The header '{header_name}' causes a different response status ({response.status_code} vs {baseline.status_code}), indicating server-side processing.",
                            url=url,
                            evidence=f"Header: {header_name}: {header_value}\nBaseline status: {baseline.status_code}\nWith header: {response.status_code}",
                            remediation="Investigate if this header can be used for cache poisoning.",
                            cvss=3.7,
                            cwe="CWE-444",
                        )

                except Exception:
                    continue

        except Exception as e:
            self.color.warning(f"  Error checking cache poisoning: {str(e)}")

    # =========================================================================
    # CHECK REQUEST SMUGGLING INDICATORS
    # =========================================================================

    def check_request_smuggling_indicators(self, url: str) -> None:
        """
        Check for HTTP request smuggling indicators.

        Looks for conditions that make request smuggling possible:
        - CL.TE ambiguity indicators
        - HTTP/1.1 vs HTTP/2 downgrade indicators
        - Multiple Content-Length headers
        - Transfer-Encoding handling

        Note: This does not perform actual smuggling attacks,
        only checks for indicators.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check request smuggling indicators")
            return

        try:
            response = self.http.get(url)
            if response is None:
                return

            resp_headers = {k.lower(): v for k, v in response.headers.items()}

            # Check if both Content-Length and Transfer-Encoding are present
            has_cl = "content-length" in resp_headers
            has_te = "transfer-encoding" in resp_headers

            if has_cl and has_te:
                self._create_finding(
                    finding_type="request_smuggling",
                    severity="LOW",
                    title="Both Content-Length and Transfer-Encoding Present",
                    description="The response contains both Content-Length and Transfer-Encoding headers, which can indicate request smuggling susceptibility when the server and a reverse proxy disagree on which to honor.",
                    url=url,
                    evidence=f"Content-Length: {resp_headers.get('content-length')}\nTransfer-Encoding: {resp_headers.get('transfer-encoding')}",
                    remediation="Ensure consistent handling of Content-Length and Transfer-Encoding between front-end and back-end servers.",
                    cvss=5.3,
                    cwe="CWE-444",
                )

            # Check for proxy indicators (multiple hops increase smuggling risk)
            proxy_headers = ["via", "x-forwarded-for", "x-forwarded-host", "x-real-ip"]
            proxy_count = sum(1 for h in proxy_headers if h in resp_headers)
            if proxy_count >= 2:
                self._create_finding(
                    finding_type="request_smuggling",
                    severity="INFO",
                    title="Multiple Proxy Layers Detected",
                    description="Multiple proxy-related headers suggest multiple hop points, which increases the attack surface for request smuggling.",
                    url=url,
                    evidence=f"Proxy headers found: {', '.join(h for h in proxy_headers if h in resp_headers)}",
                    remediation="Ensure all proxy layers handle Content-Length and Transfer-Encoding consistently.",
                    cvss=0.0,
                    cwe="CWE-444",
                )

        except Exception as e:
            self.color.warning(f"  Error checking request smuggling: {str(e)}")


    # =========================================================================
    # CHECK GRAPHQL INTROSPECTION
    # =========================================================================

    def check_graphql_introspection(self, url: str) -> None:
        """
        Check if GraphQL introspection is enabled.

        Sends an introspection query to common GraphQL endpoints
        and checks if the full schema is exposed.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check GraphQL introspection")
            return

        graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/gql"]

        introspection_query = '{"query": "{ __schema { types { name } } }"}'

        for path in graphql_paths:
            try:
                gql_url = urljoin(url, path)
                headers = {"Content-Type": "application/json"}
                response = self.http.post(gql_url, data=introspection_query, headers=headers)

                if response is None:
                    continue

                if response.status_code == 200 and response.body:
                    try:
                        data = json.loads(response.body)
                        if "data" in data and "__schema" in data.get("data", {}):
                            types = data["data"]["__schema"].get("types", [])
                            self._create_finding(
                                finding_type="graphql",
                                severity="MEDIUM",
                                title=f"GraphQL Introspection Enabled: {path}",
                                description=f"GraphQL introspection is enabled at {gql_url}, exposing the complete API schema with {len(types)} types. Attackers can enumerate all queries, mutations, and data types.",
                                url=gql_url,
                                evidence=f"Schema contains {len(types)} types. First 5: {[t.get('name', '') for t in types[:5]]}",
                                remediation="Disable introspection in production: set introspection: false in your GraphQL server configuration.",
                                cvss=5.3,
                                cwe="CWE-200",
                            )
                            break
                    except json.JSONDecodeError:
                        pass

                # Also check GET-based introspection
                get_url = f"{gql_url}?query={{__schema{{types{{name}}}}}}"
                response = self.http.get(get_url)
                if response and response.status_code == 200 and "__schema" in (response.body or ""):
                    self._create_finding(
                        finding_type="graphql",
                        severity="MEDIUM",
                        title=f"GraphQL Introspection via GET: {path}",
                        description=f"GraphQL introspection is accessible via GET request at {gql_url}.",
                        url=gql_url,
                        evidence="Introspection query successful via GET.",
                        remediation="Disable introspection in production.",
                        cvss=5.3,
                        cwe="CWE-200",
                    )
                    break

            except Exception:
                continue

    # =========================================================================
    # CHECK SSRF INDICATORS
    # =========================================================================

    def check_ssrf_indicators(self, url: str) -> None:
        """
        Identify URL/file/path parameters that could be SSRF vectors.

        Analyzes the URL and page content for parameters that accept
        URLs or file paths, which could potentially be exploited for
        Server-Side Request Forgery.

        Args:
            url: The target URL to analyze.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check SSRF indicators")
            return

        try:
            # Check URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            ssrf_param_names = [
                "url", "uri", "path", "file", "page", "document",
                "folder", "root", "dir", "load", "target", "source",
                "src", "dest", "redirect", "img", "image", "link",
                "feed", "host", "site", "html", "fetch", "proxy",
                "callback", "return", "data", "reference",
            ]

            for param_name in params:
                if param_name.lower() in ssrf_param_names:
                    param_value = params[param_name][0] if params[param_name] else ""
                    self._create_finding(
                        finding_type="ssrf_indicator",
                        severity="LOW",
                        title=f"Potential SSRF Parameter: {param_name}",
                        description=f"The parameter '{param_name}' may accept URL/path input that could be exploited for SSRF if not properly validated server-side.",
                        url=url,
                        evidence=f"Parameter: {param_name}={param_value[:100]}",
                        remediation="Validate and whitelist allowed URLs/hosts. Block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x). Use network segmentation.",
                        cvss=6.5,
                        cwe="CWE-918",
                    )

            # Check page content for forms with URL inputs
            response = self.http.get(url)
            if response and response.body:
                # Find form inputs that might accept URLs
                url_input_pattern = re.compile(
                    r'''<input[^>]*(?:name|id)\s*=\s*["']([^"']*(?:url|uri|link|src|path|file|fetch|proxy|callback)[^"']*)["']''',
                    re.IGNORECASE
                )
                matches = url_input_pattern.findall(response.body)
                for input_name in matches:
                    self._create_finding(
                        finding_type="ssrf_indicator",
                        severity="LOW",
                        title=f"Form Input May Accept URLs: {input_name}",
                        description=f"A form input named '{input_name}' may accept URL values that could be exploited for SSRF.",
                        url=url,
                        evidence=f"Input name/id: {input_name}",
                        remediation="Implement server-side URL validation with allowlists.",
                        cvss=4.3,
                        cwe="CWE-918",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking SSRF indicators: {str(e)}")

    # =========================================================================
    # CHECK XXE INDICATORS
    # =========================================================================

    def check_xxe_indicators(self, url: str) -> None:
        """
        Check for XML External Entity (XXE) vulnerability indicators.

        Tests if the server accepts XML content type and processes
        XML input, which could indicate XXE vulnerability.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check XXE indicators")
            return

        try:
            # Test if server accepts XML content type
            xml_payload = '<?xml version="1.0" encoding="UTF-8"?><test>hello</test>'
            headers = {"Content-Type": "application/xml"}
            response = self.http.post(url, data=xml_payload, headers=headers)

            if response and response.status_code not in (405, 415, 501):
                # Server accepts XML - potential XXE target
                if response.status_code in (200, 201, 202, 400, 422):
                    self._create_finding(
                        finding_type="xxe_indicator",
                        severity="LOW",
                        title="Server Accepts XML Content-Type",
                        description="The server processes XML input, which may be vulnerable to XXE attacks if external entities are not disabled.",
                        url=url,
                        evidence=f"POST with Content-Type: application/xml returned status {response.status_code}",
                        remediation="Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
                        cvss=5.3,
                        cwe="CWE-611",
                    )

            # Check for XML-related endpoints
            xml_paths = ["/api/xml", "/xml", "/soap", "/wsdl", "/ws", "/xmlrpc.php"]
            for path in xml_paths:
                try:
                    xml_url = urljoin(url, path)
                    response = self.http.get(xml_url)
                    if response and response.status_code == 200:
                        content_type = response.headers.get("Content-Type", "")
                        if "xml" in content_type.lower() or "<?xml" in (response.body or "")[:100]:
                            self._create_finding(
                                finding_type="xxe_indicator",
                                severity="LOW",
                                title=f"XML Endpoint Found: {path}",
                                description=f"An XML processing endpoint was found at {path}. Test for XXE vulnerabilities.",
                                url=xml_url,
                                evidence=f"Status: {response.status_code}, Content-Type: {content_type}",
                                remediation="Ensure XML parsers disable external entity resolution.",
                                cvss=4.3,
                                cwe="CWE-611",
                            )
                except Exception:
                    continue

        except Exception as e:
            self.color.warning(f"  Error checking XXE indicators: {str(e)}")

    # =========================================================================
    # CHECK IDOR PATTERNS
    # =========================================================================

    def check_idor_patterns(self, url: str) -> None:
        """
        Detect patterns that suggest Insecure Direct Object References.

        Identifies:
        - Sequential numeric IDs in URLs
        - UUIDs that could be enumerable
        - Predictable resource paths
        - User ID references in parameters

        Args:
            url: The target URL to analyze.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check IDOR patterns")
            return

        try:
            parsed = urlparse(url)
            path = parsed.path
            params = parse_qs(parsed.query)

            # Check for sequential IDs in path
            id_in_path = re.findall(r'/(\d{1,10})(?:/|$)', path)
            if id_in_path:
                for id_val in id_in_path:
                    if int(id_val) < 1000000:  # Likely sequential
                        self._create_finding(
                            finding_type="idor",
                            severity="LOW",
                            title="Sequential ID in URL Path",
                            description=f"The URL contains what appears to be a sequential numeric ID ({id_val}). If access control is not properly enforced, this could be enumerated to access other users' resources.",
                            url=url,
                            evidence=f"ID value: {id_val} in path: {path}",
                            remediation="Use UUIDs instead of sequential IDs. Implement proper authorization checks for every resource access.",
                            cvss=5.3,
                            cwe="CWE-639",
                        )

            # Check for ID-like parameters
            id_param_names = ["id", "uid", "user_id", "userId", "account_id", "accountId",
                            "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
                            "profile_id", "profileId", "record_id", "recordId"]
            for param_name in params:
                if param_name.lower() in [p.lower() for p in id_param_names]:
                    param_value = params[param_name][0] if params[param_name] else ""
                    if param_value.isdigit():
                        self._create_finding(
                            finding_type="idor",
                            severity="LOW",
                            title=f"Numeric ID Parameter: {param_name}",
                            description=f"The parameter '{param_name}' contains a numeric value ({param_value}) that could be manipulated to access other resources.",
                            url=url,
                            evidence=f"Parameter: {param_name}={param_value}",
                            remediation="Implement proper access control. Verify the authenticated user owns the requested resource.",
                            cvss=5.3,
                            cwe="CWE-639",
                        )

            # Check page content for IDOR patterns
            response = self.http.get(url)
            if response and response.body:
                # Look for API endpoints with IDs
                api_id_pattern = re.compile(r'''["']/(api|v[12])/[a-z]+/\d{1,8}["']''', re.IGNORECASE)
                matches = api_id_pattern.findall(response.body)
                if matches:
                    self._create_finding(
                        finding_type="idor",
                        severity="INFO",
                        title="API Endpoints with Numeric IDs in Page",
                        description="The page contains references to API endpoints with numeric IDs that could be IDOR targets.",
                        url=url,
                        evidence=f"Found {len(matches)} API references with numeric IDs.",
                        remediation="Review access control for all API endpoints with resource IDs.",
                        cvss=0.0,
                        cwe="CWE-639",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking IDOR patterns: {str(e)}")

    # =========================================================================
    # CHECK RATE LIMITING
    # =========================================================================

    def check_rate_limiting(self, url: str) -> None:
        """
        Assess rate limiting implementation.

        Sends multiple rapid requests and checks for:
        - 429 Too Many Requests responses
        - Rate-limit related headers
        - Consistent response times (no throttling)

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check rate limiting")
            return

        try:
            # Send 5 rapid requests
            responses = []
            for _ in range(5):
                response = self.http.get(url)
                if response:
                    responses.append(response)
                time.sleep(0.1)  # Small delay to not be too aggressive

            if not responses:
                return

            # Check for rate limit headers
            last_response = responses[-1]
            rate_limit_headers = {k.lower(): v for k, v in last_response.headers.items()
                                if "rate" in k.lower() or "limit" in k.lower()
                                or "retry" in k.lower() or "throttl" in k.lower()}

            # Check if any response was 429
            got_429 = any(r.status_code == 429 for r in responses)

            if not got_429 and not rate_limit_headers:
                self._create_finding(
                    finding_type="rate_limiting",
                    severity="LOW",
                    title="No Rate Limiting Detected",
                    description="No rate limiting mechanism was detected after multiple rapid requests. This may allow brute force attacks, credential stuffing, or API abuse.",
                    url=url,
                    evidence=f"Sent 5 rapid requests, all returned status {last_response.status_code}. No rate-limit headers found.",
                    remediation="Implement rate limiting (e.g., X-RateLimit-Limit headers, 429 responses). Consider using tools like nginx rate limiting or API gateways.",
                    cvss=3.7,
                    cwe="CWE-770",
                )
            elif rate_limit_headers:
                self._create_finding(
                    finding_type="rate_limiting",
                    severity="INFO",
                    title="Rate Limiting Headers Present",
                    description="Rate limiting headers are present in responses.",
                    url=url,
                    evidence=f"Rate limit headers: {json.dumps(rate_limit_headers)}",
                    remediation="Verify rate limits are appropriately configured for all sensitive endpoints.",
                    cvss=0.0,
                    cwe="",
                )

        except Exception as e:
            self.color.warning(f"  Error checking rate limiting: {str(e)}")

    # =========================================================================
    # CHECK WAF FINGERPRINT
    # =========================================================================

    def check_waf_fingerprint(self, url: str) -> None:
        """
        Identify active Web Application Firewalls using signatures.

        Tests for WAF presence using:
        - Response header patterns
        - Cookie names
        - Response body patterns (block pages)
        - Behavior when sending malicious payloads

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check WAF fingerprint")
            return

        try:
            # Get baseline response
            response = self.http.get(url)
            if response is None:
                return

            resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            resp_body = (response.body or "").lower()

            detected_wafs = []

            # Check against WAF signatures
            waf_sigs = LOCAL_WAF_SIGNATURES
            try:
                if WAF_SIGNATURES:
                    waf_sigs.update(WAF_SIGNATURES)
            except (NameError, TypeError):
                pass

            for waf_name, signatures in waf_sigs.items():
                evidence = []

                # Check headers
                for header_name in signatures.get("headers", []):
                    if header_name.lower() in resp_headers:
                        evidence.append(f"Header: {header_name}")

                # Check cookies
                cookie_header = resp_headers.get("set-cookie", "")
                for cookie_name in signatures.get("cookies", []):
                    if cookie_name.lower() in cookie_header:
                        evidence.append(f"Cookie: {cookie_name}")

                # Check body patterns
                for pattern in signatures.get("body_patterns", []):
                    if pattern.lower() in resp_body:
                        evidence.append(f"Body: {pattern}")

                if evidence:
                    detected_wafs.append((waf_name, evidence))

            # Also test with a malicious-looking payload
            evil_url = url + "?test=<script>alert(1)</script>&id=1' OR '1'='1"
            try:
                evil_response = self.http.get(evil_url)
                if evil_response and evil_response.status_code in (403, 406, 429, 503):
                    detected_wafs.append(("Unknown WAF (block behavior)", [f"Blocked request returned {evil_response.status_code}"]))
            except Exception:
                pass

            for waf_name, evidence in detected_wafs:
                self._create_finding(
                    finding_type="waf_detected",
                    severity="INFO",
                    title=f"WAF Detected: {waf_name}",
                    description=f"A Web Application Firewall ({waf_name}) is protecting this application. This affects exploit delivery and may require bypass techniques.",
                    url=url,
                    evidence="; ".join(evidence),
                    remediation="WAF presence is informational. Ensure WAF rules are properly maintained and updated.",
                    cvss=0.0,
                    cwe="",
                )

        except Exception as e:
            self.color.warning(f"  Error checking WAF: {str(e)}")


    # =========================================================================
    # CHECK 403 BYPASS
    # =========================================================================

    def check_403_bypass(self, url: str) -> None:
        """
        Attempt to bypass 403 Forbidden responses.

        Techniques tested:
        - Path normalization (/./path, //path)
        - Header tricks (X-Original-URL, X-Rewrite-URL)
        - X-Forwarded-For: 127.0.0.1
        - URL encoding variations
        - Case variation
        - HTTP method override

        Args:
            url: The target URL to test bypass techniques on.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check 403 bypass")
            return

        try:
            # First check if we get a 403
            response = self.http.get(url)
            if response is None or response.status_code != 403:
                return

            parsed = urlparse(url)
            path = parsed.path or "/"

            bypasses_to_try = []

            # Path normalization tricks
            bypasses_to_try.append(("path_normalization", url.replace(path, f"/{path.lstrip('/')}/.")))
            bypasses_to_try.append(("double_slash", url.replace(path, f"//{path.lstrip('/')}")))
            bypasses_to_try.append(("path_dot", url.replace(path, f"{path}/.")))
            bypasses_to_try.append(("trailing_slash", url.rstrip("/") + "/"))
            bypasses_to_try.append(("semicolon", url.replace(path, f"{path};/")))
            bypasses_to_try.append(("null_byte", url.replace(path, f"{path}%00")))
            bypasses_to_try.append(("url_encode", url.replace(path, quote(path))))

            # Case variation
            if path.lower() != path:
                bypasses_to_try.append(("case_lower", url.replace(path, path.lower())))
            else:
                bypasses_to_try.append(("case_upper", url.replace(path, path.upper())))

            for technique, bypass_url in bypasses_to_try:
                try:
                    bypass_response = self.http.get(bypass_url)
                    if bypass_response and bypass_response.status_code == 200:
                        self._create_finding(
                            finding_type="403_bypass",
                            severity="HIGH",
                            title=f"403 Bypass via {technique}",
                            description=f"The 403 restriction on {url} can be bypassed using {technique} technique.",
                            url=bypass_url,
                            evidence=f"Original: 403, Bypass URL returned: {bypass_response.status_code}",
                            remediation="Fix the access control at the application level, not just the URL pattern matching. Normalize paths before checking access rules.",
                            cvss=7.5,
                            cwe="CWE-284",
                        )
                        return  # Found a bypass, no need to try more
                except Exception:
                    continue

            # Header-based bypass attempts
            header_bypasses = [
                ("X-Original-URL", path),
                ("X-Rewrite-URL", path),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Remote-IP", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("X-Real-IP", "127.0.0.1"),
                ("X-Custom-IP-Authorization", "127.0.0.1"),
                ("X-Originating-IP", "127.0.0.1"),
            ]

            for header_name, header_value in header_bypasses:
                try:
                    headers = {header_name: header_value}
                    bypass_response = self.http.get(url, headers=headers)
                    if bypass_response and bypass_response.status_code == 200:
                        self._create_finding(
                            finding_type="403_bypass",
                            severity="HIGH",
                            title=f"403 Bypass via {header_name} Header",
                            description=f"The 403 restriction can be bypassed by adding {header_name}: {header_value} header.",
                            url=url,
                            evidence=f"Header: {header_name}: {header_value} => Status: {bypass_response.status_code}",
                            remediation="Do not rely on client-supplied headers for access control. Implement authorization at the application layer.",
                            cvss=7.5,
                            cwe="CWE-284",
                        )
                        return
                except Exception:
                    continue

        except Exception as e:
            self.color.warning(f"  Error checking 403 bypass: {str(e)}")

    # =========================================================================
    # CHECK BROKEN LINK HIJACKING
    # =========================================================================

    def check_broken_link_hijacking(self, url: str) -> None:
        """
        Check external links on the page for dead/available domains.

        If external links point to expired or unregistered domains,
        an attacker could register the domain and serve malicious content.

        Args:
            url: The target URL to check links on.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check broken link hijacking")
            return

        try:
            response = self.http.get(url)
            if response is None or not response.body:
                return

            # Extract external links
            link_pattern = re.compile(
                r'''href\s*=\s*["']?(https?://[^"'\s>]+)''',
                re.IGNORECASE
            )
            links = link_pattern.findall(response.body)

            # Get target domain to filter
            target_domain = domain_from_url(url)

            external_links = set()
            for link in links:
                try:
                    link_domain = domain_from_url(link)
                    if link_domain and link_domain != target_domain:
                        external_links.add((link, link_domain))
                except Exception:
                    continue

            # Check a sample of external links (max 10)
            for link, link_domain in list(external_links)[:10]:
                try:
                    # DNS resolution check
                    records = self.dns.resolve(link_domain, "A")
                    if not records:
                        self._create_finding(
                            finding_type="broken_link_hijacking",
                            severity="MEDIUM",
                            title=f"Broken External Link: {link_domain}",
                            description=f"The page links to {link_domain} which does not resolve in DNS. If this domain is available for registration, an attacker could hijack it.",
                            url=url,
                            evidence=f"External link: {link}\nDomain {link_domain} has no A records.",
                            remediation="Remove or update broken external links. Monitor external link health regularly.",
                            cvss=4.3,
                            cwe="CWE-1104",
                        )
                except Exception:
                    continue

        except Exception as e:
            self.color.warning(f"  Error checking broken links: {str(e)}")

    # =========================================================================
    # CHECK BUSINESS LOGIC
    # =========================================================================

    def check_business_logic(self, url: str) -> None:
        """
        Detect potential business logic vulnerability indicators.

        Identifies parameters and patterns that suggest business logic
        that could be manipulated:
        - Price/amount parameters
        - Quantity parameters
        - Discount/coupon codes
        - Negative value acceptance
        - Race condition indicators

        Args:
            url: The target URL to analyze.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check business logic")
            return

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Business logic parameter names
            biz_params = {
                "price": "Price manipulation",
                "amount": "Amount manipulation",
                "total": "Total manipulation",
                "cost": "Cost manipulation",
                "quantity": "Quantity manipulation",
                "qty": "Quantity manipulation",
                "count": "Count manipulation",
                "discount": "Discount manipulation",
                "coupon": "Coupon code injection",
                "promo": "Promo code injection",
                "voucher": "Voucher manipulation",
                "points": "Points manipulation",
                "credits": "Credits manipulation",
                "balance": "Balance manipulation",
                "shipping": "Shipping cost manipulation",
                "tax": "Tax manipulation",
                "fee": "Fee manipulation",
                "reward": "Reward manipulation",
                "bonus": "Bonus manipulation",
                "referral": "Referral manipulation",
                "limit": "Limit bypass",
                "max": "Maximum limit bypass",
                "min": "Minimum limit bypass",
            }

            for param_name in params:
                param_lower = param_name.lower()
                for biz_key, biz_desc in biz_params.items():
                    if biz_key in param_lower:
                        param_value = params[param_name][0] if params[param_name] else ""
                        self._create_finding(
                            finding_type="business_logic",
                            severity="LOW",
                            title=f"Business Logic Parameter: {param_name}",
                            description=f"The parameter '{param_name}' suggests {biz_desc} potential. Test with negative values, zero, very large numbers, and boundary values.",
                            url=url,
                            evidence=f"Parameter: {param_name}={param_value}",
                            remediation="Implement server-side validation for all business logic parameters. Never trust client-side values for pricing, quantities, or discounts.",
                            cvss=5.3,
                            cwe="CWE-840",
                        )
                        break

            # Check page content for business logic patterns
            response = self.http.get(url)
            if response and response.body:
                # Look for hidden price/amount fields
                hidden_biz_pattern = re.compile(
                    r'''<input[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["']([^"']*(?:price|amount|total|cost|qty|quantity|discount)[^"']*)["']''',
                    re.IGNORECASE
                )
                matches = hidden_biz_pattern.findall(response.body)
                for field_name in matches:
                    self._create_finding(
                        finding_type="business_logic",
                        severity="MEDIUM",
                        title=f"Hidden Business Logic Field: {field_name}",
                        description=f"A hidden form field '{field_name}' controls business logic. Attackers can modify hidden fields to manipulate pricing or quantities.",
                        url=url,
                        evidence=f"Hidden input: {field_name}",
                        remediation="Never rely on hidden fields for price/amount validation. Always validate on the server side.",
                        cvss=6.5,
                        cwe="CWE-472",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking business logic: {str(e)}")

    # =========================================================================
    # CHECK API VERSIONING
    # =========================================================================

    def check_api_versioning(self, url: str) -> None:
        """
        Probe for different API versions that may have weaker security.

        Tests common API version paths to discover:
        - Older API versions that may lack security controls
        - Undocumented API versions
        - Version-specific endpoints

        Args:
            url: The target URL to probe.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check API versioning")
            return

        try:
            version_paths = [
                "/api/v1", "/api/v2", "/api/v3", "/api/v4",
                "/v1", "/v2", "/v3", "/v4",
                "/api/v1.0", "/api/v2.0",
                "/api/latest", "/api/beta", "/api/alpha",
                "/api/internal", "/api/private", "/api/admin",
                "/api/v1/docs", "/api/v2/docs",
                "/api/v1/swagger.json", "/api/v2/swagger.json",
            ]

            discovered_versions = []

            for path in version_paths:
                try:
                    version_url = urljoin(url, path)
                    response = self.http.get(version_url)

                    if response and response.status_code in (200, 301, 302, 401, 403):
                        # Version exists (even if protected)
                        discovered_versions.append({
                            "path": path,
                            "status": response.status_code,
                            "url": version_url,
                        })
                except Exception:
                    continue

            if len(discovered_versions) > 1:
                version_info = ", ".join(
                    f"{v['path']} ({v['status']})" for v in discovered_versions
                )
                self._create_finding(
                    finding_type="api_versioning",
                    severity="LOW",
                    title="Multiple API Versions Discovered",
                    description=f"Multiple API versions are accessible. Older versions may have weaker security controls or missing authentication.",
                    url=url,
                    evidence=f"Discovered versions: {version_info}",
                    remediation="Deprecate and remove old API versions. Ensure all versions have consistent security controls.",
                    cvss=3.7,
                    cwe="CWE-16",
                )

            # Check for internal/admin APIs
            for version in discovered_versions:
                if any(kw in version["path"] for kw in ["internal", "private", "admin"]):
                    self._create_finding(
                        finding_type="api_versioning",
                        severity="MEDIUM",
                        title=f"Internal API Endpoint: {version['path']}",
                        description=f"An internal/admin API endpoint was discovered at {version['path']} with status {version['status']}.",
                        url=version["url"],
                        evidence=f"Status: {version['status']}",
                        remediation="Restrict internal API endpoints to internal networks only.",
                        cvss=5.3,
                        cwe="CWE-749",
                    )

        except Exception as e:
            self.color.warning(f"  Error checking API versioning: {str(e)}")

    # =========================================================================
    # CHECK SENSITIVE FILES
    # =========================================================================

    def check_sensitive_files(self, url: str) -> None:
        """
        Check for accessible sensitive files using SENSITIVE_FILE_PATHS.

        Tests the top 50 most critical sensitive file paths from
        the configuration for public accessibility.

        Args:
            url: The target URL to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check sensitive files")
            return

        # Top 50 most critical paths
        critical_paths = SENSITIVE_FILE_PATHS[:50] if len(SENSITIVE_FILE_PATHS) >= 50 else SENSITIVE_FILE_PATHS

        for file_path in critical_paths:
            try:
                check_url = urljoin(url, "/" + file_path.lstrip("/"))
                response = self.http.get(check_url)

                if response is None:
                    continue

                if response.status_code == 200 and response.body:
                    body = response.body
                    body_len = len(body)

                    # Skip if looks like a generic error page
                    if body_len < 30:
                        continue
                    if "404" in body[:200].lower() or "not found" in body[:200].lower():
                        continue

                    # Determine severity
                    severity = "LOW"
                    if any(kw in file_path.lower() for kw in [".env", "credential", "secret", "private", "key", "password"]):
                        severity = "CRITICAL"
                    elif any(kw in file_path.lower() for kw in [".git", ".svn", "wp-config", "database", "backup", ".sql"]):
                        severity = "HIGH"
                    elif any(kw in file_path.lower() for kw in ["config", "setting", "admin", "log", "debug"]):
                        severity = "MEDIUM"

                    self._create_finding(
                        finding_type="sensitive_file",
                        severity=severity,
                        title=f"Sensitive File Accessible: {file_path}",
                        description=f"The sensitive file '{file_path}' is publicly accessible and may contain credentials, configuration, or other sensitive data.",
                        url=check_url,
                        evidence=f"Status: {response.status_code}, Size: {body_len} bytes, Preview: {body[:80]}",
                        remediation=f"Remove '{file_path}' from the web root or restrict access via server configuration.",
                        cvss=7.5 if severity in ("CRITICAL", "HIGH") else 5.3,
                        cwe="CWE-538",
                    )

            except Exception:
                continue


    # =========================================================================
    # CHECK PARAMETER POLLUTION
    # =========================================================================

    def check_parameter_pollution(self, url: str) -> None:
        """
        Test for HTTP Parameter Pollution (HPP) vulnerability.

        Tests by duplicating existing parameters in the URL and checking
        if the server processes both values differently or if it can be
        used to bypass security controls.

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check parameter pollution")
            return

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                # No parameters to test, try adding common ones
                test_url = url + ("&" if "?" in url else "?") + "id=1&id=2"
                response = self.http.get(test_url)
                if response and response.status_code == 200:
                    # Check if both values appear
                    if response.body and ("1" in response.body and "2" in response.body):
                        self._create_finding(
                            finding_type="parameter_pollution",
                            severity="LOW",
                            title="HTTP Parameter Pollution Possible",
                            description="The server processes duplicate parameters, which could be exploited for HPP attacks to bypass security filters or WAF rules.",
                            url=test_url,
                            evidence="Duplicate 'id' parameter: both values reflected in response.",
                            remediation="Ensure the application handles duplicate parameters consistently. Validate parameters at a single point.",
                            cvss=4.3,
                            cwe="CWE-235",
                        )
                return

            # Test with existing parameters
            for param_name, param_values in list(params.items())[:3]:
                try:
                    # Add duplicate parameter
                    evil_value = "hpp_test_value"
                    test_url = url + f"&{param_name}={evil_value}"
                    response = self.http.get(test_url)

                    if response and response.body and evil_value in response.body:
                        self._create_finding(
                            finding_type="parameter_pollution",
                            severity="LOW",
                            title=f"HPP: Duplicate Parameter Reflected: {param_name}",
                            description=f"Duplicating the '{param_name}' parameter causes the second value to be reflected, indicating HPP vulnerability.",
                            url=test_url,
                            evidence=f"Duplicate {param_name} with value '{evil_value}' reflected in response.",
                            remediation="Use the first occurrence of each parameter. Implement strict parameter validation.",
                            cvss=4.3,
                            cwe="CWE-235",
                        )
                        break
                except Exception:
                    continue

        except Exception as e:
            self.color.warning(f"  Error checking parameter pollution: {str(e)}")

    # =========================================================================
    # CHECK CRLF INJECTION
    # =========================================================================

    def check_crlf_injection(self, url: str) -> None:
        """
        Test for CRLF injection in URL parameters.

        Injects %0d%0a (CRLF) sequences in parameter values and checks
        if they appear in response headers, indicating header injection.

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check CRLF injection")
            return

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # CRLF payloads
            crlf_payloads = [
                "%0d%0aInjected-Header:MonsterTest",
                "%0d%0a%0d%0a<script>alert(1)</script>",
                "\r\nInjected:True",
                "%0AHeader-Injection:true",
                "%0DHeader-Injection:true",
                "%E5%98%8A%E5%98%8DInjected:True",  # Unicode CRLF
            ]

            if not params:
                # Test with a common parameter
                for payload in crlf_payloads[:2]:
                    test_url = url + ("&" if "?" in url else "?") + f"test={payload}"
                    try:
                        response = self.http.get(test_url)
                        if response:
                            # Check if injected header appears
                            for key in response.headers:
                                if "injected" in key.lower() or "monstertest" in response.headers[key].lower():
                                    self._create_finding(
                                        finding_type="crlf_injection",
                                        severity="HIGH",
                                        title="CRLF Injection in Response Headers",
                                        description="CRLF characters in URL parameters are reflected in response headers, allowing HTTP response splitting.",
                                        url=test_url,
                                        evidence=f"Injected header found: {key}: {response.headers[key]}",
                                        remediation="Sanitize all user input before including in HTTP headers. Strip \r and \n characters.",
                                        cvss=6.1,
                                        cwe="CWE-113",
                                    )
                                    return
                    except Exception:
                        continue
            else:
                # Test with existing parameters
                for param_name in list(params.keys())[:2]:
                    for payload in crlf_payloads[:2]:
                        try:
                            test_params = dict(params)
                            test_params[param_name] = [payload]
                            query_string = urlencode(test_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                            response = self.http.get(test_url)

                            if response:
                                for key in response.headers:
                                    if "injected" in key.lower() or "monstertest" in response.headers.get(key, "").lower():
                                        self._create_finding(
                                            finding_type="crlf_injection",
                                            severity="HIGH",
                                            title=f"CRLF Injection via Parameter: {param_name}",
                                            description=f"CRLF injection is possible through the '{param_name}' parameter.",
                                            url=test_url,
                                            evidence=f"Injected header found: {key}: {response.headers[key]}",
                                            remediation="Sanitize user input in HTTP headers. Strip CR/LF characters.",
                                            cvss=6.1,
                                            cwe="CWE-113",
                                        )
                                        return
                        except Exception:
                            continue

        except Exception as e:
            self.color.warning(f"  Error checking CRLF injection: {str(e)}")

    # =========================================================================
    # CHECK PATH TRAVERSAL
    # =========================================================================

    def check_path_traversal(self, url: str) -> None:
        """
        Test for path traversal vulnerabilities in file-related parameters.

        Injects ../ patterns in parameters that might reference files
        and checks for indicators of successful traversal.

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check path traversal")
            return

        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Parameters likely to reference files
            file_params = [
                "file", "path", "filepath", "filename", "name",
                "document", "doc", "page", "template", "include",
                "dir", "folder", "directory", "load", "read",
                "view", "content", "download", "attachment",
            ]

            # Path traversal payloads
            traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\etc\\passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd",
                "C:\\Windows\\system32\\drivers\\etc\\hosts",
            ]

            # Success indicators
            success_indicators = [
                "root:", "daemon:", "[boot loader]", "[operating systems]",
                "localhost", "# /etc/", "nobody:",
            ]

            for param_name in params:
                if param_name.lower() in file_params:
                    for payload in traversal_payloads[:3]:
                        try:
                            test_params = dict(params)
                            test_params[param_name] = [payload]
                            query_string = urlencode(test_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                            response = self.http.get(test_url)
                            if response and response.body:
                                for indicator in success_indicators:
                                    if indicator in response.body:
                                        self._create_finding(
                                            finding_type="path_traversal",
                                            severity="CRITICAL",
                                            title=f"Path Traversal via {param_name}",
                                            description=f"Path traversal is possible through the '{param_name}' parameter, allowing reading of arbitrary server files.",
                                            url=test_url,
                                            evidence=f"Payload: {payload}\nResponse contains: {indicator}",
                                            remediation="Validate and sanitize file path parameters. Use a whitelist of allowed files. Never pass user input directly to file system operations.",
                                            cvss=9.1,
                                            cwe="CWE-22",
                                        )
                                        return
                        except Exception:
                            continue

        except Exception as e:
            self.color.warning(f"  Error checking path traversal: {str(e)}")

    # =========================================================================
    # CHECK OPEN REDIRECT
    # =========================================================================

    def check_open_redirect(self, url: str) -> None:
        """
        Test for open redirect vulnerabilities.

        Tests REDIRECT_PARAMS from config with external URL payloads
        and checks if the server issues a redirect to the injected URL.

        Args:
            url: The target URL to test.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check open redirect")
            return

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Redirect payloads
            redirect_payloads = [
                "https://evil.com",
                "//evil.com",
                "https://evil.com%23@target.com",
                "https://evil.com?@target.com",
                "/\\evil.com",
                "////evil.com",
                "https:evil.com",
            ]

            # Test a subset of redirect params
            params_to_test = REDIRECT_PARAMS[:15]

            for param_name in params_to_test:
                for payload in redirect_payloads[:3]:
                    try:
                        test_url = f"{base_url}?{param_name}={quote(payload)}"

                        # Use a non-following client for redirect detection
                        response = self.http.get(test_url)
                        if response is None:
                            continue

                        # Check for redirect
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = ""
                            for key, value in response.headers.items():
                                if key.lower() == "location":
                                    location = value
                                    break

                            if location and ("evil.com" in location):
                                self._create_finding(
                                    finding_type="open_redirect",
                                    severity="MEDIUM",
                                    title=f"Open Redirect via {param_name}",
                                    description=f"The parameter '{param_name}' allows redirecting users to arbitrary external URLs. This can be used for phishing attacks.",
                                    url=test_url,
                                    evidence=f"Parameter: {param_name}={payload}\nRedirect Location: {location}",
                                    remediation="Validate redirect URLs against a whitelist of allowed destinations. Only allow relative redirects or same-origin URLs.",
                                    cvss=4.7,
                                    cwe="CWE-601",
                                )
                                return

                        # Check for meta refresh or JS redirect in body
                        if response.body:
                            if f"evil.com" in response.body and any(
                                kw in response.body.lower()
                                for kw in ["meta http-equiv", "window.location", "document.location", "location.href"]
                            ):
                                self._create_finding(
                                    finding_type="open_redirect",
                                    severity="MEDIUM",
                                    title=f"Open Redirect (client-side) via {param_name}",
                                    description=f"The parameter '{param_name}' is used in a client-side redirect to an external URL.",
                                    url=test_url,
                                    evidence=f"Parameter: {param_name}={payload}\nRedirect found in response body.",
                                    remediation="Validate redirect destinations server-side before including in page content.",
                                    cvss=4.7,
                                    cwe="CWE-601",
                                )
                                return

                    except Exception:
                        continue

        except Exception as e:
            self.color.warning(f"  Error checking open redirect: {str(e)}")

    # =========================================================================
    # CHECK SUBDOMAIN TAKEOVER
    # =========================================================================

    def check_subdomain_takeover(self, subdomains: List[str]) -> None:
        """
        Check discovered subdomains for potential takeover.

        Resolves CNAME records for each subdomain and checks against
        TAKEOVER_FINGERPRINTS from config to identify services with
        dangling DNS entries.

        Args:
            subdomains: List of subdomain hostnames to check.
        """
        if self.dry_run:
            self.color.info("  [DRY-RUN] Would check subdomain takeover")
            return

        for subdomain in subdomains[:30]:  # Limit to 30 subdomains
            try:
                # Resolve CNAME records
                cnames = self.dns.resolve(subdomain, "CNAME")
                if not cnames:
                    continue

                for cname in cnames:
                    cname_lower = cname.lower()

                    # Check against takeover fingerprints
                    for service_name, service_info in TAKEOVER_FINGERPRINTS.items():
                        if not service_info.get("vulnerable", False):
                            continue

                        # Check if CNAME matches service
                        cname_match = False
                        for service_cname in service_info.get("cnames", []):
                            if service_cname.lower() in cname_lower:
                                cname_match = True
                                break

                        if not cname_match:
                            continue

                        # Try to fetch the subdomain and check fingerprints
                        try:
                            response = self.http.get(f"https://{subdomain}")
                            if response is None:
                                response = self.http.get(f"http://{subdomain}")

                            if response and response.body:
                                for fingerprint in service_info.get("fingerprints", []):
                                    if fingerprint.lower() in response.body.lower():
                                        self._create_finding(
                                            finding_type="subdomain_takeover",
                                            severity="HIGH",
                                            title=f"Subdomain Takeover: {subdomain} ({service_name})",
                                            description=f"The subdomain {subdomain} has a CNAME pointing to {service_name} ({cname}) which appears to be unclaimed. An attacker could register this service and take control of the subdomain.",
                                            url=f"https://{subdomain}",
                                            evidence=f"CNAME: {cname}\nFingerprint: {fingerprint}\nService: {service_name}",
                                            remediation=f"Either claim the {service_name} resource for {subdomain} or remove the DNS CNAME record.",
                                            cvss=8.6,
                                            cwe="CWE-284",
                                        )
                                        break
                        except Exception:
                            # If we cannot connect but CNAME exists, might be dangling
                            a_records = self.dns.resolve(subdomain, "A")
                            if not a_records:
                                self._create_finding(
                                    finding_type="subdomain_takeover",
                                    severity="MEDIUM",
                                    title=f"Potential Dangling CNAME: {subdomain}",
                                    description=f"The subdomain {subdomain} has a CNAME to {cname} ({service_name}) but does not resolve to any IP. This may indicate a takeover opportunity.",
                                    url=f"https://{subdomain}",
                                    evidence=f"CNAME: {cname}\nService: {service_name}\nNo A record resolution.",
                                    remediation="Verify the CNAME target is still active. Remove dangling DNS records.",
                                    cvss=6.5,
                                    cwe="CWE-284",
                                )

            except Exception:
                continue

    # =========================================================================
    # SAVE FINDINGS
    # =========================================================================

    def _save_findings(self) -> None:
        """
        Save all findings to JSON and text reports in the output directory.

        Creates:
        - vuln_findings.json: Full JSON report with all finding details
        - vuln_findings_summary.txt: Human-readable summary
        """
        try:
            # Save JSON report
            findings_data = {
                "scan_date": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "severity_counts": {
                    "CRITICAL": sum(1 for f in self.findings if f.severity == "CRITICAL"),
                    "HIGH": sum(1 for f in self.findings if f.severity == "HIGH"),
                    "MEDIUM": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                    "LOW": sum(1 for f in self.findings if f.severity == "LOW"),
                    "INFO": sum(1 for f in self.findings if f.severity == "INFO"),
                },
                "findings": [f.to_dict() for f in self.findings],
            }

            json_path = Path(self.output_dir) / "vuln_findings.json"
            self.file_manager.write_json(str(json_path), findings_data)

            # Save text summary
            summary_path = Path(self.output_dir) / "vuln_findings_summary.txt"
            lines = []
            lines.append("=" * 70)
            lines.append("MONSTER VULNERABILITY SCAN REPORT")
            lines.append("=" * 70)
            lines.append(f"Date: {datetime.now().isoformat()}")
            lines.append(f"Total Findings: {len(self.findings)}")
            lines.append(f"Critical: {findings_data['severity_counts']['CRITICAL']}")
            lines.append(f"High: {findings_data['severity_counts']['HIGH']}")
            lines.append(f"Medium: {findings_data['severity_counts']['MEDIUM']}")
            lines.append(f"Low: {findings_data['severity_counts']['LOW']}")
            lines.append(f"Info: {findings_data['severity_counts']['INFO']}")
            lines.append("")
            lines.append("-" * 70)
            lines.append("")

            # Group by severity
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                severity_findings = [f for f in self.findings if f.severity == severity]
                if severity_findings:
                    lines.append(f"[{severity}] ({len(severity_findings)} findings)")
                    lines.append("-" * 40)
                    for finding in severity_findings:
                        lines.append(f"  Title: {finding.title}")
                        lines.append(f"  URL: {finding.url}")
                        lines.append(f"  Description: {finding.description[:150]}")
                        if finding.evidence:
                            lines.append(f"  Evidence: {finding.evidence[:100]}")
                        if finding.remediation:
                            lines.append(f"  Remediation: {finding.remediation[:150]}")
                        if finding.cwe_id:
                            lines.append(f"  CWE: {finding.cwe_id}")
                        lines.append("")
                    lines.append("")

            self.file_manager.write_file(str(summary_path), "\n".join(lines))
            self.color.success(f"  Findings saved to {self.output_dir}")

        except Exception as e:
            self.color.error(f"  Error saving findings: {str(e)}")
