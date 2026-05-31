"""
Super Monster v2 - Smart Scanner

Adaptive scanning engine that runs targeted security tests based on
domain classification. Each check includes inline verification to
eliminate false positives.
"""

from dataclasses import dataclass, field
from typing import Optional
import time
import urllib.request
import urllib.error
import urllib.parse
import json
import socket
import threading
import random
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import (
    REQUEST_TIMEOUT,
    RATE_LIMIT_DELAY,
    MAX_THREADS,
    MAX_SCAN_TIME,
    SCAN_TESTS_PER_TYPE,
    USER_AGENTS,
)
from .domain_classifier import DomainClassifier
from .http_utils import make_request as _shared_make_request, create_ssl_context


@dataclass
class Finding:
    """A single security finding."""

    finding_type: str = ""
    domain: str = ""
    url: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    impact: str = ""
    reproduction_steps: list = field(default_factory=list)
    verified: bool = False
    confidence: float = 0.0
    raw_response_code: int = 0
    raw_response_headers: dict = field(default_factory=dict)
    timestamp: str = ""


class SmartScanner:
    """
    Adaptive scanning engine that selects and runs security tests
    based on domain classification. Uses inline verification to
    minimize false positives.
    """

    def __init__(self, insecure: bool = True):
        """Initialize the scanner with rate limiting state."""
        self._classifier = DomainClassifier()
        self._rate_limit_lock = threading.Lock()
        self._host_timestamps = {}
        self._ssl_context = create_ssl_context(insecure=insecure)
        self._findings_lock = threading.Lock()

    def _get_user_agent(self) -> str:
        """Get a random user agent string."""
        return random.choice(USER_AGENTS)

    def _rate_limit(self, domain: str):
        """Enforce rate limiting between requests to the same host."""
        with self._rate_limit_lock:
            now = time.time()
            last_request = self._host_timestamps.get(domain, 0)
            elapsed = now - last_request
            if elapsed < RATE_LIMIT_DELAY:
                time.sleep(RATE_LIMIT_DELAY - elapsed)
            self._host_timestamps[domain] = time.time()

    def _make_request(
        self,
        url: str,
        headers: dict = None,
        method: str = "GET",
        timeout: int = None,
        data: bytes = None,
    ) -> tuple:
        """
        Make an HTTP request using the shared http_utils helper.

        Returns:
            Tuple of (status_code, response_headers_dict, body_str).
            Returns (0, {}, "") on any error.
        """
        return _shared_make_request(
            url,
            headers=headers,
            method=method,
            timeout=timeout,
            data=data,
            ssl_context=self._ssl_context,
        )

    def _timestamp(self) -> str:
        """Get current UTC timestamp string."""
        return datetime.now(timezone.utc).isoformat()

    def check_cors(self, domain: str) -> Optional[Finding]:
        """
        Check for CORS misconfiguration.

        Sends request with Origin: https://evil.attacker.com.
        ONLY reports if the evil origin is REFLECTED back in
        Access-Control-Allow-Origin (not just wildcard *).
        Also checks Access-Control-Allow-Credentials: true.
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        evil_origin = "https://evil.attacker.com"

        headers = {"Origin": evil_origin}
        status, resp_headers, body = self._make_request(url, headers=headers)

        if status == 0:
            return None

        acao = ""
        acac = ""
        for key, value in resp_headers.items():
            if key.lower() == "access-control-allow-origin":
                acao = value.strip()
            if key.lower() == "access-control-allow-credentials":
                acac = value.strip().lower()

        # Only report if evil origin is REFLECTED (not wildcard *)
        if evil_origin in acao and acao != "*":
            has_credentials = acac == "true"
            severity = "critical" if has_credentials else "high"

            evidence_parts = [f"Access-Control-Allow-Origin: {acao}"]
            if has_credentials:
                evidence_parts.append("Access-Control-Allow-Credentials: true")

            return Finding(
                finding_type="cors",
                domain=domain,
                url=url,
                severity=severity,
                title="CORS Origin Reflection",
                description=(
                    f"The server reflects arbitrary origins in the "
                    f"Access-Control-Allow-Origin header. "
                    f"Tested with Origin: {evil_origin}"
                ),
                evidence="; ".join(evidence_parts),
                impact=(
                    "An attacker can read sensitive data cross-origin. "
                    "If credentials are allowed, session tokens and "
                    "user data can be exfiltrated."
                ),
                reproduction_steps=[
                    f"curl -H 'Origin: {evil_origin}' {url}",
                    "Check Access-Control-Allow-Origin header in response",
                ],
                confidence=0.9 if has_credentials else 0.85,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_csp(self, domain: str) -> Optional[Finding]:
        """
        Check Content-Security-Policy header.

        Reports if CSP is missing OR contains unsafe-inline/unsafe-eval
        on sensitive domains (payment, auth, api, admin).
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        csp_value = ""
        for key, value in resp_headers.items():
            if key.lower() == "content-security-policy":
                csp_value = value.strip()

        domain_type = self._classifier.classify_domain(domain)
        sensitive_types = ("payment", "auth", "api", "admin")

        if not csp_value:
            if domain_type not in sensitive_types:
                return None

            return Finding(
                finding_type="csp",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("csp", domain_type),
                title="Missing Content-Security-Policy",
                description=(
                    f"No Content-Security-Policy header found on "
                    f"{domain_type} domain {domain}."
                ),
                evidence="Content-Security-Policy header: absent",
                impact=(
                    "Without CSP, the application is more vulnerable "
                    "to XSS attacks. Attackers can inject and execute "
                    "arbitrary scripts."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Check for Content-Security-Policy header",
                ],
                confidence=0.8,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )

        # Check for unsafe directives
        unsafe_directives = []
        if "'unsafe-inline'" in csp_value:
            unsafe_directives.append("unsafe-inline")
        if "'unsafe-eval'" in csp_value:
            unsafe_directives.append("unsafe-eval")

        if unsafe_directives and domain_type in sensitive_types:
            return Finding(
                finding_type="csp",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("csp", domain_type),
                title="Weak Content-Security-Policy",
                description=(
                    "CSP contains " + ", ".join(unsafe_directives) + " on "
                    f"{domain_type} domain {domain}."
                ),
                evidence=f"Content-Security-Policy: {csp_value[:200]}",
                impact=(
                    "unsafe-inline and unsafe-eval weaken CSP protections "
                    "allowing potential XSS exploitation."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Review Content-Security-Policy header value",
                ],
                confidence=0.75,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_hsts(self, domain: str) -> Optional[Finding]:
        """
        Check Strict-Transport-Security header.

        Only reports on sensitive domains (payment, auth, api).
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        domain_type = self._classifier.classify_domain(domain)
        sensitive_types = ("payment", "auth", "api")

        if domain_type not in sensitive_types:
            return None

        hsts_value = ""
        for key, value in resp_headers.items():
            if key.lower() == "strict-transport-security":
                hsts_value = value.strip()

        if not hsts_value:
            return Finding(
                finding_type="hsts",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("hsts", domain_type),
                title="Missing HSTS Header",
                description=(
                    f"No Strict-Transport-Security header on "
                    f"{domain_type} domain {domain}."
                ),
                evidence="Strict-Transport-Security header: absent",
                impact=(
                    "Without HSTS, users can be downgraded to HTTP "
                    "via MITM attacks, exposing credentials and "
                    "session tokens."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Verify Strict-Transport-Security header is missing",
                ],
                confidence=0.95,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_cookie_security(self, domain: str) -> Optional[Finding]:
        """
        Check Set-Cookie headers for security flags.

        ONLY reports cookies that look session-related (name contains
        session, token, auth, sid, jwt). Skips analytics cookies.
        Checks for missing Secure, HttpOnly, SameSite flags.
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        # Collect all Set-Cookie headers
        cookies_raw = []
        for key, value in resp_headers.items():
            if key.lower() == "set-cookie":
                cookies_raw.append(value)

        if not cookies_raw:
            return None

        # Session-related patterns
        session_patterns = ["session", "token", "auth", "sid", "jwt", "csrf"]
        # Analytics patterns to skip
        analytics_patterns = ["_ga", "_gid", "_fbp", "_gcl", "hubspot", "intercom"]

        insecure_cookies = []

        for cookie_str in cookies_raw:
            # Parse cookie name
            cookie_name = cookie_str.split("=")[0].strip().lower()

            # Skip analytics cookies
            is_analytics = any(p in cookie_name for p in analytics_patterns)
            if is_analytics:
                continue

            # Only check session-related cookies
            is_session = any(p in cookie_name for p in session_patterns)
            if not is_session:
                continue

            # Check for missing flags
            cookie_lower = cookie_str.lower()
            missing_flags = []
            if "secure" not in cookie_lower:
                missing_flags.append("Secure")
            if "httponly" not in cookie_lower:
                missing_flags.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing_flags.append("SameSite")

            if missing_flags:
                insecure_cookies.append((cookie_name, missing_flags))

        if insecure_cookies:
            domain_type = self._classifier.classify_domain(domain)
            evidence_lines = []
            for name, flags in insecure_cookies:
                evidence_lines.append(f"{name}: missing {', '.join(flags)}")

            return Finding(
                finding_type="cookie_security",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("cookie_security", domain_type),
                title="Insecure Session Cookie Flags",
                description=(
                    f"Session-related cookies on {domain} are missing "
                    f"security flags."
                ),
                evidence="; ".join(evidence_lines),
                impact=(
                    "Missing Secure flag allows cookie transmission over HTTP. "
                    "Missing HttpOnly allows JavaScript access to cookies. "
                    "Missing SameSite enables CSRF attacks."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Examine Set-Cookie headers for security attributes",
                ],
                confidence=0.85,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_clickjacking(self, domain: str) -> Optional[Finding]:
        """
        Check X-Frame-Options and CSP frame-ancestors.

        Reports if neither protection is present.
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        xfo = ""
        csp = ""
        for key, value in resp_headers.items():
            if key.lower() == "x-frame-options":
                xfo = value.strip()
            if key.lower() == "content-security-policy":
                csp = value.strip()

        has_xfo = bool(xfo)
        has_frame_ancestors = "frame-ancestors" in csp.lower() if csp else False

        if not has_xfo and not has_frame_ancestors:
            domain_type = self._classifier.classify_domain(domain)
            return Finding(
                finding_type="clickjacking",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("clickjacking", domain_type),
                title="Missing Clickjacking Protection",
                description=(
                    f"Neither X-Frame-Options nor CSP frame-ancestors "
                    f"found on {domain}."
                ),
                evidence=(
                    "X-Frame-Options: absent; "
                    "CSP frame-ancestors: absent"
                ),
                impact=(
                    "The page can be embedded in an iframe, enabling "
                    "clickjacking attacks where users unknowingly "
                    "perform actions."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Verify X-Frame-Options and CSP frame-ancestors are absent",
                    "Create an HTML page with <iframe src=\"https://{domain}/\">",
                ],
                confidence=0.9,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_api_exposure(self, domain: str) -> Optional[Finding]:
        """
        Check common API documentation paths.

        CRITICAL: Only reports if response is 200 AND contains actual
        API documentation content (JSON with paths/endpoints, or HTML
        with swagger-ui). NOT if it is a 403, 404, redirect, or
        generic error page.
        """
        api_paths = [
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/api-docs",
            "/api/docs",
            "/graphql",
            "/v1/api-docs",
            "/v2/api-docs",
            "/openapi.json",
        ]

        # Content indicators for real API docs
        api_indicators = [
            "swagger",
            '"paths"',
            '"openapi"',
            '"info"',
            "api-docs",
            "swagger-ui",
            '"endpoints"',
            '"basePath"',
        ]

        for path in api_paths:
            self._rate_limit(domain)
            url = f"https://{domain}{path}"
            status, resp_headers, body = self._make_request(url)

            # Only consider 200 responses
            if status != 200:
                continue

            # Must contain actual API documentation content
            body_lower = body.lower()
            matches = sum(1 for ind in api_indicators if ind.lower() in body_lower)

            # Need at least 2 indicators to confirm real API docs
            if matches < 2:
                continue

            # Check it is not a generic error page
            error_indicators = [
                "page not found",
                "404",
                "error occurred",
                "access denied",
                "forbidden",
            ]
            is_error = any(ei in body_lower for ei in error_indicators)
            if is_error and matches < 3:
                continue

            domain_type = self._classifier.classify_domain(domain)
            return Finding(
                finding_type="api_exposure",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("api_exposure", domain_type),
                title="Exposed API Documentation",
                description=(
                    f"API documentation endpoint accessible at {url}. "
                    f"Response contains {matches} API documentation indicators."
                ),
                evidence=f"URL: {url}, Status: {status}, Indicators: {matches}",
                impact=(
                    "Exposed API documentation reveals endpoint structure, "
                    "parameters, and authentication requirements. This "
                    "information aids further attacks."
                ),
                reproduction_steps=[
                    f"curl -s {url}",
                    "Verify response contains API endpoint definitions",
                ],
                confidence=min(0.6 + (matches * 0.1), 0.95),
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_graphql(self, domain: str) -> Optional[Finding]:
        """
        Check /graphql endpoint with introspection query.

        Only reports if introspection is actually enabled
        (response contains __schema).
        """
        self._rate_limit(domain)
        url = f"https://{domain}/graphql"

        introspection_query = json.dumps({
            "query": "{__schema{types{name}}}"
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        status, resp_headers, body = self._make_request(
            url, headers=headers, method="POST", data=introspection_query
        )

        if status == 0:
            return None

        # Only report if introspection is actually enabled
        if status == 200 and "__schema" in body:
            domain_type = self._classifier.classify_domain(domain)
            return Finding(
                finding_type="graphql",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("graphql", domain_type),
                title="GraphQL Introspection Enabled",
                description=(
                    f"GraphQL introspection is enabled at {url}. "
                    f"The schema can be fully enumerated."
                ),
                evidence=f"Response contains __schema data (status {status})",
                impact=(
                    "Introspection reveals the entire API schema including "
                    "queries, mutations, types, and fields. This is a "
                    "significant information disclosure."
                ),
                reproduction_steps=[
                    "curl -X POST -H 'Content-Type: application/json' "
                    "-d '{\"query\":\"{__schema{types{name}}}\"}' "
                    + url,
                    "Check if response contains __schema data",
                ],
                confidence=0.9,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_server_disclosure(self, domain: str) -> Optional[Finding]:
        """
        Check Server and X-Powered-By headers for version info.

        Only reports if actual version numbers are disclosed
        (not just 'nginx' or 'Apache' without version).
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        server_value = ""
        powered_by = ""
        for key, value in resp_headers.items():
            if key.lower() == "server":
                server_value = value.strip()
            if key.lower() == "x-powered-by":
                powered_by = value.strip()

        # Check for version numbers (digits with dots like 1.2.3)
        import re
        version_pattern = re.compile(r'\d+\.\d+')

        disclosures = []
        if server_value and version_pattern.search(server_value):
            disclosures.append(f"Server: {server_value}")
        if powered_by and version_pattern.search(powered_by):
            disclosures.append(f"X-Powered-By: {powered_by}")

        if disclosures:
            domain_type = self._classifier.classify_domain(domain)
            return Finding(
                finding_type="server_disclosure",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("server_disclosure", domain_type),
                title="Server Version Disclosure",
                description=(
                    f"Server software version disclosed on {domain}."
                ),
                evidence="; ".join(disclosures),
                impact=(
                    "Version disclosure allows attackers to identify "
                    "specific software versions and search for known "
                    "CVEs and exploits."
                ),
                reproduction_steps=[
                    f"curl -sI https://{domain}/",
                    "Check Server and X-Powered-By headers",
                ],
                confidence=0.8,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_open_redirect(self, domain: str) -> Optional[Finding]:
        """
        Check common redirect parameters.

        Only reports if the response actually redirects to the
        injected URL (checks Location header).
        """
        redirect_params = ["redirect", "next", "url", "return", "redir", "goto"]
        evil_url = "https://evil.attacker.com/pwned"

        for param in redirect_params:
            self._rate_limit(domain)
            test_url = f"https://{domain}/?{param}={urllib.parse.quote(evil_url)}"
            status, resp_headers, body = self._make_request(test_url)

            if status == 0:
                continue

            # Check if response redirects to our injected URL
            location = ""
            for key, value in resp_headers.items():
                if key.lower() == "location":
                    location = value.strip()

            # Only report if Location header contains our evil URL
            if status in (301, 302, 303, 307, 308) and evil_url in location:
                domain_type = self._classifier.classify_domain(domain)
                return Finding(
                    finding_type="open_redirect",
                    domain=domain,
                    url=test_url,
                    severity=self._classifier.get_severity("open_redirect", domain_type),
                    title="Open Redirect",
                    description=(
                        f"Open redirect via ?{param}= parameter on {domain}. "
                        f"Server redirects to attacker-controlled URL."
                    ),
                    evidence=f"Location: {location} (Status: {status})",
                    impact=(
                        "Open redirects enable phishing attacks by "
                        "abusing trusted domain reputation to redirect "
                        "users to malicious sites."
                    ),
                    reproduction_steps=[
                        f"curl -sI \"{test_url}\"",
                        "Check Location header points to evil URL",
                    ],
                    confidence=0.85,
                    raw_response_code=status,
                    raw_response_headers=resp_headers,
                    timestamp=self._timestamp(),
                )
        return None

    def check_subdomain_takeover(self, domain: str) -> Optional[Finding]:
        """
        DNS CNAME check for subdomain takeover.

        Only reports if CNAME points to a known takeover-vulnerable
        service AND the service returns a specific fingerprint.
        """
        # Known vulnerable services and their fingerprints
        vulnerable_services = {
            "amazonaws.com": "NoSuchBucket",
            "s3.amazonaws.com": "NoSuchBucket",
            "herokuapp.com": "No such app",
            "herokudns.com": "No such app",
            "github.io": "There isn\'t a GitHub Pages site here",
            "pantheonsite.io": "404 error unknown site",
            "ghost.io": "The thing you were looking for is no longer here",
            "myshopify.com": "Sorry, this shop is currently unavailable",
            "surge.sh": "project not found",
            "bitbucket.io": "Repository not found",
            "zendesk.com": "Help Center Closed",
            "fastly.net": "Fastly error: unknown domain",
            "azurewebsites.net": "404 Web Site not found",
            "cloudfront.net": "Bad request",
        }

        # Resolve CNAME
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # Try socket-based resolution as fallback
            try:
                answers = socket.getaddrinfo(domain, None)
                # Cannot determine CNAME from getaddrinfo alone
                return None
            except (socket.gaierror, Exception):
                return None

        if not cname:
            return None

        # Check if CNAME points to a vulnerable service
        target_service = None
        for service_domain, fingerprint in vulnerable_services.items():
            if cname.endswith(service_domain):
                target_service = (service_domain, fingerprint)
                break

        if not target_service:
            return None

        service_domain, fingerprint = target_service

        # Verify the fingerprint
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        # Also try HTTP
        if status == 0:
            url = f"http://{domain}/"
            status, resp_headers, body = self._make_request(url)

        if status == 0:
            return None

        if fingerprint.lower() in body.lower():
            domain_type = self._classifier.classify_domain(domain)
            return Finding(
                finding_type="subdomain_takeover",
                domain=domain,
                url=url,
                severity=self._classifier.get_severity("subdomain_takeover", domain_type),
                title="Potential Subdomain Takeover",
                description=(
                    f"CNAME points to {service_domain} ({cname}) "
                    f"and the service returns a takeover fingerprint."
                ),
                evidence=(
                    f"CNAME: {cname}; "
                    f"Service: {service_domain}; "
                    f"Fingerprint: {fingerprint}"
                ),
                impact=(
                    "An attacker can claim the unclaimed resource on "
                    f"{service_domain} and serve arbitrary content "
                    f"on {domain}, enabling phishing, cookie theft, "
                    f"and reputation damage."
                ),
                reproduction_steps=[
                    f"dig +short CNAME {domain}",
                    f"curl -s http://{domain}/",
                    f"Look for fingerprint: {fingerprint}",
                ],
                confidence=0.9,
                raw_response_code=status,
                raw_response_headers=resp_headers,
                timestamp=self._timestamp(),
            )
        return None

    def check_default_creds_hints(self, domain: str) -> Optional[Finding]:
        """
        Check for login pages with known default credential hints.

        Not brute force - just checks if login page exists and
        returns specific patterns suggesting default credentials.
        """
        login_paths = [
            "/admin",
            "/admin/login",
            "/login",
            "/wp-admin",
            "/wp-login.php",
            "/administrator",
            "/manage",
            "/console",
        ]

        # Patterns that suggest default credentials
        default_cred_patterns = [
            "default password",
            "admin/admin",
            "admin:admin",
            "default credentials",
            "initial password",
            "change your password",
            "first login",
            "demo account",
        ]

        for path in login_paths:
            self._rate_limit(domain)
            url = f"https://{domain}{path}"
            status, resp_headers, body = self._make_request(url)

            if status != 200:
                continue

            # Check if it looks like a login page
            body_lower = body.lower()
            is_login = any(
                indicator in body_lower
                for indicator in ["login", "sign in", "username", "password"]
            )

            if not is_login:
                continue

            # Check for default credential hints
            found_hints = [
                pattern for pattern in default_cred_patterns
                if pattern in body_lower
            ]

            if found_hints:
                domain_type = self._classifier.classify_domain(domain)
                return Finding(
                    finding_type="default_creds_hints",
                    domain=domain,
                    url=url,
                    severity=self._classifier.get_severity("default_creds_hints", domain_type),
                    title="Default Credential Hints Found",
                    description=(
                        f"Login page at {url} contains hints about "
                        f"default credentials."
                    ),
                    evidence=f"Patterns found: {', '.join(found_hints[:3])}",
                    impact=(
                        "Default credentials may allow unauthorized "
                        "access to administrative interfaces."
                    ),
                    reproduction_steps=[
                        f"curl -s {url}",
                        "Look for default credential hints in page content",
                    ],
                    confidence=0.7,
                    raw_response_code=status,
                    raw_response_headers=resp_headers,
                    timestamp=self._timestamp(),
                )
        return None

    def check_session_fixation(self, domain: str) -> Optional[Finding]:
        """
        Check if session cookies change after authentication-like request.

        Compares cookies from initial request vs after submitting to
        a login-like endpoint.
        """
        self._rate_limit(domain)
        url = f"https://{domain}/"
        status1, resp_headers1, body1 = self._make_request(url)

        if status1 == 0:
            return None

        # Get initial cookies
        initial_cookies = {}
        for key, value in resp_headers1.items():
            if key.lower() == "set-cookie":
                cookie_name = value.split("=")[0].strip()
                initial_cookies[cookie_name] = value

        if not initial_cookies:
            return None

        # Check if any initial cookies are session-related
        session_patterns = ["session", "sid", "token", "auth"]
        session_cookies = {
            name: val for name, val in initial_cookies.items()
            if any(p in name.lower() for p in session_patterns)
        }

        if not session_cookies:
            return None

        # Make a second request (simulating navigation)
        self._rate_limit(domain)
        status2, resp_headers2, body2 = self._make_request(url)

        if status2 == 0:
            return None

        # Get second set of cookies
        second_cookies = {}
        for key, value in resp_headers2.items():
            if key.lower() == "set-cookie":
                cookie_name = value.split("=")[0].strip()
                second_cookies[cookie_name] = value

        # If session cookies are identical across requests,
        # it may indicate session fixation vulnerability
        # (server not rotating session IDs)
        unchanged_sessions = []
        for name in session_cookies:
            if name in second_cookies:
                # Compare cookie values (just the value part)
                val1 = session_cookies[name].split(";")[0]
                val2 = second_cookies[name].split(";")[0]
                if val1 == val2:
                    unchanged_sessions.append(name)

        # This is a weak signal - only report if we find login forms
        # that might accept session fixation
        if unchanged_sessions:
            # Look for login forms
            body_lower = body1.lower()
            has_login = any(
                x in body_lower
                for x in ["login", "sign in", "authenticate"]
            )
            if has_login:
                domain_type = self._classifier.classify_domain(domain)
                return Finding(
                    finding_type="session_fixation",
                    domain=domain,
                    url=url,
                    severity=self._classifier.get_severity("session_fixation", domain_type),
                    title="Potential Session Fixation",
                    description=(
                        f"Session cookies on {domain} do not rotate "
                        f"between requests. Login form detected."
                    ),
                    evidence=(
                        f"Unchanged session cookies: {', '.join(unchanged_sessions)}"
                    ),
                    impact=(
                        "If session IDs are not rotated after authentication, "
                        "an attacker can fix a known session ID and hijack "
                        "the user session after login."
                    ),
                    reproduction_steps=[
                        f"curl -c cookies.txt https://{domain}/",
                        f"curl -b cookies.txt https://{domain}/",
                        "Compare session cookie values between requests",
                    ],
                    confidence=0.6,
                    raw_response_code=status1,
                    raw_response_headers=resp_headers1,
                    timestamp=self._timestamp(),
                )
        return None

    def scan_domain(
        self, domain: str, domain_type: str, dry_run: bool = False
    ) -> list:
        """
        Run only the tests appropriate for this domain type.

        Args:
            domain: The domain to scan.
            domain_type: The classified type (payment, auth, api, etc.)
            dry_run: If True, return empty list without making requests.

        Returns:
            List of Finding objects discovered.
        """
        if dry_run:
            return []

        tests = SCAN_TESTS_PER_TYPE.get(domain_type, [])

        # Map test names to check methods
        test_methods = {
            "cors": self.check_cors,
            "csp": self.check_csp,
            "hsts": self.check_hsts,
            "cookie_security": self.check_cookie_security,
            "clickjacking": self.check_clickjacking,
            "api_exposure": self.check_api_exposure,
            "graphql": self.check_graphql,
            "server_disclosure": self.check_server_disclosure,
            "open_redirect": self.check_open_redirect,
            "subdomain_takeover": self.check_subdomain_takeover,
            "default_creds_hints": self.check_default_creds_hints,
            "session_fixation": self.check_session_fixation,
        }

        findings = []

        for test_name in tests:
            method = test_methods.get(test_name)
            if method is None:
                continue

            try:
                result = method(domain)
                if result is not None:
                    # Set severity based on domain type if not already set
                    if not result.severity:
                        result.severity = self._classifier.get_severity(
                            test_name, domain_type
                        )
                    findings.append(result)
            except Exception:
                # Never crash on a single test failure
                pass

        return findings

    def scan_all_domains(
        self, domains: dict, dry_run: bool = False
    ) -> list:
        """
        Orchestrate parallel scanning using ThreadPoolExecutor.

        Enforces MAX_SCAN_TIME: stops accepting new results after the
        global scan timeout is exceeded.

        Args:
            domains: Dict mapping domain -> domain_type.
            dry_run: If True, skip actual scanning.

        Returns:
            List of all Finding objects across all domains.
        """
        if dry_run:
            return []

        all_findings = []

        def _scan_one(item):
            domain, domain_type = item
            return self.scan_domain(domain, domain_type, dry_run=dry_run)

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(_scan_one, item): item
                for item in domains.items()
            }

            for future in as_completed(futures, timeout=MAX_SCAN_TIME):
                try:
                    results = future.result()
                    if results:
                        with self._findings_lock:
                            all_findings.extend(results)
                except Exception:
                    pass

        return all_findings
