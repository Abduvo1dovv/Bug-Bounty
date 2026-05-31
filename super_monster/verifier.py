"""
Super Monster v2 - Verifier

Double-checks every finding from the smart scanner to eliminate
false positives. Each finding type has a specialized verification
method that re-tests the issue with multiple probes.
"""

from typing import Optional
import time
import urllib.request
import urllib.error
import urllib.parse
import json
import socket
import re
from datetime import datetime, timezone

from .config import (
    REQUEST_TIMEOUT,
    RATE_LIMIT_DELAY,
    VERIFICATION_THRESHOLDS,
    MIN_VERIFICATION_ATTEMPTS,
    VERIFICATION_DELAY,
    USER_AGENTS,
)
from .smart_scanner import Finding
from .domain_classifier import DomainClassifier
from .http_utils import make_request as _shared_make_request, create_ssl_context


class Verifier:
    """
    Double-checks findings from SmartScanner to eliminate false positives.

    Each finding type has a specialized verification method that
    re-tests the issue with multiple probes and compares results
    to confirm the finding is real and exploitable.
    """

    def __init__(self, insecure: bool = True):
        """Initialize the verifier."""
        self._classifier = DomainClassifier()
        self._ssl_context = create_ssl_context(insecure=insecure)

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

    def verify_finding(self, finding: Finding) -> tuple:
        """
        Verify a finding by dispatching to type-specific verifiers.

        Args:
            finding: The Finding object to verify.

        Returns:
            Tuple of (is_verified: bool, confidence: float, details: str).
        """
        verifier_map = {
            "cors": self.verify_cors,
            "csp": self.verify_header_finding,
            "hsts": self.verify_header_finding,
            "cookie_security": self.verify_cookie_finding,
            "clickjacking": self.verify_header_finding,
            "api_exposure": self.verify_api_exposure,
            "graphql": self.verify_api_exposure,
            "server_disclosure": self.verify_header_finding,
            "open_redirect": self.verify_open_redirect,
            "subdomain_takeover": self.verify_subdomain_takeover,
            "default_creds_hints": self.verify_api_exposure,
            "session_fixation": self.verify_cookie_finding,
        }

        verifier = verifier_map.get(finding.finding_type)
        if verifier is None:
            return (False, 0.0, "No verifier available for this finding type")

        try:
            is_verified, confidence, details = verifier(finding)

            # Check against threshold
            threshold = VERIFICATION_THRESHOLDS.get(
                finding.finding_type, 0.75
            )
            if confidence < threshold:
                return (False, confidence, f"Below threshold ({threshold}): {details}")

            return (is_verified, confidence, details)
        except Exception as e:
            return (False, 0.0, f"Verification error: {str(e)}")

    def verify_cors(self, finding: Finding) -> tuple:
        """
        Re-test CORS with multiple evil origins to confirm reflection.

        Tests with multiple origins to confirm the reflection is
        consistent and not a fluke. Checks wildcard vs actual reflection.
        Uses finding.url to test the exact path where CORS was found.

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://{finding.domain}.evil.com",
        ]

        reflections = 0
        has_credentials = False
        details_parts = []

        # Use the original finding URL so path-specific CORS is verified correctly
        url = finding.url or f"https://{finding.domain}/"

        for origin in test_origins:
            time.sleep(VERIFICATION_DELAY)
            headers = {"Origin": origin}
            status, resp_headers, body = self._make_request(url, headers=headers)

            if status == 0:
                continue

            acao = ""
            acac = ""
            for key, value in resp_headers.items():
                if key.lower() == "access-control-allow-origin":
                    acao = value.strip()
                if key.lower() == "access-control-allow-credentials":
                    acac = value.strip().lower()

            # Check if our specific origin is reflected (not *)
            if origin in acao and acao != "*":
                reflections += 1
                if acac == "true":
                    has_credentials = True
                details_parts.append(f"Origin {origin} -> ACAO: {acao}")
            elif acao == "*":
                details_parts.append(f"Wildcard (*) response for {origin}")

        if reflections >= 2:
            confidence = 0.9 if has_credentials else 0.85
            if reflections == len(test_origins):
                confidence = 0.95
            details = (
                f"Confirmed reflection with {reflections}/{len(test_origins)} "
                f"origins. Credentials: {has_credentials}. "
                + "; ".join(details_parts[:2])
            )
            return (True, confidence, details)

        if reflections == 1:
            return (
                True,
                0.7,
                f"Partial confirmation (1/{len(test_origins)} origins). "
                + "; ".join(details_parts),
            )

        return (
            False,
            0.3,
            "Could not reproduce CORS reflection. " + "; ".join(details_parts),
        )

    def verify_403_bypass(self, finding: Finding) -> tuple:
        """
        Compare original 403 response with bypass attempt.

        1. Request original path -> confirm it is still 403
        2. Request bypass path -> check if status ACTUALLY changed
        3. Compare response body LENGTH - if same length, probably same page
        4. Only verify if status changed AND body is meaningfully different

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        url = finding.url
        domain = finding.domain

        # Step 1: Confirm original is still 403
        time.sleep(VERIFICATION_DELAY)
        status_orig, headers_orig, body_orig = self._make_request(url)

        if status_orig == 0:
            return (False, 0.0, "Cannot reach original URL")

        if status_orig != 403:
            return (
                False,
                0.2,
                f"Original URL no longer returns 403 (got {status_orig})",
            )

        # Step 2: Try common bypass techniques
        bypass_attempts = [
            url + "/",
            url + "/.",
            url + "%2f",
            url + ";",
            url.replace("://", "://") + "..;/",
        ]

        for bypass_url in bypass_attempts:
            time.sleep(VERIFICATION_DELAY)
            status_bypass, headers_bypass, body_bypass = self._make_request(
                bypass_url
            )

            if status_bypass == 0:
                continue

            # Step 3: Check if status actually changed
            if status_bypass == status_orig:
                continue

            # Step 4: Compare body lengths
            len_diff = abs(len(body_bypass) - len(body_orig))
            if len_diff < 50:
                # Bodies are too similar, probably same page
                continue

            # Status changed AND body is meaningfully different
            if status_bypass == 200:
                confidence = 0.85
                details = (
                    f"Bypass confirmed: {url} returns 403, "
                    f"{bypass_url} returns {status_bypass}. "
                    f"Body length diff: {len_diff} bytes."
                )
                return (True, confidence, details)

        return (
            False,
            0.2,
            "No bypass technique produced a different response.",
        )

    def verify_api_exposure(self, finding: Finding) -> tuple:
        """
        Confirm API endpoint returns actual data, not error page.

        Re-requests the endpoint and checks:
        - Content-Type is application/json
        - Response body contains structured data (not HTML error)
        - It is not a generic 200 with error message

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        url = finding.url
        time.sleep(VERIFICATION_DELAY)
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return (False, 0.0, "Cannot reach endpoint")

        if status != 200:
            return (
                False,
                0.2,
                f"Endpoint no longer returns 200 (got {status})",
            )

        # Check Content-Type
        content_type = ""
        for key, value in resp_headers.items():
            if key.lower() == "content-type":
                content_type = value.lower()

        is_json = "application/json" in content_type
        is_html_with_api = "text/html" in content_type

        # Check for structured data indicators
        body_lower = body.lower()
        api_indicators = [
            '"paths"', '"openapi"', '"swagger"',
            '"endpoints"', '"api"', '"info"',
            "__schema", '"types"', '"queries"',
        ]
        indicator_count = sum(1 for i in api_indicators if i in body_lower)

        # Check for error page indicators
        error_indicators = [
            "page not found", "404", "error occurred",
            "access denied", "forbidden", "not available",
        ]
        error_count = sum(1 for e in error_indicators if e in body_lower)

        if error_count > indicator_count:
            return (
                False,
                0.2,
                "Response appears to be an error page, not API data.",
            )

        if is_json and indicator_count >= 2:
            confidence = min(0.7 + (indicator_count * 0.05), 0.95)
            return (
                True,
                confidence,
                f"Confirmed JSON response with {indicator_count} API indicators.",
            )

        if is_html_with_api and indicator_count >= 3:
            confidence = min(0.6 + (indicator_count * 0.05), 0.9)
            return (
                True,
                confidence,
                f"HTML response with {indicator_count} API documentation indicators.",
            )

        if indicator_count >= 2:
            return (
                True,
                0.7,
                f"Response contains {indicator_count} API indicators "
                f"(Content-Type: {content_type}).",
            )

        return (
            False,
            0.3,
            f"Insufficient API indicators ({indicator_count}) in response.",
        )

    def verify_header_finding(self, finding: Finding) -> tuple:
        """
        Confirm missing headers on business-critical domains.

        Re-checks the header is actually missing (not cached response).
        Only confirms if domain is payment, auth, or api type.
        For CDN/static domains, downgrades to informational.

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        url = finding.url or f"https://{finding.domain}/"
        domain_type = self._classifier.classify_domain(finding.domain)

        # For CDN/static domains, downgrade
        if domain_type in ("cdn",):
            return (
                False,
                0.3,
                f"Finding on {domain_type} domain - downgraded to informational.",
            )

        # Re-check the header
        time.sleep(VERIFICATION_DELAY)
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return (False, 0.0, "Cannot reach target")

        # Determine which header we are checking
        finding_type = finding.finding_type
        header_checks = {
            "hsts": "strict-transport-security",
            "csp": "content-security-policy",
            "clickjacking": "x-frame-options",
            "server_disclosure": "server",
        }

        target_header = header_checks.get(finding_type, "")

        if finding_type == "server_disclosure":
            # For server disclosure, verify version number is present
            server_value = ""
            for key, value in resp_headers.items():
                if key.lower() == "server":
                    server_value = value
                elif key.lower() == "x-powered-by":
                    server_value = value

            version_pattern = re.compile(r'\d+\.\d+')
            if server_value and version_pattern.search(server_value):
                confidence = 0.85 if domain_type in ("payment", "auth", "api") else 0.7
                return (
                    True,
                    confidence,
                    f"Confirmed version disclosure: {server_value}",
                )
            return (False, 0.3, "No version number in server header")

        # For missing header checks
        header_present = False
        for key, value in resp_headers.items():
            if key.lower() == target_header:
                header_present = True
                break

        if finding_type == "clickjacking" and not header_present:
            # Also check CSP frame-ancestors
            for key, value in resp_headers.items():
                if key.lower() == "content-security-policy":
                    if "frame-ancestors" in value.lower():
                        header_present = True
                        break

        if not header_present:
            # Header is confirmed missing
            sensitive = domain_type in ("payment", "auth", "api", "admin")
            confidence = 0.9 if sensitive else 0.6
            return (
                True,
                confidence,
                f"Confirmed: {target_header} header missing on "
                f"{domain_type} domain.",
            )

        return (
            False,
            0.2,
            f"Header {target_header} is now present (may have been cached).",
        )

    def verify_cookie_finding(self, finding: Finding) -> tuple:
        """
        Confirm cookie is session-related, not analytics.

        Checks cookie name against session patterns.
        Verifies the flags are actually missing (re-request).
        Skips cookies with names like _ga, _gid, _fbp, etc.

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        url = finding.url or f"https://{finding.domain}/"

        # Re-request to get fresh cookies
        time.sleep(VERIFICATION_DELAY)
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return (False, 0.0, "Cannot reach target")

        # Collect cookies
        cookies_raw = []
        for key, value in resp_headers.items():
            if key.lower() == "set-cookie":
                cookies_raw.append(value)

        if not cookies_raw:
            return (False, 0.3, "No cookies in response on re-check")

        # Session patterns
        session_patterns = ["session", "token", "auth", "sid", "jwt", "csrf"]
        # Analytics patterns to skip
        analytics_patterns = [
            "_ga", "_gid", "_fbp", "_gcl", "hubspot",
            "intercom", "_utm", "amplitude", "mixpanel",
        ]

        confirmed_issues = []

        for cookie_str in cookies_raw:
            cookie_name = cookie_str.split("=")[0].strip().lower()

            # Skip analytics
            if any(p in cookie_name for p in analytics_patterns):
                continue

            # Must be session-related
            if not any(p in cookie_name for p in session_patterns):
                continue

            # Check flags
            cookie_lower = cookie_str.lower()
            missing = []
            if "secure" not in cookie_lower:
                missing.append("Secure")
            if "httponly" not in cookie_lower:
                missing.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing.append("SameSite")

            if missing:
                confirmed_issues.append(f"{cookie_name}: missing {', '.join(missing)}")

        if confirmed_issues:
            domain_type = self._classifier.classify_domain(finding.domain)
            sensitive = domain_type in ("payment", "auth", "api", "admin")
            confidence = 0.85 if sensitive else 0.7
            return (
                True,
                confidence,
                f"Confirmed {len(confirmed_issues)} insecure session cookie(s): "
                + "; ".join(confirmed_issues[:3]),
            )

        return (
            False,
            0.3,
            "No session cookies with missing flags found on re-check.",
        )

    def verify_open_redirect(self, finding: Finding) -> tuple:
        """
        Confirm redirect actually goes to attacker-controlled URL.

        Re-requests with redirect param and checks Location header
        contains the injected URL. Makes sure it is not just reflecting
        the param in the page body.

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        url = finding.url
        if not url:
            return (False, 0.0, "No URL to verify")

        # Re-request with the same URL
        time.sleep(VERIFICATION_DELAY)
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            return (False, 0.0, "Cannot reach target")

        # Check Location header
        location = ""
        for key, value in resp_headers.items():
            if key.lower() == "location":
                location = value.strip()

        # The URL should contain an evil redirect target
        evil_indicators = ["evil", "attacker", "pwned"]
        has_evil_in_location = any(
            ind in location.lower() for ind in evil_indicators
        )

        if status in (301, 302, 303, 307, 308) and has_evil_in_location:
            # Confirmed: server redirects to our evil URL
            # Try a second evil URL to double-confirm
            time.sleep(VERIFICATION_DELAY)

            # Parse the URL and change the redirect target
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            # Find the redirect param
            redirect_params = ["redirect", "next", "url", "return", "redir", "goto"]
            redirect_param = None
            for rp in redirect_params:
                if rp in params:
                    redirect_param = rp
                    break

            if redirect_param:
                # Test with a different evil URL
                second_evil = "https://second-evil.example.com/test"
                new_params = {redirect_param: second_evil}
                new_query = urllib.parse.urlencode(new_params)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                status2, headers2, body2 = self._make_request(new_url)
                location2 = ""
                for key, value in headers2.items():
                    if key.lower() == "location":
                        location2 = value.strip()

                if second_evil in location2:
                    return (
                        True,
                        0.95,
                        f"Double-confirmed: redirects to arbitrary URLs. "
                        f"Location: {location}",
                    )

            return (
                True,
                0.85,
                f"Confirmed redirect to evil URL. Location: {location}",
            )

        # Check if evil URL only appears in body (not actual redirect)
        if any(ind in body.lower() for ind in evil_indicators):
            return (
                False,
                0.3,
                "Evil URL reflected in body but no actual redirect (not exploitable).",
            )

        return (
            False,
            0.2,
            f"Could not confirm redirect (status: {status}, location: {location}).",
        )

    def verify_subdomain_takeover(self, finding: Finding) -> tuple:
        """
        Confirm CNAME and service fingerprint.

        Re-resolves DNS and re-checks that the service returns
        the takeover fingerprint.

        Returns:
            Tuple of (is_verified, confidence, details).
        """
        domain = finding.domain

        # Re-resolve CNAME
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return (False, 0.0, "Cannot resolve CNAME")

        if not cname:
            return (False, 0.2, "No CNAME record found on re-check")

        # Known vulnerable services
        vulnerable_services = {
            "amazonaws.com": "NoSuchBucket",
            "s3.amazonaws.com": "NoSuchBucket",
            "herokuapp.com": "No such app",
            "herokudns.com": "No such app",
            "github.io": "There isn\'t a GitHub Pages site here",
            "myshopify.com": "Sorry, this shop is currently unavailable",
            "azurewebsites.net": "404 Web Site not found",
            "cloudfront.net": "Bad request",
            "fastly.net": "Fastly error: unknown domain",
        }

        target_service = None
        for service_domain, fingerprint in vulnerable_services.items():
            if cname.endswith(service_domain):
                target_service = (service_domain, fingerprint)
                break

        if not target_service:
            return (
                False,
                0.3,
                f"CNAME {cname} does not point to a known vulnerable service.",
            )

        service_domain, fingerprint = target_service

        # Re-check fingerprint
        time.sleep(VERIFICATION_DELAY)
        url = f"https://{domain}/"
        status, resp_headers, body = self._make_request(url)

        if status == 0:
            url = f"http://{domain}/"
            status, resp_headers, body = self._make_request(url)

        if status == 0:
            return (False, 0.4, f"Cannot reach {domain} but CNAME exists: {cname}")

        if fingerprint.lower() in body.lower():
            return (
                True,
                0.95,
                f"Confirmed: CNAME -> {cname}, "
                f"fingerprint '{fingerprint}' present in response.",
            )

        return (
            False,
            0.4,
            f"CNAME points to {cname} but fingerprint not found in response.",
        )

    def verify_all(self, findings: list) -> list:
        """
        Verify all findings and return only verified ones.

        For each finding, calls verify_finding. Filters out any
        that do not pass verification. Returns verified findings
        sorted by severity.

        Args:
            findings: List of Finding objects to verify.

        Returns:
            List of verified Finding objects sorted by severity.
        """
        from .config import SEVERITY_ORDER

        verified_findings = []

        for finding in findings:
            is_verified, confidence, details = self.verify_finding(finding)

            if is_verified:
                finding.verified = True
                finding.confidence = confidence
                if not finding.evidence:
                    finding.evidence = details
                verified_findings.append(finding)

        # Sort by severity (critical first)
        verified_findings.sort(
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

        return verified_findings
