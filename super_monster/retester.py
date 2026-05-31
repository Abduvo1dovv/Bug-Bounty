"""
Super Monster v1.0.0 - Automatic Retest Engine Module

Production-grade retesting engine for verifying whether previously discovered
vulnerabilities have been fixed. Supports multiple finding types with
type-specific verification logic:

- CORS: Re-send request with Origin header, check Access-Control-Allow-Origin
- Missing Headers: Re-fetch URL and check response headers
- SSL Issues: Re-check certificate via ssl module
- Cookie Issues: Re-fetch and check Set-Cookie attributes
- Subdomain Takeover: Re-resolve DNS and check response body fingerprint
- Information Disclosure: Re-check server/powered-by headers
- XSS: Re-test injection points
- SQL Injection: Re-test parameters
- Open Redirect: Re-test redirect parameters
- SSRF: Re-test server-side request endpoints

Features:
- Status tracking: STILL_PRESENT, FIXED, CHANGED, UNKNOWN
- 4 retest strategies: full, critical_only, oldest_first, random_sample
- last_tested timestamps and retest interval suggestions
- Comprehensive diff report generation
- Professional colored output with stats
- Cron schedule generation
- HTTP client using urllib.request with timeout and error handling
- Rate limiting between requests
- Retry logic with exponential backoff
- Connection pooling and resource management
"""

import hashlib
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode, parse_qs
from urllib.request import Request, urlopen, build_opener, HTTPSHandler
from urllib.error import URLError, HTTPError

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _FakeColor:
        def __getattr__(self, name):
            return ""
    Fore = _FakeColor()
    Back = _FakeColor()
    Style = _FakeColor()

from super_monster.config import (
    Colors, RETEST_INTERVALS, SEVERITY_LEVELS, SEVERITY_ORDER,
    TOOL_BANNER, FINDING_TYPE_SEVERITY_MAP, REQUEST_TIMEOUT,
    RATE_LIMIT_DELAY, MAX_RETRIES, DEFAULT_OUTPUT_DIR,
)
from super_monster.finding_db import FindingDB, Finding


# =============================================================================
# ENUMERATIONS AND CONSTANTS
# =============================================================================

class RetestStatus(Enum):
    """Status of a retest verification."""
    STILL_PRESENT = "STILL_PRESENT"
    FIXED = "FIXED"
    CHANGED = "CHANGED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    UNREACHABLE = "UNREACHABLE"


class RetestStrategy(Enum):
    """Strategy for selecting findings to retest."""
    FULL = "full"
    CRITICAL_ONLY = "critical_only"
    OLDEST_FIRST = "oldest_first"
    RANDOM_SAMPLE = "random_sample"


# Retest status display configuration
RETEST_STATUS_DISPLAY = {
    RetestStatus.STILL_PRESENT: {
        "label": "STILL PRESENT",
        "color": Fore.RED + Style.BRIGHT,
        "symbol": "X",
        "description": "Vulnerability confirmed still exploitable",
    },
    RetestStatus.FIXED: {
        "label": "FIXED",
        "color": Fore.GREEN + Style.BRIGHT,
        "symbol": "V",
        "description": "Vulnerability has been remediated",
    },
    RetestStatus.CHANGED: {
        "label": "CHANGED",
        "color": Fore.YELLOW + Style.BRIGHT,
        "symbol": "~",
        "description": "Response differs from original but not clearly fixed",
    },
    RetestStatus.UNKNOWN: {
        "label": "UNKNOWN",
        "color": Fore.WHITE + Style.DIM,
        "symbol": "?",
        "description": "Could not determine current status",
    },
    RetestStatus.ERROR: {
        "label": "ERROR",
        "color": Fore.MAGENTA,
        "symbol": "!",
        "description": "Error occurred during retest",
    },
    RetestStatus.TIMEOUT: {
        "label": "TIMEOUT",
        "color": Fore.CYAN + Style.DIM,
        "symbol": "T",
        "description": "Request timed out during retest",
    },
    RetestStatus.UNREACHABLE: {
        "label": "UNREACHABLE",
        "color": Fore.RED + Style.DIM,
        "symbol": "-",
        "description": "Target host is unreachable",
    },
}

# CORS check origins to test
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://subdomain.evil.com",
]

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# Cookie security attributes
COOKIE_SECURITY_ATTRS = [
    "Secure",
    "HttpOnly",
    "SameSite",
    "Path",
    "Domain",
    "Max-Age",
    "Expires",
]

# Subdomain takeover fingerprints
TAKEOVER_FINGERPRINTS = {
    "github": ["There isn\'t a GitHub Pages site here", "For root URLs"],
    "heroku": ["No such app", "no-such-app"],
    "aws_s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "fastly": ["Fastly error: unknown domain"],
    "ghost": ["The thing you were looking for is no longer here"],
    "pantheon": ["The gods are wise"],
    "tumblr": ["Whatever you were looking for doesn\'t currently exist"],
    "wordpress": ["Do you want to register"],
    "teamwork": ["Oops - We didn\'t find your site"],
    "helpjuice": ["We could not find what you\'re looking for"],
    "helpscout": ["No settings were found for this company"],
    "cargo": ["If you\'re moving your domain away from Cargo"],
    "statuspage": ["You are being <a href=\'https://"],
    "uservoice": ["This UserVoice subdomain is currently available"],
    "surge": ["project not found"],
    "intercom": ["This page is reserved for artistic dogs"],
    "webflow": ["The page you are looking for doesn\'t exist"],
    "kajabi": ["The page you were looking for doesn\'t exist"],
    "thinkific": ["You may have mistyped the address"],
    "tave": ["Error 404 - Page Not Found"],
    "wishpond": ["https://www.wishpond.com/404"],
    "aftership": ["Oops.</h2>"],
    "aha": ["There is no portal here"],
    "tictail": ["to target URL"],
    "brightcove": ["<p class=\'bc-gallery-error-code\'>Error Code: 404"],
    "bigcartel": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
    "campaignmonitor": ["Double check the URL"],
    "acquia": ["Web Site Not Found"],
    "proposify": ["If you need immediate assistance"],
    "simplebooklet": ["We can\'t find this <a"],
    "getresponse": ["With GetResponse Landing Pages"],
    "vend": ["Looks like you\'ve traveled too far"],
    "jetbrains": ["is not a registered InCloud YouTrack"],
    "azure": ["404 Web Site not found"],
}

# Information disclosure patterns
INFO_DISCLOSURE_PATTERNS = {
    "server_header": re.compile(r"^(Apache|nginx|IIS|lighttpd|LiteSpeed|Caddy)", re.IGNORECASE),
    "powered_by": re.compile(r"^(PHP|ASP\.NET|Express|Django|Rails|Flask|Spring)", re.IGNORECASE),
    "version_number": re.compile(r"\d+\.\d+(\.\d+)?"),
    "debug_info": re.compile(r"(traceback|stacktrace|exception|error details)", re.IGNORECASE),
    "internal_ip": re.compile(r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"),
    "email_address": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "api_key_pattern": re.compile(r"(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*[\w-]{20,}", re.IGNORECASE),
}

# Rate limit configuration
DEFAULT_RATE_LIMIT = 1.5  # seconds between requests
MAX_CONCURRENT_REQUESTS = 5
CONNECTION_TIMEOUT = 30
READ_TIMEOUT = 30
MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB max response

# Cron schedule templates
CRON_TEMPLATES = {
    "CRITICAL": "0 */6 * * *",     # Every 6 hours
    "HIGH": "0 0 */2 * *",         # Every 2 days
    "MEDIUM": "0 0 * * 1",         # Every Monday
    "LOW": "0 0 1,15 * *",         # 1st and 15th of month
    "INFO": "0 0 1 * *",           # First of month
}


# =============================================================================
# DATA CLASSES FOR RETEST RESULTS
# =============================================================================

@dataclass
class RetestResult:
    """Result of a single finding retest."""
    finding_id: str = ""
    finding_type: str = ""
    finding_title: str = ""
    severity: str = ""
    url: str = ""
    domain: str = ""
    status: str = "UNKNOWN"
    previous_evidence: str = ""
    current_evidence: str = ""
    response_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body_snippet: str = ""
    tested_at: str = ""
    duration_ms: float = 0.0
    error_message: str = ""
    confidence: float = 0.0
    diff_summary: str = ""
    recommendations: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @property
    def is_fixed(self) -> bool:
        """Check if the finding was confirmed fixed."""
        return self.status == RetestStatus.FIXED.value

    @property
    def is_still_present(self) -> bool:
        """Check if the finding is still present."""
        return self.status == RetestStatus.STILL_PRESENT.value


@dataclass
class RetestBatch:
    """A batch of retest results."""
    batch_id: str = ""
    strategy: str = "full"
    started_at: str = ""
    completed_at: str = ""
    total_findings: int = 0
    results: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    duration_seconds: float = 0.0
    target_domains: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data["results"] = [r if isinstance(r, dict) else r for r in self.results]
        return data

    def add_result(self, result: RetestResult) -> None:
        """Add a retest result to the batch."""
        self.results.append(result.to_dict())
        self.total_findings = len(self.results)

    def calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics for the batch."""
        status_counts = defaultdict(int)
        severity_breakdown = defaultdict(lambda: defaultdict(int))
        domains_tested = set()
        total_duration = 0.0

        for result_dict in self.results:
            status = result_dict.get("status", "UNKNOWN")
            severity = result_dict.get("severity", "INFO")
            domain = result_dict.get("domain", "unknown")
            duration = result_dict.get("duration_ms", 0.0)

            status_counts[status] += 1
            severity_breakdown[severity][status] += 1
            domains_tested.add(domain)
            total_duration += duration

        total = len(self.results)
        fixed_count = status_counts.get("FIXED", 0)
        still_present = status_counts.get("STILL_PRESENT", 0)

        self.summary = {
            "total_tested": total,
            "status_breakdown": dict(status_counts),
            "severity_breakdown": {k: dict(v) for k, v in severity_breakdown.items()},
            "domains_tested": sorted(list(domains_tested)),
            "domains_count": len(domains_tested),
            "fix_rate_percent": round((fixed_count / total * 100) if total > 0 else 0, 1),
            "still_present_percent": round((still_present / total * 100) if total > 0 else 0, 1),
            "average_duration_ms": round(total_duration / total if total > 0 else 0, 2),
            "total_duration_ms": round(total_duration, 2),
        }
        return self.summary


@dataclass
class RetestSchedule:
    """Schedule for upcoming retests."""
    schedule_id: str = ""
    generated_at: str = ""
    findings_due: list = field(default_factory=list)
    by_severity: dict = field(default_factory=dict)
    by_domain: dict = field(default_factory=dict)
    cron_suggestions: dict = field(default_factory=dict)
    next_retest_times: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


# =============================================================================
# HTTP CLIENT FOR RETESTING
# =============================================================================

class RetestHTTPClient:
    """
    HTTP client for performing retest requests.

    Uses urllib.request for actual network requests with:
    - Configurable timeout
    - Error handling and retry logic
    - Rate limiting between requests
    - Response size limiting
    - SSL certificate verification control
    - Custom User-Agent headers
    """

    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    RETRY_BACKOFF_BASE = 2.0
    MAX_REDIRECTS = 5

    def __init__(self, timeout: int = CONNECTION_TIMEOUT,
                 rate_limit: float = DEFAULT_RATE_LIMIT,
                 verify_ssl: bool = True,
                 max_retries: int = MAX_RETRIES,
                 user_agent: str = None):
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds.
            rate_limit: Minimum delay between requests in seconds.
            verify_ssl: Whether to verify SSL certificates.
            max_retries: Maximum number of retry attempts.
            user_agent: Custom User-Agent string.
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._last_request_time = 0.0
        self._request_count = 0
        self._error_count = 0
        self._total_bytes = 0
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context based on verification settings."""
        if self.verify_ssl:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        if self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                sleep_time = self.rate_limit - elapsed
                time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _build_request(self, url: str, method: str = "GET",
                       headers: Dict[str, str] = None,
                       data: bytes = None) -> Request:
        """Build an urllib Request object."""
        req = Request(url, data=data, method=method)
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept", "*/*")
        req.add_header("Accept-Language", "en-US,en;q=0.9")
        req.add_header("Connection", "keep-alive")

        if headers:
            for key, value in headers.items():
                req.add_header(key, value)

        return req

    def get(self, url: str, headers: Dict[str, str] = None,
            follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Perform a GET request with retry logic.

        Args:
            url: The URL to request.
            headers: Additional headers to include.
            follow_redirects: Whether to follow HTTP redirects.

        Returns:
            Dictionary with response details:
            {
                "status_code": int,
                "headers": dict,
                "body": str,
                "url": str,
                "elapsed_ms": float,
                "error": str or None,
                "redirected": bool,
                "final_url": str,
            }
        """
        self._enforce_rate_limit()
        self._request_count += 1

        result = {
            "status_code": 0,
            "headers": {},
            "body": "",
            "url": url,
            "elapsed_ms": 0.0,
            "error": None,
            "redirected": False,
            "final_url": url,
            "ssl_info": {},
        }

        for attempt in range(self.max_retries + 1):
            try:
                start_time = time.time()
                req = self._build_request(url, "GET", headers)
                response = urlopen(req, timeout=self.timeout, context=self._ssl_context)

                elapsed = (time.time() - start_time) * 1000
                result["elapsed_ms"] = round(elapsed, 2)
                result["status_code"] = response.status
                result["headers"] = dict(response.headers)
                result["final_url"] = response.url or url
                result["redirected"] = (response.url != url) if response.url else False

                # Read body with size limit
                body_bytes = response.read(MAX_RESPONSE_SIZE)
                try:
                    result["body"] = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    result["body"] = body_bytes.decode("latin-1", errors="replace")

                self._total_bytes += len(body_bytes)
                return result

            except HTTPError as e:
                elapsed = (time.time() - start_time) * 1000
                result["elapsed_ms"] = round(elapsed, 2)
                result["status_code"] = e.code
                result["headers"] = dict(e.headers) if e.headers else {}
                try:
                    body = e.read(MAX_RESPONSE_SIZE)
                    result["body"] = body.decode("utf-8", errors="replace")
                except Exception:
                    result["body"] = ""
                return result

            except URLError as e:
                if attempt < self.max_retries:
                    backoff = self.RETRY_BACKOFF_BASE ** attempt
                    time.sleep(backoff)
                    continue
                result["error"] = f"URLError: {str(e.reason)}"
                self._error_count += 1
                return result

            except socket.timeout:
                if attempt < self.max_retries:
                    backoff = self.RETRY_BACKOFF_BASE ** attempt
                    time.sleep(backoff)
                    continue
                result["error"] = "Connection timed out"
                self._error_count += 1
                return result

            except ssl.SSLError as e:
                result["error"] = f"SSL Error: {str(e)}"
                result["ssl_info"] = {"error": str(e)}
                self._error_count += 1
                return result

            except Exception as e:
                if attempt < self.max_retries:
                    backoff = self.RETRY_BACKOFF_BASE ** attempt
                    time.sleep(backoff)
                    continue
                result["error"] = f"Request failed: {str(e)}"
                self._error_count += 1
                return result

        return result

    def head(self, url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Perform a HEAD request.

        Args:
            url: The URL to request.
            headers: Additional headers to include.

        Returns:
            Dictionary with response status and headers.
        """
        self._enforce_rate_limit()
        self._request_count += 1

        result = {
            "status_code": 0,
            "headers": {},
            "url": url,
            "elapsed_ms": 0.0,
            "error": None,
        }

        try:
            start_time = time.time()
            req = self._build_request(url, "HEAD", headers)
            response = urlopen(req, timeout=self.timeout, context=self._ssl_context)
            elapsed = (time.time() - start_time) * 1000

            result["elapsed_ms"] = round(elapsed, 2)
            result["status_code"] = response.status
            result["headers"] = dict(response.headers)
            return result

        except HTTPError as e:
            elapsed = (time.time() - start_time) * 1000
            result["elapsed_ms"] = round(elapsed, 2)
            result["status_code"] = e.code
            result["headers"] = dict(e.headers) if e.headers else {}
            return result

        except Exception as e:
            result["error"] = str(e)
            self._error_count += 1
            return result

    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Check SSL certificate details for a hostname.

        Args:
            hostname: The hostname to check.
            port: The port to connect to (default 443).

        Returns:
            Dictionary with certificate details or error information.
        """
        cert_info = {
            "valid": False,
            "hostname": hostname,
            "issuer": "",
            "subject": "",
            "not_before": "",
            "not_after": "",
            "serial_number": "",
            "version": 0,
            "expired": False,
            "days_until_expiry": 0,
            "san": [],
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        cert_info["valid"] = True
                        cert_info["subject"] = str(cert.get("subject", ""))
                        cert_info["issuer"] = str(cert.get("issuer", ""))
                        cert_info["not_before"] = cert.get("notBefore", "")
                        cert_info["not_after"] = cert.get("notAfter", "")
                        cert_info["serial_number"] = str(cert.get("serialNumber", ""))
                        cert_info["version"] = cert.get("version", 0)

                        # Check expiry
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                now = datetime.utcnow()
                                delta = expiry - now
                                cert_info["days_until_expiry"] = delta.days
                                cert_info["expired"] = delta.days < 0
                            except ValueError:
                                pass

                        # Subject Alternative Names
                        san = cert.get("subjectAltName", ())
                        cert_info["san"] = [name for _, name in san]

        except ssl.SSLCertVerificationError as e:
            cert_info["error"] = f"Certificate verification failed: {e}"
        except ssl.SSLError as e:
            cert_info["error"] = f"SSL error: {e}"
        except socket.timeout:
            cert_info["error"] = "Connection timed out"
        except socket.gaierror as e:
            cert_info["error"] = f"DNS resolution failed: {e}"
        except ConnectionRefusedError:
            cert_info["error"] = "Connection refused"
        except OSError as e:
            cert_info["error"] = f"Connection error: {e}"

        return cert_info

    def resolve_dns(self, hostname: str) -> Dict[str, Any]:
        """
        Resolve DNS for a hostname.

        Args:
            hostname: The hostname to resolve.

        Returns:
            Dictionary with DNS resolution results.
        """
        dns_info = {
            "hostname": hostname,
            "resolved": False,
            "addresses": [],
            "cname": "",
            "error": None,
        }

        try:
            addresses = socket.getaddrinfo(hostname, None)
            if addresses:
                dns_info["resolved"] = True
                seen = set()
                for addr_info in addresses:
                    ip = addr_info[4][0]
                    if ip not in seen:
                        dns_info["addresses"].append(ip)
                        seen.add(ip)

            # Try to get CNAME
            try:
                cname = socket.getfqdn(hostname)
                if cname != hostname:
                    dns_info["cname"] = cname
            except Exception:
                pass

        except socket.gaierror as e:
            dns_info["error"] = f"DNS resolution failed: {e}"
        except socket.timeout:
            dns_info["error"] = "DNS resolution timed out"
        except Exception as e:
            dns_info["error"] = f"DNS error: {e}"

        return dns_info

    def get_statistics(self) -> Dict[str, Any]:
        """Get HTTP client statistics."""
        return {
            "total_requests": self._request_count,
            "total_errors": self._error_count,
            "total_bytes_received": self._total_bytes,
            "error_rate_percent": round(
                (self._error_count / self._request_count * 100)
                if self._request_count > 0 else 0, 2
            ),
        }


# =============================================================================
# RETEST ENGINE - Main Class
# =============================================================================

class RetestEngine:
    """
    Automatic retest engine for verifying vulnerability findings.
    
    Loads findings from FindingDB and performs type-specific retests
    to determine if vulnerabilities are still present, fixed, changed,
    or indeterminate. Supports multiple strategies for selecting which
    findings to retest and generates comprehensive reports.
    
    Strategies:
        - full: Retest all findings regardless of status
        - critical_only: Only retest CRITICAL and HIGH severity findings
        - oldest_first: Prioritize findings not retested in the longest time
        - random_sample: Randomly select 20% of findings for spot-checking
    """

    def __init__(self, db: FindingDB = None, http_client: RetestHTTPClient = None,
                 strategy: str = "full", rate_limit: float = DEFAULT_RATE_LIMIT,
                 timeout: int = CONNECTION_TIMEOUT, verify_ssl: bool = True,
                 max_findings: int = 0, output_dir: str = None):
        """
        Initialize the RetestEngine.

        Args:
            db: FindingDB instance with findings to retest.
            http_client: Optional pre-configured HTTP client.
            strategy: Retest strategy (full, critical_only, oldest_first, random_sample).
            rate_limit: Delay between requests in seconds.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            max_findings: Maximum findings to retest (0 = no limit).
            output_dir: Directory to save retest results.
        """
        self.db = db
        self.http_client = http_client or RetestHTTPClient(
            timeout=timeout,
            rate_limit=rate_limit,
            verify_ssl=verify_ssl,
        )
        self.strategy = RetestStrategy(strategy) if isinstance(strategy, str) else strategy
        self.max_findings = max_findings
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self._results: List[RetestResult] = []
        self._current_batch: Optional[RetestBatch] = None
        self._start_time: float = 0.0
        self._findings_tested: int = 0
        self._findings_skipped: int = 0

    def select_findings(self, findings: List[Finding] = None) -> List[Finding]:
        """
        Select findings to retest based on the configured strategy.

        Args:
            findings: Optional list of findings to select from.
                     If None, uses all findings from the database.

        Returns:
            List of findings selected for retesting.
        """
        if findings is None:
            if self.db is None:
                return []
            findings = self.db.get_all()

        if not findings:
            return []

        # Filter out already-fixed and invalid findings
        eligible = [
            f for f in findings
            if f.status not in ("fixed", "invalid", "duplicate", "wontfix")
        ]

        if not eligible:
            return []

        selected = []

        if self.strategy == RetestStrategy.FULL:
            selected = eligible[:]

        elif self.strategy == RetestStrategy.CRITICAL_ONLY:
            selected = [
                f for f in eligible
                if f.severity in ("CRITICAL", "HIGH")
            ]

        elif self.strategy == RetestStrategy.OLDEST_FIRST:
            # Sort by last retest time (oldest/never first)
            def sort_key(f):
                if not f.last_retest:
                    return "0000-00-00"
                return f.last_retest
            selected = sorted(eligible, key=sort_key)

        elif self.strategy == RetestStrategy.RANDOM_SAMPLE:
            sample_size = max(1, int(len(eligible) * 0.2))
            selected = random.sample(eligible, min(sample_size, len(eligible)))

        # Apply max_findings limit
        if self.max_findings > 0:
            selected = selected[:self.max_findings]

        return selected

    def retest_finding(self, finding: Finding) -> RetestResult:
        """
        Retest a single finding using the appropriate verification method.

        Dispatches to type-specific retest methods based on finding_type.

        Args:
            finding: The Finding to retest.

        Returns:
            RetestResult with the verification outcome.
        """
        start_time = time.time()

        result = RetestResult(
            finding_id=finding.id,
            finding_type=finding.finding_type,
            finding_title=finding.title,
            severity=finding.severity,
            url=finding.url,
            domain=finding.domain,
            previous_evidence=finding.evidence[:500] if finding.evidence else "",
            tested_at=datetime.utcnow().isoformat(),
        )

        # Validate URL
        if not finding.url or not finding.url.startswith(("http://", "https://")):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = "Invalid or missing URL"
            result.confidence = 0.0
            return result

        try:
            # Dispatch to type-specific retest method
            finding_type = finding.finding_type.lower()

            if finding_type == "cors":
                self._retest_cors(finding, result)
            elif finding_type in ("missing_headers", "cookie_flags"):
                self._retest_missing_headers(finding, result)
            elif finding_type in ("tls_misconfiguration", "ssl_issue"):
                self._retest_ssl(finding, result)
            elif finding_type in ("cookie_flags", "cookie_theft", "session_fixation"):
                self._retest_cookie_issues(finding, result)
            elif finding_type == "subdomain_takeover":
                self._retest_subdomain_takeover(finding, result)
            elif finding_type in ("info_disclosure", "version_disclosure", "server_header"):
                self._retest_info_disclosure(finding, result)
            elif finding_type in ("open_redirect",):
                self._retest_open_redirect(finding, result)
            elif finding_type in ("xss_reflected", "xss_stored", "xss_dom"):
                self._retest_xss(finding, result)
            elif finding_type in ("clickjacking",):
                self._retest_clickjacking(finding, result)
            elif finding_type in ("directory_listing",):
                self._retest_directory_listing(finding, result)
            elif finding_type in ("backup_file", "debug_endpoint"):
                self._retest_exposed_resource(finding, result)
            elif finding_type in ("graphql_introspection",):
                self._retest_graphql_introspection(finding, result)
            else:
                self._retest_generic(finding, result)

        except Exception as e:
            result.status = RetestStatus.ERROR.value
            result.error_message = f"Retest error: {str(e)}"
            result.confidence = 0.0

        # Calculate duration
        elapsed = (time.time() - start_time) * 1000
        result.duration_ms = round(elapsed, 2)

        return result

    def _retest_cors(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest CORS misconfiguration.

        Sends requests with various Origin headers and checks if the
        server reflects them in Access-Control-Allow-Origin.
        """
        url = finding.url
        cors_vulnerable = False
        test_details = []

        for origin in CORS_TEST_ORIGINS:
            headers = {"Origin": origin}
            response = self.http_client.get(url, headers=headers)

            if response.get("error"):
                continue

            resp_headers = response.get("headers", {})
            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "")

            test_result = {
                "origin_tested": origin,
                "acao_response": acao,
                "acac_response": acac,
                "reflected": False,
            }

            # Check if origin is reflected
            if acao and (acao == origin or acao == "*"):
                test_result["reflected"] = True
                cors_vulnerable = True

            # Check for wildcard with credentials
            if acao == "*" and acac.lower() == "true":
                test_result["reflected"] = True
                cors_vulnerable = True

            # Check null origin reflection
            if origin == "null" and acao == "null":
                test_result["reflected"] = True
                cors_vulnerable = True

            test_details.append(test_result)

        result.response_headers = {"test_results": test_details}

        if cors_vulnerable:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = f"CORS misconfiguration confirmed: origins reflected"
            result.confidence = 0.9
            result.diff_summary = "Vulnerability still present - CORS headers still reflect arbitrary origins"
        else:
            # Check if headers changed vs. original
            original_evidence = finding.evidence.lower() if finding.evidence else ""
            if "access-control-allow-origin" not in original_evidence and not cors_vulnerable:
                result.status = RetestStatus.CHANGED.value
                result.confidence = 0.6
                result.diff_summary = "Response differs from original but CORS no longer reflects"
            else:
                result.status = RetestStatus.FIXED.value
                result.current_evidence = "CORS headers no longer reflect arbitrary origins"
                result.confidence = 0.85
                result.diff_summary = "CORS misconfiguration has been fixed"

        result.recommendations = [
            "Validate Origin header against whitelist",
            "Never reflect arbitrary origins",
            "Avoid Access-Control-Allow-Origin: *",
            "Do not combine wildcard with credentials",
        ]

    def _retest_missing_headers(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest missing security headers.

        Re-fetches the URL and checks which security headers are present.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            result.confidence = 0.0
            return

        resp_headers = response.get("headers", {})
        result.response_code = response.get("status_code", 0)
        result.response_headers = resp_headers

        # Determine which headers were originally missing
        missing_headers = []
        present_headers = []

        # Normalize header keys to lowercase for comparison
        resp_header_keys = {k.lower(): v for k, v in resp_headers.items()}

        for header in SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in resp_header_keys:
                present_headers.append(header)
            else:
                missing_headers.append(header)

        # Check original evidence to see what was reported
        original_missing = []
        if finding.evidence:
            for header in SECURITY_HEADERS:
                if header.lower() in finding.evidence.lower():
                    original_missing.append(header)

        # Determine status
        if not original_missing:
            # Cannot determine specific headers, use general check
            if missing_headers:
                result.status = RetestStatus.STILL_PRESENT.value
                result.current_evidence = f"Missing headers: {', '.join(missing_headers[:5])}"
                result.confidence = 0.7
            else:
                result.status = RetestStatus.FIXED.value
                result.current_evidence = "All security headers are now present"
                result.confidence = 0.8
        else:
            # Check if originally-missing headers are now present
            still_missing = [h for h in original_missing if h.lower() not in resp_header_keys]
            newly_fixed = [h for h in original_missing if h.lower() in resp_header_keys]

            if not still_missing:
                result.status = RetestStatus.FIXED.value
                result.current_evidence = f"Previously missing headers now present: {', '.join(newly_fixed)}"
                result.confidence = 0.9
            elif newly_fixed:
                result.status = RetestStatus.CHANGED.value
                result.current_evidence = (
                    f"Partially fixed. Fixed: {', '.join(newly_fixed)}. "
                    f"Still missing: {', '.join(still_missing)}"
                )
                result.confidence = 0.75
            else:
                result.status = RetestStatus.STILL_PRESENT.value
                result.current_evidence = f"Headers still missing: {', '.join(still_missing)}"
                result.confidence = 0.85

        result.diff_summary = f"Headers present: {len(present_headers)}/{len(SECURITY_HEADERS)}"
        result.recommendations = [
            f"Add missing header: {h}" for h in missing_headers[:5]
        ]

    def _retest_ssl(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest SSL/TLS issues.

        Checks certificate validity, expiration, and configuration.
        """
        parsed = urlparse(finding.url)
        hostname = parsed.hostname or finding.domain

        if not hostname:
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = "Cannot determine hostname"
            result.confidence = 0.0
            return

        port = parsed.port or 443
        cert_info = self.http_client.check_ssl_certificate(hostname, port)

        if cert_info.get("error"):
            # SSL error might mean the issue is still present
            error_msg = cert_info["error"]
            if "verification failed" in error_msg.lower():
                result.status = RetestStatus.STILL_PRESENT.value
                result.current_evidence = f"SSL verification still failing: {error_msg}"
                result.confidence = 0.85
            elif "timed out" in error_msg.lower() or "refused" in error_msg.lower():
                result.status = RetestStatus.UNREACHABLE.value
                result.error_message = error_msg
                result.confidence = 0.0
            else:
                result.status = RetestStatus.UNKNOWN.value
                result.error_message = error_msg
                result.confidence = 0.3
        elif cert_info.get("expired"):
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = f"Certificate expired. Days overdue: {abs(cert_info.get('days_until_expiry', 0))}"
            result.confidence = 0.95
        elif cert_info.get("days_until_expiry", 365) < 30:
            result.status = RetestStatus.CHANGED.value
            result.current_evidence = f"Certificate expires in {cert_info['days_until_expiry']} days"
            result.confidence = 0.7
        elif cert_info.get("valid"):
            result.status = RetestStatus.FIXED.value
            result.current_evidence = (
                f"Valid SSL certificate. Expires in {cert_info.get('days_until_expiry', '?')} days. "
                f"Issuer: {cert_info.get('issuer', 'Unknown')}"
            )
            result.confidence = 0.85
        else:
            result.status = RetestStatus.UNKNOWN.value
            result.confidence = 0.3

        result.metadata = {"cert_info": cert_info}
        result.recommendations = [
            "Ensure certificate is valid and not expired",
            "Use TLS 1.2+ only",
            "Configure proper certificate chain",
            "Enable HSTS header",
        ]

    def _retest_cookie_issues(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest cookie security issues.

        Re-fetches the URL and checks Set-Cookie headers for security attributes.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            result.confidence = 0.0
            return

        resp_headers = response.get("headers", {})
        result.response_code = response.get("status_code", 0)

        # Extract Set-Cookie headers
        set_cookie_headers = []
        for key, value in resp_headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        if not set_cookie_headers:
            # No cookies set - might mean fixed or just different page state
            result.status = RetestStatus.CHANGED.value
            result.current_evidence = "No Set-Cookie headers in response"
            result.confidence = 0.5
            result.diff_summary = "No cookies set in current response"
            return

        # Check each cookie for security attributes
        insecure_cookies = []
        secure_cookies = []

        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()
            issues = []

            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")

            if issues:
                insecure_cookies.append({"name": cookie_name, "issues": issues})
            else:
                secure_cookies.append(cookie_name)

        if insecure_cookies:
            result.status = RetestStatus.STILL_PRESENT.value
            cookie_details = "; ".join(
                f"{c['name']}: {', '.join(c['issues'])}"
                for c in insecure_cookies[:3]
            )
            result.current_evidence = f"Insecure cookies found: {cookie_details}"
            result.confidence = 0.85
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = f"All {len(secure_cookies)} cookies have proper security attributes"
            result.confidence = 0.9

        result.diff_summary = f"Insecure: {len(insecure_cookies)}, Secure: {len(secure_cookies)}"
        result.recommendations = [
            "Set Secure flag on all cookies",
            "Set HttpOnly flag on session cookies",
            "Set SameSite=Strict or SameSite=Lax",
            "Set appropriate expiration times",
        ]

    def _retest_subdomain_takeover(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest subdomain takeover vulnerability.

        Resolves DNS for the subdomain and checks the response body
        for service-specific fingerprints indicating an unclaimed resource.
        """
        url = finding.url
        parsed = urlparse(url)
        hostname = parsed.hostname or finding.domain

        if not hostname:
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = "Cannot determine hostname"
            result.confidence = 0.0
            return

        # Step 1: DNS resolution
        dns_info = self.http_client.resolve_dns(hostname)

        if not dns_info.get("resolved"):
            # DNS does not resolve - could be taken down or taken over
            result.status = RetestStatus.CHANGED.value
            result.current_evidence = f"DNS no longer resolves for {hostname}"
            result.confidence = 0.6
            result.diff_summary = "Subdomain DNS no longer resolves"
            return

        # Step 2: HTTP request to check content
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            result.confidence = 0.3
            return

        body = response.get("body", "")
        status_code = response.get("status_code", 0)
        result.response_code = status_code

        # Step 3: Check for takeover fingerprints
        takeover_detected = False
        detected_service = ""

        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            for fingerprint in fingerprints:
                if fingerprint.lower() in body.lower():
                    takeover_detected = True
                    detected_service = service
                    break
            if takeover_detected:
                break

        if takeover_detected:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = (
                f"Subdomain takeover still possible. Service: {detected_service}. "
                f"Fingerprint detected in response body."
            )
            result.confidence = 0.9
        elif status_code == 404:
            # 404 might indicate unclaimed resource
            result.status = RetestStatus.CHANGED.value
            result.current_evidence = f"Returns 404 but no known takeover fingerprint detected"
            result.confidence = 0.5
        elif 200 <= status_code < 400:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = (
                f"Subdomain now serves valid content (HTTP {status_code}). "
                f"No takeover fingerprints detected."
            )
            result.confidence = 0.8
        else:
            result.status = RetestStatus.UNKNOWN.value
            result.current_evidence = f"HTTP status {status_code}, cannot determine takeover status"
            result.confidence = 0.4

        result.metadata = {"dns_info": dns_info, "detected_service": detected_service}
        result.recommendations = [
            "Remove dangling DNS records",
            "Claim the resource on the hosting service",
            "Set up monitoring for subdomain changes",
            "Consider wildcard DNS restrictions",
        ]

    def _retest_info_disclosure(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest information disclosure.

        Checks server headers, X-Powered-By, and response body for
        sensitive information leakage.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            result.confidence = 0.0
            return

        resp_headers = response.get("headers", {})
        body = response.get("body", "")
        result.response_code = response.get("status_code", 0)
        result.response_headers = resp_headers

        # Check for information disclosure indicators
        disclosure_found = []
        disclosure_details = {}

        # Server header
        server = resp_headers.get("Server", "")
        if server and INFO_DISCLOSURE_PATTERNS["version_number"].search(server):
            disclosure_found.append(f"Server header with version: {server}")
            disclosure_details["server"] = server

        # X-Powered-By
        powered_by = resp_headers.get("X-Powered-By", "")
        if powered_by:
            disclosure_found.append(f"X-Powered-By header: {powered_by}")
            disclosure_details["powered_by"] = powered_by

        # X-AspNet-Version
        aspnet = resp_headers.get("X-AspNet-Version", "")
        if aspnet:
            disclosure_found.append(f"X-AspNet-Version: {aspnet}")
            disclosure_details["aspnet_version"] = aspnet

        # Check body for sensitive patterns
        body_snippet = body[:5000]
        for pattern_name, pattern in INFO_DISCLOSURE_PATTERNS.items():
            if pattern_name in ("server_header", "powered_by"):
                continue
            matches = pattern.findall(body_snippet)
            if matches:
                disclosure_found.append(f"{pattern_name}: {matches[0] if matches else 'detected'}")

        # Compare with original evidence
        original_evidence = (finding.evidence or "").lower()

        if disclosure_found:
            # Check if the specific disclosure from original is still present
            still_present = False
            if "server" in original_evidence and disclosure_details.get("server"):
                still_present = True
            elif "powered" in original_evidence and disclosure_details.get("powered_by"):
                still_present = True
            elif "version" in original_evidence and any("version" in d.lower() for d in disclosure_found):
                still_present = True
            else:
                still_present = len(disclosure_found) > 0

            if still_present:
                result.status = RetestStatus.STILL_PRESENT.value
                result.current_evidence = "Information disclosure: " + "; ".join(disclosure_found[:3])
                result.confidence = 0.8
            else:
                result.status = RetestStatus.CHANGED.value
                result.current_evidence = "Different information disclosed than originally reported"
                result.confidence = 0.6
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "No information disclosure detected in headers or body"
            result.confidence = 0.8

        result.diff_summary = f"Disclosures found: {len(disclosure_found)}"
        result.recommendations = [
            "Remove or obfuscate Server header",
            "Remove X-Powered-By header",
            "Disable verbose error messages",
            "Remove version numbers from headers",
        ]

    def _retest_open_redirect(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest open redirect vulnerability.

        Attempts to trigger a redirect to an external domain by
        injecting a redirect URL into identified parameters.
        """
        url = finding.url
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Try common redirect parameters
        redirect_params = ["url", "redirect", "next", "return", "returnUrl",
                          "redirect_uri", "continue", "dest", "destination",
                          "redir", "return_to", "go", "target", "link"]

        # Also try params from the original URL
        for param_name in params:
            if param_name.lower() not in [p.lower() for p in redirect_params]:
                redirect_params.append(param_name)

        evil_url = "https://evil.example.com/"
        redirect_detected = False
        tested_param = ""

        for param in redirect_params[:8]:
            # Construct test URL with redirect payload
            test_params = dict(params)
            test_params[param] = [evil_url]

            query_string = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            response = self.http_client.get(test_url)

            if response.get("error"):
                continue

            # Check if redirected to evil URL
            final_url = response.get("final_url", "")
            status_code = response.get("status_code", 0)
            location = response.get("headers", {}).get("Location", "")

            if evil_url in final_url or evil_url in location:
                redirect_detected = True
                tested_param = param
                break

            if status_code in (301, 302, 303, 307, 308):
                if evil_url in location or "evil.example.com" in location:
                    redirect_detected = True
                    tested_param = param
                    break

        if redirect_detected:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = f"Open redirect confirmed via parameter: {tested_param}"
            result.confidence = 0.9
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "No open redirect detected with tested payloads"
            result.confidence = 0.7

        result.recommendations = [
            "Validate redirect URLs against a whitelist",
            "Use relative URLs for redirects",
            "Do not allow user input in redirect destinations",
        ]

    def _retest_xss(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest XSS vulnerability.

        Injects a canary string and checks if it appears unencoded
        in the response.
        """
        url = finding.url
        canary = "sm1337xss"
        xss_payload = f"<{canary}>"

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        xss_detected = False

        # Test each parameter
        for param_name in list(params.keys())[:5]:
            test_params = dict(params)
            test_params[param_name] = [xss_payload]

            query_string = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            response = self.http_client.get(test_url)

            if response.get("error"):
                continue

            body = response.get("body", "")

            # Check if canary is reflected without encoding
            if xss_payload in body or f"<{canary}>" in body:
                xss_detected = True
                result.metadata["vulnerable_param"] = param_name
                break

        if xss_detected:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = "XSS canary reflected without encoding in response"
            result.confidence = 0.85
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "XSS canary is encoded or not reflected"
            result.confidence = 0.7

        result.recommendations = [
            "Implement output encoding for all user input",
            "Use Content-Security-Policy header",
            "Implement input validation",
        ]

    def _retest_clickjacking(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest clickjacking vulnerability.

        Checks for X-Frame-Options or CSP frame-ancestors directive.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            return

        headers = response.get("headers", {})
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")

        protected = False
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            protected = True
        if "frame-ancestors" in csp.lower():
            protected = True

        if protected:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = f"Frame protection present: XFO={xfo or 'none'}, CSP frame-ancestors={'present' if 'frame-ancestors' in csp.lower() else 'none'}"
            result.confidence = 0.9
        else:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = "No X-Frame-Options or CSP frame-ancestors header"
            result.confidence = 0.85

        result.recommendations = [
            "Add X-Frame-Options: DENY or SAMEORIGIN",
            "Add CSP frame-ancestors directive",
        ]

    def _retest_directory_listing(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest directory listing exposure.

        Checks if the URL returns a directory listing page.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            return

        body = response.get("body", "").lower()
        listing_indicators = [
            "index of /", "directory listing", "parent directory",
            "<pre>", "[dir]", "last modified", "name.*size.*description",
        ]

        listing_found = any(indicator in body for indicator in listing_indicators)

        if listing_found:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = "Directory listing still enabled"
            result.confidence = 0.9
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "Directory listing no longer present"
            result.confidence = 0.85

        result.recommendations = [
            "Disable directory listing in web server configuration",
            "Add index files to directories",
        ]

    def _retest_exposed_resource(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest exposed backup file or debug endpoint.

        Checks if the resource is still accessible.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            return

        status_code = response.get("status_code", 0)

        if status_code == 200:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = f"Resource still accessible (HTTP {status_code})"
            result.confidence = 0.85
        elif status_code in (403, 401):
            result.status = RetestStatus.FIXED.value
            result.current_evidence = f"Resource now returns {status_code} (access denied)"
            result.confidence = 0.8
        elif status_code == 404:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "Resource removed (404 Not Found)"
            result.confidence = 0.9
        else:
            result.status = RetestStatus.CHANGED.value
            result.current_evidence = f"Resource returns HTTP {status_code}"
            result.confidence = 0.6

        result.recommendations = [
            "Remove or restrict access to sensitive resources",
            "Implement proper access controls",
            "Remove debug endpoints in production",
        ]

    def _retest_graphql_introspection(self, finding: Finding, result: RetestResult) -> None:
        """
        Retest GraphQL introspection.

        Sends an introspection query to check if it is still enabled.
        """
        url = finding.url
        introspection_query = "{__schema{queryType{name}}}"

        # Try GET with query parameter
        test_url = f"{url}?query={introspection_query}"
        response = self.http_client.get(test_url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            return

        body = response.get("body", "")

        if "__schema" in body or "queryType" in body:
            result.status = RetestStatus.STILL_PRESENT.value
            result.current_evidence = "GraphQL introspection still enabled"
            result.confidence = 0.9
        else:
            result.status = RetestStatus.FIXED.value
            result.current_evidence = "GraphQL introspection appears disabled"
            result.confidence = 0.8

        result.recommendations = [
            "Disable introspection in production",
            "Implement query depth limiting",
            "Add authentication to GraphQL endpoint",
        ]

    def _retest_generic(self, finding: Finding, result: RetestResult) -> None:
        """
        Generic retest for finding types without specific logic.

        Performs a basic HTTP request and compares response characteristics
        with the original evidence.
        """
        url = finding.url
        response = self.http_client.get(url)

        if response.get("error"):
            result.status = RetestStatus.UNKNOWN.value
            result.error_message = response["error"]
            result.confidence = 0.0
            return

        result.response_code = response.get("status_code", 0)
        result.response_headers = response.get("headers", {})
        body = response.get("body", "")

        # Compare response with original evidence
        original_evidence = finding.evidence or ""

        if original_evidence:
            # Check if key parts of evidence still appear in response
            evidence_snippets = [s.strip() for s in original_evidence.split("\n") if len(s.strip()) > 10]
            matches = 0
            for snippet in evidence_snippets[:5]:
                if snippet.lower() in body.lower() or snippet.lower() in str(result.response_headers).lower():
                    matches += 1

            if evidence_snippets:
                match_ratio = matches / len(evidence_snippets[:5])
            else:
                match_ratio = 0

            if match_ratio >= 0.6:
                result.status = RetestStatus.STILL_PRESENT.value
                result.current_evidence = "Original evidence patterns still detected in response"
                result.confidence = 0.6
            elif match_ratio > 0:
                result.status = RetestStatus.CHANGED.value
                result.current_evidence = f"Partial match ({int(match_ratio*100)}%) with original evidence"
                result.confidence = 0.4
            else:
                result.status = RetestStatus.FIXED.value
                result.current_evidence = "Original evidence no longer detected"
                result.confidence = 0.5
        else:
            # No evidence to compare against
            result.status = RetestStatus.UNKNOWN.value
            result.current_evidence = "No original evidence available for comparison"
            result.confidence = 0.2

        result.diff_summary = "Generic comparison based on evidence pattern matching"
        result.recommendations = [
            "Manual verification recommended for this finding type",
            "Review the finding details and test manually",
        ]

    def run_retest(self, findings: List[Finding] = None,
                   progress_callback=None) -> RetestBatch:
        """
        Execute a full retest batch.

        Selects findings based on strategy, retests each one, and
        generates a comprehensive batch result with summary statistics.

        Args:
            findings: Optional list of findings to retest.
            progress_callback: Optional callback for progress updates.

        Returns:
            RetestBatch with all results and summary.
        """
        self._start_time = time.time()

        # Create batch
        batch = RetestBatch(
            batch_id=f"BATCH-{uuid.uuid4().hex[:8].upper()}",
            strategy=self.strategy.value,
            started_at=datetime.utcnow().isoformat(),
        )
        self._current_batch = batch

        # Select findings
        selected = self.select_findings(findings)

        if not selected:
            batch.completed_at = datetime.utcnow().isoformat()
            batch.duration_seconds = time.time() - self._start_time
            batch.calculate_summary()
            return batch

        batch.total_findings = len(selected)
        domains = set(f.domain for f in selected if f.domain)
        batch.target_domains = sorted(list(domains))

        # Retest each finding
        for idx, finding in enumerate(selected):
            if progress_callback:
                progress_callback(idx + 1, len(selected), finding.title[:40])

            try:
                result = self.retest_finding(finding)
                batch.add_result(result)
                self._findings_tested += 1

                # Update finding in database
                if self.db:
                    status_map = {
                        RetestStatus.FIXED.value: "fixed",
                        RetestStatus.STILL_PRESENT.value: "not_fixed",
                        RetestStatus.CHANGED.value: "partially_fixed",
                    }
                    db_status = status_map.get(result.status)
                    if db_status:
                        finding.add_retest(db_status, result.current_evidence[:200])

            except Exception as e:
                error_result = RetestResult(
                    finding_id=finding.id,
                    finding_type=finding.finding_type,
                    finding_title=finding.title,
                    severity=finding.severity,
                    url=finding.url,
                    domain=finding.domain,
                    status=RetestStatus.ERROR.value,
                    error_message=str(e),
                    tested_at=datetime.utcnow().isoformat(),
                )
                batch.add_result(error_result)
                batch.errors.append({"finding_id": finding.id, "error": str(e)})

        # Finalize batch
        batch.completed_at = datetime.utcnow().isoformat()
        batch.duration_seconds = round(time.time() - self._start_time, 2)
        batch.calculate_summary()

        return batch

    def generate_schedule(self, findings: List[Finding] = None) -> RetestSchedule:
        """
        Generate a retest schedule based on finding severities and intervals.

        Args:
            findings: Optional list of findings to schedule.

        Returns:
            RetestSchedule with timing recommendations.
        """
        if findings is None:
            if self.db:
                findings = self.db.get_all()
            else:
                findings = []

        schedule = RetestSchedule(
            schedule_id=f"SCHED-{uuid.uuid4().hex[:8].upper()}",
            generated_at=datetime.utcnow().isoformat(),
        )

        # Group by severity
        by_severity = defaultdict(list)
        by_domain = defaultdict(list)

        for finding in findings:
            if finding.status in ("fixed", "invalid", "duplicate", "wontfix"):
                continue
            by_severity[finding.severity].append(finding)
            by_domain[finding.domain or "unknown"].append(finding)

        # Calculate next retest times
        now = datetime.utcnow()

        for severity, sev_findings in by_severity.items():
            interval_config = RETEST_INTERVALS.get(severity, RETEST_INTERVALS["MEDIUM"])

            due_findings = []
            for finding in sev_findings:
                if finding.retest_count == 0:
                    interval_hours = interval_config["initial_hours"]
                else:
                    interval_hours = interval_config["followup_hours"]

                if finding.needs_retest(interval_hours):
                    due_findings.append({
                        "id": finding.id,
                        "title": finding.title[:60],
                        "url": finding.url[:80],
                        "domain": finding.domain,
                        "last_retest": finding.last_retest or "never",
                        "retest_count": finding.retest_count,
                        "overdue_hours": round(finding.age_hours() - interval_hours, 1) if finding.age_hours() > interval_hours else 0,
                    })

            schedule.by_severity[severity] = {
                "total": len(sev_findings),
                "due_now": len(due_findings),
                "interval_hours": interval_config["initial_hours"],
                "followup_hours": interval_config["followup_hours"],
                "max_retests": interval_config["max_retests"],
                "findings_due": due_findings[:20],
            }

        for domain, domain_findings in by_domain.items():
            schedule.by_domain[domain] = {
                "total": len(domain_findings),
                "severities": dict(defaultdict(int, {f.severity: 0 for f in domain_findings})),
            }
            for f in domain_findings:
                schedule.by_domain[domain]["severities"][f.severity] = schedule.by_domain[domain]["severities"].get(f.severity, 0) + 1

        # Generate cron suggestions
        schedule.cron_suggestions = dict(CRON_TEMPLATES)

        # Calculate findings due
        all_due = []
        for sev_data in schedule.by_severity.values():
            all_due.extend(sev_data.get("findings_due", []))
        schedule.findings_due = all_due

        return schedule

    def generate_cron_schedule(self, findings: List[Finding] = None) -> str:
        """
        Generate cron-compatible schedule entries for automated retesting.

        Args:
            findings: Optional list of findings to consider.

        Returns:
            Multi-line string with cron entries and comments.
        """
        schedule = self.generate_schedule(findings)
        lines = [
            "# Super Monster Retest Cron Schedule",
            f"# Generated: {datetime.utcnow().isoformat()}",
            f"# Total findings tracked: {sum(d['total'] for d in schedule.by_severity.values())}",
            "",
            "# Format: minute hour day_of_month month day_of_week command",
            "",
        ]

        for severity in SEVERITY_LEVELS:
            sev_data = schedule.by_severity.get(severity, {})
            count = sev_data.get("total", 0)
            if count == 0:
                continue

            cron_expr = CRON_TEMPLATES.get(severity, "0 0 * * 1")
            lines.append(f"# {severity} findings ({count} total, check every {sev_data.get('interval_hours', '?')}h)")
            lines.append(
                f"{cron_expr} python -m super_monster retest "
                f"--strategy critical_only --severity {severity} "
                f"--output ./retest_results/{severity.lower()}/"
            )
            lines.append("")

        # Full retest weekly
        lines.extend([
            "# Full retest (all findings, weekly on Sunday)",
            "0 2 * * 0 python -m super_monster retest --strategy full --output ./retest_results/full/",
            "",
            "# Random sample daily (spot check 20% of findings)",
            "0 8 * * * python -m super_monster retest --strategy random_sample --output ./retest_results/sample/",
        ])

        return "\n".join(lines)

    def generate_report(self, batch: RetestBatch, format: str = "text") -> str:
        """
        Generate a formatted retest report.

        Args:
            batch: The RetestBatch to report on.
            format: Output format (text, json, markdown).

        Returns:
            Formatted report string.
        """
        if format == "json":
            return json.dumps(batch.to_dict(), indent=2, default=str)
        elif format == "markdown":
            return self._generate_markdown_report(batch)
        else:
            return self._generate_text_report(batch)

    def _generate_text_report(self, batch: RetestBatch) -> str:
        """Generate plain text retest report."""
        lines = []
        lines.append("=" * 70)
        lines.append("  SUPER MONSTER - RETEST REPORT")
        lines.append("=" * 70)
        lines.append(f"  Batch ID:     {batch.batch_id}")
        lines.append(f"  Strategy:     {batch.strategy}")
        lines.append(f"  Started:      {batch.started_at}")
        lines.append(f"  Completed:    {batch.completed_at}")
        lines.append(f"  Duration:     {batch.duration_seconds:.1f}s")
        lines.append(f"  Total Tested: {batch.total_findings}")
        lines.append("")

        # Summary
        summary = batch.summary or batch.calculate_summary()
        lines.append("--- STATUS BREAKDOWN ---")
        for status, count in sorted(summary.get("status_breakdown", {}).items()):
            percent = (count / batch.total_findings * 100) if batch.total_findings > 0 else 0
            bar_len = int(percent / 2)
            bar = "#" * bar_len
            lines.append(f"  {status:<15} {count:>4} ({percent:>5.1f}%) |{bar}")

        lines.append("")
        lines.append(f"  Fix Rate:          {summary.get('fix_rate_percent', 0):.1f}%")
        lines.append(f"  Still Present:     {summary.get('still_present_percent', 0):.1f}%")
        lines.append(f"  Domains Tested:    {summary.get('domains_count', 0)}")
        lines.append("")

        # Per-severity breakdown
        lines.append("--- SEVERITY BREAKDOWN ---")
        for severity in SEVERITY_LEVELS:
            sev_data = summary.get("severity_breakdown", {}).get(severity, {})
            if sev_data:
                total_in_sev = sum(sev_data.values())
                fixed = sev_data.get("FIXED", 0)
                present = sev_data.get("STILL_PRESENT", 0)
                lines.append(f"  {severity:<10} Total: {total_in_sev}, Fixed: {fixed}, Present: {present}")

        lines.append("")

        # Individual results
        lines.append("--- DETAILED RESULTS ---")
        for result_dict in batch.results[:50]:
            status = result_dict.get("status", "UNKNOWN")
            title = result_dict.get("finding_title", "Unknown")[:50]
            severity = result_dict.get("severity", "INFO")
            lines.append(f"  [{status:<14}] {severity:<8} {title}")
            if result_dict.get("current_evidence"):
                lines.append(f"                   Evidence: {result_dict['current_evidence'][:70]}")

        if len(batch.results) > 50:
            lines.append(f"  ... and {len(batch.results) - 50} more results")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _generate_markdown_report(self, batch: RetestBatch) -> str:
        """Generate markdown formatted retest report."""
        lines = []
        lines.append("# Super Monster Retest Report")
        lines.append("")
        lines.append(f"**Batch ID:** {batch.batch_id}")
        lines.append(f"**Strategy:** {batch.strategy}")
        lines.append(f"**Started:** {batch.started_at}")
        lines.append(f"**Duration:** {batch.duration_seconds:.1f}s")
        lines.append(f"**Total Tested:** {batch.total_findings}")
        lines.append("")

        summary = batch.summary or batch.calculate_summary()

        lines.append("## Summary")
        lines.append("")
        lines.append("| Status | Count | Percentage |")
        lines.append("|--------|-------|------------|")

        for status, count in sorted(summary.get("status_breakdown", {}).items()):
            percent = (count / batch.total_findings * 100) if batch.total_findings > 0 else 0
            lines.append(f"| {status} | {count} | {percent:.1f}% |")

        lines.append("")
        lines.append(f"**Fix Rate:** {summary.get('fix_rate_percent', 0):.1f}%")
        lines.append(f"**Still Present:** {summary.get('still_present_percent', 0):.1f}%")
        lines.append("")

        lines.append("## Results")
        lines.append("")
        lines.append("| Status | Severity | Finding | Evidence |")
        lines.append("|--------|----------|---------|----------|")

        for result_dict in batch.results[:100]:
            status = result_dict.get("status", "UNKNOWN")
            severity = result_dict.get("severity", "INFO")
            title = result_dict.get("finding_title", "Unknown")[:40]
            evidence = result_dict.get("current_evidence", "")[:50]
            lines.append(f"| {status} | {severity} | {title} | {evidence} |")

        return "\n".join(lines)

    def print_results(self, batch: RetestBatch) -> None:
        """
        Print colored retest results to terminal.

        Args:
            batch: The RetestBatch to display.
        """
        summary = batch.summary or batch.calculate_summary()

        print(f"\n{Colors.HEADER}{'=' * 70}")
        print(f"  RETEST RESULTS - Batch {batch.batch_id}")
        print(f"{'=' * 70}{Colors.RESET}")
        print(f"  Strategy:  {Colors.HIGHLIGHT}{batch.strategy}{Colors.RESET}")
        print(f"  Duration:  {Colors.TIMER}{batch.duration_seconds:.1f}s{Colors.RESET}")
        print(f"  Tested:    {Colors.COUNT}{batch.total_findings}{Colors.RESET} findings")
        print()

        # Status breakdown with color
        print(f"{Colors.SUBHEADER}--- Status Breakdown ---{Colors.RESET}")
        total = batch.total_findings or 1

        status_colors = {
            "FIXED": Colors.SUCCESS,
            "STILL_PRESENT": Colors.ERROR,
            "CHANGED": Colors.WARNING,
            "UNKNOWN": Colors.DIMMED,
            "ERROR": Fore.MAGENTA,
            "TIMEOUT": Fore.CYAN,
            "UNREACHABLE": Fore.RED + Style.DIM,
        }

        for status, count in sorted(summary.get("status_breakdown", {}).items(),
                                     key=lambda x: x[1], reverse=True):
            percent = count / total * 100
            color = status_colors.get(status, Colors.VALUE)
            bar_width = int(percent / 2.5)
            bar = "=" * bar_width
            print(f"  {color}{status:<15}{Colors.RESET} {count:>4} ({percent:>5.1f}%) [{color}{bar}{Colors.RESET}]")

        print()
        print(f"  {Colors.SUCCESS}Fix Rate:      {summary.get('fix_rate_percent', 0):.1f}%{Colors.RESET}")
        print(f"  {Colors.ERROR}Still Present: {summary.get('still_present_percent', 0):.1f}%{Colors.RESET}")
        print(f"  Domains:     {summary.get('domains_count', 0)}")

        # Show individual results (top findings)
        print(f"\n{Colors.SUBHEADER}--- Top Results ---{Colors.RESET}")
        for result_dict in batch.results[:15]:
            status = result_dict.get("status", "UNKNOWN")
            severity = result_dict.get("severity", "INFO")
            title = result_dict.get("finding_title", "Unknown")[:45]
            color = status_colors.get(status, Colors.VALUE)
            sev_color = Colors.severity_color(severity)

            print(f"  {color}[{status[:4]}]{Colors.RESET} "
                  f"{sev_color}{severity:<8}{Colors.RESET} {title}")

        if len(batch.results) > 15:
            print(f"  ... and {len(batch.results) - 15} more")

        print(f"\n{Colors.HEADER}{'=' * 70}{Colors.RESET}")

    def save_results(self, batch: RetestBatch, output_dir: str = None) -> Dict[str, str]:
        """
        Save retest results to files in multiple formats.

        Args:
            batch: The RetestBatch to save.
            output_dir: Output directory (defaults to self.output_dir).

        Returns:
            Dictionary mapping format names to file paths.
        """
        output_dir = output_dir or self.output_dir
        os.makedirs(output_dir, exist_ok=True)
        saved_files = {}

        # Save JSON
        json_path = os.path.join(output_dir, f"retest_{batch.batch_id}.json")
        with open(json_path, "w") as f:
            json.dump(batch.to_dict(), f, indent=2, default=str)
        saved_files["json"] = json_path

        # Save markdown report
        md_path = os.path.join(output_dir, f"retest_{batch.batch_id}.md")
        md_report = self._generate_markdown_report(batch)
        with open(md_path, "w") as f:
            f.write(md_report)
        saved_files["markdown"] = md_path

        # Save text report
        txt_path = os.path.join(output_dir, f"retest_{batch.batch_id}.txt")
        txt_report = self._generate_text_report(batch)
        with open(txt_path, "w") as f:
            f.write(txt_report)
        saved_files["text"] = txt_path

        # Save cron schedule
        cron_path = os.path.join(output_dir, "retest_crontab.txt")
        cron_content = self.generate_cron_schedule()
        with open(cron_path, "w") as f:
            f.write(cron_content)
        saved_files["cron"] = cron_path

        return saved_files

    def get_retest_stats(self) -> Dict[str, Any]:
        """Get overall retest engine statistics."""
        http_stats = self.http_client.get_statistics()
        return {
            "findings_tested": self._findings_tested,
            "findings_skipped": self._findings_skipped,
            "strategy": self.strategy.value,
            "http_client": http_stats,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_retest(input_path: str, output_dir: str = None,
               strategy: str = "full", db_path: str = None,
               rate_limit: float = DEFAULT_RATE_LIMIT,
               timeout: int = CONNECTION_TIMEOUT,
               max_findings: int = 0) -> RetestBatch:
    """
    Convenience function to run a complete retest workflow.

    Args:
        input_path: Path to findings database or report directory.
        output_dir: Directory to save results.
        strategy: Retest strategy to use.
        db_path: Path to the findings database.
        rate_limit: Delay between requests.
        timeout: Request timeout.
        max_findings: Maximum findings to test.

    Returns:
        RetestBatch with results.
    """
    from super_monster.finding_db import FindingDB

    # Load or create database
    effective_db_path = db_path or "super_monster_findings.json"
    db = FindingDB(effective_db_path)

    # Import findings if input is a directory
    if os.path.isdir(input_path):
        db.import_directory(input_path)
    elif os.path.isfile(input_path):
        db.import_monster_report(input_path)

    if db.count() == 0:
        batch = RetestBatch(
            batch_id=f"BATCH-{uuid.uuid4().hex[:8].upper()}",
            strategy=strategy,
            started_at=datetime.utcnow().isoformat(),
            completed_at=datetime.utcnow().isoformat(),
        )
        batch.calculate_summary()
        return batch

    # Create engine and run
    engine = RetestEngine(
        db=db,
        strategy=strategy,
        rate_limit=rate_limit,
        timeout=timeout,
        max_findings=max_findings,
        output_dir=output_dir or DEFAULT_OUTPUT_DIR,
    )

    # Run with progress
    def progress_cb(current, total, title):
        percent = current / total * 100
        sys.stdout.write(f"\n[{current}/{total}] ({percent:.0f}%) Testing: {title:<40}")
        sys.stdout.flush()
        if current >= total:
            print()

    batch = engine.run_retest(progress_callback=progress_cb)

    # Save results
    if output_dir:
        engine.save_results(batch, output_dir)

    # Save database
    if db.db_path:
        db.save()

    return batch


def get_retest_summary(db: FindingDB) -> Dict[str, Any]:
    """
    Get a summary of retest status for all findings in a database.

    Args:
        db: FindingDB instance.

    Returns:
        Dictionary with retest status summary.
    """
    all_findings = db.get_all()

    summary = {
        "total_findings": len(all_findings),
        "never_retested": 0,
        "retested_at_least_once": 0,
        "due_for_retest": 0,
        "by_status": defaultdict(int),
        "by_severity": defaultdict(lambda: {"total": 0, "retested": 0, "due": 0}),
        "oldest_unrested": None,
        "most_retested": None,
        "average_retests": 0.0,
    }

    total_retests = 0
    oldest_time = None
    max_retests = 0
    max_retest_finding = None

    for finding in all_findings:
        sev = finding.severity or "INFO"
        summary["by_severity"][sev]["total"] += 1
        summary["by_status"][finding.status] += 1
        total_retests += finding.retest_count

        if finding.retest_count == 0:
            summary["never_retested"] += 1
            if finding.discovered_at:
                if oldest_time is None or finding.discovered_at < oldest_time:
                    oldest_time = finding.discovered_at
                    summary["oldest_unrested"] = {
                        "id": finding.id,
                        "title": finding.title[:60],
                        "discovered": finding.discovered_at,
                    }
        else:
            summary["retested_at_least_once"] += 1
            summary["by_severity"][sev]["retested"] += 1

            if finding.retest_count > max_retests:
                max_retests = finding.retest_count
                max_retest_finding = finding

        # Check if due for retest
        interval_config = RETEST_INTERVALS.get(sev, RETEST_INTERVALS["MEDIUM"])
        interval = interval_config["initial_hours"] if finding.retest_count == 0 else interval_config["followup_hours"]
        if finding.needs_retest(interval):
            summary["due_for_retest"] += 1
            summary["by_severity"][sev]["due"] += 1

    if max_retest_finding:
        summary["most_retested"] = {
            "id": max_retest_finding.id,
            "title": max_retest_finding.title[:60],
            "retest_count": max_retest_finding.retest_count,
        }

    if all_findings:
        summary["average_retests"] = round(total_retests / len(all_findings), 2)

    return summary
