"""
Monster v2.0.0 Utilities Module

Contains all shared utility classes and helper functions used by the
Monster toolkit modules: ColorOutput, HTTPClient, DNSResolver, FileManager,
ProxyManager, RequestLogger, and various encoding/hashing/network helpers.
"""

import os
import re
import sys
import csv
import json
import time
import socket
import struct
import hashlib
import base64
import tempfile
import threading
import logging
from io import StringIO
from pathlib import Path
from datetime import datetime
from urllib.parse import (
    urlparse, urlunparse, urlencode, quote, unquote,
    parse_qs, parse_qsl, urljoin
)
from urllib.request import (
    Request, urlopen, build_opener, HTTPCookieProcessor,
    ProxyHandler, HTTPSHandler
)
from urllib.error import URLError, HTTPError
from http.cookiejar import CookieJar
from html import escape as html_escape, unescape as html_unescape
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set


# =============================================================================
# COLOR CONSTANTS (with colorama fallback)
# =============================================================================

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    RESET = Style.RESET_ALL
    BG_RED = Back.RED
    BG_GREEN = Back.GREEN
    BG_YELLOW = Back.YELLOW
    BG_BLUE = Back.BLUE
except ImportError:
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    WHITE = ""
    BRIGHT = ""
    DIM = ""
    RESET = ""
    BG_RED = ""
    BG_GREEN = ""
    BG_YELLOW = ""
    BG_BLUE = ""


# =============================================================================
# COLOR OUTPUT CLASS
# =============================================================================

class ColorOutput:
    """Handles all colored terminal output for the Monster toolkit."""

    @staticmethod
    def banner():
        """Display the Monster toolkit banner."""
        banner_text = f"""
{RED}{BRIGHT}
  __  __                 _
 |  \/  | ___  _ __  ___| |_ ___ _ __
 | |\/| |/ _ \| '_ \/ __| __/ _ \ '__|
 | |  | | (_) | | | \__ \ ||  __/ |
 |_|  |_|\___/|_| |_|___/\__\___|_|
{RESET}
{CYAN}  Bug Bounty Reconnaissance & Vulnerability Assessment Toolkit v2.0.0{RESET}
{DIM}  Passive/Semi-Passive Security Assessment{RESET}
"""
        print(banner_text)

    @staticmethod
    def info(msg: str):
        """Display an informational message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {BLUE}[INFO]{RESET} {msg}")

    @staticmethod
    def success(msg: str):
        """Display a success message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {GREEN}[+]{RESET} {msg}")

    @staticmethod
    def warning(msg: str):
        """Display a warning message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {YELLOW}[!]{RESET} {msg}")

    @staticmethod
    def error(msg: str):
        """Display an error message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {RED}[-]{RESET} {msg}")

    @staticmethod
    def critical(msg: str):
        """Display a critical error message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {BG_RED}{WHITE}[CRITICAL]{RESET} {RED}{msg}{RESET}")

    @staticmethod
    def finding(severity: str, title: str, detail: str = ""):
        """Display a security finding with severity level."""
        severity_colors = {
            "critical": f"{BG_RED}{WHITE}",
            "high": f"{RED}{BRIGHT}",
            "medium": f"{YELLOW}{BRIGHT}",
            "low": f"{BLUE}",
            "info": f"{CYAN}",
        }
        color = severity_colors.get(severity.lower(), CYAN)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  {DIM}[{timestamp}]{RESET} {color}[{severity.upper()}]{RESET} {BRIGHT}{title}{RESET}")
        if detail:
            print(f"           {DIM}{detail}{RESET}")

    @staticmethod
    def progress(current: int, total: int, prefix: str = "Progress"):
        """Display a progress indicator."""
        percent = (current / total * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = f"{'=' * filled}{'-' * (bar_len - filled)}"
        print(f"\r  {CYAN}[{prefix}]{RESET} [{bar}] {percent:.1f}% ({current}/{total})", end="", flush=True)
        if current >= total:
            print()

    @staticmethod
    def table(headers: List[str], rows: List[List[str]], title: str = ""):
        """Display data in a formatted table."""
        if title:
            print(f"\n  {BRIGHT}{title}{RESET}")
            print(f"  {'=' * len(title)}")

        if not rows:
            print(f"  {DIM}No data to display{RESET}")
            return

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Print header
        header_line = "  "
        for i, h in enumerate(headers):
            header_line += f"{BRIGHT}{h:<{col_widths[i]}}{RESET}  "
        print(header_line)
        print("  " + "  ".join("-" * w for w in col_widths))

        # Print rows
        for row in rows:
            row_line = "  "
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    row_line += f"{str(cell):<{col_widths[i]}}  "
            print(row_line)

    @staticmethod
    def section_header(title: str):
        """Display a section header."""
        print(f"\n  {BRIGHT}{CYAN}{'=' * 60}{RESET}")
        print(f"  {BRIGHT}{CYAN}  {title}{RESET}")
        print(f"  {BRIGHT}{CYAN}{'=' * 60}{RESET}\n")


# =============================================================================
# RATE LIMITER CLASS
# =============================================================================

class RateLimiter:
    """Thread-safe rate limiter for controlling request frequency."""

    def __init__(self, delay: float = 1.0):
        """
        Initialize the rate limiter.

        Args:
            delay: Minimum delay between requests in seconds.
        """
        self.delay = delay
        self.last_request = 0.0
        self._lock = threading.Lock()

    def wait(self):
        """Wait until the required delay has passed since the last request."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.delay:
                sleep_time = self.delay - elapsed
                time.sleep(sleep_time)
            self.last_request = time.time()

    def set_delay(self, delay: float):
        """Update the delay interval."""
        with self._lock:
            self.delay = delay

    def reset(self):
        """Reset the last request timestamp."""
        with self._lock:
            self.last_request = 0.0


# =============================================================================
# HTTP CLIENT CLASS
# =============================================================================

@dataclass
class HTTPResponse:
    """Container for HTTP response data."""
    url: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    redirect_url: Optional[str] = None
    content_length: int = 0


class HTTPClient:
    """
    HTTP client using urllib with support for cookies, proxies,
    request logging, retry logic, and custom headers.
    """

    def __init__(
        self,
        user_agent: str = None,
        timeout: int = 15,
        max_retries: int = 3,
        follow_redirects: bool = True,
        proxy: str = None,
        cookies: Dict[str, str] = None,
        verify_ssl: bool = True,
        rate_limiter: RateLimiter = None,
        logger: "RequestLogger" = None,
    ):
        """
        Initialize the HTTP client.

        Args:
            user_agent: Custom User-Agent string.
            timeout: Request timeout in seconds.
            max_retries: Number of retry attempts on failure.
            follow_redirects: Whether to follow HTTP redirects.
            proxy: Proxy URL (http://host:port or socks5://host:port).
            cookies: Dictionary of cookies to include.
            verify_ssl: Whether to verify SSL certificates.
            rate_limiter: RateLimiter instance for request throttling.
            logger: RequestLogger instance for logging requests.
        """
        from monster.config import DEFAULT_USER_AGENT
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.rate_limiter = rate_limiter
        self.logger = logger
        self._session_cookies = CookieJar()
        self._default_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _build_opener(self):
        """Build urllib opener with configured handlers."""
        handlers = [HTTPCookieProcessor(self._session_cookies)]
        if self.proxy:
            proxy_handler = ProxyHandler({
                "http": self.proxy,
                "https": self.proxy,
            })
            handlers.append(proxy_handler)
        if not self.verify_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(HTTPSHandler(context=ctx))
        return build_opener(*handlers)

    def _prepare_headers(self, extra_headers: Dict[str, str] = None) -> Dict[str, str]:
        """Merge default headers with extra headers."""
        headers = dict(self._default_headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: bytes = None,
        headers: Dict[str, str] = None,
    ) -> HTTPResponse:
        """Execute a single HTTP request with retry logic."""
        if self.rate_limiter:
            self.rate_limiter.wait()

        merged_headers = self._prepare_headers(headers)
        response = HTTPResponse(url=url)

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                req = Request(url, data=data, headers=merged_headers, method=method)
                opener = self._build_opener()

                resp = opener.open(req, timeout=self.timeout)
                response.status_code = resp.status
                response.headers = dict(resp.headers)
                response.body = resp.read().decode("utf-8", errors="replace")
                response.elapsed = time.time() - start_time
                response.content_length = len(response.body)
                response.url = resp.url

                if self.logger:
                    self.logger.log_request(method, url, merged_headers, data)
                    self.logger.log_response(response)

                return response

            except HTTPError as e:
                response.status_code = e.code
                response.headers = dict(e.headers) if e.headers else {}
                try:
                    response.body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    response.body = ""
                response.elapsed = time.time() - start_time
                response.content_length = len(response.body)

                if self.logger:
                    self.logger.log_request(method, url, merged_headers, data)
                    self.logger.log_response(response)

                return response

            except URLError as e:
                response.error = str(e.reason)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return response

            except Exception as e:
                response.error = str(e)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                return response

        return response

    def get(self, url: str, headers: Dict[str, str] = None) -> HTTPResponse:
        """Send a GET request."""
        return self._make_request(url, method="GET", headers=headers)

    def post(self, url: str, data: Any = None, headers: Dict[str, str] = None) -> HTTPResponse:
        """Send a POST request."""
        if isinstance(data, dict):
            data = urlencode(data).encode("utf-8")
            if headers is None:
                headers = {}
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        return self._make_request(url, method="POST", data=data, headers=headers)

    def head(self, url: str, headers: Dict[str, str] = None) -> HTTPResponse:
        """Send a HEAD request."""
        return self._make_request(url, method="HEAD", headers=headers)

    def options(self, url: str, headers: Dict[str, str] = None) -> HTTPResponse:
        """Send an OPTIONS request."""
        return self._make_request(url, method="OPTIONS", headers=headers)

    def set_proxy(self, proxy: str):
        """Update the proxy URL."""
        self.proxy = proxy

    def set_cookies(self, cookies: Dict[str, str]):
        """Update the cookie jar."""
        self.cookies.update(cookies)

    def clear_cookies(self):
        """Clear all cookies."""
        self.cookies.clear()
        self._session_cookies.clear()



# =============================================================================
# DNS RESOLVER CLASS
# =============================================================================

class DNSResolver:
    """
    DNS resolution utility supporting multiple record types,
    zone transfer attempts, reverse DNS, and batch resolution.
    """

    # DNS record type constants
    TYPE_A = 1
    TYPE_NS = 2
    TYPE_CNAME = 5
    TYPE_SOA = 6
    TYPE_MX = 15
    TYPE_TXT = 16
    TYPE_AAAA = 28
    TYPE_SRV = 33

    def __init__(self, nameserver: str = None, timeout: int = 5):
        """
        Initialize the DNS resolver.

        Args:
            nameserver: Custom DNS server to query.
            timeout: Query timeout in seconds.
        """
        self.nameserver = nameserver or "8.8.8.8"
        self.timeout = timeout

    def resolve(self, domain: str, record_type: str = "A") -> List[str]:
        """
        Resolve a domain name to the specified record type.

        Args:
            domain: The domain to resolve.
            record_type: DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA).

        Returns:
            List of resolved values.
        """
        results = []
        try:
            if record_type.upper() == "A":
                answers = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                results = list(set(addr[4][0] for addr in answers))
            elif record_type.upper() == "AAAA":
                try:
                    answers = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
                    results = list(set(addr[4][0] for addr in answers))
                except socket.gaierror:
                    pass
            elif record_type.upper() == "CNAME":
                try:
                    cname = socket.getfqdn(domain)
                    if cname != domain:
                        results = [cname]
                except Exception:
                    pass
            elif record_type.upper() in ("MX", "TXT", "NS", "SOA", "SRV"):
                # For advanced record types, attempt raw DNS query
                results = self._raw_dns_query(domain, record_type.upper())
            else:
                # Fallback to A record
                answers = socket.getaddrinfo(domain, None, socket.AF_INET)
                results = list(set(addr[4][0] for addr in answers))
        except socket.gaierror as e:
            pass
        except Exception as e:
            pass
        return results

    def _raw_dns_query(self, domain: str, record_type: str) -> List[str]:
        """
        Perform a raw DNS query using UDP socket.

        Args:
            domain: Domain to query.
            record_type: Record type string.

        Returns:
            List of results (simplified parsing).
        """
        type_map = {
            "A": 1, "NS": 2, "CNAME": 5, "SOA": 6,
            "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
        }
        qtype = type_map.get(record_type, 1)

        # Build DNS query packet
        transaction_id = os.urandom(2)
        flags = b"\x01\x00"  # Standard query with recursion desired
        questions = b"\x00\x01"
        answer_rrs = b"\x00\x00"
        authority_rrs = b"\x00\x00"
        additional_rrs = b"\x00\x00"

        # Encode domain name
        qname = b""
        for part in domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        qtype_bytes = struct.pack("!H", qtype)
        qclass = b"\x00\x01"  # IN class

        packet = (
            transaction_id + flags + questions + answer_rrs +
            authority_rrs + additional_rrs + qname + qtype_bytes + qclass
        )

        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (self.nameserver, 53))
            response, _ = sock.recvfrom(4096)
            sock.close()

            # Parse response (simplified)
            if len(response) > 12:
                answer_count = struct.unpack("!H", response[6:8])[0]
                if answer_count > 0:
                    # Skip the question section
                    offset = 12
                    # Skip QNAME
                    while offset < len(response) and response[offset] != 0:
                        if response[offset] & 0xC0 == 0xC0:
                            offset += 2
                            break
                        offset += response[offset] + 1
                    else:
                        offset += 1
                    offset += 4  # Skip QTYPE and QCLASS

                    # Parse answers
                    for _ in range(min(answer_count, 20)):
                        if offset >= len(response):
                            break
                        # Skip name (could be pointer)
                        if offset < len(response) and response[offset] & 0xC0 == 0xC0:
                            offset += 2
                        else:
                            while offset < len(response) and response[offset] != 0:
                                offset += response[offset] + 1
                            offset += 1

                        if offset + 10 > len(response):
                            break

                        rtype = struct.unpack("!H", response[offset:offset + 2])[0]
                        offset += 2
                        offset += 2  # Skip class
                        offset += 4  # Skip TTL
                        rdlength = struct.unpack("!H", response[offset:offset + 2])[0]
                        offset += 2

                        if offset + rdlength > len(response):
                            break

                        rdata = response[offset:offset + rdlength]
                        offset += rdlength

                        if rtype == 1 and rdlength == 4:  # A record
                            ip = ".".join(str(b) for b in rdata)
                            results.append(ip)
                        elif rtype == 28 and rdlength == 16:  # AAAA record
                            ip = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
                            results.append(ip)
                        elif rtype == 15:  # MX record
                            priority = struct.unpack("!H", rdata[:2])[0]
                            mx_name = self._parse_dns_name(response, offset - rdlength + 2)
                            results.append(f"{priority} {mx_name}")
                        elif rtype == 16:  # TXT record
                            txt_len = rdata[0]
                            txt = rdata[1:1 + txt_len].decode("utf-8", errors="replace")
                            results.append(txt)
                        elif rtype in (2, 5):  # NS or CNAME
                            name = self._parse_dns_name(response, offset - rdlength)
                            results.append(name)

        except socket.timeout:
            pass
        except Exception:
            pass

        return results

    def _parse_dns_name(self, data: bytes, offset: int) -> str:
        """Parse a DNS name from response data with pointer handling."""
        parts = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)

            length = data[offset]
            if length == 0:
                break
            elif length & 0xC0 == 0xC0:
                # Pointer
                pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
                offset = pointer
            else:
                offset += 1
                part = data[offset:offset + length].decode("utf-8", errors="replace")
                parts.append(part)
                offset += length

        return ".".join(parts)

    def resolve_all(self, domain: str) -> Dict[str, List[str]]:
        """
        Resolve all common record types for a domain.

        Args:
            domain: The domain to resolve.

        Returns:
            Dictionary mapping record types to their values.
        """
        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        results = {}
        for rtype in record_types:
            records = self.resolve(domain, rtype)
            if records:
                results[rtype] = records
        return results

    def reverse_dns(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address to look up.

        Returns:
            Hostname if found, None otherwise.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def zone_transfer(self, domain: str, nameserver: str = None) -> List[str]:
        """
        Attempt a DNS zone transfer (AXFR).

        Args:
            domain: Target domain.
            nameserver: NS to attempt transfer from.

        Returns:
            List of discovered records (empty if transfer denied).
        """
        ns = nameserver or self.nameserver
        results = []

        try:
            # Build AXFR query
            transaction_id = os.urandom(2)
            flags = b"\x00\x00"
            questions = b"\x00\x01"
            answer_rrs = b"\x00\x00"
            authority_rrs = b"\x00\x00"
            additional_rrs = b"\x00\x00"

            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"

            qtype = struct.pack("!H", 252)  # AXFR
            qclass = b"\x00\x01"

            query = (
                transaction_id + flags + questions + answer_rrs +
                authority_rrs + additional_rrs + qname + qtype + qclass
            )

            # AXFR uses TCP
            length = struct.pack("!H", len(query))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ns, 53))
            sock.send(length + query)

            # Read response
            data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            sock.close()

            if len(data) > 4:
                # Simplified parsing - look for readable strings
                # In practice, full AXFR parsing would be more complex
                answer_count = struct.unpack("!H", data[8:10])[0] if len(data) > 10 else 0
                if answer_count > 0:
                    results.append(f"Zone transfer possible for {domain} from {ns}")

        except (socket.error, socket.timeout, ConnectionRefusedError):
            pass
        except Exception:
            pass

        return results

    def batch_resolve(self, domains: List[str], record_type: str = "A", max_threads: int = 10) -> Dict[str, List[str]]:
        """
        Resolve multiple domains concurrently.

        Args:
            domains: List of domains to resolve.
            record_type: DNS record type to query.
            max_threads: Maximum concurrent threads.

        Returns:
            Dictionary mapping domains to their resolved values.
        """
        results = {}

        def _resolve_single(domain):
            records = self.resolve(domain, record_type)
            return domain, records

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(_resolve_single, d): d for d in domains}
            for future in as_completed(futures):
                try:
                    domain, records = future.result()
                    if records:
                        results[domain] = records
                except Exception:
                    pass

        return results



# =============================================================================
# FILE MANAGER CLASS
# =============================================================================

class FileManager:
    """
    Handles file I/O operations with atomic writes, directory management,
    and support for multiple output formats (JSON, text, HTML, CSV).
    """

    def __init__(self, output_dir: str = "monster_output"):
        """
        Initialize the FileManager.

        Args:
            output_dir: Base directory for output files.
        """
        self.output_dir = Path(output_dir)
        self.ensure_dir(self.output_dir)

    def ensure_dir(self, path: Path):
        """Create directory if it does not exist."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

    def save_json(self, data: Any, filename: str, subdir: str = "") -> Path:
        """
        Save data as a JSON file with atomic write.

        Args:
            data: Data to serialize.
            filename: Output filename.
            subdir: Optional subdirectory within output_dir.

        Returns:
            Path to the saved file.
        """
        target_dir = self.output_dir / subdir if subdir else self.output_dir
        self.ensure_dir(target_dir)
        filepath = target_dir / filename

        # Atomic write using temp file
        temp_fd, temp_path = tempfile.mkstemp(dir=str(target_dir), suffix=".tmp")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            os.replace(temp_path, str(filepath))
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        return filepath

    def save_text(self, content: str, filename: str, subdir: str = "") -> Path:
        """
        Save text content to a file with atomic write.

        Args:
            content: Text content to save.
            filename: Output filename.
            subdir: Optional subdirectory.

        Returns:
            Path to the saved file.
        """
        target_dir = self.output_dir / subdir if subdir else self.output_dir
        self.ensure_dir(target_dir)
        filepath = target_dir / filename

        temp_fd, temp_path = tempfile.mkstemp(dir=str(target_dir), suffix=".tmp")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temp_path, str(filepath))
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        return filepath

    def save_html(self, content: str, filename: str, subdir: str = "") -> Path:
        """
        Save HTML content to a file.

        Args:
            content: HTML content to save.
            filename: Output filename (should end with .html).
            subdir: Optional subdirectory.

        Returns:
            Path to the saved file.
        """
        if not filename.endswith(".html"):
            filename += ".html"
        return self.save_text(content, filename, subdir)

    def save_csv(self, headers: List[str], rows: List[List[Any]], filename: str, subdir: str = "") -> Path:
        """
        Save data as a CSV file.

        Args:
            headers: Column headers.
            rows: List of row data.
            filename: Output filename.
            subdir: Optional subdirectory.

        Returns:
            Path to the saved file.
        """
        target_dir = self.output_dir / subdir if subdir else self.output_dir
        self.ensure_dir(target_dir)
        filepath = target_dir / filename

        if not filename.endswith(".csv"):
            filepath = target_dir / (filename + ".csv")

        temp_fd, temp_path = tempfile.mkstemp(dir=str(target_dir), suffix=".tmp")
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            os.replace(temp_path, str(filepath))
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        return filepath

    def append_text(self, content: str, filename: str, subdir: str = "") -> Path:
        """Append text to an existing file or create it."""
        target_dir = self.output_dir / subdir if subdir else self.output_dir
        self.ensure_dir(target_dir)
        filepath = target_dir / filename

        with open(filepath, "a", encoding="utf-8") as f:
            f.write(content)

        return filepath

    def read_json(self, filepath: str) -> Any:
        """Read and parse a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def read_text(self, filepath: str) -> str:
        """Read a text file."""
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

    def list_files(self, subdir: str = "", pattern: str = "*") -> List[Path]:
        """List files in the output directory matching a pattern."""
        target_dir = self.output_dir / subdir if subdir else self.output_dir
        if target_dir.exists():
            return list(target_dir.glob(pattern))
        return []


# =============================================================================
# PROXY MANAGER CLASS
# =============================================================================

class ProxyManager:
    """
    Manages a pool of proxy servers with rotation and connectivity testing.
    """

    def __init__(self, proxy_file: str = None):
        """
        Initialize the ProxyManager.

        Args:
            proxy_file: Path to a file containing proxy URLs (one per line).
        """
        self.proxies: List[str] = []
        self.working_proxies: List[str] = []
        self.current_index = 0
        self._lock = threading.Lock()

        if proxy_file:
            self.load_from_file(proxy_file)

    def load_from_file(self, filepath: str):
        """
        Load proxies from a file.

        Args:
            filepath: Path to proxy list file.
        """
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Normalize proxy format
                        if not line.startswith(("http://", "https://", "socks")):
                            line = f"http://{line}"
                        self.proxies.append(line)
        except (IOError, OSError) as e:
            pass

    def add_proxy(self, proxy: str):
        """Add a proxy to the pool."""
        if not proxy.startswith(("http://", "https://", "socks")):
            proxy = f"http://{proxy}"
        self.proxies.append(proxy)

    def rotate(self) -> Optional[str]:
        """
        Get the next proxy in rotation.

        Returns:
            Next proxy URL or None if pool is empty.
        """
        with self._lock:
            pool = self.working_proxies if self.working_proxies else self.proxies
            if not pool:
                return None
            proxy = pool[self.current_index % len(pool)]
            self.current_index += 1
            return proxy

    def test_connectivity(self, test_url: str = "http://httpbin.org/ip", timeout: int = 10) -> List[str]:
        """
        Test all proxies for connectivity.

        Args:
            test_url: URL to test against.
            timeout: Connection timeout.

        Returns:
            List of working proxies.
        """
        self.working_proxies = []

        def _test_proxy(proxy):
            try:
                proxy_handler = ProxyHandler({
                    "http": proxy,
                    "https": proxy,
                })
                opener = build_opener(proxy_handler)
                req = Request(test_url)
                resp = opener.open(req, timeout=timeout)
                if resp.status == 200:
                    return proxy
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(_test_proxy, p): p for p in self.proxies}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.working_proxies.append(result)

        return self.working_proxies

    def remove_proxy(self, proxy: str):
        """Remove a proxy from the pool."""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)

    @property
    def count(self) -> int:
        """Return total number of proxies."""
        return len(self.proxies)

    @property
    def working_count(self) -> int:
        """Return number of working proxies."""
        return len(self.working_proxies)


# =============================================================================
# REQUEST LOGGER CLASS
# =============================================================================

class RequestLogger:
    """Logs HTTP requests and responses to a file for debugging and analysis."""

    def __init__(self, log_file: str = "monster_requests.log", enabled: bool = True):
        """
        Initialize the RequestLogger.

        Args:
            log_file: Path to the log file.
            enabled: Whether logging is active.
        """
        self.log_file = Path(log_file)
        self.enabled = enabled
        self._lock = threading.Lock()

        if self.enabled:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_request(self, method: str, url: str, headers: Dict[str, str], body: bytes = None):
        """Log an outgoing HTTP request."""
        if not self.enabled:
            return

        with self._lock:
            timestamp = datetime.now().isoformat()
            entry = f"\n{'=' * 60}\n"
            entry += f"[{timestamp}] REQUEST\n"
            entry += f"{method} {url}\n"
            entry += f"Headers:\n"
            for key, value in headers.items():
                entry += f"  {key}: {value}\n"
            if body:
                try:
                    body_str = body.decode("utf-8")[:500]
                    entry += f"Body: {body_str}\n"
                except Exception:
                    entry += f"Body: <binary data, {len(body)} bytes>\n"

            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(entry)
            except IOError:
                pass

    def log_response(self, response: "HTTPResponse"):
        """Log an HTTP response."""
        if not self.enabled:
            return

        with self._lock:
            timestamp = datetime.now().isoformat()
            entry = f"\n[{timestamp}] RESPONSE\n"
            entry += f"Status: {response.status_code}\n"
            entry += f"URL: {response.url}\n"
            entry += f"Elapsed: {response.elapsed:.3f}s\n"
            entry += f"Headers:\n"
            for key, value in response.headers.items():
                entry += f"  {key}: {value}\n"
            if response.body:
                body_preview = response.body[:500]
                entry += f"Body preview: {body_preview}\n"
            if response.error:
                entry += f"Error: {response.error}\n"
            entry += f"{'=' * 60}\n"

            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(entry)
            except IOError:
                pass

    def clear(self):
        """Clear the log file."""
        if self.log_file.exists():
            self.log_file.unlink()



# =============================================================================
# URL HELPER FUNCTIONS
# =============================================================================

def domain_from_url(url: str) -> str:
    """
    Extract the domain from a URL.

    Args:
        url: The URL to parse.

    Returns:
        Domain string.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


def normalize_url(url: str) -> str:
    """
    Normalize a URL by standardizing scheme, removing fragments,
    sorting query parameters, and removing tracking parameters.

    Args:
        url: URL to normalize.

    Returns:
        Normalized URL string.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Remove fragment
    # Sort query params and remove tracking
    tracking_params = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "msclkid", "ref", "source", "mc_cid", "mc_eid",
    }
    params = parse_qsl(parsed.query)
    filtered_params = [(k, v) for k, v in params if k.lower() not in tracking_params]
    filtered_params.sort()
    query = urlencode(filtered_params)

    # Normalize path
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    return urlunparse((scheme, netloc, path, "", query, ""))


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.

    Args:
        domain: String to validate.

    Returns:
        True if valid domain, False otherwise.
    """
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot
    if domain.endswith("."):
        domain = domain[:-1]

    # Check each label
    labels = domain.split(".")
    if len(labels) < 2:
        return False

    pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not pattern.match(label):
            return False

    return True


def is_ip(address: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).

    Args:
        address: String to check.

    Returns:
        True if valid IP, False otherwise.
    """
    # Try IPv4
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except (socket.error, OSError):
        pass

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except (socket.error, OSError):
        pass

    return False


def extract_domain(url_or_domain: str) -> str:
    """
    Extract the base domain from a URL or domain string.
    Handles URLs, domains, and subdomains.

    Args:
        url_or_domain: Input string.

    Returns:
        Extracted domain.
    """
    # If it looks like a URL, parse it
    if "://" in url_or_domain:
        parsed = urlparse(url_or_domain)
        host = parsed.netloc.split(":")[0]
    else:
        host = url_or_domain.split(":")[0].split("/")[0]

    return host.lower().strip(".")


def url_dedup(urls: List[str]) -> List[str]:
    """
    Deduplicate a list of URLs using normalization.
    Removes tracking parameters and normalizes before comparing.

    Args:
        urls: List of URLs to deduplicate.

    Returns:
        Deduplicated list of URLs.
    """
    seen: Set[str] = set()
    unique: List[str] = []

    for url in urls:
        normalized = normalize_url(url)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(url)

    return unique


def extract_params_from_url(url: str) -> Dict[str, List[str]]:
    """
    Extract query parameters from a URL.

    Args:
        url: URL to parse.

    Returns:
        Dictionary of parameter names to their values.
    """
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def safe_filename(name: str, max_length: int = 200) -> str:
    """
    Convert a string to a safe filename.

    Args:
        name: String to convert.
        max_length: Maximum filename length.

    Returns:
        Safe filename string.
    """
    # Replace unsafe characters
    safe = re.sub(r'[<>:"/\|?*\x00-\x1f]', '_', name)
    # Replace multiple underscores
    safe = re.sub(r'_+', '_', safe)
    # Trim
    safe = safe.strip('. _')
    # Limit length
    if len(safe) > max_length:
        safe = safe[:max_length]
    # Fallback
    if not safe:
        safe = "unnamed"
    return safe


# =============================================================================
# ENCODING UTILITIES
# =============================================================================

def base64_encode(data: str) -> str:
    """Base64 encode a string."""
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def base64_decode(data: str) -> str:
    """Base64 decode a string."""
    # Handle URL-safe base64
    data = data.replace("-", "+").replace("_", "/")
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data).decode("utf-8", errors="replace")


def url_encode(data: str) -> str:
    """URL encode a string."""
    return quote(data, safe="")


def url_decode(data: str) -> str:
    """URL decode a string."""
    return unquote(data)


def html_entity_encode(data: str) -> str:
    """HTML entity encode a string."""
    return html_escape(data, quote=True)


def html_entity_decode(data: str) -> str:
    """HTML entity decode a string."""
    return html_unescape(data)


def hex_encode(data: str) -> str:
    """Hex encode a string."""
    return data.encode("utf-8").hex()


def hex_decode(data: str) -> str:
    """Hex decode a string."""
    return bytes.fromhex(data).decode("utf-8", errors="replace")


# =============================================================================
# HASH UTILITIES
# =============================================================================

def md5(data: str) -> str:
    """Calculate MD5 hash of a string."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def sha1(data: str) -> str:
    """Calculate SHA1 hash of a string."""
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def sha256(data: str) -> str:
    """Calculate SHA256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha512(data: str) -> str:
    """Calculate SHA512 hash of a string."""
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


def md5_file(filepath: str) -> str:
    """Calculate MD5 hash of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1_file(filepath: str) -> str:
    """Calculate SHA1 hash of a file."""
    h = hashlib.sha1()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(filepath: str) -> str:
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha512_file(filepath: str) -> str:
    """Calculate SHA512 hash of a file."""
    h = hashlib.sha512()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
# NETWORK UTILITIES
# =============================================================================

def get_local_ip() -> str:
    """
    Get the local IP address of this machine.

    Returns:
        Local IP address string.
    """
    try:
        # Connect to a public DNS to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_network_interfaces() -> List[Dict[str, str]]:
    """
    Detect network interfaces on the system.

    Returns:
        List of dictionaries with interface information.
    """
    interfaces = []
    try:
        # Get all addresses
        hostname = socket.gethostname()
        addrs = socket.getaddrinfo(hostname, None)
        seen = set()
        for addr in addrs:
            ip = addr[4][0]
            family = "IPv4" if addr[0] == socket.AF_INET else "IPv6"
            key = f"{family}:{ip}"
            if key not in seen:
                seen.add(key)
                interfaces.append({
                    "address": ip,
                    "family": family,
                    "hostname": hostname,
                })
    except Exception:
        pass

    # Always include loopback
    interfaces.append({
        "address": "127.0.0.1",
        "family": "IPv4",
        "hostname": "localhost",
    })

    return interfaces

