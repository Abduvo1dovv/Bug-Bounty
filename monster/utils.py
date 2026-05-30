"""
Monster - Shared utilities.

HTTP client, DNS resolver, colored output, file management, rate limiting,
and common helper functions.
"""

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from monster.config import DEFAULT_USER_AGENT, RATE_LIMIT_DELAY, TIMEOUT

# ---------------------------------------------------------------------------
# Color Constants (following apk_analyzer pattern)
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    C_RED = Fore.RED
    C_YEL = Fore.YELLOW
    C_GRN = Fore.GREEN
    C_CYN = Fore.CYAN
    C_MAG = Fore.MAGENTA
    C_WHT = Fore.WHITE
    C_RST = Style.RESET_ALL
    C_BLD = Style.BRIGHT
except Exception:
    C_RED = C_YEL = C_GRN = C_CYN = C_MAG = C_WHT = C_RST = C_BLD = ""


# ---------------------------------------------------------------------------
# ColorOutput - Formatted terminal output
# ---------------------------------------------------------------------------

class ColorOutput:
    """Provides colored, prefixed terminal output for Monster toolkit."""

    BANNER = r"""
  __  __  ___  _  _ ___ _____ ___ ___
 |  \/  |/ _ \| \| / __|_   _| __| _ \
 | |\/| | (_) | .` \__ \ | | | _||   /
 |_|  |_|\___/|_|\_|___/ |_| |___|_|_\
    Bug Bounty Recon & Vuln Scanner v1.0
"""

    @staticmethod
    def banner():
        """Print the Monster banner."""
        print(f"{C_CYN}{C_BLD}{ColorOutput.BANNER}{C_RST}")

    @staticmethod
    def info(msg):
        """Print informational message."""
        print(f"{C_CYN}[MONSTER]{C_RST} {msg}")

    @staticmethod
    def success(msg):
        """Print success message."""
        print(f"{C_GRN}[+]{C_RST} {msg}")

    @staticmethod
    def warning(msg):
        """Print warning message."""
        print(f"{C_YEL}[!]{C_RST} {msg}")

    @staticmethod
    def error(msg):
        """Print error message."""
        print(f"{C_RED}[-]{C_RST} {msg}")

    @staticmethod
    def critical(msg):
        """Print critical message."""
        print(f"{C_RED}{C_BLD}[!!]{C_RST} {msg}")

    @staticmethod
    def finding(severity, msg):
        """Print a finding with severity-based coloring."""
        colors = {
            "critical": C_RED + C_BLD,
            "high": C_RED,
            "medium": C_YEL,
            "low": C_CYN,
            "info": C_WHT,
        }
        color = colors.get(severity.lower(), C_WHT)
        print(f"{color}[*]{C_RST} [{severity.upper()}] {msg}")

    @staticmethod
    def progress(current, total, msg=""):
        """Print progress indicator."""
        pct = (current / total * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "#" * filled + "-" * (bar_len - filled)
        sys.stdout.write(
            f"\r{C_CYN}[MONSTER]{C_RST} [{bar}] {pct:.0f}% ({current}/{total}) {msg}"
        )
        if current >= total:
            sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# RateLimiter - Thread-safe rate limiting
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe rate limiter using simple delay between requests."""

    def __init__(self, delay=RATE_LIMIT_DELAY):
        self._delay = delay
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self):
        """Block until rate limit delay has passed since last call."""
        with self._lock:
            elapsed = time.time() - self._last_call
            if elapsed < self._delay:
                time.sleep(self._delay - elapsed)
            self._last_call = time.time()


# ---------------------------------------------------------------------------
# HTTPClient - urllib-based HTTP client with rate limiting
# ---------------------------------------------------------------------------

class HTTPClient:
    """HTTP client with rate limiting, timeout, and error handling."""

    def __init__(self, user_agent=None, timeout=None, rate_limit=None,
                 verify_ssl=True):
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.timeout = timeout or TIMEOUT
        self.rate_limit = rate_limit or RATE_LIMIT_DELAY
        self.verify_ssl = verify_ssl
        self._limiter = RateLimiter(self.rate_limit)

        # SSL context
        if verify_ssl:
            self._ssl_context = ssl.create_default_context()
        else:
            self._ssl_context = ssl._create_unverified_context()

    def get(self, url, headers=None):
        """
        Perform an HTTP GET request.

        Args:
            url: The URL to request.
            headers: Optional dict of additional headers.

        Returns:
            Tuple of (status_code, headers_dict, body) on success,
            or None on failure.
        """
        self._limiter.wait()

        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        try:
            req = urllib.request.Request(url, headers=req_headers, method="GET")

            # Build opener that does NOT follow redirects automatically
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(
                NoRedirectHandler,
                urllib.request.HTTPSHandler(context=self._ssl_context),
            )

            response = opener.open(req, timeout=self.timeout)
            status_code = response.getcode()
            resp_headers = dict(response.headers)
            body = response.read().decode("utf-8", errors="replace")
            return (status_code, resp_headers, body)

        except urllib.error.HTTPError as e:
            status_code = e.code
            resp_headers = dict(e.headers) if e.headers else {}
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return (status_code, resp_headers, body)

        except urllib.error.URLError as e:
            reason = str(e.reason) if hasattr(e, "reason") else str(e)
            ColorOutput.warning(f"Connection error for {url}: {reason}")
            return None

        except socket.timeout:
            ColorOutput.warning(f"Timeout for {url}")
            return None

        except ssl.SSLError as e:
            ColorOutput.warning(f"SSL error for {url}: {e}")
            return None

        except OSError as e:
            ColorOutput.warning(f"Network error for {url}: {e}")
            return None

        except Exception as e:
            ColorOutput.warning(f"Unexpected error for {url}: {e}")
            return None


# ---------------------------------------------------------------------------
# DNSResolver - DNS resolution via socket and subprocess fallback
# ---------------------------------------------------------------------------

class DNSResolver:
    """DNS resolver using socket.getaddrinfo and subprocess fallback."""

    @staticmethod
    def resolve(domain, record_type="A"):
        """
        Resolve a domain for the given record type.

        Args:
            domain: The domain name to resolve.
            record_type: DNS record type (A, AAAA, CNAME, MX, TXT, NS).

        Returns:
            List of resolved values, or empty list on failure.
        """
        record_type = record_type.upper()

        # Use socket for A/AAAA records
        if record_type in ("A", "AAAA"):
            family = socket.AF_INET if record_type == "A" else socket.AF_INET6
            try:
                results = socket.getaddrinfo(domain, None, family)
                return list(set(r[4][0] for r in results))
            except (socket.gaierror, OSError):
                return []

        # For other record types, use subprocess
        return DNSResolver._subprocess_resolve(domain, record_type)

    @staticmethod
    def _subprocess_resolve(domain, record_type):
        """Resolve using dig (preferred) or nslookup (fallback)."""
        # Try dig first
        try:
            result = subprocess.run(
                ["dig", "+short", record_type, domain],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = [
                    line.strip()
                    for line in result.stdout.strip().split("\n")
                    if line.strip() and not line.startswith(";")
                ]
                return lines
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Fallback to nslookup
        try:
            result = subprocess.run(
                ["nslookup", f"-type={record_type}", domain],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                lines = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "=" in line and "server" not in line.lower():
                        value = line.split("=")[-1].strip()
                        if value:
                            lines.append(value)
                return lines
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return []

    @staticmethod
    def get_all_records(domain):
        """
        Get all common DNS record types for a domain.

        Returns:
            Dict mapping record type to list of values.
        """
        records = {}
        for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
            result = DNSResolver.resolve(domain, rtype)
            if result:
                records[rtype] = result
        return records


# ---------------------------------------------------------------------------
# FileManager - Output file management
# ---------------------------------------------------------------------------

class FileManager:
    """Manages output directory and file writing with atomic support."""

    def __init__(self, output_dir):
        self.output_dir = output_dir

    def ensure_dir(self):
        """Create the output directory if it does not exist."""
        os.makedirs(self.output_dir, exist_ok=True)

    def save_json(self, data, filename):
        """Save data as a JSON file."""
        self.ensure_dir()
        filepath = os.path.join(self.output_dir, filename)
        self._atomic_write(filepath, json.dumps(data, indent=2, default=str))
        return filepath

    def save_text(self, content, filename):
        """Save content as a text file."""
        self.ensure_dir()
        filepath = os.path.join(self.output_dir, filename)
        self._atomic_write(filepath, content)
        return filepath

    def save_html(self, content, filename):
        """Save content as an HTML file."""
        self.ensure_dir()
        filepath = os.path.join(self.output_dir, filename)
        self._atomic_write(filepath, content)
        return filepath

    @staticmethod
    def _atomic_write(filepath, content):
        """Write content to file atomically using a temp file and rename."""
        dirpath = os.path.dirname(filepath)
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix=".monster_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)
                os.replace(tmp_path, filepath)
            except Exception:
                os.unlink(tmp_path)
                raise
        except OSError:
            # Fallback to direct write if atomic write fails
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def domain_from_url(url):
    """Extract domain from a URL string."""
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def is_ip(string):
    """Check if a string is an IP address (IPv4 or IPv6)."""
    try:
        socket.inet_pton(socket.AF_INET, string)
        return True
    except (socket.error, OSError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, string)
        return True
    except (socket.error, OSError):
        pass
    return False


def normalize_url(url):
    """Normalize a URL by adding scheme if missing and removing trailing slash."""
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url):
    """Extract the domain (hostname) from a URL."""
    return domain_from_url(url)


def is_valid_domain(domain):
    """Validate that a string looks like a valid domain name."""
    if not domain or len(domain) > 253:
        return False
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    return bool(pattern.match(domain))


def safe_filename(string):
    """Convert a string to a safe filename."""
    safe = re.sub(r"[^\w\-.]", "_", string)
    return safe[:200] if safe else "unnamed"
