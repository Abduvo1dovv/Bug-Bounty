"""
Super Monster v2 - HTTP Utilities

Shared HTTP request helper and SSL context used by both SmartScanner
and Verifier. Centralizes request logic to avoid duplication.
"""

import random
import socket
import ssl
import sys
import urllib.request
import urllib.error

from .config import REQUEST_TIMEOUT, USER_AGENTS


def create_ssl_context(insecure: bool = True) -> ssl.SSLContext:
    """
    Create an SSL context for HTTPS requests.

    Args:
        insecure: If True, disables certificate verification (default for
                  bug bounty scanning of external targets). If False, uses
                  the system default certificate verification.

    Returns:
        Configured ssl.SSLContext instance.
    """
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_request(
    url: str,
    headers: dict = None,
    method: str = "GET",
    timeout: int = None,
    data: bytes = None,
    ssl_context: ssl.SSLContext = None,
) -> tuple:
    """
    Make an HTTP request using urllib.

    This is the shared request helper used by both SmartScanner and Verifier.

    Args:
        url: The URL to request.
        headers: Optional dict of HTTP headers.
        method: HTTP method (GET, POST, etc.).
        timeout: Request timeout in seconds (defaults to REQUEST_TIMEOUT).
        data: Optional request body bytes (for POST).
        ssl_context: Optional SSL context. If None, creates an insecure one.

    Returns:
        Tuple of (status_code, response_headers_dict, body_str).
        Returns (0, {}, "") on any error.
    """
    if timeout is None:
        timeout = REQUEST_TIMEOUT

    if headers is None:
        headers = {}

    if "User-Agent" not in headers:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    if ssl_context is None:
        ssl_context = create_ssl_context(insecure=True)

    try:
        req = urllib.request.Request(
            url, headers=headers, method=method, data=data
        )
        response = urllib.request.urlopen(
            req, timeout=timeout, context=ssl_context
        )
        status_code = response.getcode()
        resp_headers = dict(response.headers)
        body = response.read().decode("utf-8", errors="replace")
        return (status_code, resp_headers, body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return (e.code, dict(e.headers) if e.headers else {}, body)
    except (urllib.error.URLError, socket.timeout, OSError, Exception):
        return (0, {}, "")


def print_insecure_warning():
    """Print a warning message when running in insecure (no TLS verification) mode."""
    print(
        "[!] WARNING: TLS certificate verification is disabled (--insecure). "
        "Connections may be intercepted by MITM attacks.",
        file=sys.stderr,
    )
