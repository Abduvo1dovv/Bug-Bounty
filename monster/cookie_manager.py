"""
Monster v2.0.0 Cookie Manager Module

Comprehensive cookie management, session persistence, security analysis,
JWT decoding, and browser cookie extraction utilities for bug bounty
reconnaissance and security assessment.
"""

import os
import re
import sys
import json
import time
import base64
import hashlib
import platform
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urlencode, quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
from http.cookiejar import CookieJar as StdCookieJar

from monster.utils import ColorOutput, HTTPClient, FileManager, RateLimiter, normalize_url, domain_from_url
from monster.config import DEFAULT_USER_AGENT, TIMEOUT


# =============================================================================
# COOKIE DATA CONTAINER
# =============================================================================

@dataclass
class Cookie:
    """Represents a single HTTP cookie with all attributes."""
    name: str = ""
    value: str = ""
    domain: str = ""
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    expires: Optional[float] = None
    max_age: Optional[int] = None
    creation_time: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if this cookie has expired."""
        if self.expires is None:
            return False
        return time.time() > self.expires

    def is_session_cookie(self) -> bool:
        """Check if this is a session cookie (no expiry)."""
        return self.expires is None and self.max_age is None

    def matches_domain(self, target_domain: str) -> bool:
        """Check if this cookie matches the given domain."""
        if not self.domain:
            return False
        cookie_domain = self.domain.lower().lstrip(".")
        target = target_domain.lower().lstrip(".")
        if cookie_domain == target:
            return True
        if target.endswith("." + cookie_domain):
            return True
        return False

    def matches_path(self, target_path: str) -> bool:
        """Check if this cookie matches the given path."""
        if not self.path:
            return True
        return target_path.startswith(self.path)

    def to_dict(self) -> Dict[str, Any]:
        """Convert cookie to dictionary representation."""
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "expires": self.expires,
            "max_age": self.max_age,
            "creation_time": self.creation_time,
            "last_accessed": self.last_accessed,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Cookie":
        """Create a Cookie from a dictionary."""
        return cls(
            name=data.get("name", ""),
            value=data.get("value", ""),
            domain=data.get("domain", ""),
            path=data.get("path", "/"),
            secure=data.get("secure", False),
            httponly=data.get("httponly", False),
            samesite=data.get("samesite", ""),
            expires=data.get("expires"),
            max_age=data.get("max_age"),
            creation_time=data.get("creation_time", time.time()),
            last_accessed=data.get("last_accessed", time.time()),
        )

    def to_netscape_line(self) -> str:
        """Convert cookie to Netscape format line."""
        domain_flag = "TRUE" if self.domain.startswith(".") else "FALSE"
        secure_flag = "TRUE" if self.secure else "FALSE"
        exp = int(self.expires) if self.expires else 0
        return f"{self.domain}	{domain_flag}	{self.path}	{secure_flag}	{exp}	{self.name}	{self.value}"

    def __repr__(self) -> str:
        return f"Cookie(name={self.name!r}, domain={self.domain!r}, path={self.path!r})"


# =============================================================================
# COOKIE MANAGER CLASS
# =============================================================================

class CookieManager:
    """
    Main cookie management orchestrator.
    
    Handles loading, saving, querying, and manipulating HTTP cookies
    from various sources (Netscape format, JSON, browser exports).
    Provides domain-matching, expiry management, and iteration support.
    """

    def __init__(self, cookie_file: str = None, output_dir: str = None):
        """
        Initialize the CookieManager.

        Args:
            cookie_file: Optional path to a cookie file to load on init.
            output_dir: Optional output directory for saving cookies.
        """
        self._cookies: List[Cookie] = []
        self._output_dir = output_dir or "monster_output"
        self._file_manager = FileManager(self._output_dir)
        self._color = ColorOutput()

        if cookie_file:
            self._auto_load(cookie_file)

    def _auto_load(self, filepath: str):
        """Auto-detect format and load cookies from file."""
        filepath = str(filepath)
        if not os.path.isfile(filepath):
            self._color.warning(f"Cookie file not found: {filepath}")
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()

            if content.startswith("[") or content.startswith("{"):
                self.load_from_json(filepath)
            else:
                self.load_from_netscape(filepath)
        except Exception as e:
            self._color.error(f"Failed to auto-load cookies: {e}")

    def load_from_netscape(self, filepath: str) -> int:
        """
        Parse and load cookies from a Netscape/Mozilla format cookie file.

        The Netscape cookie format has tab-separated fields:
        domain, domain_flag, path, secure, expires, name, value

        Args:
            filepath: Path to the Netscape format cookie file.

        Returns:
            Number of cookies loaded.
        """
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split("\t")
                    if len(parts) < 7:
                        continue

                    domain = parts[0]
                    path = parts[2]
                    secure = parts[3].upper() == "TRUE"
                    try:
                        expires = float(parts[4]) if parts[4] != "0" else None
                    except (ValueError, IndexError):
                        expires = None
                    name = parts[5]
                    value = parts[6] if len(parts) > 6 else ""

                    cookie = Cookie(
                        name=name,
                        value=value,
                        domain=domain,
                        path=path,
                        secure=secure,
                        expires=expires,
                    )
                    self._cookies.append(cookie)
                    count += 1

            self._color.success(f"Loaded {count} cookies from Netscape file: {filepath}")
        except FileNotFoundError:
            self._color.error(f"Cookie file not found: {filepath}")
        except PermissionError:
            self._color.error(f"Permission denied reading: {filepath}")
        except Exception as e:
            self._color.error(f"Error loading Netscape cookies: {e}")

        return count

    def load_from_json(self, filepath: str) -> int:
        """
        Parse and load cookies from a JSON format file.

        Supports both array of cookie objects and single cookie object formats.
        Compatible with browser extension exports and EditThisCookie format.

        Args:
            filepath: Path to the JSON cookie file.

        Returns:
            Number of cookies loaded.
        """
        count = 0
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                data = [data]

            if not isinstance(data, list):
                self._color.error(f"Invalid JSON cookie format in: {filepath}")
                return 0

            for item in data:
                if not isinstance(item, dict):
                    continue

                cookie = Cookie(
                    name=item.get("name", item.get("Name", "")),
                    value=item.get("value", item.get("Value", "")),
                    domain=item.get("domain", item.get("Domain", "")),
                    path=item.get("path", item.get("Path", "/")),
                    secure=item.get("secure", item.get("Secure", False)),
                    httponly=item.get("httponly", item.get("httpOnly", item.get("HttpOnly", False))),
                    samesite=item.get("samesite", item.get("sameSite", item.get("SameSite", ""))),
                    expires=item.get("expires", item.get("expirationDate", item.get("Expires", None))),
                )
                self._cookies.append(cookie)
                count += 1

            self._color.success(f"Loaded {count} cookies from JSON file: {filepath}")
        except json.JSONDecodeError as e:
            self._color.error(f"Invalid JSON in cookie file: {e}")
        except FileNotFoundError:
            self._color.error(f"Cookie file not found: {filepath}")
        except Exception as e:
            self._color.error(f"Error loading JSON cookies: {e}")

        return count

    def save_to_file(self, filepath: str = None, format: str = "json") -> bool:
        """
        Save all cookies to a file in the specified format.

        Args:
            filepath: Output file path. If None, uses default output dir.
            format: Output format - 'json' or 'netscape'.

        Returns:
            True if saved successfully, False otherwise.
        """
        if not filepath:
            ext = ".json" if format == "json" else ".txt"
            filepath = os.path.join(self._output_dir, f"cookies{ext}")

        try:
            os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)

            if format == "json":
                data = [c.to_dict() for c in self._cookies]
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            elif format == "netscape":
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("# Netscape HTTP Cookie File\n")
                    f.write("# Generated by Monster v2.0.0\n")
                    f.write(f"# Date: {datetime.now().isoformat()}\n\n")
                    for cookie in self._cookies:
                        f.write(cookie.to_netscape_line() + "\n")
            else:
                self._color.error(f"Unsupported format: {format}")
                return False

            self._color.success(f"Saved {len(self._cookies)} cookies to: {filepath}")
            return True
        except Exception as e:
            self._color.error(f"Error saving cookies: {e}")
            return False

    def get_cookies_for_domain(self, domain: str) -> List[Cookie]:
        """
        Return all cookies that match the given domain.

        Performs subdomain matching: cookies for .example.com
        will match sub.example.com.

        Args:
            domain: The domain to match cookies against.

        Returns:
            List of matching Cookie objects.
        """
        matching = []
        for cookie in self._cookies:
            if cookie.matches_domain(domain) and not cookie.is_expired():
                cookie.last_accessed = time.time()
                matching.append(cookie)
        return matching

    def set_cookie(
        self,
        name: str,
        value: str,
        domain: str,
        path: str = "/",
        secure: bool = False,
        httponly: bool = False,
        samesite: str = "",
        expires: float = None,
    ) -> Cookie:
        """
        Set or update a cookie in the jar.

        If a cookie with the same name and domain exists, it is updated.
        Otherwise, a new cookie is created.

        Args:
            name: Cookie name.
            value: Cookie value.
            domain: Cookie domain.
            path: Cookie path (default '/').
            secure: Secure flag.
            httponly: HttpOnly flag.
            samesite: SameSite attribute.
            expires: Expiration timestamp.

        Returns:
            The created or updated Cookie object.
        """
        # Check if cookie already exists
        for i, existing in enumerate(self._cookies):
            if existing.name == name and existing.domain == domain:
                self._cookies[i] = Cookie(
                    name=name,
                    value=value,
                    domain=domain,
                    path=path,
                    secure=secure,
                    httponly=httponly,
                    samesite=samesite,
                    expires=expires,
                    creation_time=existing.creation_time,
                    last_accessed=time.time(),
                )
                return self._cookies[i]

        # Create new cookie
        cookie = Cookie(
            name=name,
            value=value,
            domain=domain,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            expires=expires,
        )
        self._cookies.append(cookie)
        return cookie

    def delete_cookie(self, name: str, domain: str) -> bool:
        """
        Delete a cookie by name and domain.

        Args:
            name: Cookie name to delete.
            domain: Cookie domain to match.

        Returns:
            True if a cookie was deleted, False if not found.
        """
        original_count = len(self._cookies)
        self._cookies = [
            c for c in self._cookies
            if not (c.name == name and c.domain == domain)
        ]
        deleted = len(self._cookies) < original_count
        if deleted:
            self._color.info(f"Deleted cookie: {name} ({domain})")
        return deleted

    def clear_expired(self) -> int:
        """
        Remove all expired cookies from the jar.

        Returns:
            Number of expired cookies removed.
        """
        original_count = len(self._cookies)
        self._cookies = [c for c in self._cookies if not c.is_expired()]
        removed = original_count - len(self._cookies)
        if removed > 0:
            self._color.info(f"Cleared {removed} expired cookies")
        return removed

    def clear_all(self) -> int:
        """
        Remove all cookies from the jar.

        Returns:
            Number of cookies removed.
        """
        count = len(self._cookies)
        self._cookies = []
        return count

    def get_all(self) -> List[Cookie]:
        """Return all cookies in the jar."""
        return list(self._cookies)

    def get_domains(self) -> List[str]:
        """Return list of unique domains in the cookie jar."""
        domains = set()
        for cookie in self._cookies:
            domains.add(cookie.domain)
        return sorted(domains)

    def find_by_name(self, name: str) -> List[Cookie]:
        """Find all cookies with the given name across all domains."""
        return [c for c in self._cookies if c.name == name]

    def count(self) -> int:
        """Return the total number of cookies in the jar."""
        return len(self._cookies)

    def __len__(self) -> int:
        """Support len() on the cookie manager."""
        return len(self._cookies)

    def __iter__(self):
        """Support iteration over cookies."""
        return iter(self._cookies)

    def __contains__(self, name: str) -> bool:
        """Support 'in' operator to check if a cookie name exists."""
        return any(c.name == name for c in self._cookies)

    def to_header_string(self, domain: str) -> str:
        """
        Generate a Cookie header string for the given domain.

        Args:
            domain: Target domain for cookie matching.

        Returns:
            Formatted cookie header string (name=value; name2=value2).
        """
        cookies = self.get_cookies_for_domain(domain)
        if not cookies:
            return ""
        return "; ".join(f"{c.name}={c.value}" for c in cookies)

    def from_set_cookie_header(self, header: str, request_domain: str = "") -> Cookie:
        """
        Parse a Set-Cookie response header and add cookie to jar.

        Args:
            header: The Set-Cookie header value.
            request_domain: The domain the request was made to.

        Returns:
            The parsed Cookie object.
        """
        parts = header.split(";")
        if not parts:
            return None

        # First part is name=value
        name_value = parts[0].strip()
        if "=" in name_value:
            name, value = name_value.split("=", 1)
        else:
            name = name_value
            value = ""

        cookie = Cookie(name=name.strip(), value=value.strip())

        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if "=" in part:
                attr_name, attr_value = part.split("=", 1)
                attr_name = attr_name.strip().lower()
                attr_value = attr_value.strip()

                if attr_name == "domain":
                    cookie.domain = attr_value
                elif attr_name == "path":
                    cookie.path = attr_value
                elif attr_name == "expires":
                    try:
                        from email.utils import parsedate_to_datetime
                        dt = parsedate_to_datetime(attr_value)
                        cookie.expires = dt.timestamp()
                    except (ValueError, TypeError):
                        pass
                elif attr_name == "max-age":
                    try:
                        cookie.max_age = int(attr_value)
                        cookie.expires = time.time() + cookie.max_age
                    except ValueError:
                        pass
                elif attr_name == "samesite":
                    cookie.samesite = attr_value
            else:
                attr_lower = part.lower()
                if attr_lower == "secure":
                    cookie.secure = True
                elif attr_lower == "httponly":
                    cookie.httponly = True

        # Default domain from request
        if not cookie.domain and request_domain:
            cookie.domain = request_domain

        self._cookies.append(cookie)
        return cookie

    def summary(self) -> Dict[str, Any]:
        """Generate a summary of the cookie jar contents."""
        domains = {}
        expired_count = 0
        secure_count = 0
        httponly_count = 0
        session_count = 0

        for cookie in self._cookies:
            domain = cookie.domain
            if domain not in domains:
                domains[domain] = 0
            domains[domain] += 1

            if cookie.is_expired():
                expired_count += 1
            if cookie.secure:
                secure_count += 1
            if cookie.httponly:
                httponly_count += 1
            if cookie.is_session_cookie():
                session_count += 1

        return {
            "total_cookies": len(self._cookies),
            "domains": domains,
            "domain_count": len(domains),
            "expired_count": expired_count,
            "secure_count": secure_count,
            "httponly_count": httponly_count,
            "session_cookie_count": session_count,
        }


# =============================================================================
# SESSION PERSISTENCE CLASS
# =============================================================================

class SessionPersistence:
    """
    Save and load session state between runs.
    
    Provides persistent storage for session data including cookies,
    authentication tokens, and custom session metadata. Sessions are
    stored as JSON files in the output directory.
    """

    def __init__(self, output_dir: str = None):
        """
        Initialize session persistence.

        Args:
            output_dir: Directory for storing session files.
        """
        self._output_dir = output_dir or "monster_output"
        self._sessions_dir = os.path.join(self._output_dir, "sessions")
        os.makedirs(self._sessions_dir, exist_ok=True)
        self._color = ColorOutput()

    def _session_path(self, session_name: str) -> str:
        """Get the file path for a session name."""
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", session_name)
        return os.path.join(self._sessions_dir, f"{safe_name}.json")

    def save_session(self, session_data: Dict[str, Any], session_name: str = "default") -> bool:
        """
        Save session data to a persistent file.

        Args:
            session_data: Dictionary containing session state.
            session_name: Name identifier for the session.

        Returns:
            True if saved successfully.
        """
        try:
            filepath = self._session_path(session_name)
            save_data = {
                "session_name": session_name,
                "saved_at": datetime.now().isoformat(),
                "version": "2.0.0",
                "data": session_data,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(save_data, f, indent=2, default=str)

            self._color.success(f"Session saved: {session_name}")
            return True
        except Exception as e:
            self._color.error(f"Failed to save session '{session_name}': {e}")
            return False

    def load_session(self, session_name: str = "default") -> Optional[Dict[str, Any]]:
        """
        Load session data from a persistent file.

        Args:
            session_name: Name identifier for the session to load.

        Returns:
            Session data dictionary or None if not found.
        """
        try:
            filepath = self._session_path(session_name)
            if not os.path.isfile(filepath):
                self._color.warning(f"Session not found: {session_name}")
                return None

            with open(filepath, "r", encoding="utf-8") as f:
                save_data = json.load(f)

            self._color.success(f"Session loaded: {session_name}")
            return save_data.get("data", {})
        except json.JSONDecodeError:
            self._color.error(f"Corrupt session file: {session_name}")
            return None
        except Exception as e:
            self._color.error(f"Failed to load session '{session_name}': {e}")
            return None

    def list_sessions(self) -> List[Dict[str, str]]:
        """
        List all available saved sessions.

        Returns:
            List of dicts with session name, path, and modification time.
        """
        sessions = []
        try:
            if not os.path.isdir(self._sessions_dir):
                return sessions

            for filename in os.listdir(self._sessions_dir):
                if filename.endswith(".json"):
                    filepath = os.path.join(self._sessions_dir, filename)
                    stat = os.stat(filepath)
                    session_name = filename[:-5]  # Remove .json
                    sessions.append({
                        "name": session_name,
                        "path": filepath,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "size": stat.st_size,
                    })
        except Exception as e:
            self._color.error(f"Error listing sessions: {e}")

        return sorted(sessions, key=lambda s: s["modified"], reverse=True)

    def delete_session(self, session_name: str) -> bool:
        """
        Delete a saved session file.

        Args:
            session_name: Name of the session to delete.

        Returns:
            True if deleted successfully.
        """
        try:
            filepath = self._session_path(session_name)
            if os.path.isfile(filepath):
                os.remove(filepath)
                self._color.info(f"Deleted session: {session_name}")
                return True
            else:
                self._color.warning(f"Session not found: {session_name}")
                return False
        except Exception as e:
            self._color.error(f"Failed to delete session '{session_name}': {e}")
            return False

    def session_exists(self, session_name: str) -> bool:
        """Check if a session exists."""
        return os.path.isfile(self._session_path(session_name))

    def export_session(self, session_name: str, export_path: str) -> bool:
        """
        Export a session to a specified file path.

        Args:
            session_name: Session to export.
            export_path: Destination file path.

        Returns:
            True if exported successfully.
        """
        try:
            data = self.load_session(session_name)
            if data is None:
                return False

            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            self._color.error(f"Export failed: {e}")
            return False

    def import_session(self, import_path: str, session_name: str = None) -> bool:
        """
        Import a session from a file.

        Args:
            import_path: Path to the session file to import.
            session_name: Name to use for the imported session.

        Returns:
            True if imported successfully.
        """
        try:
            with open(import_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            name = session_name or os.path.splitext(os.path.basename(import_path))[0]
            return self.save_session(data, name)
        except Exception as e:
            self._color.error(f"Import failed: {e}")
            return False

    def clear_all_sessions(self) -> int:
        """
        Delete all saved sessions.

        Returns:
            Number of sessions deleted.
        """
        count = 0
        try:
            for filename in os.listdir(self._sessions_dir):
                if filename.endswith(".json"):
                    os.remove(os.path.join(self._sessions_dir, filename))
                    count += 1
        except Exception as e:
            self._color.error(f"Error clearing sessions: {e}")
        return count


# =============================================================================
# COOKIE FORMAT CONVERTER CLASS
# =============================================================================

class CookieFormatConverter:
    """
    Convert cookies between various formats.
    
    Supports Netscape, JSON, cURL, Burp Suite, browser exports,
    and HAR file extraction. Useful for interoperability between
    different security tools and browser automation.
    """

    def __init__(self):
        """Initialize the format converter."""
        self._color = ColorOutput()

    def netscape_to_json(self, netscape_str: str) -> List[Dict[str, Any]]:
        """
        Convert Netscape format cookie string to JSON-compatible list.

        Args:
            netscape_str: Multi-line string in Netscape cookie format.

        Returns:
            List of cookie dictionaries.
        """
        cookies = []
        for line in netscape_str.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")
            if len(parts) < 7:
                continue

            try:
                expires = float(parts[4]) if parts[4] != "0" else None
            except ValueError:
                expires = None

            cookies.append({
                "domain": parts[0],
                "include_subdomains": parts[1].upper() == "TRUE",
                "path": parts[2],
                "secure": parts[3].upper() == "TRUE",
                "expires": expires,
                "name": parts[5],
                "value": parts[6] if len(parts) > 6 else "",
            })

        return cookies

    def json_to_netscape(self, cookies_list: List[Dict[str, Any]]) -> str:
        """
        Convert a list of cookie dictionaries to Netscape format string.

        Args:
            cookies_list: List of cookie dictionaries.

        Returns:
            Netscape format cookie file content.
        """
        lines = [
            "# Netscape HTTP Cookie File",
            "# Generated by Monster v2.0.0",
            f"# Date: {datetime.now().isoformat()}",
            "",
        ]

        for cookie in cookies_list:
            domain = cookie.get("domain", "")
            include_sub = "TRUE" if cookie.get("include_subdomains", domain.startswith(".")) else "FALSE"
            path = cookie.get("path", "/")
            secure = "TRUE" if cookie.get("secure", False) else "FALSE"
            expires = str(int(cookie.get("expires", 0) or 0))
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            lines.append(f"{domain}\t{include_sub}\t{path}\t{secure}\t{expires}\t{name}\t{value}")

        return "\n".join(lines)

    def to_curl_format(self, cookies_list: List[Dict[str, Any]]) -> str:
        """
        Convert cookies to cURL command format.

        Args:
            cookies_list: List of cookie dictionaries.

        Returns:
            cURL -b flag format string.
        """
        if not cookies_list:
            return ""

        cookie_pairs = []
        for cookie in cookies_list:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if name:
                cookie_pairs.append(f"{name}={value}")

        return "; ".join(cookie_pairs)

    def to_curl_command(self, cookies_list: List[Dict[str, Any]], url: str = "https://example.com") -> str:
        """
        Generate a full cURL command with cookies.

        Args:
            cookies_list: List of cookie dictionaries.
            url: Target URL for the cURL command.

        Returns:
            Complete cURL command string.
        """
        cookie_str = self.to_curl_format(cookies_list)
        if cookie_str:
            return f'curl -b "{cookie_str}" "{url}"'
        return f'curl "{url}"'

    def to_burp_format(self, cookies_list: List[Dict[str, Any]]) -> str:
        """
        Convert cookies to Burp Suite format.

        Burp Suite uses a pipe-separated format for cookie jar exports.

        Args:
            cookies_list: List of cookie dictionaries.

        Returns:
            Burp Suite compatible cookie format string.
        """
        lines = []
        for cookie in cookies_list:
            domain = cookie.get("domain", "")
            path = cookie.get("path", "/")
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            expires = cookie.get("expires", "")
            if expires:
                try:
                    exp_dt = datetime.fromtimestamp(float(expires))
                    expires_str = exp_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
                except (ValueError, TypeError, OSError):
                    expires_str = ""
            else:
                expires_str = "Session"

            secure = "Yes" if cookie.get("secure", False) else "No"
            httponly = "Yes" if cookie.get("httponly", False) else "No"
            lines.append(f"{domain}|{path}|{name}|{value}|{expires_str}|{secure}|{httponly}")

        header = "# Burp Suite Cookie Export\n# Domain|Path|Name|Value|Expires|Secure|HttpOnly\n"
        return header + "\n".join(lines)

    def from_browser_export(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse cookies from a browser export file.

        Supports JSON exports from browser extensions like EditThisCookie,
        Cookie-Editor, and similar tools.

        Args:
            filepath: Path to the browser export file.

        Returns:
            List of normalized cookie dictionaries.
        """
        cookies = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                data = [data]

            for item in data:
                if not isinstance(item, dict):
                    continue

                cookie = {
                    "name": item.get("name", item.get("Name", "")),
                    "value": item.get("value", item.get("Value", "")),
                    "domain": item.get("domain", item.get("Domain", "")),
                    "path": item.get("path", item.get("Path", "/")),
                    "secure": item.get("secure", item.get("Secure", False)),
                    "httponly": item.get("httpOnly", item.get("HttpOnly", item.get("httponly", False))),
                    "samesite": item.get("sameSite", item.get("SameSite", "")),
                    "expires": item.get("expirationDate", item.get("expires", item.get("Expires", None))),
                }
                cookies.append(cookie)

        except json.JSONDecodeError as e:
            self._color.error(f"Invalid JSON in browser export: {e}")
        except FileNotFoundError:
            self._color.error(f"Browser export file not found: {filepath}")
        except Exception as e:
            self._color.error(f"Error parsing browser export: {e}")

        return cookies

    def from_har_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Extract cookies from an HTTP Archive (HAR) file.

        Parses both request cookies and response Set-Cookie headers
        from HAR file entries.

        Args:
            filepath: Path to the HAR file.

        Returns:
            List of cookie dictionaries extracted from the HAR.
        """
        cookies = []
        seen = set()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                har_data = json.load(f)

            entries = har_data.get("log", {}).get("entries", [])

            for entry in entries:
                # Extract request cookies
                request_cookies = entry.get("request", {}).get("cookies", [])
                for rc in request_cookies:
                    key = f"{rc.get('name', '')}|{rc.get('domain', '')}"
                    if key not in seen:
                        seen.add(key)
                        cookies.append({
                            "name": rc.get("name", ""),
                            "value": rc.get("value", ""),
                            "domain": rc.get("domain", ""),
                            "path": rc.get("path", "/"),
                            "secure": rc.get("secure", False),
                            "httponly": rc.get("httpOnly", False),
                            "expires": rc.get("expires", None),
                        })

                # Extract response cookies
                response_cookies = entry.get("response", {}).get("cookies", [])
                for rc in response_cookies:
                    key = f"{rc.get('name', '')}|{rc.get('domain', '')}"
                    if key not in seen:
                        seen.add(key)
                        cookies.append({
                            "name": rc.get("name", ""),
                            "value": rc.get("value", ""),
                            "domain": rc.get("domain", ""),
                            "path": rc.get("path", "/"),
                            "secure": rc.get("secure", False),
                            "httponly": rc.get("httpOnly", False),
                            "expires": rc.get("expires", None),
                        })

                # Also check Set-Cookie headers in response
                response_headers = entry.get("response", {}).get("headers", [])
                for header in response_headers:
                    if header.get("name", "").lower() == "set-cookie":
                        parsed = self._parse_set_cookie(header.get("value", ""))
                        if parsed:
                            key = f"{parsed.get('name', '')}|{parsed.get('domain', '')}"
                            if key not in seen:
                                seen.add(key)
                                cookies.append(parsed)

            self._color.success(f"Extracted {len(cookies)} cookies from HAR file")
        except json.JSONDecodeError:
            self._color.error(f"Invalid JSON in HAR file: {filepath}")
        except FileNotFoundError:
            self._color.error(f"HAR file not found: {filepath}")
        except Exception as e:
            self._color.error(f"Error parsing HAR file: {e}")

        return cookies

    def _parse_set_cookie(self, header_value: str) -> Optional[Dict[str, Any]]:
        """Parse a Set-Cookie header value into a cookie dict."""
        parts = header_value.split(";")
        if not parts:
            return None

        name_value = parts[0].strip()
        if "=" not in name_value:
            return None

        name, value = name_value.split("=", 1)
        cookie = {
            "name": name.strip(),
            "value": value.strip(),
            "domain": "",
            "path": "/",
            "secure": False,
            "httponly": False,
            "samesite": "",
            "expires": None,
        }

        for part in parts[1:]:
            part = part.strip()
            if "=" in part:
                attr_name, attr_value = part.split("=", 1)
                attr_name = attr_name.strip().lower()
                attr_value = attr_value.strip()
                if attr_name == "domain":
                    cookie["domain"] = attr_value
                elif attr_name == "path":
                    cookie["path"] = attr_value
                elif attr_name == "samesite":
                    cookie["samesite"] = attr_value
                elif attr_name == "max-age":
                    try:
                        cookie["expires"] = time.time() + int(attr_value)
                    except ValueError:
                        pass
            else:
                lower = part.lower()
                if lower == "secure":
                    cookie["secure"] = True
                elif lower == "httponly":
                    cookie["httponly"] = True

        return cookie

    def to_python_requests_format(self, cookies_list: List[Dict[str, Any]]) -> str:
        """
        Convert cookies to Python requests library format.

        Args:
            cookies_list: List of cookie dictionaries.

        Returns:
            Python code string for setting cookies in requests.
        """
        lines = ["import requests", "", "session = requests.Session()", ""]
        for cookie in cookies_list:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            domain = cookie.get("domain", "")
            lines.append(f'session.cookies.set("{name}", "{value}", domain="{domain}")')
        return "\n".join(lines)


# =============================================================================
# AUTHENTICATED CLIENT CLASS
# =============================================================================

class AuthenticatedClient:
    """
    Wraps HTTPClient with automatic cookie management.
    
    Automatically adds cookies from the CookieManager to all requests
    and handles Set-Cookie response headers to update the cookie jar.
    Supports cookie-based authentication flows.
    """

    def __init__(self, cookie_manager: CookieManager, base_url: str = None, proxy: str = None):
        """
        Initialize the authenticated client.

        Args:
            cookie_manager: CookieManager instance for cookie storage.
            base_url: Optional base URL to prepend to relative paths.
            proxy: Optional proxy URL (http://host:port).
        """
        self._cookie_manager = cookie_manager
        self._base_url = base_url.rstrip("/") if base_url else ""
        self._http_client = HTTPClient(proxy=proxy)
        self._color = ColorOutput()
        self._request_count = 0
        self._last_response = None

    def _resolve_url(self, url: str) -> str:
        """Resolve relative URLs using base_url."""
        if url.startswith(("http://", "https://")):
            return url
        if self._base_url:
            return f"{self._base_url}/{url.lstrip('/')}"
        return url

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        return domain_from_url(url)

    def _build_cookie_header(self, url: str) -> str:
        """Build Cookie header value for the given URL."""
        domain = self._get_domain(url)
        return self._cookie_manager.to_header_string(domain)

    def _merge_headers(self, url: str, headers: Dict[str, str] = None) -> Dict[str, str]:
        """Merge custom headers with cookie header."""
        merged = headers.copy() if headers else {}
        cookie_str = self._build_cookie_header(url)
        if cookie_str:
            merged["Cookie"] = cookie_str
        return merged

    def handle_set_cookie(self, response_headers: Dict[str, str], request_domain: str = ""):
        """
        Process Set-Cookie headers from a response and update the cookie jar.

        Args:
            response_headers: Response headers dictionary.
            request_domain: The domain the request was made to.
        """
        for header_name, header_value in response_headers.items():
            if header_name.lower() == "set-cookie":
                # Handle multiple Set-Cookie values (comma-separated in some cases)
                cookie_values = [header_value]
                if "," in header_value:
                    # Be careful not to split date values
                    potential_cookies = []
                    current = ""
                    for part in header_value.split(","):
                        if re.match(r"\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)", part.strip()):
                            current += "," + part
                        else:
                            if current:
                                potential_cookies.append(current)
                            current = part
                    if current:
                        potential_cookies.append(current)
                    if len(potential_cookies) > 1:
                        cookie_values = potential_cookies

                for cv in cookie_values:
                    self._cookie_manager.from_set_cookie_header(cv.strip(), request_domain)

    def get(self, url: str, headers: Dict[str, str] = None):
        """
        Perform a GET request with automatic cookie injection.

        Args:
            url: Target URL.
            headers: Optional additional headers.

        Returns:
            HTTPResponse object.
        """
        full_url = self._resolve_url(url)
        merged_headers = self._merge_headers(full_url, headers)
        response = self._http_client.get(full_url, headers=merged_headers)
        self._request_count += 1

        if response and response.headers:
            self.handle_set_cookie(response.headers, self._get_domain(full_url))

        self._last_response = response
        return response

    def post(self, url: str, data: str = None, headers: Dict[str, str] = None):
        """
        Perform a POST request with automatic cookie injection.

        Args:
            url: Target URL.
            data: Optional POST body data.
            headers: Optional additional headers.

        Returns:
            HTTPResponse object.
        """
        full_url = self._resolve_url(url)
        merged_headers = self._merge_headers(full_url, headers)
        response = self._http_client.post(full_url, data=data, headers=merged_headers)
        self._request_count += 1

        if response and response.headers:
            self.handle_set_cookie(response.headers, self._get_domain(full_url))

        self._last_response = response
        return response

    def head(self, url: str, headers: Dict[str, str] = None):
        """
        Perform a HEAD request with automatic cookie injection.

        Args:
            url: Target URL.
            headers: Optional additional headers.

        Returns:
            HTTPResponse object.
        """
        full_url = self._resolve_url(url)
        merged_headers = self._merge_headers(full_url, headers)
        response = self._http_client.head(full_url, headers=merged_headers)
        self._request_count += 1

        if response and response.headers:
            self.handle_set_cookie(response.headers, self._get_domain(full_url))

        self._last_response = response
        return response

    def get_request_count(self) -> int:
        """Return the total number of requests made."""
        return self._request_count

    def get_last_response(self):
        """Return the most recent response."""
        return self._last_response

    def get_cookies(self) -> List[Cookie]:
        """Return all cookies currently in the jar."""
        return self._cookie_manager.get_all()

    def clear_cookies(self):
        """Clear all cookies from the jar."""
        self._cookie_manager.clear_all()


# =============================================================================
# COOKIE SECURITY ANALYZER CLASS
# =============================================================================

class CookieSecurityAnalyzer:
    """
    Analyze cookies for security misconfigurations.
    
    Checks for missing security flags (HttpOnly, Secure, SameSite),
    overly broad scoping, session fixation risks, and generates
    comprehensive security reports.
    """

    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"
    SEVERITY_INFO = "info"

    def __init__(self, cookies_list: List[Any] = None):
        """
        Initialize the security analyzer.

        Args:
            cookies_list: List of Cookie objects or cookie dicts to analyze.
        """
        self._cookies = cookies_list or []
        self._findings = []
        self._color = ColorOutput()

    def _normalize_cookie(self, cookie) -> Dict[str, Any]:
        """Normalize cookie to dict format regardless of input type."""
        if isinstance(cookie, dict):
            return cookie
        if hasattr(cookie, "to_dict"):
            return cookie.to_dict()
        return {
            "name": getattr(cookie, "name", ""),
            "value": getattr(cookie, "value", ""),
            "domain": getattr(cookie, "domain", ""),
            "path": getattr(cookie, "path", "/"),
            "secure": getattr(cookie, "secure", False),
            "httponly": getattr(cookie, "httponly", False),
            "samesite": getattr(cookie, "samesite", ""),
            "expires": getattr(cookie, "expires", None),
        }

    def check_httponly(self) -> List[Dict[str, Any]]:
        """
        Check for cookies missing the HttpOnly flag.

        Cookies without HttpOnly can be accessed via JavaScript,
        making them vulnerable to XSS-based theft.

        Returns:
            List of findings for cookies missing HttpOnly.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            if not c.get("httponly", False):
                findings.append({
                    "severity": self.SEVERITY_MEDIUM,
                    "type": "missing_httponly",
                    "cookie_name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{c.get('name', '')}' is missing HttpOnly flag. "
                                   f"This cookie can be accessed via JavaScript (document.cookie).",
                    "recommendation": "Set the HttpOnly flag to prevent client-side script access.",
                })
        return findings

    def check_secure_flag(self) -> List[Dict[str, Any]]:
        """
        Check for cookies missing the Secure flag.

        Cookies without Secure can be transmitted over unencrypted HTTP,
        exposing them to network-level interception.

        Returns:
            List of findings for cookies missing Secure flag.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            if not c.get("secure", False):
                findings.append({
                    "severity": self.SEVERITY_MEDIUM,
                    "type": "missing_secure_flag",
                    "cookie_name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{c.get('name', '')}' is missing Secure flag. "
                                   f"This cookie can be transmitted over unencrypted HTTP connections.",
                    "recommendation": "Set the Secure flag to ensure cookie is only sent over HTTPS.",
                })
        return findings

    def check_samesite(self) -> List[Dict[str, Any]]:
        """
        Check for cookies with missing or weak SameSite attribute.

        Cookies without SameSite or with SameSite=None are vulnerable
        to Cross-Site Request Forgery (CSRF) attacks.

        Returns:
            List of findings for cookies with SameSite issues.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            samesite = c.get("samesite", "").lower()

            if not samesite:
                findings.append({
                    "severity": self.SEVERITY_LOW,
                    "type": "missing_samesite",
                    "cookie_name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{c.get('name', '')}' has no SameSite attribute set. "
                                   f"Browser defaults may not provide CSRF protection.",
                    "recommendation": "Set SameSite=Strict or SameSite=Lax for CSRF protection.",
                })
            elif samesite == "none":
                findings.append({
                    "severity": self.SEVERITY_MEDIUM,
                    "type": "samesite_none",
                    "cookie_name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{c.get('name', '')}' has SameSite=None, "
                                   f"allowing cross-site requests to include this cookie.",
                    "recommendation": "Use SameSite=Strict or SameSite=Lax unless cross-site access is required.",
                })
        return findings

    def check_expiry(self) -> List[Dict[str, Any]]:
        """
        Check cookie expiration settings.

        Identifies cookies with no expiry (session cookies), extremely
        long expiry periods, and already-expired cookies.

        Returns:
            List of findings related to cookie expiry.
        """
        findings = []
        now = time.time()
        one_year = 365 * 24 * 60 * 60

        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            expires = c.get("expires")
            name = c.get("name", "")

            if expires is None:
                findings.append({
                    "severity": self.SEVERITY_INFO,
                    "type": "no_expiry",
                    "cookie_name": name,
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{name}' has no expiration (session cookie). "
                                   f"It will be deleted when the browser closes.",
                    "recommendation": "Consider setting an appropriate expiry for persistent auth.",
                })
            elif isinstance(expires, (int, float)):
                if expires < now:
                    findings.append({
                        "severity": self.SEVERITY_INFO,
                        "type": "already_expired",
                        "cookie_name": name,
                        "domain": c.get("domain", ""),
                        "description": f"Cookie '{name}' has already expired.",
                        "recommendation": "Remove expired cookies from the jar.",
                    })
                elif (expires - now) > (2 * one_year):
                    findings.append({
                        "severity": self.SEVERITY_LOW,
                        "type": "excessive_expiry",
                        "cookie_name": name,
                        "domain": c.get("domain", ""),
                        "description": f"Cookie '{name}' has an expiry more than 2 years in the future. "
                                       f"Long-lived cookies increase the window for session hijacking.",
                        "recommendation": "Reduce cookie lifetime to minimize risk exposure.",
                    })
        return findings

    def check_domain_scope(self) -> List[Dict[str, Any]]:
        """
        Check for overly broad domain scoping.

        Cookies scoped to parent domains (e.g., .example.com) are accessible
        to all subdomains, increasing the attack surface.

        Returns:
            List of findings for broad domain scoping.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            domain = c.get("domain", "")
            name = c.get("name", "")

            if domain.startswith("."):
                parts = domain.lstrip(".").split(".")
                if len(parts) <= 2:
                    findings.append({
                        "severity": self.SEVERITY_MEDIUM,
                        "type": "broad_domain_scope",
                        "cookie_name": name,
                        "domain": domain,
                        "description": f"Cookie '{name}' is scoped to '{domain}' (top-level domain). "
                                       f"All subdomains can access this cookie.",
                        "recommendation": "Restrict cookie domain to specific subdomains where possible.",
                    })
                elif len(parts) == 3:
                    findings.append({
                        "severity": self.SEVERITY_LOW,
                        "type": "subdomain_wildcard",
                        "cookie_name": name,
                        "domain": domain,
                        "description": f"Cookie '{name}' is scoped to '{domain}', "
                                       f"accessible by all subdomains under this scope.",
                        "recommendation": "Verify that subdomain-scoped access is intentional.",
                    })
        return findings

    def check_path_scope(self) -> List[Dict[str, Any]]:
        """
        Check for overly broad path scoping.

        Cookies with path=/ are sent with every request to the domain,
        which may not be necessary.

        Returns:
            List of findings for path scoping issues.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            path = c.get("path", "/")
            name = c.get("name", "")

            if path == "/":
                findings.append({
                    "severity": self.SEVERITY_INFO,
                    "type": "root_path_scope",
                    "cookie_name": name,
                    "domain": c.get("domain", ""),
                    "description": f"Cookie '{name}' has root path scope (/). "
                                   f"It will be sent with every request to the domain.",
                    "recommendation": "Consider restricting path scope if cookie is only needed for specific endpoints.",
                })
        return findings

    def detect_session_fixation_risk(self) -> List[Dict[str, Any]]:
        """
        Detect potential session fixation vulnerabilities.

        Identifies session cookies that lack proper security attributes,
        making them susceptible to session fixation attacks.

        Returns:
            List of findings related to session fixation risk.
        """
        findings = []
        session_patterns = [
            "session", "sess", "sid", "jsessionid", "phpsessid",
            "asp.net_sessionid", "connect.sid", "laravel_session",
        ]

        for cookie in self._cookies:
            c = self._normalize_cookie(cookie)
            name = c.get("name", "").lower()

            is_session = any(p in name for p in session_patterns)
            if not is_session:
                continue

            risks = []
            if not c.get("httponly", False):
                risks.append("missing HttpOnly")
            if not c.get("secure", False):
                risks.append("missing Secure")
            if not c.get("samesite", ""):
                risks.append("missing SameSite")

            if risks:
                findings.append({
                    "severity": self.SEVERITY_HIGH,
                    "type": "session_fixation_risk",
                    "cookie_name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "description": f"Session cookie '{c.get('name', '')}' has security weaknesses: "
                                   f"{', '.join(risks)}. This increases session fixation/hijacking risk.",
                    "recommendation": "Ensure all session cookies have HttpOnly, Secure, and SameSite attributes.",
                    "risks": risks,
                })
        return findings

    def full_analysis(self) -> Dict[str, Any]:
        """
        Run all security checks and return comprehensive results.

        Returns:
            Dictionary containing all findings organized by check type.
        """
        results = {
            "httponly": self.check_httponly(),
            "secure_flag": self.check_secure_flag(),
            "samesite": self.check_samesite(),
            "expiry": self.check_expiry(),
            "domain_scope": self.check_domain_scope(),
            "path_scope": self.check_path_scope(),
            "session_fixation": self.detect_session_fixation_risk(),
        }

        # Summary statistics
        all_findings = []
        for check_findings in results.values():
            all_findings.extend(check_findings)

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for finding in all_findings:
            sev = finding.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        results["summary"] = {
            "total_cookies": len(self._cookies),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
        }

        return results

    def generate_report(self) -> str:
        """
        Generate a formatted text security report.

        Returns:
            Multi-line string containing the formatted security report.
        """
        results = self.full_analysis()
        lines = []
        lines.append("=" * 70)
        lines.append("  COOKIE SECURITY ANALYSIS REPORT")
        lines.append("  Generated by Monster v2.0.0")
        lines.append(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append("")

        summary = results.get("summary", {})
        lines.append(f"  Total Cookies Analyzed: {summary.get('total_cookies', 0)}")
        lines.append(f"  Total Findings: {summary.get('total_findings', 0)}")
        lines.append("")

        sev_counts = summary.get("severity_counts", {})
        lines.append("  Severity Breakdown:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                lines.append(f"    [{sev.upper()}] {count}")
        lines.append("")
        lines.append("-" * 70)

        # Detail sections
        check_names = {
            "httponly": "HttpOnly Flag Check",
            "secure_flag": "Secure Flag Check",
            "samesite": "SameSite Attribute Check",
            "expiry": "Expiry Configuration Check",
            "domain_scope": "Domain Scope Check",
            "path_scope": "Path Scope Check",
            "session_fixation": "Session Fixation Risk Check",
        }

        for check_key, check_title in check_names.items():
            findings = results.get(check_key, [])
            if findings:
                lines.append("")
                lines.append(f"  [{check_title}]")
                lines.append(f"  {'-' * len(check_title)}")
                for f in findings:
                    lines.append(f"    [{f['severity'].upper()}] {f['cookie_name']} ({f['domain']})")
                    lines.append(f"      {f['description']}")
                    lines.append(f"      Recommendation: {f['recommendation']}")
                    lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        return "\n".join(lines)


# =============================================================================
# SESSION TOKEN DETECTOR CLASS
# =============================================================================

class SessionTokenDetector:
    """
    Identify and classify cookies by their purpose.
    
    Detects session cookies, authentication tokens, CSRF tokens,
    and tracking cookies using pattern matching and heuristics.
    """

    SESSION_PATTERNS = [
        "jsessionid", "phpsessid", "asp.net_sessionid", "aspsessionid",
        "connect.sid", "session_id", "sessionid", "session", "sess_id",
        "sid", "laravel_session", "ci_session", "flask_session",
        "django_session", "_session", "rack.session", "beaker.session",
        "play_session", "symfony_session", "express.sid", "koa.sid",
        "tornado_session", "cherrypy_session", "webpy_session",
    ]

    AUTH_PATTERNS = [
        "auth", "token", "access_token", "refresh_token", "bearer",
        "jwt", "id_token", "login", "credential", "api_key", "apikey",
        "auth_token", "authtoken", "user_token", "logged_in",
        "remember_me", "remember_token", "persistent_login",
        "keep_login", "stay_logged_in", "oauth_token",
        "sso_token", "saml_token", "openid_token",
    ]

    CSRF_PATTERNS = [
        "csrf", "xsrf", "_token", "csrftoken", "csrf_token",
        "xsrf_token", "anti_csrf", "anticsrf", "authenticity_token",
        "verification_token", "__requestverificationtoken",
        "csrfmiddlewaretoken", "_csrf_token", "form_token",
        "secure_token", "x-csrf-token", "x-xsrf-token",
    ]

    TRACKING_PATTERNS = [
        "_ga", "_gid", "_gat", "_utm", "fbp", "_fbp", "_fbc",
        "optimizely", "amplitude", "mixpanel", "_mkto", "hubspot",
        "_hjid", "_hjfirstseen", "intercom", "drift", "crisp",
        "mouseflow", "hotjar", "crazyegg", "clicktale", "fullstory",
        "_clck", "_clsk", "ajs_anonymous_id", "ajs_user_id",
        "segment", "heap", "pendo", "_pk_id", "_pk_ses",
        "matomo", "piwik", "__utma", "__utmb", "__utmc", "__utmz",
        "yandex", "_ym_uid", "_ym_d", "pardot", "munchkin",
    ]

    def __init__(self, cookies_list: List[Any] = None):
        """
        Initialize the session token detector.

        Args:
            cookies_list: List of Cookie objects or cookie dicts to classify.
        """
        self._cookies = cookies_list or []
        self._color = ColorOutput()

    def _get_name(self, cookie) -> str:
        """Get cookie name from object or dict."""
        if isinstance(cookie, dict):
            return cookie.get("name", "").lower()
        return getattr(cookie, "name", "").lower()

    def _get_value(self, cookie) -> str:
        """Get cookie value from object or dict."""
        if isinstance(cookie, dict):
            return cookie.get("value", "")
        return getattr(cookie, "value", "")

    def identify_session_cookies(self) -> List[Dict[str, Any]]:
        """
        Identify cookies that are likely session identifiers.

        Uses pattern matching on cookie names and value characteristics
        (high entropy, specific lengths) to identify session cookies.

        Returns:
            List of identified session cookies with confidence scores.
        """
        results = []
        for cookie in self._cookies:
            name = self._get_name(cookie)
            value = self._get_value(cookie)
            confidence = 0.0
            reasons = []

            # Check name patterns
            for pattern in self.SESSION_PATTERNS:
                if pattern in name or name == pattern:
                    confidence += 0.6
                    reasons.append(f"Name matches session pattern: {pattern}")
                    break

            # Check value characteristics (high entropy, hex/base64)
            if len(value) >= 20:
                confidence += 0.2
                reasons.append("Long value (20+ chars)")

            if re.match(r"^[a-f0-9]{20,}$", value, re.IGNORECASE):
                confidence += 0.3
                reasons.append("Hex-encoded value")
            elif re.match(r"^[A-Za-z0-9+/=]{20,}$", value):
                confidence += 0.2
                reasons.append("Base64-like value")

            if confidence > 0.4:
                results.append({
                    "cookie_name": name,
                    "value_preview": value[:20] + "..." if len(value) > 20 else value,
                    "confidence": min(confidence, 1.0),
                    "reasons": reasons,
                    "type": "session",
                })

        return results

    def identify_auth_tokens(self) -> List[Dict[str, Any]]:
        """
        Identify cookies that contain authentication tokens.

        Returns:
            List of identified auth token cookies.
        """
        results = []
        for cookie in self._cookies:
            name = self._get_name(cookie)
            value = self._get_value(cookie)
            confidence = 0.0
            reasons = []

            for pattern in self.AUTH_PATTERNS:
                if pattern in name:
                    confidence += 0.5
                    reasons.append(f"Name matches auth pattern: {pattern}")
                    break

            # Check if value looks like JWT
            if value.count(".") == 2 and len(value) > 50:
                parts = value.split(".")
                try:
                    base64.urlsafe_b64decode(parts[0] + "==")
                    confidence += 0.4
                    reasons.append("Value appears to be a JWT")
                except Exception:
                    pass

            # Check for bearer-like tokens
            if re.match(r"^[A-Za-z0-9_-]{30,}$", value):
                confidence += 0.2
                reasons.append("Long alphanumeric token value")

            if confidence > 0.3:
                results.append({
                    "cookie_name": name,
                    "value_preview": value[:20] + "..." if len(value) > 20 else value,
                    "confidence": min(confidence, 1.0),
                    "reasons": reasons,
                    "type": "auth",
                })

        return results

    def identify_csrf_tokens(self) -> List[Dict[str, Any]]:
        """
        Identify cookies that contain CSRF protection tokens.

        Returns:
            List of identified CSRF token cookies.
        """
        results = []
        for cookie in self._cookies:
            name = self._get_name(cookie)
            value = self._get_value(cookie)
            confidence = 0.0
            reasons = []

            for pattern in self.CSRF_PATTERNS:
                if pattern in name or name == pattern:
                    confidence += 0.7
                    reasons.append(f"Name matches CSRF pattern: {pattern}")
                    break

            # CSRF tokens are typically medium-length random strings
            if 20 <= len(value) <= 128 and re.match(r"^[A-Za-z0-9_-]+$", value):
                confidence += 0.2
                reasons.append("Value has typical CSRF token characteristics")

            if confidence > 0.4:
                results.append({
                    "cookie_name": name,
                    "value_preview": value[:20] + "..." if len(value) > 20 else value,
                    "confidence": min(confidence, 1.0),
                    "reasons": reasons,
                    "type": "csrf",
                })

        return results

    def identify_tracking_cookies(self) -> List[Dict[str, Any]]:
        """
        Identify cookies used for analytics and tracking.

        Returns:
            List of identified tracking cookies.
        """
        results = []
        for cookie in self._cookies:
            name = self._get_name(cookie)
            value = self._get_value(cookie)
            confidence = 0.0
            reasons = []

            for pattern in self.TRACKING_PATTERNS:
                if pattern in name or name == pattern:
                    confidence += 0.7
                    reasons.append(f"Name matches tracking pattern: {pattern}")
                    break

            # Long expiry is typical of tracking cookies
            if isinstance(cookie, dict):
                expires = cookie.get("expires")
            else:
                expires = getattr(cookie, "expires", None)

            if expires and isinstance(expires, (int, float)):
                days_until_expiry = (expires - time.time()) / (24 * 60 * 60)
                if days_until_expiry > 365:
                    confidence += 0.2
                    reasons.append("Very long expiry (1+ year)")

            if confidence > 0.4:
                results.append({
                    "cookie_name": name,
                    "value_preview": value[:20] + "..." if len(value) > 20 else value,
                    "confidence": min(confidence, 1.0),
                    "reasons": reasons,
                    "type": "tracking",
                })

        return results

    def classify_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Classify all cookies by their detected purpose.

        Returns:
            Dictionary with keys: session, auth, csrf, tracking, unknown.
        """
        classified = {
            "session": self.identify_session_cookies(),
            "auth": self.identify_auth_tokens(),
            "csrf": self.identify_csrf_tokens(),
            "tracking": self.identify_tracking_cookies(),
            "unknown": [],
        }

        # Find cookies not classified in any category
        classified_names = set()
        for category in ["session", "auth", "csrf", "tracking"]:
            for item in classified[category]:
                classified_names.add(item["cookie_name"])

        for cookie in self._cookies:
            name = self._get_name(cookie)
            if name not in classified_names:
                classified["unknown"].append({
                    "cookie_name": name,
                    "type": "unknown",
                })

        return classified


# =============================================================================
# JWT ANALYZER CLASS
# =============================================================================

class JWTAnalyzer:
    """
    Decode and analyze JSON Web Tokens (JWTs).
    
    Decodes JWT headers and payloads without signature verification,
    checks expiry claims, identifies weak algorithms, and extracts
    all embedded claims for security analysis.
    """

    WEAK_ALGORITHMS = ["none", "None", "NONE", "HS256"]
    STRONG_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

    def __init__(self):
        """Initialize the JWT analyzer."""
        self._color = ColorOutput()

    def _base64_decode_jwt(self, segment: str) -> bytes:
        """
        Decode a base64url-encoded JWT segment.

        Args:
            segment: Base64url-encoded string.

        Returns:
            Decoded bytes.
        """
        # Add padding if necessary
        padding = 4 - len(segment) % 4
        if padding != 4:
            segment += "=" * padding
        return base64.urlsafe_b64decode(segment)

    def _split_token(self, token: str) -> Tuple[str, str, str]:
        """
        Split a JWT into its three parts.

        Args:
            token: The JWT string.

        Returns:
            Tuple of (header, payload, signature) base64 strings.

        Raises:
            ValueError: If the token doesn't have 3 parts.
        """
        token = token.strip()
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
        return parts[0], parts[1], parts[2]

    def decode_header(self, token: str) -> Dict[str, Any]:
        """
        Decode the JWT header (first segment).

        Args:
            token: The JWT string.

        Returns:
            Dictionary containing the header claims (alg, typ, kid, etc.).
        """
        try:
            header_b64, _, _ = self._split_token(token)
            header_bytes = self._base64_decode_jwt(header_b64)
            return json.loads(header_bytes)
        except (ValueError, json.JSONDecodeError) as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to decode header: {e}"}

    def decode_payload(self, token: str) -> Dict[str, Any]:
        """
        Decode the JWT payload (second segment).

        Args:
            token: The JWT string.

        Returns:
            Dictionary containing the payload claims.
        """
        try:
            _, payload_b64, _ = self._split_token(token)
            payload_bytes = self._base64_decode_jwt(payload_b64)
            return json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError) as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to decode payload: {e}"}

    def decode_full(self, token: str) -> Dict[str, Any]:
        """
        Fully decode a JWT into header, payload, and signature info.

        Args:
            token: The JWT string.

        Returns:
            Dictionary with 'header', 'payload', and 'signature' keys.
        """
        try:
            header_b64, payload_b64, sig_b64 = self._split_token(token)

            header = json.loads(self._base64_decode_jwt(header_b64))
            payload = json.loads(self._base64_decode_jwt(payload_b64))
            signature = sig_b64  # Keep as base64 (can't decode without key)

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "signature_length": len(sig_b64),
                "is_valid_structure": True,
            }
        except Exception as e:
            return {
                "header": {},
                "payload": {},
                "signature": "",
                "is_valid_structure": False,
                "error": str(e),
            }

    def check_expiry(self, token: str) -> Dict[str, Any]:
        """
        Check the expiration claim of a JWT.

        Args:
            token: The JWT string.

        Returns:
            Dictionary with expiry information:
            - is_expired: bool
            - exp_time: datetime string or None
            - time_remaining: seconds remaining or negative if expired
            - issued_at: datetime string or None
        """
        payload = self.decode_payload(token)
        if "error" in payload:
            return {"error": payload["error"], "is_expired": None}

        result = {
            "is_expired": None,
            "exp_time": None,
            "time_remaining": None,
            "issued_at": None,
            "not_before": None,
        }

        now = time.time()

        # Check exp claim
        exp = payload.get("exp")
        if exp is not None:
            try:
                exp_time = float(exp)
                result["exp_time"] = datetime.fromtimestamp(exp_time).isoformat()
                result["is_expired"] = now > exp_time
                result["time_remaining"] = exp_time - now
            except (ValueError, TypeError, OSError):
                result["exp_time"] = "invalid"

        # Check iat claim
        iat = payload.get("iat")
        if iat is not None:
            try:
                result["issued_at"] = datetime.fromtimestamp(float(iat)).isoformat()
            except (ValueError, TypeError, OSError):
                pass

        # Check nbf claim
        nbf = payload.get("nbf")
        if nbf is not None:
            try:
                result["not_before"] = datetime.fromtimestamp(float(nbf)).isoformat()
            except (ValueError, TypeError, OSError):
                pass

        return result

    def check_algorithm(self, token: str) -> Dict[str, Any]:
        """
        Check the algorithm used in the JWT.

        Args:
            token: The JWT string.

        Returns:
            Dictionary with algorithm analysis:
            - algorithm: str
            - is_weak: bool
            - severity: str
            - recommendation: str
        """
        header = self.decode_header(token)
        if "error" in header:
            return {"error": header["error"]}

        alg = header.get("alg", "unknown")
        result = {
            "algorithm": alg,
            "is_weak": False,
            "severity": "info",
            "recommendation": "",
        }

        if alg.lower() == "none":
            result["is_weak"] = True
            result["severity"] = "critical"
            result["recommendation"] = "Algorithm 'none' means no signature verification. This is a critical vulnerability."
        elif alg == "HS256":
            result["is_weak"] = True
            result["severity"] = "medium"
            result["recommendation"] = (
                "HS256 uses symmetric keys. If the server uses asymmetric keys (RSA/ECDSA) "
                "but accepts HS256, this enables algorithm confusion attacks."
            )
        elif alg in self.STRONG_ALGORITHMS:
            result["is_weak"] = False
            result["severity"] = "info"
            result["recommendation"] = f"Algorithm {alg} is considered strong."
        else:
            result["severity"] = "low"
            result["recommendation"] = f"Unknown algorithm '{alg}'. Verify it is intentional."

        return result

    def extract_claims(self, token: str) -> Dict[str, Any]:
        """
        Extract and categorize all claims from a JWT.

        Args:
            token: The JWT string.

        Returns:
            Dictionary with categorized claims:
            - registered: standard JWT claims (iss, sub, aud, exp, etc.)
            - public: well-known public claims
            - private: application-specific claims
        """
        payload = self.decode_payload(token)
        if "error" in payload:
            return {"error": payload["error"]}

        registered_claims = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}
        public_claims = {"name", "email", "email_verified", "phone_number", "address",
                        "given_name", "family_name", "nickname", "preferred_username",
                        "picture", "website", "gender", "birthdate", "zoneinfo",
                        "locale", "updated_at", "azp", "nonce", "auth_time",
                        "at_hash", "c_hash", "acr", "amr", "scope", "roles"}

        result = {
            "registered": {},
            "public": {},
            "private": {},
            "all_claims": list(payload.keys()),
        }

        for key, value in payload.items():
            if key in registered_claims:
                result["registered"][key] = value
            elif key in public_claims:
                result["public"][key] = value
            else:
                result["private"][key] = value

        return result

    def analyze(self, token: str) -> Dict[str, Any]:
        """
        Perform comprehensive JWT analysis.

        Args:
            token: The JWT string.

        Returns:
            Complete analysis dictionary with all JWT information.
        """
        result = {
            "token_preview": token[:50] + "..." if len(token) > 50 else token,
            "token_length": len(token),
            "structure": self.decode_full(token),
            "expiry": self.check_expiry(token),
            "algorithm": self.check_algorithm(token),
            "claims": self.extract_claims(token),
            "findings": [],
        }

        # Collect security findings
        alg_check = result["algorithm"]
        if alg_check.get("is_weak"):
            result["findings"].append({
                "severity": alg_check.get("severity", "medium"),
                "issue": f"Weak algorithm: {alg_check.get('algorithm', 'unknown')}",
                "detail": alg_check.get("recommendation", ""),
            })

        expiry_check = result["expiry"]
        if expiry_check.get("is_expired"):
            result["findings"].append({
                "severity": "info",
                "issue": "Token is expired",
                "detail": f"Expired at: {expiry_check.get('exp_time', 'unknown')}",
            })
        elif expiry_check.get("exp_time") is None and expiry_check.get("is_expired") is None:
            result["findings"].append({
                "severity": "low",
                "issue": "No expiration claim",
                "detail": "Token has no 'exp' claim and never expires.",
            })

        # Check for sensitive data in payload
        payload = result["structure"].get("payload", {})
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "private_key"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                result["findings"].append({
                    "severity": "high",
                    "issue": f"Potentially sensitive data in claim: {key}",
                    "detail": "JWTs are only encoded, not encrypted. Sensitive data should not be stored in JWT payloads.",
                })

        return result

    def is_jwt(self, value: str) -> bool:
        """
        Check if a string appears to be a JWT.

        Args:
            value: String to check.

        Returns:
            True if the string looks like a valid JWT structure.
        """
        if not value or "." not in value:
            return False

        parts = value.split(".")
        if len(parts) != 3:
            return False

        try:
            # Try to decode header
            header_bytes = self._base64_decode_jwt(parts[0])
            header = json.loads(header_bytes)
            return "alg" in header or "typ" in header
        except Exception:
            return False


# =============================================================================
# COOKIE SCOPE MAPPER CLASS
# =============================================================================

class CookieScopeMapper:
    """
    Map cookie domains and paths to understand scope relationships.
    
    Identifies shared cookies across subdomains, detects overly broad
    scoping, finds duplicate cookies, and visualizes the cookie
    domain/path hierarchy.
    """

    def __init__(self, cookies_list: List[Any] = None):
        """
        Initialize the scope mapper.

        Args:
            cookies_list: List of Cookie objects or cookie dicts.
        """
        self._cookies = cookies_list or []
        self._color = ColorOutput()

    def _normalize(self, cookie) -> Dict[str, Any]:
        """Normalize cookie to dict."""
        if isinstance(cookie, dict):
            return cookie
        if hasattr(cookie, "to_dict"):
            return cookie.to_dict()
        return {
            "name": getattr(cookie, "name", ""),
            "value": getattr(cookie, "value", ""),
            "domain": getattr(cookie, "domain", ""),
            "path": getattr(cookie, "path", "/"),
            "secure": getattr(cookie, "secure", False),
            "httponly": getattr(cookie, "httponly", False),
        }

    def map_by_domain(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group all cookies by their domain.

        Returns:
            Dictionary mapping domain names to lists of cookies.
        """
        domain_map = {}
        for cookie in self._cookies:
            c = self._normalize(cookie)
            domain = c.get("domain", "unknown")
            if domain not in domain_map:
                domain_map[domain] = []
            domain_map[domain].append(c)

        return domain_map

    def map_by_path(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group all cookies by their path.

        Returns:
            Dictionary mapping paths to lists of cookies.
        """
        path_map = {}
        for cookie in self._cookies:
            c = self._normalize(cookie)
            path = c.get("path", "/")
            if path not in path_map:
                path_map[path] = []
            path_map[path].append(c)

        return path_map

    def find_shared_cookies(self) -> List[Dict[str, Any]]:
        """
        Find cookies that are shared across multiple subdomains.

        Cookies with wildcard domains (starting with .) are accessible
        from any subdomain, which may be a security concern.

        Returns:
            List of findings about shared cookies.
        """
        shared = []
        for cookie in self._cookies:
            c = self._normalize(cookie)
            domain = c.get("domain", "")

            if domain.startswith("."):
                base_domain = domain.lstrip(".")
                # Count how many other cookies share this parent domain
                matching = [
                    self._normalize(other)
                    for other in self._cookies
                    if self._normalize(other).get("domain", "").endswith(base_domain)
                ]

                if len(matching) > 1:
                    shared.append({
                        "cookie_name": c.get("name", ""),
                        "domain": domain,
                        "shared_with_count": len(matching),
                        "description": f"Cookie '{c.get('name', '')}' on '{domain}' is accessible "
                                       f"by {len(matching)} cookies on the same base domain.",
                    })

        # Deduplicate
        seen = set()
        unique_shared = []
        for item in shared:
            key = f"{item['cookie_name']}|{item['domain']}"
            if key not in seen:
                seen.add(key)
                unique_shared.append(item)

        return unique_shared

    def detect_broad_scope(self) -> List[Dict[str, Any]]:
        """
        Detect cookies with overly broad domain or path scope.

        Returns:
            List of findings about broadly-scoped cookies.
        """
        findings = []
        for cookie in self._cookies:
            c = self._normalize(cookie)
            domain = c.get("domain", "")
            path = c.get("path", "/")
            name = c.get("name", "")

            # Check for TLD-level domain scope
            clean_domain = domain.lstrip(".")
            parts = clean_domain.split(".")
            if domain.startswith(".") and len(parts) <= 2:
                findings.append({
                    "cookie_name": name,
                    "domain": domain,
                    "path": path,
                    "issue": "tld_scope",
                    "description": f"Cookie '{name}' is scoped to TLD-level domain '{domain}'. "
                                   f"This gives all subdomains access.",
                    "severity": "medium",
                })

            # Check for root path with broad domain
            if path == "/" and domain.startswith("."):
                findings.append({
                    "cookie_name": name,
                    "domain": domain,
                    "path": path,
                    "issue": "broad_scope_combination",
                    "description": f"Cookie '{name}' has both wildcard domain '{domain}' "
                                   f"and root path '/'. Maximum exposure.",
                    "severity": "low",
                })

        return findings

    def find_duplicates(self) -> List[Dict[str, Any]]:
        """
        Find duplicate cookies (same name, different domains/paths).

        Returns:
            List of duplicate cookie groups.
        """
        name_groups = {}
        for cookie in self._cookies:
            c = self._normalize(cookie)
            name = c.get("name", "")
            if name not in name_groups:
                name_groups[name] = []
            name_groups[name].append(c)

        duplicates = []
        for name, cookies in name_groups.items():
            if len(cookies) > 1:
                duplicates.append({
                    "cookie_name": name,
                    "count": len(cookies),
                    "domains": [c.get("domain", "") for c in cookies],
                    "paths": [c.get("path", "/") for c in cookies],
                    "description": f"Cookie '{name}' exists {len(cookies)} times across "
                                   f"different domains/paths.",
                })

        return duplicates

    def get_hierarchy(self) -> Dict[str, Any]:
        """
        Build a hierarchical view of cookie scopes.

        Returns:
            Nested dictionary representing the domain/path hierarchy.
        """
        hierarchy = {}
        for cookie in self._cookies:
            c = self._normalize(cookie)
            domain = c.get("domain", "unknown")
            path = c.get("path", "/")
            name = c.get("name", "")

            if domain not in hierarchy:
                hierarchy[domain] = {}
            if path not in hierarchy[domain]:
                hierarchy[domain][path] = []
            hierarchy[domain][path].append(name)

        return hierarchy

    def summary(self) -> Dict[str, Any]:
        """Generate a summary of cookie scope analysis."""
        domain_map = self.map_by_domain()
        return {
            "total_cookies": len(self._cookies),
            "unique_domains": len(domain_map),
            "domains": {d: len(cookies) for d, cookies in domain_map.items()},
            "shared_cookies": len(self.find_shared_cookies()),
            "broad_scope_findings": len(self.detect_broad_scope()),
            "duplicates": len(self.find_duplicates()),
        }


# =============================================================================
# COOKIE REPLAY TESTER CLASS
# =============================================================================

class CookieReplayTester:
    """
    Test cookie validity by replaying them against target endpoints.
    
    Verifies if session cookies are still valid, tests the impact of
    removing specific cookies, and compares responses with different
    cookie sets to understand authentication requirements.
    """

    def __init__(self, http_client: HTTPClient = None):
        """
        Initialize the cookie replay tester.

        Args:
            http_client: HTTPClient instance for making requests.
        """
        self._http_client = http_client or HTTPClient()
        self._color = ColorOutput()
        self._rate_limiter = RateLimiter(delay=1.0)

    def _make_request(self, url: str, cookies: Dict[str, str] = None, method: str = "GET") -> Dict[str, Any]:
        """Make a request with optional cookies and return normalized result."""
        headers = {}
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            headers["Cookie"] = cookie_str

        self._rate_limiter.wait()

        try:
            if method.upper() == "GET":
                response = self._http_client.get(url, headers=headers)
            elif method.upper() == "POST":
                response = self._http_client.post(url, headers=headers)
            else:
                response = self._http_client.get(url, headers=headers)

            return {
                "status_code": response.status_code if response else 0,
                "body_length": len(response.body) if response and response.body else 0,
                "headers": response.headers if response else {},
                "error": response.error if response else "No response",
                "redirect_url": response.redirect_url if response else None,
            }
        except Exception as e:
            return {
                "status_code": 0,
                "body_length": 0,
                "headers": {},
                "error": str(e),
                "redirect_url": None,
            }

    def _cookies_to_dict(self, cookies) -> Dict[str, str]:
        """Convert various cookie formats to a simple name:value dict."""
        if isinstance(cookies, dict):
            return cookies
        if isinstance(cookies, list):
            result = {}
            for c in cookies:
                if isinstance(c, dict):
                    result[c.get("name", "")] = c.get("value", "")
                elif hasattr(c, "name") and hasattr(c, "value"):
                    result[c.name] = c.value
            return result
        return {}

    def test_session_valid(self, url: str, cookies) -> bool:
        """
        Test if the given cookies still provide a valid session.

        Makes a request with the cookies and checks if the response
        indicates an authenticated state (not a redirect to login,
        not a 401/403).

        Args:
            url: URL that requires authentication.
            cookies: Cookies to test (dict, list, or Cookie objects).

        Returns:
            True if the session appears valid.
        """
        cookie_dict = self._cookies_to_dict(cookies)
        result = self._make_request(url, cookie_dict)

        # Check for signs of invalid session
        status = result.get("status_code", 0)
        if status in (401, 403):
            return False
        if status in (301, 302, 303, 307, 308):
            redirect = result.get("redirect_url", "")
            if redirect and any(p in redirect.lower() for p in ["login", "signin", "auth", "sso"]):
                return False

        # Check response body for login indicators
        # (We only have status code and headers in this simplified check)
        if status == 200:
            return True

        return status < 400

    def test_without_cookie(self, url: str, cookies, cookie_name: str) -> Dict[str, Any]:
        """
        Test the impact of removing a specific cookie.

        Makes two requests: one with all cookies, one without the
        specified cookie, and compares the responses.

        Args:
            url: Target URL.
            cookies: Full cookie set.
            cookie_name: Name of the cookie to remove.

        Returns:
            Dictionary with comparison results.
        """
        cookie_dict = self._cookies_to_dict(cookies)

        # Request with all cookies
        result_with = self._make_request(url, cookie_dict)

        # Request without the specified cookie
        reduced_cookies = {k: v for k, v in cookie_dict.items() if k != cookie_name}
        result_without = self._make_request(url, reduced_cookies)

        status_changed = result_with["status_code"] != result_without["status_code"]
        size_diff = abs(result_with["body_length"] - result_without["body_length"])
        redirect_changed = result_with.get("redirect_url") != result_without.get("redirect_url")

        impact = "none"
        if status_changed:
            if result_without["status_code"] in (401, 403):
                impact = "critical"
            elif result_without["status_code"] in (301, 302, 303):
                impact = "high"
            else:
                impact = "medium"
        elif size_diff > 100:
            impact = "low"
        elif redirect_changed:
            impact = "medium"

        return {
            "cookie_name": cookie_name,
            "impact": impact,
            "status_with": result_with["status_code"],
            "status_without": result_without["status_code"],
            "size_with": result_with["body_length"],
            "size_without": result_without["body_length"],
            "status_changed": status_changed,
            "size_difference": size_diff,
            "redirect_changed": redirect_changed,
            "redirect_with": result_with.get("redirect_url"),
            "redirect_without": result_without.get("redirect_url"),
        }

    def compare_responses(self, url: str, cookies_a, cookies_b) -> Dict[str, Any]:
        """
        Compare responses using two different cookie sets.

        Args:
            url: Target URL.
            cookies_a: First cookie set.
            cookies_b: Second cookie set.

        Returns:
            Dictionary comparing the two responses.
        """
        dict_a = self._cookies_to_dict(cookies_a)
        dict_b = self._cookies_to_dict(cookies_b)

        result_a = self._make_request(url, dict_a)
        result_b = self._make_request(url, dict_b)

        return {
            "url": url,
            "response_a": {
                "status_code": result_a["status_code"],
                "body_length": result_a["body_length"],
                "redirect": result_a.get("redirect_url"),
            },
            "response_b": {
                "status_code": result_b["status_code"],
                "body_length": result_b["body_length"],
                "redirect": result_b.get("redirect_url"),
            },
            "differences": {
                "status_differs": result_a["status_code"] != result_b["status_code"],
                "size_difference": abs(result_a["body_length"] - result_b["body_length"]),
                "redirect_differs": result_a.get("redirect_url") != result_b.get("redirect_url"),
            },
            "cookies_a_count": len(dict_a),
            "cookies_b_count": len(dict_b),
        }

    def test_all_cookies_individually(self, url: str, cookies) -> List[Dict[str, Any]]:
        """
        Test the impact of removing each cookie one at a time.

        Args:
            url: Target URL.
            cookies: Full cookie set.

        Returns:
            List of results for each cookie removal test.
        """
        cookie_dict = self._cookies_to_dict(cookies)
        results = []

        for cookie_name in cookie_dict:
            result = self.test_without_cookie(url, cookie_dict, cookie_name)
            results.append(result)

        # Sort by impact
        impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        results.sort(key=lambda r: impact_order.get(r.get("impact", "none"), 5))

        return results


# =============================================================================
# BROWSER COOKIE EXTRACTOR CLASS
# =============================================================================

class BrowserCookieExtractor:
    """
    Provides browser cookie database paths and extraction guidance.
    
    Identifies cookie storage locations for Chrome, Firefox, and Edge
    across Windows, macOS, and Linux. Provides instructions for manual
    cookie extraction and format conversion.
    """

    def __init__(self):
        """Initialize the browser cookie extractor."""
        self._color = ColorOutput()
        self._system = platform.system().lower()
        self._home = str(Path.home())

    def get_chrome_cookie_path(self) -> str:
        """
        Get the Chrome cookie database path for the current OS.

        Returns:
            Path to Chrome's Cookies SQLite database.
        """
        if self._system == "windows":
            local_app = os.environ.get("LOCALAPPDATA", "")
            return os.path.join(local_app, "Google", "Chrome", "User Data", "Default", "Cookies")
        elif self._system == "darwin":
            return os.path.join(self._home, "Library", "Application Support", "Google", "Chrome", "Default", "Cookies")
        else:  # Linux
            return os.path.join(self._home, ".config", "google-chrome", "Default", "Cookies")

    def get_firefox_cookie_path(self) -> str:
        """
        Get the Firefox cookie database path for the current OS.

        Note: Firefox uses profile directories with random names.
        This returns the profile directory pattern.

        Returns:
            Path pattern to Firefox's cookies.sqlite database.
        """
        if self._system == "windows":
            app_data = os.environ.get("APPDATA", "")
            return os.path.join(app_data, "Mozilla", "Firefox", "Profiles", "*.default*", "cookies.sqlite")
        elif self._system == "darwin":
            return os.path.join(self._home, "Library", "Application Support", "Firefox", "Profiles", "*.default*", "cookies.sqlite")
        else:  # Linux
            return os.path.join(self._home, ".mozilla", "firefox", "*.default*", "cookies.sqlite")

    def get_edge_cookie_path(self) -> str:
        """
        Get the Microsoft Edge cookie database path for the current OS.

        Returns:
            Path to Edge's Cookies SQLite database.
        """
        if self._system == "windows":
            local_app = os.environ.get("LOCALAPPDATA", "")
            return os.path.join(local_app, "Microsoft", "Edge", "User Data", "Default", "Cookies")
        elif self._system == "darwin":
            return os.path.join(self._home, "Library", "Application Support", "Microsoft Edge", "Default", "Cookies")
        else:  # Linux
            return os.path.join(self._home, ".config", "microsoft-edge", "Default", "Cookies")

    def get_brave_cookie_path(self) -> str:
        """
        Get the Brave browser cookie database path for the current OS.

        Returns:
            Path to Brave's Cookies SQLite database.
        """
        if self._system == "windows":
            local_app = os.environ.get("LOCALAPPDATA", "")
            return os.path.join(local_app, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies")
        elif self._system == "darwin":
            return os.path.join(self._home, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Cookies")
        else:  # Linux
            return os.path.join(self._home, ".config", "BraveSoftware", "Brave-Browser", "Default", "Cookies")

    def get_opera_cookie_path(self) -> str:
        """
        Get the Opera browser cookie database path for the current OS.

        Returns:
            Path to Opera's Cookies SQLite database.
        """
        if self._system == "windows":
            app_data = os.environ.get("APPDATA", "")
            return os.path.join(app_data, "Opera Software", "Opera Stable", "Cookies")
        elif self._system == "darwin":
            return os.path.join(self._home, "Library", "Application Support", "com.operasoftware.Opera", "Cookies")
        else:  # Linux
            return os.path.join(self._home, ".config", "opera", "Cookies")

    def get_all_paths(self) -> Dict[str, str]:
        """
        Get cookie database paths for all supported browsers.

        Returns:
            Dictionary mapping browser names to their cookie paths.
        """
        return {
            "chrome": self.get_chrome_cookie_path(),
            "firefox": self.get_firefox_cookie_path(),
            "edge": self.get_edge_cookie_path(),
            "brave": self.get_brave_cookie_path(),
            "opera": self.get_opera_cookie_path(),
        }

    def check_browser_availability(self) -> Dict[str, bool]:
        """
        Check which browser cookie databases exist on this system.

        Returns:
            Dictionary mapping browser names to availability.
        """
        paths = self.get_all_paths()
        availability = {}
        for browser, path in paths.items():
            if "*" in path:
                # Firefox uses glob pattern
                import glob
                matches = glob.glob(path)
                availability[browser] = len(matches) > 0
            else:
                availability[browser] = os.path.isfile(path)
        return availability

    def extraction_instructions(self) -> str:
        """
        Generate instructions for manually extracting browser cookies.

        Returns:
            Formatted multi-line string with extraction instructions.
        """
        instructions = []
        instructions.append("=" * 60)
        instructions.append("  BROWSER COOKIE EXTRACTION GUIDE")
        instructions.append("  Monster v2.0.0")
        instructions.append("=" * 60)
        instructions.append("")
        instructions.append("  [Method 1: Browser Extensions (Recommended)]")
        instructions.append("  -------------------------------------------")
        instructions.append("  1. Install 'EditThisCookie' or 'Cookie-Editor' extension")
        instructions.append("  2. Navigate to the target site")
        instructions.append("  3. Click the extension icon")
        instructions.append("  4. Export cookies as JSON")
        instructions.append("  5. Save to a file and use: CookieManager(cookie_file='exported.json')")
        instructions.append("")
        instructions.append("  [Method 2: Browser DevTools]")
        instructions.append("  ----------------------------")
        instructions.append("  1. Open DevTools (F12)")
        instructions.append("  2. Go to Application > Cookies (Chrome) or Storage > Cookies (Firefox)")
        instructions.append("  3. Right-click > Copy All (or use console)")
        instructions.append("  4. Console: JSON.stringify(document.cookie.split('; ').map(c => {")
        instructions.append("     const [name,...v] = c.split('=');")
        instructions.append("     return {name, value: v.join('=')};")
        instructions.append("  }))")
        instructions.append("")
        instructions.append("  [Method 3: cURL Export]")
        instructions.append("  ----------------------")
        instructions.append("  1. Open DevTools Network tab")
        instructions.append("  2. Right-click a request > Copy > Copy as cURL")
        instructions.append("  3. Extract the -b 'cookie_string' parameter")
        instructions.append("")
        instructions.append("  [Method 4: Netscape Format (wget/curl)]")
        instructions.append("  ----------------------------------------")
        instructions.append("  Firefox: Use 'cookies.txt' extension")
        instructions.append("  Chrome: Use 'Get cookies.txt' extension")
        instructions.append("  Format: domain\tTRUE\tpath\tTRUE\texpires\tname\tvalue")
        instructions.append("")
        instructions.append("  [Method 5: SQLite Direct Access]")
        instructions.append("  ---------------------------------")
        instructions.append("  Note: Browser must be closed first!")
        instructions.append("")

        paths = self.get_all_paths()
        for browser, path in paths.items():
            instructions.append(f"  {browser.title()}: {path}")

        instructions.append("")
        instructions.append("  SQLite query:")
        instructions.append("  sqlite3 <path> 'SELECT host_key, name, value, path, is_secure,")
        instructions.append("    is_httponly, expires_utc FROM cookies WHERE host_key LIKE \'%target.com%\''")
        instructions.append("")
        instructions.append("  WARNING: Chrome/Edge encrypt cookie values on newer versions.")
        instructions.append("  Use the DPAPI (Windows) or Keychain (macOS) to decrypt.")
        instructions.append("")
        instructions.append("  [Security Notes]")
        instructions.append("  ----------------")
        instructions.append("  - Only extract cookies for authorized testing")
        instructions.append("  - Store exported cookies securely (they grant access)")
        instructions.append("  - Delete exported files after testing")
        instructions.append("  - Never share cookie files in public repositories")
        instructions.append("")
        instructions.append("=" * 60)

        return "\n".join(instructions)

    def get_cookie_table_schema(self, browser: str = "chrome") -> str:
        """
        Get the SQLite schema for a browser's cookie table.

        Args:
            browser: Browser name (chrome, firefox, edge).

        Returns:
            SQL schema string.
        """
        schemas = {
            "chrome": (
                "CREATE TABLE cookies (\n"
                "  creation_utc INTEGER NOT NULL,\n"
                "  host_key TEXT NOT NULL,\n"
                "  top_frame_site_key TEXT NOT NULL,\n"
                "  name TEXT NOT NULL,\n"
                "  value TEXT NOT NULL,\n"
                "  encrypted_value BLOB NOT NULL,\n"
                "  path TEXT NOT NULL,\n"
                "  expires_utc INTEGER NOT NULL,\n"
                "  is_secure INTEGER NOT NULL,\n"
                "  is_httponly INTEGER NOT NULL,\n"
                "  last_access_utc INTEGER NOT NULL,\n"
                "  has_expires INTEGER NOT NULL,\n"
                "  is_persistent INTEGER NOT NULL,\n"
                "  priority INTEGER NOT NULL,\n"
                "  samesite INTEGER NOT NULL,\n"
                "  source_scheme INTEGER NOT NULL,\n"
                "  source_port INTEGER NOT NULL,\n"
                "  last_update_utc INTEGER NOT NULL\n"
                ");"
            ),
            "firefox": (
                "CREATE TABLE moz_cookies (\n"
                "  id INTEGER PRIMARY KEY,\n"
                "  originAttributes TEXT NOT NULL DEFAULT \'\',\n"
                "  name TEXT,\n"
                "  value TEXT,\n"
                "  host TEXT,\n"
                "  path TEXT,\n"
                "  expiry INTEGER,\n"
                "  lastAccessed INTEGER,\n"
                "  creationTime INTEGER,\n"
                "  isSecure INTEGER,\n"
                "  isHttpOnly INTEGER,\n"
                "  inBrowserElement INTEGER DEFAULT 0,\n"
                "  sameSite INTEGER DEFAULT 0,\n"
                "  rawSameSite INTEGER DEFAULT 0,\n"
                "  schemeMap INTEGER DEFAULT 0\n"
                ");"
            ),
            "edge": (
                "-- Edge uses the same schema as Chrome\n"
                "-- See Chrome schema above"
            ),
        }
        return schemas.get(browser.lower(), "Schema not available for this browser.")
