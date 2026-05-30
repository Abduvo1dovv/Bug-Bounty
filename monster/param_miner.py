"""
Monster v2.0.0 Parameter Mining Module

Comprehensive parameter discovery, reflection detection, input vector mapping,
form extraction, and parameter categorization for web application security
testing and bug bounty reconnaissance.
"""

import os
import re
import sys
import json
import time
import random
import string
import hashlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote, unquote, parse_qs, parse_qsl, urljoin
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
from html.parser import HTMLParser

from monster.utils import ColorOutput, HTTPClient, FileManager, RateLimiter, normalize_url, domain_from_url
from monster.config import DEFAULT_USER_AGENT, TIMEOUT


# =============================================================================
# PARAM MINER MAIN ORCHESTRATOR
# =============================================================================

class ParamMiner:
    """
    Main parameter mining orchestrator.

    Coordinates hidden parameter discovery, reflection detection,
    input vector mapping, and form extraction across target URLs.
    Aggregates results from all sub-modules into a unified report.
    """

    def __init__(self, targets=None, output_dir=None, options=None):
        """
        Initialize the parameter miner.

        Args:
            targets: List of target URLs to analyze.
            output_dir: Directory for output files.
            options: Optional configuration dict.
        """
        self._targets = targets or []
        self._output_dir = output_dir or "monster_output"
        self._options = options or {}
        self._color = ColorOutput()
        self._file_manager = FileManager(self._output_dir)
        self._rate_limiter = RateLimiter(delay=self._options.get("delay", 1.0))
        self._http_client = HTTPClient(
            user_agent=self._options.get("user_agent"),
            timeout=self._options.get("timeout", TIMEOUT),
            proxy=self._options.get("proxy"),
            rate_limiter=self._rate_limiter,
        )
        self._discovery = HiddenParamDiscovery(self._http_client)
        self._reflection = ParamReflectionDetector(self._http_client)
        self._mapper = InputVectorMapper(self._http_client)
        self._form_extractor = FormExtractor()
        self._categorizer = URLParamCategorizer()
        self._results = {}

    def run(self):
        """
        Run parameter mining against all targets.

        Returns:
            Dictionary with results for each target URL.
        """
        self._color.section_header("Parameter Mining")
        self._color.info(f"Targets: {len(self._targets)} URLs")
        results = {}
        for i, target in enumerate(self._targets):
            self._color.progress(i + 1, len(self._targets), "Mining params")
            target_result = self._analyze_target(target)
            results[target] = target_result
        self._results = results
        self._save_results()
        return results

    def _analyze_target(self, url):
        """Analyze a single target URL for parameters."""
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "existing_params": [],
            "hidden_params": [],
            "reflected_params": [],
            "input_vectors": {},
            "forms": [],
            "param_categories": {},
        }
        try:
            input_vectors = self._mapper.map_url(url)
            result["input_vectors"] = input_vectors
            result["existing_params"] = input_vectors.get("query_params", [])
            max_params = self._options.get("max_params", 50)
            hidden = self._discovery.discover(url)
            result["hidden_params"] = hidden[:max_params]
            all_params = result["existing_params"] + [p["name"] for p in hidden[:20]]
            for param_item in all_params[:30]:
                pname = param_item if isinstance(param_item, str) else param_item.get("name", "")
                if pname:
                    reflection = self._reflection.check_reflection(url, pname)
                    if reflection.get("reflected"):
                        result["reflected_params"].append(reflection)
            all_param_names = [p if isinstance(p, str) else p.get("name", "") for p in all_params]
            for pname in all_param_names:
                if pname:
                    result["param_categories"][pname] = self._categorizer.categorize(pname)
            response = self._http_client.get(url)
            if response and response.body:
                result["forms"] = self._form_extractor.extract_forms(response.body, url)
        except Exception as e:
            result["error"] = str(e)
            self._color.error(f"Error analyzing {url}: {e}")
        return result

    def _save_results(self):
        """Save mining results to output file."""
        try:
            output_path = os.path.join(self._output_dir, "param_mining_results.json")
            os.makedirs(self._output_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, indent=2, default=str)
            self._color.success(f"Results saved to: {output_path}")
        except Exception as e:
            self._color.error(f"Failed to save results: {e}")

    def get_results(self):
        """Return the mining results."""
        return self._results

    def add_target(self, url):
        """Add a target URL to the list."""
        if url not in self._targets:
            self._targets.append(url)

    def set_targets(self, targets):
        """Replace the target list."""
        self._targets = targets


# =============================================================================
# HIDDEN PARAMETER DISCOVERY CLASS
# =============================================================================

class HiddenParamDiscovery:
    """
    Discover hidden parameters by testing common parameter names.

    Tests URLs with common hidden parameter names and detects changes
    in response that indicate the parameter is accepted by the server.
    Uses a comprehensive wordlist of 200+ parameter names commonly
    found in web applications.
    """

    COMMON_HIDDEN_PARAMS = [
        "debug", "test", "admin", "verbose", "internal", "dev", "staging", "beta",
        "preview", "source", "ref", "callback", "jsonp", "format", "type", "action",
        "cmd", "exec", "query", "search", "filter", "sort", "order", "limit",
        "offset", "page", "id", "uid", "user_id", "account", "token", "key",
        "secret", "password", "pass", "auth", "session", "role", "permissions", "config",
        "settings", "env", "mode", "version", "v", "lang", "locale", "redirect",
        "url", "next", "return", "back", "forward", "goto", "dest", "target",
        "path", "file", "dir", "folder", "download", "upload", "import", "export",
        "backup", "restore", "delete", "remove", "update", "edit", "modify", "create",
        "add", "insert", "register", "login", "logout", "reset", "verify", "confirm",
        "activate", "enable", "disable", "force", "override", "bypass", "skip", "ignore",
        "allow", "deny", "block", "grant", "revoke", "include", "exclude", "hidden",
        "private", "public", "raw", "encoded", "decoded", "compressed", "cached", "proxy",
        "gateway", "upstream", "downstream", "origin", "host", "domain", "subdomain", "port",
        "protocol", "scheme", "method", "endpoint", "route", "controller", "view", "template",
        "render", "compile", "execute", "eval", "process", "transform", "convert", "parse",
        "serialize", "deserialize", "validate", "sanitize", "escape", "unescape", "encrypt", "decrypt",
        "sign", "verify_signature", "hash", "checksum", "nonce", "timestamp", "expire", "ttl",
        "timeout", "delay", "wait", "retry", "max", "min", "count", "total",
        "size", "length", "width", "height", "depth", "level", "priority", "weight",
        "score", "rank", "index", "position", "start", "end", "from", "to",
        "range", "between", "above", "below", "equal", "contains", "matches", "like",
        "regex", "pattern", "format_str", "template_str", "expression", "condition", "flag", "switch",
        "toggle", "option", "param", "arg", "var", "value", "data", "payload",
        "body", "content", "message", "text", "html", "xml", "json_data", "csv_data",
        "sql", "graphql", "rest", "soap", "rpc", "webhook", "callback_url", "notify",
        "alert", "email", "phone", "sms", "push", "log", "trace", "profile",
        "benchmark", "metrics", "stats", "monitor", "health", "status", "info", "about",
        "help", "docs", "api_key", "client_id", "client_secret", "app_id", "app_secret", "consumer_key",
        "consumer_secret", "access_token", "refresh_token", "bearer", "jwt", "oauth", "saml", "openid",
        "sso", "mfa", "otp", "pin", "code", "challenge", "response_type", "grant_type",
        "scope", "state", "nonce_param", "redirect_uri", "response_mode", "display", "prompt", "login_hint",
        "acr_values", "claims", "request_uri", "registration", "userinfo", "introspect", "revoke_token",
    ]

    def __init__(self, http_client=None):
        """
        Initialize hidden parameter discovery.

        Args:
            http_client: HTTPClient instance for making requests.
        """
        self._http_client = http_client or HTTPClient()
        self._color = ColorOutput()
        self._rate_limiter = RateLimiter(delay=0.5)

    def _get_baseline(self, url):
        """Get a baseline response for comparison."""
        try:
            response = self._http_client.get(url)
            if response:
                return {
                    "status_code": response.status_code,
                    "body_length": len(response.body) if response.body else 0,
                    "headers": response.headers,
                    "body_hash": hashlib.md5(response.body.encode()).hexdigest() if response.body else "",
                }
        except Exception:
            pass
        return {"status_code": 0, "body_length": 0, "headers": {}, "body_hash": ""}

    def discover(self, url, params_to_test=None):
        """
        Discover hidden parameters for a URL.

        Tests each parameter from the wordlist and compares the response
        to a baseline to detect accepted parameters.

        Args:
            url: Target URL to test.
            params_to_test: Optional custom parameter list.

        Returns:
            List of discovered hidden parameters with details.
        """
        params = params_to_test or self.COMMON_HIDDEN_PARAMS
        found_params = []
        baseline = self._get_baseline(url)
        if baseline["status_code"] == 0:
            self._color.warning(f"Could not get baseline for: {url}")
            return found_params
        parsed = urlparse(url)
        existing_params = set(dict(parse_qsl(parsed.query)).keys())
        for param in params:
            if param in existing_params:
                continue
            self._rate_limiter.wait()
            is_found = self.test_param(url, param, baseline)
            if is_found:
                found_params.append({
                    "name": param,
                    "url": url,
                    "detection_method": "response_difference",
                    "found_at": datetime.now().isoformat(),
                })
        return found_params

    def test_param(self, url, param_name, baseline=None):
        """
        Test if a specific parameter changes the response.

        Args:
            url: Target URL.
            param_name: Parameter name to test.
            baseline: Optional pre-computed baseline.

        Returns:
            True if the parameter appears to be accepted.
        """
        if baseline is None:
            baseline = self._get_baseline(url)
        canary = "monster" + hashlib.md5(param_name.encode()).hexdigest()[:8]
        parsed = urlparse(url)
        existing_params = parse_qs(parsed.query)
        existing_params[param_name] = [canary]
        new_query = urlencode(existing_params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        try:
            response = self._http_client.get(test_url)
            if not response:
                return False
            status_diff = response.status_code != baseline["status_code"]
            body_len = len(response.body) if response.body else 0
            size_diff = abs(body_len - baseline["body_length"]) > 50
            body_hash = hashlib.md5(response.body.encode()).hexdigest() if response.body else ""
            content_diff = body_hash != baseline["body_hash"]
            if status_diff and response.status_code not in (404, 500, 502, 503):
                return True
            if size_diff and content_diff:
                if response.body and canary in response.body:
                    return True
                if abs(body_len - baseline["body_length"]) > 200:
                    return True
            return False
        except Exception:
            return False

    def get_param_count(self):
        """Return the number of parameters in the wordlist."""
        return len(self.COMMON_HIDDEN_PARAMS)


# =============================================================================
# PARAM REFLECTION DETECTOR CLASS
# =============================================================================

class ParamReflectionDetector:
    """
    Detect reflected parameters in HTTP responses.

    Injects unique canary values into parameters and checks if they
    are reflected in the response body, headers, or attributes.
    Classifies the reflection context to assess XSS potential.
    """

    def __init__(self, http_client=None):
        """Initialize the reflection detector."""
        self._http_client = http_client or HTTPClient()
        self._color = ColorOutput()
        self._rate_limiter = RateLimiter(delay=0.5)

    def generate_canary(self):
        """
        Generate a unique canary value for reflection testing.

        Returns:
            Unique canary string unlikely to appear naturally.
        """
        random_part = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"mstr{random_part}xref"

    def check_reflection(self, url, param_name, canary=None):
        """
        Check if a parameter value is reflected in the response.

        Args:
            url: Target URL.
            param_name: Parameter name to test.
            canary: Optional custom canary value.

        Returns:
            Dictionary with reflection detection results.
        """
        if canary is None:
            canary = self.generate_canary()
        result = {
            "reflected": False,
            "param_name": param_name,
            "canary": canary,
            "contexts": [],
            "count": 0,
            "url": url,
        }
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param_name] = canary
        new_query = urlencode(params)
        test_url = parsed._replace(query=new_query).geturl()
        self._rate_limiter.wait()
        try:
            response = self._http_client.get(test_url)
            if not response or not response.body:
                return result
            body = response.body
            if canary in body:
                result["reflected"] = True
                result["count"] = body.count(canary)
                result["contexts"] = self.classify_context(body, canary)
            for header_name, header_value in (response.headers or {}).items():
                if canary in str(header_value):
                    result["reflected"] = True
                    if "header" not in result["contexts"]:
                        result["contexts"].append("header")
        except Exception as e:
            result["error"] = str(e)
        return result

    def classify_context(self, response_body, canary):
        """
        Classify the reflection context of a canary in the response.

        Args:
            response_body: The full response body HTML.
            canary: The canary string to locate.

        Returns:
            List of context strings: html_body, attribute, js, url, comment, style.
        """
        contexts = []
        body = response_body
        positions = []
        start = 0
        while True:
            pos = body.find(canary, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        for pos in positions:
            context_start = max(0, pos - 200)
            before = body[context_start:pos]
            # Check if inside HTML comment
            if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
                if "comment" not in contexts:
                    contexts.append("comment")
                continue
            # Check if inside script tag
            script_open = before.rfind("<script")
            script_close = before.rfind("</script")
            if script_open > script_close:
                if "js" not in contexts:
                    contexts.append("js")
                continue
            # Check if inside style tag
            style_open = before.rfind("<style")
            style_close = before.rfind("</style")
            if style_open > style_close:
                if "style" not in contexts:
                    contexts.append("style")
                continue
            # Check if inside HTML attribute
            attr_pattern = re.search(
                r'(href|src|action|value|data-[a-z]+|on[a-z]+|style|class|id|name)\s*=\s*["\'][^"\']*$',
                before,
                re.IGNORECASE
            )
            if attr_pattern:
                attr_name = attr_pattern.group(1).lower()
                if attr_name in ("href", "src", "action"):
                    if "url" not in contexts:
                        contexts.append("url")
                elif attr_name.startswith("on"):
                    if "js" not in contexts:
                        contexts.append("js")
                else:
                    if "attribute" not in contexts:
                        contexts.append("attribute")
                continue
            # Check tag vs body context
            last_open = before.rfind("<")
            last_close = before.rfind(">")
            if last_open > last_close:
                if "attribute" not in contexts:
                    contexts.append("attribute")
            else:
                if "html_body" not in contexts:
                    contexts.append("html_body")
        if not contexts and canary in body:
            contexts.append("html_body")
        return contexts

    def scan_url(self, url):
        """
        Scan all existing parameters of a URL for reflection.

        Args:
            url: Target URL with query parameters.

        Returns:
            List of reflected parameters with their contexts.
        """
        reflected = []
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        for param_name in params:
            result = self.check_reflection(url, param_name)
            if result.get("reflected"):
                reflected.append(result)
        return reflected

    def test_special_chars(self, url, param_name):
        """
        Test which special characters are reflected unencoded.

        Args:
            url: Target URL.
            param_name: Parameter to test.

        Returns:
            Dictionary mapping special chars to their reflection status.
        """
        special_chars = {
            "<": "less_than",
            ">": "greater_than",
            '\"': "double_quote",
            "'": "single_quote",
            "&": "ampersand",
            "/": "forward_slash",
            "\\": "backslash",
            "`": "backtick",
            "{": "left_brace",
            "}": "right_brace",
            "(": "left_paren",
            ")": "right_paren",
        }
        results = {}
        for char, name in special_chars.items():
            canary = f"mst{char}ref"
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query))
            params[param_name] = canary
            new_query = urlencode(params)
            test_url = parsed._replace(query=new_query).geturl()
            self._rate_limiter.wait()
            try:
                response = self._http_client.get(test_url)
                if response and response.body:
                    results[name] = {
                        "char": char,
                        "reflected_raw": canary in response.body,
                        "encoded": quote(char) in response.body if canary not in response.body else False,
                    }
                else:
                    results[name] = {"char": char, "reflected_raw": False, "encoded": False}
            except Exception:
                results[name] = {"char": char, "reflected_raw": False, "encoded": False, "error": True}
        return results


# =============================================================================
# INPUT VECTOR MAPPER CLASS
# =============================================================================

class InputVectorMapper:
    """
    Map all input vectors for a given URL.

    Identifies all ways data can be passed to a web endpoint:
    query parameters, form fields, headers, cookies, JSON body
    fields, and URL path segments.
    """

    INTERESTING_HEADERS = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP",
        "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization", "X-Client-IP",
        "True-Client-IP", "Forwarded", "Via", "X-Requested-With",
        "X-HTTP-Method-Override", "X-Method-Override", "X-Original-Method", "Content-Type",
        "Accept", "Accept-Language", "Accept-Encoding", "Origin",
        "Referer", "Host", "X-Host", "X-Forwarded-Server",
        "X-Remote-IP", "X-Remote-Addr", "X-ProxyUser-Ip", "Client-IP",
        "CF-Connecting-IP", "Fastly-Client-IP", "X-Cluster-Client-IP",
    ]

    def __init__(self, http_client=None):
        """Initialize the input vector mapper."""
        self._http_client = http_client or HTTPClient()
        self._color = ColorOutput()

    def map_url(self, url):
        """
        Map all input vectors for a URL.

        Args:
            url: Target URL to analyze.

        Returns:
            Dictionary with all identified input vectors.
        """
        result = {
            "url": url,
            "query_params": self.extract_query_params(url),
            "path_segments": self.extract_path_segments(url),
            "headers_of_interest": self.extract_headers_of_interest(),
            "json_params": [],
            "response_cookies": [],
            "content_type": "",
            "allows_methods": [],
        }
        try:
            response = self._http_client.get(url)
            if response:
                ct = response.headers.get("content-type", "") if response.headers else ""
                result["content_type"] = ct
                set_cookie = response.headers.get("set-cookie", "") if response.headers else ""
                if set_cookie:
                    result["response_cookies"] = self._parse_cookie_names(set_cookie)
                if response.body:
                    result["json_params"] = self.identify_json_params(url, response.body)
        except Exception as e:
            result["error"] = str(e)
        return result

    def extract_query_params(self, url):
        """
        Extract query parameters from a URL.

        Args:
            url: URL to parse.

        Returns:
            List of dicts with name and value keys.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        return [{"name": name, "value": value} for name, value in params]

    def extract_path_segments(self, url):
        """
        Extract and analyze URL path segments.

        Identifies segments that might be parameters (IDs, slugs, etc.).

        Args:
            url: URL to parse.

        Returns:
            List of path segment analysis dicts.
        """
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if not path:
            return []
        segments = path.split("/")
        results = []
        for i, segment in enumerate(segments):
            seg_info = {"position": i, "value": segment, "type": "static", "is_parameter": False}
            if re.match(r"^\\d+$", segment):
                seg_info["type"] = "numeric_id"
                seg_info["is_parameter"] = True
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", segment, re.IGNORECASE):
                seg_info["type"] = "uuid"
                seg_info["is_parameter"] = True
            elif re.match(r"^[0-9a-f]{20,64}$", segment, re.IGNORECASE):
                seg_info["type"] = "hash"
                seg_info["is_parameter"] = True
            elif "." in segment and len(segment.split(".")[-1]) <= 5:
                seg_info["type"] = "filename"
                seg_info["is_parameter"] = True
            elif re.match(r"^[A-Za-z0-9+/=]{10,}$", segment) and len(segment) > 15:
                seg_info["type"] = "base64"
                seg_info["is_parameter"] = True
            elif re.match(r"^v\\d+(\\.\\d+)*$", segment):
                seg_info["type"] = "version"
            elif "-" in segment and len(segment) > 5:
                seg_info["type"] = "slug"
                seg_info["is_parameter"] = True
            elif "%" in segment:
                seg_info["type"] = "encoded"
                seg_info["is_parameter"] = True
            results.append(seg_info)
        return results

    def extract_headers_of_interest(self):
        """Return list of headers that may be processed as input."""
        return list(self.INTERESTING_HEADERS)

    def identify_json_params(self, url, response_body=None):
        """
        Identify JSON parameters from response body analysis.

        Args:
            url: Target URL.
            response_body: Optional pre-fetched response body.

        Returns:
            List of identified JSON parameter names with types.
        """
        params = []
        body = response_body
        if not body:
            try:
                response = self._http_client.get(url)
                body = response.body if response else ""
            except Exception:
                return params
        if not body:
            return params
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key, value in data.items():
                    params.append({"name": key, "type": type(value).__name__})
            return params
        except (json.JSONDecodeError, ValueError):
            pass
        json_patterns = [
            r'var\s+\w+\s*=\s*(\{[^}]{5,}\})',
            r'data\s*[=:]\s*(\{[^}]{5,}\})',
            r'config\s*[=:]\s*(\{[^}]{5,}\})',
        ]
        for pattern in json_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches[:5]:
                try:
                    obj = json.loads(match)
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if not any(p["name"] == key for p in params):
                                params.append({"name": key, "type": type(value).__name__})
                except (json.JSONDecodeError, ValueError):
                    continue
        return params

    def _parse_cookie_names(self, set_cookie_header):
        """Extract cookie names from Set-Cookie header."""
        names = []
        for part in set_cookie_header.split(","):
            part = part.strip()
            if "=" in part:
                name = part.split("=")[0].strip()
                if name.lower() not in ("path", "domain", "expires", "max-age", "samesite"):
                    names.append(name)
        return names


# =============================================================================
# FORM EXTRACTOR CLASS
# =============================================================================

class FormExtractor:
    """
    Parse and analyze HTML forms.

    Extracts form details including action URLs, methods, input fields,
    hidden fields, CSRF tokens, and file upload indicators. Classifies
    form purpose for security analysis prioritization.
    """

    def __init__(self):
        """Initialize the form extractor."""
        self._color = ColorOutput()

    def extract_forms(self, html_content, base_url=""):
        """
        Extract all forms from HTML content.

        Args:
            html_content: HTML source code.
            base_url: Base URL for resolving relative action URLs.

        Returns:
            List of form dictionaries with complete details.
        """
        forms = []
        form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
        for match in form_pattern.finditer(html_content):
            form_html = match.group(0)
            form_data = self.parse_form(form_html, base_url)
            if form_data:
                forms.append(form_data)
        return forms

    def parse_form(self, form_html, base_url=""):
        """
        Parse a single HTML form into structured data.

        Args:
            form_html: HTML string containing the form element.
            base_url: Base URL for resolving relative URLs.

        Returns:
            Dictionary with form details.
        """
        result = {
            "action": "", "method": "GET", "enctype": "",
            "id": "", "name": "", "fields": [],
            "hidden_fields": [], "buttons": [],
            "has_file_upload": False, "has_csrf_token": False,
            "purpose": "unknown", "textarea_fields": [], "select_fields": [],
        }
        # Extract form tag attributes
        form_tag_match = re.match(r"<form([^>]*)>", form_html, re.IGNORECASE)
        if form_tag_match:
            attrs = form_tag_match.group(1)
            action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if action_m:
                action = action_m.group(1)
                if base_url and not action.startswith(("http://", "https://", "//")):
                    action = urljoin(base_url, action)
                result["action"] = action
            method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if method_m:
                result["method"] = method_m.group(1).upper()
            enctype_m = re.search(r'enctype\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if enctype_m:
                result["enctype"] = enctype_m.group(1)
            id_m = re.search(r'id\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if id_m:
                result["id"] = id_m.group(1)
            name_m = re.search(r'name\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            if name_m:
                result["name"] = name_m.group(1)
        # Extract input fields
        input_pattern = re.compile(r"<input([^>]*)/?\s*>", re.IGNORECASE)
        for input_match in input_pattern.finditer(form_html):
            attrs = input_match.group(1)
            field = self._parse_input_attrs(attrs)
            ftype = field.get("type", "").lower()
            if ftype == "hidden":
                result["hidden_fields"].append(field)
            elif ftype in ("submit", "button", "image"):
                result["buttons"].append(field)
            elif ftype == "file":
                result["fields"].append(field)
                result["has_file_upload"] = True
            else:
                result["fields"].append(field)
        # Extract textarea fields
        ta_pattern = re.compile(r"<textarea([^>]*)>(.*?)</textarea>", re.DOTALL | re.IGNORECASE)
        for ta_match in ta_pattern.finditer(form_html):
            field = self._parse_input_attrs(ta_match.group(1))
            field["type"] = "textarea"
            field["value"] = ta_match.group(2).strip()
            result["textarea_fields"].append(field)
            result["fields"].append(field)
        # Extract select fields
        sel_pattern = re.compile(r"<select([^>]*)>(.*?)</select>", re.DOTALL | re.IGNORECASE)
        for sel_match in sel_pattern.finditer(form_html):
            field = self._parse_input_attrs(sel_match.group(1))
            field["type"] = "select"
            field["options"] = self._parse_select_options(sel_match.group(2))
            result["select_fields"].append(field)
            result["fields"].append(field)
        # Check for CSRF tokens
        csrf_tokens = self.detect_csrf_tokens(result)
        result["has_csrf_token"] = len(csrf_tokens) > 0
        result["csrf_tokens"] = csrf_tokens
        result["purpose"] = self.classify_form_purpose(result)
        return result

    def _parse_input_attrs(self, attrs_str):
        """Parse input element attributes."""
        field = {"type": "text", "name": "", "value": "", "id": "", "placeholder": "", "required": False}
        type_m = re.search(r'type\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if type_m:
            field["type"] = type_m.group(1).lower()
        name_m = re.search(r'name\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if name_m:
            field["name"] = name_m.group(1)
        value_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if value_m:
            field["value"] = value_m.group(1)
        id_m = re.search(r'id\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if id_m:
            field["id"] = id_m.group(1)
        ph_m = re.search(r'placeholder\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if ph_m:
            field["placeholder"] = ph_m.group(1)
        if "required" in attrs_str.lower():
            field["required"] = True
        return field

    def _parse_select_options(self, options_html):
        """Parse select element options."""
        options = []
        opt_pattern = re.compile(r"<option([^>]*)>(.*?)</option>", re.DOTALL | re.IGNORECASE)
        for opt_match in opt_pattern.finditer(options_html):
            attrs = opt_match.group(1)
            text = opt_match.group(2).strip()
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            value = val_m.group(1) if val_m else text
            selected = "selected" in attrs.lower()
            options.append({"value": value, "text": text, "selected": selected})
        return options

    def detect_csrf_tokens(self, form):
        """
        Detect CSRF protection tokens in a form.

        Args:
            form: Parsed form dictionary.

        Returns:
            List of detected CSRF token fields.
        """
        csrf_patterns = [
            "csrf", "xsrf", "_token", "csrftoken", "csrf_token",
            "xsrf_token", "anti_csrf", "authenticity_token",
            "verification_token", "__requestverificationtoken",
            "csrfmiddlewaretoken", "form_token", "secure_token",
        ]
        tokens = []
        for field in form.get("hidden_fields", []):
            name = field.get("name", "").lower()
            for pattern in csrf_patterns:
                if pattern in name:
                    tokens.append({"name": field.get("name", ""), "value": field.get("value", ""), "pattern_matched": pattern})
                    break
        return tokens

    def detect_file_uploads(self, form):
        """
        Detect file upload fields in a form.

        Args:
            form: Parsed form dictionary.

        Returns:
            List of file upload field details.
        """
        uploads = []
        for field in form.get("fields", []):
            if field.get("type", "").lower() == "file":
                uploads.append({"name": field.get("name", ""), "id": field.get("id", "")})
        if form.get("enctype") == "multipart/form-data" and not uploads:
            uploads.append({"note": "Form uses multipart/form-data but no file input found"})
        return uploads

    def classify_form_purpose(self, form):
        """
        Classify the likely purpose of a form.

        Args:
            form: Parsed form dictionary.

        Returns:
            String classification of form purpose.
        """
        all_field_names = []
        for field in form.get("fields", []) + form.get("hidden_fields", []):
            name = field.get("name", "").lower()
            if name:
                all_field_names.append(name)
        field_types = [f.get("type", "").lower() for f in form.get("fields", [])]
        action = form.get("action", "").lower()
        has_password = "password" in field_types or any("pass" in n for n in all_field_names)
        has_username = any(n in all_field_names for n in ["username", "user", "email", "login", "user_id"])
        if has_password and has_username:
            if any(n in all_field_names for n in ["confirm_password", "password_confirm", "password2"]):
                return "register"
            if any(p in action for p in ["register", "signup", "sign_up", "create_account"]):
                return "register"
            return "login"
        if any(n in all_field_names for n in ["q", "query", "search", "keyword", "term", "s"]):
            return "search"
        if "search" in action:
            return "search"
        if form.get("has_file_upload"):
            return "upload"
        if any(n in all_field_names for n in ["message", "body", "comment", "feedback"]):
            if any(n in all_field_names for n in ["email", "name", "subject"]):
                return "contact"
        if any(p in action for p in ["settings", "profile", "preferences", "account"]):
            return "settings"
        if any(n in all_field_names for n in ["card", "credit_card", "cvv", "expiry", "billing"]):
            return "payment"
        if has_password and not has_username:
            if any(p in action for p in ["reset", "forgot", "recover", "change_password"]):
                return "password_reset"
        return "unknown"

    def extract_hidden_fields(self, form):
        """
        Extract all hidden fields from a form.

        Args:
            form: Parsed form dictionary.

        Returns:
            List of hidden field name/value pairs.
        """
        return form.get("hidden_fields", [])


# =============================================================================
# URL PARAMETER CATEGORIZER CLASS
# =============================================================================

class URLParamCategorizer:
    """
    Categorize URL parameters by their likely purpose.

    Classifies parameters into categories (identifier, filter, pagination,
    sort, auth, file_path, redirect, search, debug) and detects parameters
    that may be prone to specific vulnerability classes.
    """

    IDENTIFIER_PATTERNS = [
        "id", "uid", "user_id", "userid", "account_id", "accountid",
        "item_id", "itemid", "product_id", "productid", "order_id", "orderid",
        "invoice_id", "doc_id", "document_id", "post_id", "comment_id", "thread_id",
        "message_id", "msg_id", "ref", "reference", "number", "num",
        "no", "pk", "key", "uuid", "guid", "hash",
        "slug", "handle", "sku", "code", "serial",
    ]

    FILTER_PATTERNS = [
        "filter", "status", "state", "type", "category", "cat",
        "tag", "label", "group", "class", "kind", "genre",
        "color", "size", "brand", "model", "year", "month",
        "day", "date", "from_date", "to_date", "date_from", "date_to",
        "created", "updated", "modified", "active", "enabled", "disabled",
        "verified", "approved", "pending", "published", "draft", "archived",
        "deleted", "visible",
    ]

    PAGINATION_PATTERNS = [
        "page", "p", "pg", "offset", "skip", "start",
        "cursor", "after", "before", "next", "prev", "previous",
        "limit", "per_page", "perpage", "page_size", "pagesize", "count",
        "max_results", "max_items", "first", "last",
    ]

    SORT_PATTERNS = [
        "sort", "order", "orderby", "order_by", "sortby", "sort_by",
        "direction", "dir", "asc", "desc", "sort_order", "sort_field",
        "sort_column", "rank", "priority", "weight",
    ]

    AUTH_PATTERNS = [
        "token", "auth", "api_key", "apikey", "key", "secret",
        "session", "sid", "access_token", "refresh_token", "bearer", "jwt",
        "oauth_token", "client_id", "client_secret", "app_id", "app_key", "password",
        "pass", "passwd", "credentials", "username", "user", "login",
    ]

    FILE_PATH_PATTERNS = [
        "file", "path", "filepath", "filename", "dir", "directory",
        "folder", "document", "doc", "attachment", "upload", "download",
        "resource", "asset", "image", "img", "src", "source",
        "template", "include", "require", "load", "read", "view",
        "display", "show", "open", "fetch", "get_file", "page_file",
        "content_file", "config_file",
    ]

    REDIRECT_PATTERNS = [
        "redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnurl",
        "return_to", "returnto", "next", "next_url", "goto", "go",
        "url", "uri", "dest", "destination", "target", "link",
        "to", "out", "forward", "fwd", "continue", "continue_url",
        "back", "back_url", "callback", "callback_url", "redir", "rurl",
        "location", "checkout_url", "success_url", "cancel_url", "error_url", "logout_redirect",
        "post_login", "landing",
    ]

    SEARCH_PATTERNS = [
        "q", "query", "search", "keyword", "keywords", "term",
        "terms", "find", "lookup", "s", "text", "input",
        "phrase", "contains", "match", "like", "pattern",
    ]

    DEBUG_PATTERNS = [
        "debug", "test", "testing", "dev", "development", "verbose",
        "trace", "log", "logging", "profile", "profiling", "benchmark",
        "timing", "internal", "admin", "mode", "env", "environment",
        "config", "version", "v", "show_errors", "display_errors", "error_reporting",
    ]

    def __init__(self):
        """Initialize the URL parameter categorizer."""
        self._color = ColorOutput()

    def categorize(self, param_name):
        """
        Categorize a parameter by its name.

        Args:
            param_name: The parameter name to categorize.

        Returns:
            Category string.
        """
        name_lower = param_name.lower()
        if any(p == name_lower or p in name_lower for p in self.REDIRECT_PATTERNS):
            return "redirect"
        if any(p == name_lower or p in name_lower for p in self.AUTH_PATTERNS):
            return "auth"
        if any(p == name_lower or p in name_lower for p in self.FILE_PATH_PATTERNS):
            return "file_path"
        if any(p == name_lower or p in name_lower for p in self.DEBUG_PATTERNS):
            return "debug"
        if any(p == name_lower or p in name_lower for p in self.SEARCH_PATTERNS):
            return "search"
        if any(p == name_lower or p in name_lower for p in self.PAGINATION_PATTERNS):
            return "pagination"
        if any(p == name_lower or p in name_lower for p in self.SORT_PATTERNS):
            return "sort"
        if any(p == name_lower or p in name_lower for p in self.IDENTIFIER_PATTERNS):
            return "identifier"
        if any(p == name_lower or p in name_lower for p in self.FILTER_PATTERNS):
            return "filter"
        return "unknown"

    def detect_idor_prone(self, params):
        """
        Detect parameters that may be prone to IDOR vulnerabilities.

        Args:
            params: List of parameter names.

        Returns:
            List of IDOR-prone parameters with risk assessment.
        """
        idor_indicators = [
            "id", "uid", "user_id", "userid", "account_id", "accountid",
            "profile_id", "customer_id", "order_id", "invoice_id", "document_id", "doc_id",
            "file_id", "message_id", "msg_id", "thread_id", "comment_id", "post_id",
            "item_id", "product_id", "ref", "reference", "number", "num",
            "pk", "record_id", "entry_id", "ticket_id", "case_id", "project_id",
            "team_id", "group_id", "org_id", "organization_id", "company_id", "report_id",
            "session_id", "transaction_id", "payment_id",
        ]
        results = []
        for param in params:
            param_lower = param.lower()
            for indicator in idor_indicators:
                if indicator == param_lower or param_lower.endswith("_" + indicator):
                    results.append({
                        "param": param,
                        "risk": "high",
                        "vulnerability": "IDOR",
                        "description": f"Parameter '{param}' appears to reference an internal object.",
                        "test_suggestion": "Increment/change the ID value and check for authorization bypass.",
                    })
                    break
        return results

    def detect_ssrf_prone(self, params):
        """
        Detect parameters that may be prone to SSRF vulnerabilities.

        Args:
            params: List of parameter names.

        Returns:
            List of SSRF-prone parameters with risk assessment.
        """
        ssrf_indicators = [
            "url", "uri", "link", "href", "src", "source",
            "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
            "callback", "callback_url", "webhook", "webhook_url", "feed", "feed_url",
            "rss", "xml_url", "api_url", "endpoint", "host", "hostname",
            "domain", "server", "proxy", "proxy_url", "forward", "forward_url",
            "fetch", "fetch_url", "load", "load_url", "request", "request_url",
            "site", "site_url", "image_url", "img_url", "avatar_url", "icon_url",
            "logo_url", "pdf_url", "document_url", "file_url", "download_url", "upload_url",
        ]
        results = []
        for param in params:
            param_lower = param.lower()
            for indicator in ssrf_indicators:
                if indicator == param_lower or param_lower.endswith("_" + indicator):
                    results.append({
                        "param": param,
                        "risk": "high",
                        "vulnerability": "SSRF",
                        "description": f"Parameter '{param}' may accept URLs for server-side fetching.",
                        "test_suggestion": "Try http://127.0.0.1, http://localhost, cloud metadata endpoints.",
                    })
                    break
        return results

    def detect_injection_prone(self, params):
        """
        Detect parameters that may be prone to injection vulnerabilities.

        Args:
            params: List of parameter names.

        Returns:
            List of injection-prone parameters with risk assessment.
        """
        sql_indicators = [
            "id", "uid", "user_id", "query", "search", "q", "filter", "sort",
            "order", "orderby", "order_by", "where", "column", "table", "field", "select",
            "limit", "offset",
        ]
        cmd_indicators = [
            "cmd", "exec", "command", "execute", "run", "system",
            "shell", "process", "ping", "host", "ip", "filename",
            "file", "path", "dir", "directory", "template", "include",
        ]
        template_indicators = [
            "template", "view", "render", "layout", "theme", "content",
            "text", "message", "body", "subject", "expression", "formula",
            "eval",
        ]
        results = []
        for param in params:
            param_lower = param.lower()
            for indicator in sql_indicators:
                if indicator == param_lower:
                    results.append({
                        "param": param,
                        "risk": "high",
                        "vulnerability": "SQL Injection",
                        "description": f"Parameter '{param}' may be used in database queries.",
                    })
                    break
            for indicator in cmd_indicators:
                if indicator == param_lower:
                    results.append({
                        "param": param,
                        "risk": "critical",
                        "vulnerability": "Command Injection",
                        "description": f"Parameter '{param}' may be used in OS command execution.",
                    })
                    break
            for indicator in template_indicators:
                if indicator == param_lower:
                    results.append({
                        "param": param,
                        "risk": "medium",
                        "vulnerability": "Template Injection (SSTI)",
                        "description": f"Parameter '{param}' may be rendered in a template engine.",
                    })
                    break
        return results

    def full_analysis(self, url):
        """
        Perform full parameter analysis on a URL.

        Args:
            url: URL to analyze.

        Returns:
            Comprehensive analysis dictionary.
        """
        parsed = urlparse(url)
        params = [name for name, _ in parse_qsl(parsed.query)]
        categories = {}
        for param in params:
            categories[param] = self.categorize(param)
        return {
            "url": url,
            "total_params": len(params),
            "params": params,
            "categories": categories,
            "category_counts": self._count_categories(categories),
            "idor_prone": self.detect_idor_prone(params),
            "ssrf_prone": self.detect_ssrf_prone(params),
            "injection_prone": self.detect_injection_prone(params),
        }

    def _count_categories(self, categories):
        """Count parameters per category."""
        counts = {}
        for category in categories.values():
            counts[category] = counts.get(category, 0) + 1
        return counts
