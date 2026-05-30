"""
Monster - JavaScript Intelligence Engine.

Downloads and analyzes JavaScript files from discovered endpoints to extract
API endpoints, secrets, tokens, internal URLs, authentication flows,
GraphQL queries, WebSocket endpoints, and deprecated API versions.
"""

import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from monster.config import PATTERNS
from monster.utils import ColorOutput, FileManager, HTTPClient, normalize_url


# ---------------------------------------------------------------------------
# JSResults dataclass
# ---------------------------------------------------------------------------

@dataclass
class JSResults:
    """Results from JavaScript analysis of a target."""

    target: str
    js_files_found: int = 0
    endpoints: List[dict] = field(default_factory=list)
    secrets: List[dict] = field(default_factory=list)
    auth_flows: List[dict] = field(default_factory=list)
    graphql: List[dict] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    api_versions: dict = field(default_factory=dict)
    debug_info: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Common JS paths to probe
# ---------------------------------------------------------------------------

COMMON_JS_PATHS = [
    "/static/js/bundle.js",
    "/static/js/main.js",
    "/static/js/app.js",
    "/static/js/vendor.js",
    "/assets/js/app.js",
    "/assets/js/main.js",
    "/assets/js/vendor.js",
    "/dist/bundle.js",
    "/dist/app.js",
    "/dist/main.js",
    "/bundle.js",
    "/app.js",
    "/main.js",
    "/vendor.js",
    "/runtime.js",
    "/polyfills.js",
]


# ---------------------------------------------------------------------------
# JSAnalyzer class
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """JavaScript Intelligence Engine for bug bounty reconnaissance."""

    MAX_JS_SIZE = 10 * 1024 * 1024  # 10MB

    def __init__(self, targets: List[str], output_dir: str,
                 options: dict = None):
        self.targets = targets
        self.output_dir = output_dir
        self.options = options or {}
        self.http = HTTPClient(verify_ssl=False)
        self.file_manager = FileManager(output_dir)

    # ------------------------------------------------------------------
    # JS File Discovery
    # ------------------------------------------------------------------

    def discover_js_files(self, url: str) -> List[str]:
        """
        Discover JavaScript files from a target URL.

        Fetches the HTML page and parses for <script src="..."> tags.
        Also checks common JS paths and looks for .map source maps.

        Args:
            url: The target URL to analyze.

        Returns:
            List of absolute JS file URLs.
        """
        url = normalize_url(url)
        js_urls = set()

        # Fetch the page and parse script tags
        response = self.http.get(url)
        if response:
            status, headers, body = response
            if status == 200 and body:
                # Parse <script src="..."> tags
                script_pattern = re.compile(
                    r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
                    re.IGNORECASE
                )
                for match in script_pattern.finditer(body):
                    src = match.group(1)
                    abs_url = self._make_absolute(src, url)
                    if abs_url and self._is_js_url(abs_url):
                        js_urls.add(abs_url)

        # Check common JS paths
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in COMMON_JS_PATHS:
            js_urls.add(base + path)

        # Check for webpack chunk patterns
        webpack_patterns = [
            "/static/js/0.chunk.js",
            "/static/js/1.chunk.js",
            "/static/js/2.chunk.js",
        ]
        for path in webpack_patterns:
            js_urls.add(base + path)

        # Add .map source map URLs for each discovered JS file
        map_urls = set()
        for js_url in js_urls:
            map_urls.add(js_url + ".map")
        js_urls.update(map_urls)

        return list(js_urls)

    def _make_absolute(self, src: str, base_url: str) -> Optional[str]:
        """Convert a relative URL to absolute."""
        if not src:
            return None
        # Skip data URIs and inline scripts
        if src.startswith("data:") or src.startswith("javascript:"):
            return None
        # Already absolute
        if src.startswith("http://") or src.startswith("https://"):
            return src
        # Protocol-relative
        if src.startswith("//"):
            parsed = urllib.parse.urlparse(base_url)
            return f"{parsed.scheme}:{src}"
        # Relative URL
        return urllib.parse.urljoin(base_url, src)

    def _is_js_url(self, url: str) -> bool:
        """Check if a URL likely points to a JavaScript file."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        return (
            path.endswith(".js")
            or path.endswith(".mjs")
            or path.endswith(".jsx")
            or ".js?" in path
            or "/js/" in path
        )

    # ------------------------------------------------------------------
    # JS Content Downloader
    # ------------------------------------------------------------------

    def download_js(self, url: str) -> Optional[str]:
        """
        Download JavaScript file content.

        Skips files larger than 10MB.

        Args:
            url: URL of the JS file to download.

        Returns:
            Content string or None on failure.
        """
        response = self.http.get(url)
        if not response:
            return None

        status, headers, body = response
        if status != 200:
            return None

        # Check content length if available
        content_length = headers.get("Content-Length") or headers.get(
            "content-length", "0"
        )
        try:
            if int(content_length) > self.MAX_JS_SIZE:
                ColorOutput.warning(
                    f"Skipping {url} - exceeds 10MB size limit"
                )
                return None
        except (ValueError, TypeError):
            pass

        # Check actual body size
        if len(body) > self.MAX_JS_SIZE:
            ColorOutput.warning(f"Skipping {url} - exceeds 10MB size limit")
            return None

        return body

    # ------------------------------------------------------------------
    # API Endpoint Extraction
    # ------------------------------------------------------------------

    def extract_endpoints(self, content: str) -> List[dict]:
        """
        Extract API endpoints from JavaScript content.

        Looks for fetch(), axios, $.ajax, XMLHttpRequest patterns,
        relative/absolute URLs, and route definitions.

        Args:
            content: JavaScript source content.

        Returns:
            List of endpoint dicts with type and value.
        """
        endpoints = []
        seen = set()

        # fetch('/path') and fetch("/path")
        fetch_pattern = re.compile(
            r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""", re.IGNORECASE
        )
        for m in fetch_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "fetch", "value": val})

        # axios.get('/path'), axios.post('/path'), etc.
        axios_pattern = re.compile(
            r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)"""
            r"""\s*\(\s*['"`]([^'"`\s]+)['"`]""",
            re.IGNORECASE,
        )
        for m in axios_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "axios", "value": val})

        # $.ajax({url: '/path'})
        ajax_pattern = re.compile(
            r"""\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""",
            re.IGNORECASE,
        )
        for m in ajax_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "ajax", "value": val})

        # XMLHttpRequest .open("GET", "/path")
        xhr_pattern = re.compile(
            r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]"""
            r"""\s*,\s*['"`]([^'"`]+)['"`]""",
            re.IGNORECASE,
        )
        for m in xhr_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "xhr", "value": val})

        # Relative API URLs: /api/v[0-9]+/..., /api/..., /v[0-9]+/...
        api_pattern = re.compile(
            r"""['"`](/(?:api/v\d+|api|v\d+)/[^\s'"`<>{}]+)['"`]"""
        )
        for m in api_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "api_path", "value": val})

        # Absolute URLs in strings
        abs_url_pattern = re.compile(
            r"""['"`](https?://[^\s'"`<>{}]+)['"`]"""
        )
        for m in abs_url_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "url", "value": val})

        # Route definitions: path: "/...", route: "/..."
        route_pattern = re.compile(
            r"""(?:path|route)\s*:\s*['"`](/[^\s'"`]+)['"`]""",
            re.IGNORECASE,
        )
        for m in route_pattern.finditer(content):
            val = m.group(1)
            if val not in seen:
                seen.add(val)
                endpoints.append({"type": "route", "value": val})

        return endpoints

    # ------------------------------------------------------------------
    # Secret Extraction
    # ------------------------------------------------------------------

    def extract_secrets_from_content(self, content: str) -> List[dict]:
        """
        Extract secrets from JavaScript content using config PATTERNS.

        For each match, records pattern name, truncated value preview,
        line number, and surrounding context.

        Also detects Firebase config objects (apiKey + authDomain + projectId
        in nearby lines).

        Args:
            content: JavaScript source content.

        Returns:
            List of dicts with type, value_preview, context, and line.
        """
        secrets = []
        lines = content.split("\n")

        # Check each pattern from config
        for pattern_name, pattern_regex in PATTERNS.items():
            try:
                compiled = re.compile(pattern_regex)
            except re.error:
                continue

            for line_num, line in enumerate(lines, 1):
                for m in compiled.finditer(line):
                    matched_value = m.group(0)
                    value_preview = self._truncate_secret(matched_value)

                    # Get context (10 chars before and after)
                    start = max(0, m.start() - 10)
                    end = min(len(line), m.end() + 10)
                    context = line[start:end]

                    secrets.append({
                        "type": pattern_name,
                        "value_preview": value_preview,
                        "context": context,
                        "line": line_num,
                    })

        # Special detection for Firebase config objects
        firebase_secrets = self._detect_firebase_config(content, lines)
        secrets.extend(firebase_secrets)

        return secrets

    def _truncate_secret(self, value: str) -> str:
        """Truncate a secret to show only first/last 4 chars."""
        if len(value) <= 12:
            return value[:4] + "..." + value[-4:]
        return value[:4] + "..." + value[-4:]

    def _detect_firebase_config(self, content: str,
                                lines: List[str]) -> List[dict]:
        """Detect Firebase config objects with multiple keys together."""
        findings = []

        # Look for Firebase config pattern: apiKey + authDomain + projectId
        # within a window of nearby lines
        firebase_keys = ["apiKey", "authDomain", "projectId"]
        window_size = 10

        for i, line in enumerate(lines):
            if "apiKey" in line:
                # Check surrounding lines for other Firebase keys
                start = max(0, i - window_size)
                end = min(len(lines), i + window_size)
                window = "\n".join(lines[start:end])

                found_keys = [k for k in firebase_keys if k in window]
                if len(found_keys) >= 3:
                    findings.append({
                        "type": "Firebase Config Object",
                        "value_preview": "Firebase config detected",
                        "context": f"Keys found: {', '.join(found_keys)}",
                        "line": i + 1,
                    })
                    break  # Only report once per content

        return findings

    # ------------------------------------------------------------------
    # Authentication Flow Detection
    # ------------------------------------------------------------------

    def detect_auth_flows(self, content: str) -> List[dict]:
        """
        Detect authentication flow patterns in JavaScript content.

        Looks for OAuth endpoints, JWT patterns, token refresh logic,
        auth headers, session management, and CSRF handling.

        Args:
            content: JavaScript source content.

        Returns:
            List of auth flow finding dicts.
        """
        findings = []
        lines = content.split("\n")

        auth_patterns = {
            "OAuth Endpoint": re.compile(
                r"""['"`/](?:oauth|authorize|/auth/|/token)['"`/]""",
                re.IGNORECASE,
            ),
            "JWT Operation": re.compile(
                r"""jwt\s*\.\s*(?:decode|verify|sign)|jsonwebtoken""",
                re.IGNORECASE,
            ),
            "Token Refresh": re.compile(
                r"""refresh[_-]?token|refreshToken|/token/refresh""",
                re.IGNORECASE,
            ),
            "Auth Header": re.compile(
                r"""Authorization\s*:\s*Bearer|x-auth-token|x-api-key""",
                re.IGNORECASE,
            ),
            "Session Storage": re.compile(
                r"""sessionStorage|localStorage\s*\.\s*getItem\s*\(\s*['"`]token['"`]\)|document\.cookie""",
                re.IGNORECASE,
            ),
            "CSRF Token": re.compile(
                r"""csrf|_csrf|X-CSRF-Token|csrftoken""", re.IGNORECASE
            ),
        }

        for line_num, line in enumerate(lines, 1):
            for flow_type, pattern in auth_patterns.items():
                if pattern.search(line):
                    findings.append({
                        "type": flow_type,
                        "line": line_num,
                        "context": line.strip()[:100],
                    })

        # Deduplicate by type + context
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["context"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    # ------------------------------------------------------------------
    # GraphQL Detection
    # ------------------------------------------------------------------

    def detect_graphql(self, content: str) -> List[dict]:
        """
        Detect GraphQL queries, mutations, and endpoints in JS content.

        Finds gql`...` template literals, query/mutation patterns,
        GraphQL endpoint URLs, and introspection queries.

        Args:
            content: JavaScript source content.

        Returns:
            List of GraphQL finding dicts with type and value.
        """
        findings = []
        seen = set()

        # gql`...` template literals
        gql_pattern = re.compile(r"gql\s*`([^`]+)`", re.DOTALL)
        for m in gql_pattern.finditer(content):
            val = m.group(1).strip()[:200]
            key = ("query", val[:50])
            if key not in seen:
                seen.add(key)
                findings.append({"type": "query", "value": val})

        # query { ... } and mutation { ... } patterns
        query_pattern = re.compile(
            r"\b(query|mutation)\s+\w*\s*(?:\([^)]*\))?\s*\{",
            re.IGNORECASE,
        )
        for m in query_pattern.finditer(content):
            # Get some context after the match
            start = m.start()
            end = min(len(content), start + 200)
            val = content[start:end]
            op_type = m.group(1).lower()
            key = (op_type, val[:50])
            if key not in seen:
                seen.add(key)
                findings.append({"type": op_type, "value": val})

        # GraphQL endpoint URLs
        endpoint_pattern = re.compile(
            r"""['"`]((?:https?://[^\s'"`]*)?/(?:graphql|gql|api/graphql)[^\s'"`]*)['"`]""",
            re.IGNORECASE,
        )
        for m in endpoint_pattern.finditer(content):
            val = m.group(1)
            key = ("endpoint", val)
            if key not in seen:
                seen.add(key)
                findings.append({"type": "endpoint", "value": val})

        # Introspection queries
        introspection_pattern = re.compile(
            r"__schema|__type|IntrospectionQuery", re.IGNORECASE
        )
        for m in introspection_pattern.finditer(content):
            val = m.group(0)
            key = ("introspection", val)
            if key not in seen:
                seen.add(key)
                findings.append({"type": "introspection", "value": val})

        return findings

    # ------------------------------------------------------------------
    # WebSocket Detection
    # ------------------------------------------------------------------

    def detect_websockets(self, content: str) -> List[str]:
        """
        Detect WebSocket endpoint URLs in JavaScript content.

        Finds ws:// and wss:// URLs, new WebSocket() calls,
        socket.io connections, and SockJS patterns.

        Args:
            content: JavaScript source content.

        Returns:
            List of WebSocket endpoint URL strings.
        """
        ws_urls = set()

        # ws:// and wss:// URLs
        ws_url_pattern = re.compile(r"""wss?://[^\s'"`<>{}]+""")
        for m in ws_url_pattern.finditer(content):
            ws_urls.add(m.group(0).rstrip("'\"`,);"))

        # new WebSocket('...')
        ws_constructor_pattern = re.compile(
            r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE
        )
        for m in ws_constructor_pattern.finditer(content):
            ws_urls.add(m.group(1))

        # socket.io: io.connect('...'), io('...')
        socketio_pattern = re.compile(
            r"""io\s*(?:\.connect)?\s*\(\s*['"`]([^'"`]+)['"`]""",
            re.IGNORECASE,
        )
        for m in socketio_pattern.finditer(content):
            ws_urls.add(m.group(1))

        # SockJS: new SockJS('...')
        sockjs_pattern = re.compile(
            r"""new\s+SockJS\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE
        )
        for m in sockjs_pattern.finditer(content):
            ws_urls.add(m.group(1))

        return list(ws_urls)

    # ------------------------------------------------------------------
    # API Version Detection
    # ------------------------------------------------------------------

    def detect_api_versions(self, content: str) -> dict:
        """
        Detect API versions referenced in JavaScript content.

        Finds /api/v1/, /api/v2/, /v1/, /v2/ patterns, groups by
        base path, and flags potentially deprecated older versions.

        Args:
            content: JavaScript source content.

        Returns:
            Dict with version_map and deprecated list.
        """
        version_pattern = re.compile(
            r"""(/(?:api/)?v(\d+)/[^\s'"`<>{}]*)""", re.IGNORECASE
        )

        version_map = {}  # base_path -> set of versions

        for m in version_pattern.finditer(content):
            full_path = m.group(1)
            version_num = int(m.group(2))

            # Extract base path (everything after /vN/)
            base_match = re.match(
                r"/(?:api/)?v\d+/(.+)", full_path, re.IGNORECASE
            )
            if base_match:
                base_path = base_match.group(1).split("?")[0].rstrip("/")
            else:
                base_path = full_path

            if base_path not in version_map:
                version_map[base_path] = set()
            version_map[base_path].add(version_num)

        # Identify deprecated versions (older versions when newer exist)
        deprecated = []
        serializable_map = {}
        for base_path, versions in version_map.items():
            sorted_versions = sorted(versions)
            serializable_map[base_path] = sorted_versions
            if len(sorted_versions) > 1:
                max_version = sorted_versions[-1]
                for v in sorted_versions[:-1]:
                    deprecated.append({
                        "path": base_path,
                        "version": f"v{v}",
                        "latest": f"v{max_version}",
                        "note": "Potentially deprecated - newer version exists",
                    })

        return {
            "version_map": serializable_map,
            "deprecated": deprecated,
        }

    # ------------------------------------------------------------------
    # Debug/Dev Detection
    # ------------------------------------------------------------------

    def detect_debug_info(self, content: str) -> List[dict]:
        """
        Detect debug and development artifacts in JavaScript content.

        Finds console.log with variable content, debugger statements,
        TODO/FIXME/HACK/XXX comments, sourceMappingURL references,
        and __DEV__/NODE_ENV checks that leak in production.

        Args:
            content: JavaScript source content.

        Returns:
            List of debug finding dicts.
        """
        findings = []
        lines = content.split("\n")

        debug_patterns = {
            "Console Debug": re.compile(
                r"""console\s*\.\s*(?:log|debug|error)\s*\(\s*(?:[^)]*(?:\$\{|[\w.]+\s*[,+])|['"`][^'"`]*['"`]\s*,\s*\w)""",
                re.IGNORECASE,
            ),
            "Debugger Statement": re.compile(
                r"""\bdebugger\s*;""", re.IGNORECASE
            ),
            "Dev Comment": re.compile(
                r"""(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX)\b[^*]*""",
                re.IGNORECASE,
            ),
            "Source Map Reference": re.compile(
                r"""sourceMappingURL\s*=""", re.IGNORECASE
            ),
            "Dev Mode Check": re.compile(
                r"""__DEV__|process\.env\.NODE_ENV\s*!==\s*['"`]production['"`]""",
                re.IGNORECASE,
            ),
        }

        for line_num, line in enumerate(lines, 1):
            for debug_type, pattern in debug_patterns.items():
                if pattern.search(line):
                    findings.append({
                        "type": debug_type,
                        "line": line_num,
                        "context": line.strip()[:120],
                    })

        # Deduplicate
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["context"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    # ------------------------------------------------------------------
    # Run - Orchestrator
    # ------------------------------------------------------------------

    def run(self) -> List[JSResults]:
        """
        Orchestrate JavaScript analysis for all targets.

        For each target: discover JS files, download them, run all
        extractors, aggregate and deduplicate results, output progress,
        and save results.

        Returns:
            List of JSResults for each target.
        """
        ColorOutput.info("Starting JavaScript Intelligence Engine")
        all_results = []

        for idx, target in enumerate(self.targets, 1):
            ColorOutput.info(
                f"Analyzing target {idx}/{len(self.targets)}: {target}"
            )
            result = self._analyze_target(target)
            all_results.append(result)

            # Summary for this target
            ColorOutput.success(
                f"Target {target}: {result.js_files_found} JS files found"
            )
            ColorOutput.info(
                f"  Endpoints: {len(result.endpoints)}, "
                f"Secrets: {len(result.secrets)}, "
                f"Auth flows: {len(result.auth_flows)}, "
                f"GraphQL: {len(result.graphql)}, "
                f"WebSockets: {len(result.websockets)}"
            )

            # Highlight critical findings
            if result.secrets:
                for secret in result.secrets:
                    ColorOutput.critical(
                        f"[!!] Secret found: {secret['type']} "
                        f"- {secret['value_preview']} (line {secret['line']})"
                    )

        # Save results
        self._save_results(all_results)

        return all_results

    def _analyze_target(self, target: str) -> JSResults:
        """Analyze a single target URL."""
        url = normalize_url(target)
        result = JSResults(target=target)

        # Discover JS files
        ColorOutput.info(f"  Discovering JavaScript files...")
        js_urls = self.discover_js_files(url)
        result.js_files_found = len(js_urls)
        ColorOutput.info(f"  Found {len(js_urls)} potential JS file URLs")

        # Download and analyze each JS file
        all_endpoints = []
        all_secrets = []
        all_auth_flows = []
        all_graphql = []
        all_websockets = []
        all_debug = []
        all_content = ""

        downloaded = 0
        for js_url in js_urls:
            content = self.download_js(js_url)
            if content:
                downloaded += 1
                all_content += content + "\n"

                # Run extractors
                all_endpoints.extend(self.extract_endpoints(content))
                all_secrets.extend(self.extract_secrets_from_content(content))
                all_auth_flows.extend(self.detect_auth_flows(content))
                all_graphql.extend(self.detect_graphql(content))
                all_websockets.extend(self.detect_websockets(content))
                all_debug.extend(self.detect_debug_info(content))

        ColorOutput.info(
            f"  Successfully downloaded {downloaded}/{len(js_urls)} files"
        )

        # API version detection on aggregated content
        api_versions = self.detect_api_versions(all_content)

        # Deduplicate results
        result.endpoints = self._dedupe_dicts(all_endpoints, "value")
        result.secrets = self._dedupe_dicts(all_secrets, "value_preview")
        result.auth_flows = self._dedupe_dicts(all_auth_flows, "context")
        result.graphql = self._dedupe_dicts(all_graphql, "value")
        result.websockets = list(set(all_websockets))
        result.api_versions = api_versions
        result.debug_info = self._dedupe_dicts(all_debug, "context")

        return result

    def _dedupe_dicts(self, items: List[dict], key: str) -> List[dict]:
        """Deduplicate a list of dicts by a specific key."""
        seen = set()
        unique = []
        for item in items:
            val = item.get(key, "")
            if val not in seen:
                seen.add(val)
                unique.append(item)
        return unique

    def _save_results(self, results: List[JSResults]):
        """Save analysis results to JSON file."""
        output = []
        for r in results:
            output.append({
                "target": r.target,
                "js_files_found": r.js_files_found,
                "endpoints": r.endpoints,
                "secrets": r.secrets,
                "auth_flows": r.auth_flows,
                "graphql": r.graphql,
                "websockets": r.websockets,
                "api_versions": r.api_versions,
                "debug_info": r.debug_info,
            })

        filepath = self.file_manager.save_json(output, "js_analysis.json")
        ColorOutput.success(f"Results saved to {filepath}")
