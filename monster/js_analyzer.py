"""
Monster v2.0.0 JavaScript Analyzer Module

Comprehensive JavaScript analysis for bug bounty reconnaissance.
Discovers JS files, extracts endpoints, detects secrets, analyzes
DOM sinks, prototype pollution vectors, postMessage issues, and more.

Features:
    - JavaScript file discovery (HTML parsing, common paths, sourcemaps)
    - Endpoint extraction (API paths, fetch/axios/XHR calls)
    - Secret detection (API keys, tokens, credentials)
    - Dependency identification (React, Angular, Vue, jQuery, etc.)
    - DOM sink analysis (innerHTML, eval, document.write)
    - Prototype pollution detection
    - JSONP endpoint discovery
    - PostMessage security analysis
    - Storage key extraction (localStorage, sessionStorage, cookies)
    - Service worker analysis
    - Webpack chunk discovery
    - GraphQL operation extraction
    - WebSocket URL discovery
    - Debug information detection
    - Authentication flow analysis

Usage:
    from monster.js_analyzer import JSAnalyzer, JSResults
    analyzer = JSAnalyzer(["https://example.com"], "./output")
    results = analyzer.run()
"""

import re
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set
from urllib.parse import urlparse, urljoin, urlencode, quote, unquote

from monster.utils import (
    ColorOutput, HTTPClient, FileManager, RateLimiter,
    normalize_url, domain_from_url
)
from monster.config import PATTERNS


# =============================================================================
# RESULT DATACLASS
# =============================================================================

@dataclass
class JSResults:
    """
    Container for JavaScript analysis results.

    Holds all findings from analyzing JavaScript files for a given target,
    including discovered endpoints, secrets, authentication flows,
    GraphQL operations, WebSocket URLs, and various security issues.

    Attributes:
        target: The target URL or domain being analyzed.
        js_files_found: Total number of JS files discovered.
        endpoints: List of extracted API endpoints with metadata.
        secrets: List of detected secrets/credentials.
        auth_flows: List of authentication flow patterns found.
        graphql: List of GraphQL operations discovered.
        websockets: List of WebSocket URLs found.
        api_versions: Dict mapping API version to endpoints.
        debug_info: List of debug/development artifacts found.
        dom_sinks: List of DOM-based XSS sinks.
        prototype_pollution: List of prototype pollution vectors.
        postmessage_issues: List of postMessage security issues.
        storage_keys: List of browser storage operations.
        dependencies: List of detected JS libraries/frameworks.
    """
    target: str = ""
    js_files_found: int = 0
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    auth_flows: List[Dict[str, Any]] = field(default_factory=list)
    graphql: List[Dict[str, Any]] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    api_versions: Dict[str, List[str]] = field(default_factory=dict)
    debug_info: List[Dict[str, Any]] = field(default_factory=list)
    dom_sinks: List[Dict[str, Any]] = field(default_factory=list)
    prototype_pollution: List[Dict[str, Any]] = field(default_factory=list)
    postmessage_issues: List[Dict[str, Any]] = field(default_factory=list)
    storage_keys: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "js_files_found": self.js_files_found,
            "endpoints": self.endpoints,
            "secrets": self.secrets,
            "auth_flows": self.auth_flows,
            "graphql": self.graphql,
            "websockets": self.websockets,
            "api_versions": self.api_versions,
            "debug_info": self.debug_info,
            "dom_sinks": self.dom_sinks,
            "prototype_pollution": self.prototype_pollution,
            "postmessage_issues": self.postmessage_issues,
            "storage_keys": self.storage_keys,
            "dependencies": self.dependencies,
        }

    def summary(self) -> str:
        """Return a brief human-readable summary of findings."""
        parts = []
        parts.append(f"Target: {self.target}")
        parts.append(f"JS Files: {self.js_files_found}")
        parts.append(f"Endpoints: {len(self.endpoints)}")
        parts.append(f"Secrets: {len(self.secrets)}")
        parts.append(f"DOM Sinks: {len(self.dom_sinks)}")
        parts.append(f"Proto Pollution: {len(self.prototype_pollution)}")
        parts.append(f"PostMessage: {len(self.postmessage_issues)}")
        parts.append(f"Storage Keys: {len(self.storage_keys)}")
        parts.append(f"Dependencies: {len(self.dependencies)}")
        parts.append(f"GraphQL Ops: {len(self.graphql)}")
        parts.append(f"WebSockets: {len(self.websockets)}")
        return " | ".join(parts)


# =============================================================================
# COMMON JAVASCRIPT PATHS
# =============================================================================

COMMON_JS_PATHS = [
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/js/vendor.js",
    "/js/chunk-vendors.js",
    "/static/js/main.js",
    "/static/js/app.js",
    "/static/js/bundle.js",
    "/static/js/vendor.js",
    "/dist/js/app.js",
    "/dist/js/chunk-vendors.js",
    "/assets/js/app.js",
    "/assets/js/main.js",
    "/assets/application.js",
    "/build/bundle.js",
    "/build/static/js/main.js",
    "/public/js/app.js",
    "/public/js/bundle.js",
    "/bundle.js",
    "/app.js",
    "/main.js",
    "/vendor.js",
    "/runtime.js",
    "/polyfills.js",
    "/webpack-runtime.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/pages/_app.js",
    "/static/js/runtime-main.js",
    "/static/js/2.chunk.js",
    "/static/js/main.chunk.js",
    "/wp-includes/js/jquery/jquery.min.js",
    "/wp-content/themes/theme/js/main.js",
    "/sites/default/files/js/js_bundle.js",
    "/misc/drupal.js",
    "/core/misc/drupal.js",
]


# =============================================================================
# ADDITIONAL INLINE PATTERNS FOR SECRET DETECTION
# =============================================================================

ADDITIONAL_SECRET_PATTERNS = {
    "Hardcoded Password": r'''(?i)(?:password|passwd|pwd)\s*[=:]\s*["'][^"' ]{4,}["']''',
    "Hardcoded API Key Assignment": r'''(?i)(?:api_key|apikey|api_secret)\s*[=:]\s*["'][A-Za-z0-9_\-]{16,}["']''',
    "Hardcoded Token Assignment": r'''(?i)(?:token|auth_token|access_token|secret_token)\s*[=:]\s*["'][A-Za-z0-9_\-]{16,}["']''',
    "Private Key Inline": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Authorization Header Hardcoded": r'''(?i)["']Authorization["']\s*:\s*["'](?:Bearer|Basic|Token)\s+[A-Za-z0-9+/=_\-.]+["']''',
    "Database URL with Credentials": r'''(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@[^\s"'/]+''',
    "Internal IP Address": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Base64 Encoded Secret": r'''(?i)(?:secret|key|token|password)\s*[=:]\s*["'][A-Za-z0-9+/]{32,}={0,2}["']''',
    "S3 Bucket URL": r"(?:https?://)?[a-z0-9][a-z0-9\-.]*\.s3[\-.][a-z0-9\-]+\.amazonaws\.com",
    "Google Maps API Key": r'''(?i)(?:google|gmap|maps)[_\-]?(?:api)?[_\-]?key["']?\s*[=:]\s*["']?AIza[0-9A-Za-z\-_]{35}''',
    "Twilio SID": r"AC[a-zA-Z0-9_\-]{32}",
}


# =============================================================================
# DEPENDENCY SIGNATURES
# =============================================================================

DEPENDENCY_SIGNATURES = {
    "React": {
        "patterns": [
            r"react\.production\.min\.js",
            r"react\.development\.js",
            r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
            r"React\.createElement",
            r"ReactDOM\.render",
            r"ReactDOM\.createRoot",
            r"_reactRoot\$",
            r"__NEXT_DATA__",
            r"react-dom",
        ],
        "version_pattern": r"react[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Angular": {
        "patterns": [
            r"angular\.min\.js",
            r"angular\.js",
            r'ng-version="(\d+)',
            r"ng-app",
            r"ng-controller",
            r"@angular/core",
            r"__ng_zone__",
            r"platformBrowserDynamic",
            r"zone\.js",
        ],
        "version_pattern": r"angular[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Vue.js": {
        "patterns": [
            r"vue\.min\.js",
            r"vue\.runtime",
            r"vue\.global",
            r"__vue__",
            r"Vue\.component",
            r"new Vue\(",
            r"createApp\(",
            r"v-bind:",
            r"v-model",
        ],
        "version_pattern": r"vue[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "jQuery": {
        "patterns": [
            r"jquery[\.\-]\d",
            r"jquery\.min\.js",
            r"jQuery\.fn\.jquery",
            r"\$\.ajax",
            r"\$\.fn\.jquery",
            r"jQuery\.ajax",
        ],
        "version_pattern": r"jquery[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Lodash": {
        "patterns": [
            r"lodash\.min\.js",
            r"lodash\.js",
            r"_\.chunk",
            r"_\.debounce",
            r"_\.throttle",
            r"_\.merge",
        ],
        "version_pattern": r"lodash[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Moment.js": {
        "patterns": [
            r"moment\.min\.js",
            r"moment\.js",
            r"moment\(",
            r"moment\.locale",
            r"moment\.tz",
        ],
        "version_pattern": r"moment[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Axios": {
        "patterns": [
            r"axios\.min\.js",
            r"axios\.create\(",
            r"axios\.get\(",
            r"axios\.post\(",
            r"axios\.interceptors",
        ],
        "version_pattern": r"axios[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Webpack": {
        "patterns": [
            r"webpackJsonp",
            r"__webpack_require__",
            r"webpack_modules",
            r"webpackChunk",
            r"__webpack_exports__",
        ],
        "version_pattern": r"webpack[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Bootstrap": {
        "patterns": [
            r"bootstrap\.min\.js",
            r"bootstrap\.bundle",
            r"bootstrap\.js",
            r"Bootstrap v",
        ],
        "version_pattern": r"[Bb]ootstrap[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "D3.js": {
        "patterns": [
            r"d3\.min\.js",
            r"d3\.js",
            r"d3\.select",
            r"d3\.scale",
        ],
        "version_pattern": r"d3[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Three.js": {
        "patterns": [
            r"three\.min\.js",
            r"THREE\.Scene",
            r"THREE\.WebGLRenderer",
        ],
        "version_pattern": r"three[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Socket.IO": {
        "patterns": [
            r"socket\.io\.js",
            r"socket\.io\.min\.js",
            r"io\.connect\(",
            r"io\(",
        ],
        "version_pattern": r"socket\.io[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Ember.js": {
        "patterns": [
            r"ember\.min\.js",
            r"ember\.js",
            r"Ember\.Application",
            r"ember-cli",
        ],
        "version_pattern": r"ember[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Backbone.js": {
        "patterns": [
            r"backbone\.min\.js",
            r"Backbone\.Model",
            r"Backbone\.View",
            r"Backbone\.Collection",
        ],
        "version_pattern": r"backbone[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Svelte": {
        "patterns": [
            r"svelte",
            r"__svelte",
            r"SvelteComponent",
        ],
        "version_pattern": r"svelte[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Next.js": {
        "patterns": [
            r"__NEXT_DATA__",
            r"_next/static",
            r"next/router",
            r"NextRouter",
        ],
        "version_pattern": r"next[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Nuxt.js": {
        "patterns": [
            r"__NUXT__",
            r"nuxt\.js",
            r"_nuxt/",
        ],
        "version_pattern": r"nuxt[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Express": {
        "patterns": [
            r"express\(",
            r"express\.Router",
            r"X-Powered-By.*Express",
        ],
        "version_pattern": r"express[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Tailwind CSS": {
        "patterns": [
            r"tailwindcss",
            r"tailwind\.config",
        ],
        "version_pattern": r"tailwindcss[/@ ]v?(\d+\.\d+\.\d+)",
    },
    "Material UI": {
        "patterns": [
            r"@mui/material",
            r"@material-ui",
            r"MuiButton",
            r"makeStyles",
        ],
        "version_pattern": r"@mui/material[/@ ]v?(\d+\.\d+\.\d+)",
    },
}



# =============================================================================
# JS ANALYZER CLASS
# =============================================================================

class JSAnalyzer:
    """
    Comprehensive JavaScript analyzer for security assessment.

    Discovers JavaScript files from target URLs, downloads and analyzes
    their content to find endpoints, secrets, vulnerabilities, and
    other security-relevant information.

    Attributes:
        targets: List of target URLs to analyze.
        output_dir: Directory for saving analysis results.
        options: Additional configuration options.
        http: HTTPClient instance for making requests.
        file_manager: FileManager for saving results.
        dry_run: If True, skip actual network requests.
        color: ColorOutput instance for terminal output.
        results: List of JSResults from analysis.
    """

    def __init__(
        self,
        targets: List[str],
        output_dir: str = "./output",
        options: Dict[str, Any] = None,
    ):
        """
        Initialize the JavaScript analyzer.

        Args:
            targets: List of target URLs to analyze.
            output_dir: Directory for output files.
            options: Additional options dict. Supported keys:
                - dry_run (bool): Skip network requests.
                - rate_limit (float): Delay between requests in seconds.
                - timeout (int): HTTP request timeout.
                - max_file_size (int): Maximum JS file size to download.
                - user_agent (str): Custom User-Agent string.
                - follow_redirects (bool): Follow HTTP redirects.
                - verify_ssl (bool): Verify SSL certificates.
        """
        self.targets = targets if isinstance(targets, list) else [targets]
        self.output_dir = output_dir
        self.options = options or {}
        self.dry_run = self.options.get("dry_run", False)
        self.color = ColorOutput()
        self.results: List[JSResults] = []

        # Initialize HTTP client
        rate_limit = self.options.get("rate_limit", 1.0)
        rate_limiter = RateLimiter(rate_limit)
        self.http = HTTPClient(
            timeout=self.options.get("timeout", 15),
            rate_limiter=rate_limiter,
            verify_ssl=self.options.get("verify_ssl", True),
        )

        # Initialize file manager
        self.file_manager = FileManager(output_dir)

        # Analysis state
        self._analyzed_urls: Set[str] = set()
        self._js_cache: Dict[str, str] = {}
        self._max_file_size = self.options.get("max_file_size", 10 * 1024 * 1024)

    def run(self) -> List[JSResults]:
        """
        Run JavaScript analysis on all targets.

        Orchestrates the full analysis pipeline for each target:
        1. Discover JavaScript files
        2. Download and cache JS content
        3. Beautify minified code
        4. Extract endpoints
        5. Detect secrets
        6. Identify dependencies
        7. Find DOM sinks
        8. Detect prototype pollution
        9. Find JSONP endpoints
        10. Analyze postMessage usage
        11. Extract storage keys
        12. Analyze service workers
        13. Discover webpack chunks
        14. Extract GraphQL operations
        15. Find WebSocket URLs
        16. Detect debug info
        17. Identify auth flows

        Returns:
            List of JSResults objects, one per target.
        """
        self.color.info("Starting JavaScript analysis...")
        self.color.info(f"Targets: {len(self.targets)}")

        for target in self.targets:
            try:
                self.color.info(f"Analyzing: {target}")
                result = self._analyze_target(target)
                self.results.append(result)
                self.color.success(
                    f"Completed analysis for {target}: "
                    f"{result.js_files_found} JS files, "
                    f"{len(result.endpoints)} endpoints, "
                    f"{len(result.secrets)} secrets"
                )
            except Exception as e:
                self.color.error(f"Error analyzing {target}: {str(e)}")
                error_result = JSResults(target=target)
                self.results.append(error_result)

        # Save all results
        self._save_results(self.results)
        self.color.success(f"JavaScript analysis complete. {len(self.results)} targets processed.")
        return self.results

    def _analyze_target(self, target: str) -> JSResults:
        """
        Perform full JavaScript analysis on a single target.

        Args:
            target: The target URL to analyze.

        Returns:
            JSResults object with all findings.
        """
        result = JSResults(target=target)

        # Step 1: Discover JS files
        js_urls = self.discover_js_files(target)
        result.js_files_found = len(js_urls)
        self.color.info(f"  Found {len(js_urls)} JavaScript files")

        # Step 2: Download and analyze each JS file
        all_js_content = []
        for js_url in js_urls:
            try:
                content = self.download_js(js_url)
                if content:
                    all_js_content.append((js_url, content))
                    self._js_cache[js_url] = content
            except Exception as e:
                self.color.warning(f"  Failed to download {js_url}: {str(e)}")

        # Step 3: Analyze each JS file
        for js_url, content in all_js_content:
            try:
                # Beautify for better analysis
                beautified = self.beautify_js(content)

                # Extract endpoints
                endpoints = self.extract_endpoints(beautified, js_url)
                result.endpoints.extend(endpoints)

                # Detect secrets
                secrets = self.detect_secrets(beautified, js_url)
                result.secrets.extend(secrets)

                # Detect dependencies
                deps = self.detect_dependencies(beautified)
                result.dependencies.extend(deps)

                # DOM sinks
                sinks = self.detect_dom_sinks(beautified)
                result.dom_sinks.extend(sinks)

                # Prototype pollution
                pollution = self.detect_prototype_pollution(beautified)
                result.prototype_pollution.extend(pollution)

                # JSONP endpoints
                jsonp = self.detect_jsonp_endpoints(beautified)
                result.endpoints.extend(jsonp)

                # PostMessage analysis
                postmsg = self.analyze_postmessage(beautified)
                result.postmessage_issues.extend(postmsg)

                # Storage keys
                storage = self.extract_storage_keys(beautified)
                result.storage_keys.extend(storage)

                # Service workers
                sw = self.analyze_service_workers(beautified)
                result.auth_flows.extend(sw)

                # Webpack chunks
                chunks = self.discover_webpack_chunks(beautified, js_url)
                for chunk_url in chunks:
                    if chunk_url not in self._analyzed_urls:
                        self._analyzed_urls.add(chunk_url)

                # GraphQL
                gql = self.extract_graphql(beautified)
                result.graphql.extend(gql)

                # WebSocket URLs
                ws_urls = self.extract_websocket_urls(beautified)
                result.websockets.extend(ws_urls)

                # Debug info
                debug = self.detect_debug_info(beautified)
                result.debug_info.extend(debug)

            except Exception as e:
                self.color.warning(f"  Error analyzing {js_url}: {str(e)}")

        # Deduplicate results
        result.endpoints = self._deduplicate_dicts(result.endpoints, "url")
        result.secrets = self._deduplicate_dicts(result.secrets, "matched_value")
        result.websockets = list(set(result.websockets))
        result.dependencies = self._deduplicate_dicts(result.dependencies, "name")

        return result

    def _deduplicate_dicts(self, items: List[Dict], key: str) -> List[Dict]:
        """Remove duplicate dictionaries based on a key field."""
        seen = set()
        unique = []
        for item in items:
            val = item.get(key, "")
            if val not in seen:
                seen.add(val)
                unique.append(item)
        return unique

    # =========================================================================
    # DISCOVER JS FILES
    # =========================================================================

    def discover_js_files(self, url: str) -> List[str]:
        """
        Discover JavaScript files associated with a URL.

        Combines multiple discovery methods:
        1. Parse HTML page for <script> tags with src attributes
        2. Check common JavaScript paths
        3. Look for source map files (.map)
        4. Check for inline scripts
        5. Look for webpack manifest

        Args:
            url: The target URL to discover JS files from.

        Returns:
            List of absolute URLs to JavaScript files.
        """
        js_urls = set()
        base_url = normalize_url(url)

        if self.dry_run:
            # In dry-run mode, return common paths as potential JS files
            self.color.info("  [DRY-RUN] Simulating JS file discovery")
            for path in COMMON_JS_PATHS[:10]:
                resolved = self._resolve_url(base_url, path)
                js_urls.add(resolved)
            return list(js_urls)

        # Method 1: Parse HTML for script tags
        try:
            response = self.http.get(base_url)
            if response and response.status_code == 200 and response.body:
                html_content = response.body

                # Find script tags with src
                script_src_pattern = re.compile(
                    r'<script[^>]+src=["\'](.*?)["\'\s>]',
                    re.IGNORECASE | re.DOTALL
                )
                matches = script_src_pattern.findall(html_content)
                for src in matches:
                    src = src.strip()
                    if src and not src.startswith("data:"):
                        resolved = self._resolve_url(base_url, src)
                        if self._is_js_url(resolved):
                            js_urls.add(resolved)

                # Find script tags with type=module
                module_pattern = re.compile(
                    r'<script[^>]+type=["\'\s]module["\'\s][^>]+src=["\'](.*?)["\'\s>]',
                    re.IGNORECASE | re.DOTALL
                )
                module_matches = module_pattern.findall(html_content)
                for src in module_matches:
                    src = src.strip()
                    if src:
                        resolved = self._resolve_url(base_url, src)
                        js_urls.add(resolved)

                # Find dynamically loaded scripts
                dynamic_pattern = re.compile(
                    r'(?:loadScript|appendScript|addScript)\s*\(["\'](.*?\.js)["\'\s]',
                    re.IGNORECASE
                )
                dynamic_matches = dynamic_pattern.findall(html_content)
                for src in dynamic_matches:
                    resolved = self._resolve_url(base_url, src)
                    js_urls.add(resolved)

                # Extract inline scripts for analysis
                inline_scripts = self._extract_inline_scripts(html_content)
                if inline_scripts:
                    # Store inline scripts with a special identifier
                    for i, script in enumerate(inline_scripts):
                        cache_key = f"{base_url}#inline-{i}"
                        self._js_cache[cache_key] = script

        except Exception as e:
            self.color.warning(f"  Error fetching HTML from {base_url}: {str(e)}")

        # Method 2: Check common JS paths
        for path in COMMON_JS_PATHS:
            try:
                check_url = self._resolve_url(base_url, path)
                if check_url not in js_urls:
                    response = self.http.get(check_url)
                    if response and response.status_code == 200:
                        content_type = response.headers.get("Content-Type", "")
                        if "javascript" in content_type or "application/js" in content_type:
                            js_urls.add(check_url)
                        elif response.body and self._looks_like_js(response.body[:500]):
                            js_urls.add(check_url)
            except Exception:
                pass

        # Method 3: Look for source map files
        for js_url in list(js_urls):
            map_url = js_url + ".map"
            try:
                response = self.http.get(map_url)
                if response and response.status_code == 200:
                    self.color.success(f"  Found source map: {map_url}")
                    # Parse source map for original file references
                    try:
                        map_data = json.loads(response.body)
                        sources = map_data.get("sources", [])
                        for source in sources:
                            if source.endswith(".js") or source.endswith(".ts"):
                                resolved = self._resolve_url(js_url, source)
                                js_urls.add(resolved)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        # Method 4: Check for webpack manifest
        manifest_paths = [
            "/asset-manifest.json",
            "/manifest.json",
            "/build/asset-manifest.json",
            "/static/asset-manifest.json",
        ]
        for manifest_path in manifest_paths:
            try:
                manifest_url = self._resolve_url(base_url, manifest_path)
                response = self.http.get(manifest_url)
                if response and response.status_code == 200:
                    try:
                        manifest = json.loads(response.body)
                        # React-style asset manifest
                        files = manifest.get("files", manifest.get("entrypoints", {}))
                        if isinstance(files, dict):
                            for key, path in files.items():
                                if isinstance(path, str) and path.endswith(".js"):
                                    resolved = self._resolve_url(base_url, path)
                                    js_urls.add(resolved)
                        elif isinstance(files, list):
                            for path in files:
                                if isinstance(path, str) and path.endswith(".js"):
                                    resolved = self._resolve_url(base_url, path)
                                    js_urls.add(resolved)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        return list(js_urls)

    def _is_js_url(self, url: str) -> bool:
        """Check if a URL likely points to a JavaScript file."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        js_extensions = (".js", ".mjs", ".jsx", ".ts", ".tsx")
        if any(path.endswith(ext) for ext in js_extensions):
            return True
        # Check for versioned JS files like app.12345.js
        if re.search(r'\.([a-f0-9]{6,})\.js$', path):
            return True
        # Check for chunk files
        if re.search(r'chunk[\-.]\w+\.js$', path):
            return True
        return False

    def _looks_like_js(self, content: str) -> bool:
        """Heuristic check if content looks like JavaScript."""
        js_indicators = [
            "function ", "var ", "const ", "let ", "class ",
            "export ", "import ", "require(", "module.exports",
            "window.", "document.", "console.", "return ",
        ]
        matches = sum(1 for ind in js_indicators if ind in content)
        return matches >= 2

    # =========================================================================
    # DOWNLOAD JS
    # =========================================================================

    def download_js(self, url: str) -> Optional[str]:
        """
        Download JavaScript content from a URL.

        Handles encoding issues, enforces size limits, and caches
        downloaded content to avoid duplicate requests.

        Args:
            url: The URL of the JavaScript file to download.

        Returns:
            The JavaScript content as a string, or None if download failed.
            Returns cached content if URL was previously downloaded.
        """
        # Check cache first
        if url in self._js_cache:
            return self._js_cache[url]

        if self.dry_run:
            self.color.info(f"  [DRY-RUN] Would download: {url}")
            return None

        try:
            response = self.http.get(url)
            if response is None:
                return None

            if response.status_code != 200:
                return None

            # Check content length
            content_length = response.content_length
            if content_length > self._max_file_size:
                self.color.warning(
                    f"  Skipping {url}: file too large ({content_length} bytes)"
                )
                return None

            content = response.body
            if not content:
                return None

            # Verify it looks like JavaScript
            if not self._looks_like_js(content[:1000]):
                # Check Content-Type as fallback
                content_type = response.headers.get("Content-Type", "")
                if "javascript" not in content_type and "ecmascript" not in content_type:
                    return None

            # Cache the content
            self._js_cache[url] = content
            return content

        except Exception as e:
            self.color.warning(f"  Error downloading {url}: {str(e)}")
            return None


    # =========================================================================
    # BEAUTIFY JS
    # =========================================================================

    def beautify_js(self, content: str) -> str:
        """
        Basic regex-based JavaScript beautifier.

        Adds newlines and indentation to minified JavaScript code
        to make it more readable for analysis. This is not a full parser
        but handles common minification patterns.

        Transformations applied:
        1. Add newlines after semicolons (not inside strings or parens)
        2. Add newlines after opening braces
        3. Add newlines before closing braces
        4. Indent nested blocks
        5. Normalize whitespace
        6. Unminify common patterns (short variable names to descriptive)

        Args:
            content: Minified JavaScript content.

        Returns:
            Beautified JavaScript with proper formatting.
        """
        if not content:
            return ""

        # If already well-formatted (has reasonable line lengths), skip
        lines = content.split("\n")
        if len(lines) > 50:
            avg_length = sum(len(l) for l in lines[:100]) / min(len(lines), 100)
            if avg_length < 200:
                return content

        result = content

        # Step 1: Normalize line endings
        result = result.replace("\r\n", "\n").replace("\r", "\n")

        # Step 2: Add newlines after semicolons not inside strings
        # Simple approach: split on ; but preserve strings
        result = re.sub(r';(?![^"]*"[^"]*$)', ";\n", result)

        # Step 3: Add newlines after opening braces
        result = re.sub(r'\{(?!\})', "{\n", result)

        # Step 4: Add newlines before closing braces
        result = re.sub(r'(?<!\{)\}', "\n}", result)

        # Step 5: Add newlines after closing braces followed by keywords
        result = re.sub(
            r'\}\s*(else|catch|finally|while)',
            "}\n\\1",
            result
        )

        # Step 6: Normalize multiple newlines
        result = re.sub(r'\n{3,}', "\n\n", result)

        # Step 7: Basic indentation
        indented_lines = []
        indent_level = 0
        for line in result.split("\n"):
            stripped = line.strip()
            if not stripped:
                indented_lines.append("")
                continue

            # Decrease indent for closing braces/brackets
            if stripped.startswith("}") or stripped.startswith("]") or stripped.startswith(")"):
                indent_level = max(0, indent_level - 1)

            indented_lines.append("    " * indent_level + stripped)

            # Increase indent for opening braces/brackets
            open_count = stripped.count("{") + stripped.count("[")
            close_count = stripped.count("}") + stripped.count("]")
            if open_count > close_count:
                indent_level += 1
            elif close_count > open_count and indent_level > 0:
                indent_level = max(0, indent_level - 1)

        # Step 8: Unminify common single-letter variables in function params
        beautified = "\n".join(indented_lines)

        # Restore some readability for common patterns
        beautified = re.sub(r'\bfunction\s*\(\s*([a-z])\s*,\s*([a-z])\s*,\s*([a-z])\s*\)',
                           lambda m: f"function({m.group(1)}, {m.group(2)}, {m.group(3)})",
                           beautified)

        # Add spacing around operators
        beautified = re.sub(r'([^=!<>])=([^=])', r'\1 = \2', beautified)
        beautified = re.sub(r'===', ' === ', beautified)
        beautified = re.sub(r'!==', ' !== ', beautified)

        return beautified

    # =========================================================================
    # EXTRACT ENDPOINTS
    # =========================================================================

    def extract_endpoints(self, js_content: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract API endpoints and URLs from JavaScript content.

        Uses comprehensive regex patterns to find:
        - /api/xxx paths
        - fetch() calls
        - axios calls
        - XMLHttpRequest.open() calls
        - $.ajax URLs
        - Full URLs (http/https)
        - Relative paths
        - Route definitions (Express, React Router, etc.)

        Args:
            js_content: The JavaScript content to analyze.
            base_url: The base URL for resolving relative paths.

        Returns:
            List of endpoint dictionaries with keys:
            - url: The discovered endpoint URL
            - method_hint: HTTP method if detectable (GET, POST, etc.)
            - context_line: The line of code where endpoint was found
            - source: The JS file URL
            - confidence: high/medium/low
        """
        endpoints = []
        if not js_content:
            return endpoints

        lines = js_content.split("\n")

        # Pattern 1: fetch() calls
        fetch_patterns = [
            # fetch("url") or fetch('url')
            re.compile(r'fetch\s*\(\s*["\'`]((?:https?://|/)[^"\'`\s]+)["\'`]', re.IGNORECASE),
            # fetch(url, { method: "POST" })
            re.compile(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]\s*,\s*\{[^}]*method\s*:\s*["\'`](\w+)["\'`]', re.IGNORECASE),
            # fetch(`${baseUrl}/path`)
            re.compile(r'fetch\s*\(\s*`[^`]*(/[a-zA-Z][a-zA-Z0-9/_\-]+)[^`]*`', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in fetch_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    url = match.group(1)
                    method = "GET"
                    if len(match.groups()) > 1 and match.group(2):
                        method = match.group(2).upper()
                    endpoints.append({
                        "url": self._resolve_url(base_url, url),
                        "method_hint": method,
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "high",
                        "line_number": i + 1,
                    })

        # Pattern 2: axios calls
        axios_patterns = [
            # axios.get("url"), axios.post("url"), etc.
            re.compile(r'axios\.(get|post|put|delete|patch|head|options)\s*\(\s*["\'`]((?:https?://|/)[^"\'`]+)["\'`]', re.IGNORECASE),
            # axios({ url: "...", method: "..." })
            re.compile(r'axios\s*\(\s*\{[^}]*url\s*:\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
            # axios.create({ baseURL: "..." })
            re.compile(r'axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["\'`]((?:https?://)[^"\'`]+)["\'`]', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in axios_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    groups = match.groups()
                    if len(groups) >= 2:
                        method = groups[0].upper()
                        url = groups[1]
                    else:
                        method = "GET"
                        url = groups[0]
                    endpoints.append({
                        "url": self._resolve_url(base_url, url),
                        "method_hint": method,
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "high",
                        "line_number": i + 1,
                    })

        # Pattern 3: XMLHttpRequest
        xhr_patterns = [
            # xhr.open("GET", "url")
            re.compile(r'\.open\s*\(\s*["\'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
            # new XMLHttpRequest() followed by open
            re.compile(r'XMLHttpRequest[^;]*\.open\s*\(\s*["\'`](\w+)["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in xhr_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    method = match.group(1).upper()
                    url = match.group(2)
                    endpoints.append({
                        "url": self._resolve_url(base_url, url),
                        "method_hint": method,
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "high",
                        "line_number": i + 1,
                    })

        # Pattern 4: jQuery AJAX
        jquery_patterns = [
            # $.ajax({ url: "...", type: "..." })
            re.compile(r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
            # $.get("url"), $.post("url")
            re.compile(r'\$\.(get|post|getJSON)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
            # $.ajax("url")
            re.compile(r'\$\.ajax\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in jquery_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    groups = match.groups()
                    if len(groups) >= 2:
                        method = groups[0].upper()
                        url = groups[1]
                    else:
                        method = "GET"
                        url = groups[0]
                    if method == "GETJSON":
                        method = "GET"
                    endpoints.append({
                        "url": self._resolve_url(base_url, url),
                        "method_hint": method,
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "high",
                        "line_number": i + 1,
                    })

        # Pattern 5: Full URLs (http/https)
        url_pattern = re.compile(
            r'["\'`](https?://[a-zA-Z0-9][a-zA-Z0-9._\-]*(?:/[^"\'`\s]*)?)["\'`]',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            matches = url_pattern.finditer(line)
            for match in matches:
                url = match.group(1)
                # Filter out common non-API URLs
                if self._is_interesting_url(url):
                    endpoints.append({
                        "url": url,
                        "method_hint": "UNKNOWN",
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "medium",
                        "line_number": i + 1,
                    })

        # Pattern 6: API paths (relative)
        api_path_pattern = re.compile(
            r'["\'`](/(?:api|v[0-9]+|rest|graphql|auth|oauth|admin|internal)/[a-zA-Z0-9/_\-]+)["\'`]',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            matches = api_path_pattern.finditer(line)
            for match in matches:
                path = match.group(1)
                endpoints.append({
                    "url": self._resolve_url(base_url, path),
                    "method_hint": "UNKNOWN",
                    "context_line": line.strip()[:200],
                    "source": base_url,
                    "confidence": "medium",
                    "line_number": i + 1,
                })

        # Pattern 7: Route definitions
        route_patterns = [
            # Express: app.get("/path", ...), router.post("/path", ...)
            re.compile(r'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
            # React Router: path="/route"
            re.compile(r'path\s*[=:]\s*["\'`](/[^"\'`]+)["\'`]', re.IGNORECASE),
            # Angular routes: { path: "route", ... }
            re.compile(r'\{\s*path\s*:\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in route_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    groups = match.groups()
                    if len(groups) >= 2:
                        method = groups[0].upper()
                        path = groups[1]
                    else:
                        method = "GET"
                        path = groups[0]
                    if path and not path.startswith("*"):
                        endpoints.append({
                            "url": self._resolve_url(base_url, path),
                            "method_hint": method,
                            "context_line": line.strip()[:200],
                            "source": base_url,
                            "confidence": "medium",
                            "line_number": i + 1,
                        })

        # Pattern 8: String concatenation patterns for URLs
        concat_patterns = [
            # baseUrl + "/path"
            re.compile(r'(?:baseUrl|apiUrl|baseURL|API_URL|BASE_URL|apiBase|endpoint)\s*\+\s*["\'`](/[^"\'`]+)["\'`]', re.IGNORECASE),
            # "/api" + "/endpoint"
            re.compile(r'["\'`](/api[^"\'`]*)["\'`]\s*\+\s*["\'`](/[^"\'`]+)["\'`]', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in concat_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    path = match.group(1)
                    if len(match.groups()) > 1:
                        path = match.group(1) + match.group(2)
                    endpoints.append({
                        "url": self._resolve_url(base_url, path),
                        "method_hint": "UNKNOWN",
                        "context_line": line.strip()[:200],
                        "source": base_url,
                        "confidence": "low",
                        "line_number": i + 1,
                    })

        return endpoints

    def _is_interesting_url(self, url: str) -> bool:
        """Check if a URL is potentially interesting for security analysis."""
        # Skip common CDN and static asset URLs
        boring_domains = [
            "googleapis.com", "gstatic.com", "google.com",
            "facebook.com", "fbcdn.net", "twitter.com",
            "cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
            "cdnjs.cloudflare.com", "maxcdn.bootstrapcdn.com",
            "fonts.googleapis.com", "ajax.googleapis.com",
            "code.jquery.com", "stackpath.bootstrapcdn.com",
        ]
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        for boring in boring_domains:
            if boring in domain:
                return False

        # Skip image/font/css files
        path = parsed.path.lower()
        boring_extensions = [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".css", ".less", ".scss",
            ".mp3", ".mp4", ".webm", ".ogg",
        ]
        for ext in boring_extensions:
            if path.endswith(ext):
                return False

        return True


    # =========================================================================
    # DETECT SECRETS
    # =========================================================================

    def detect_secrets(self, js_content: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Detect secrets, credentials, and sensitive data in JavaScript content.

        Uses patterns from monster.config.PATTERNS plus additional inline
        patterns specific to JavaScript contexts.

        Args:
            js_content: The JavaScript content to scan.
            source_url: The URL where this JS was found (for reporting).

        Returns:
            List of secret dictionaries with keys:
            - pattern_name: Name of the pattern that matched
            - matched_value: The actual matched string (truncated for safety)
            - line_number: Line number where found
            - severity: CRITICAL/HIGH/MEDIUM/LOW
            - source_url: Where the JS file was found
            - context: Surrounding code context
        """
        secrets = []
        if not js_content:
            return secrets

        lines = js_content.split("\n")

        # Use PATTERNS from config
        for pattern_name, pattern_str in PATTERNS.items():
            try:
                regex = re.compile(pattern_str, re.IGNORECASE)
                for i, line in enumerate(lines):
                    matches = regex.finditer(line)
                    for match in matches:
                        matched_value = match.group(0)

                        # Skip if it looks like a placeholder or example
                        if self._is_placeholder(matched_value):
                            continue

                        # Determine severity based on pattern
                        severity = self._classify_secret_severity(pattern_name)

                        # Truncate matched value for safety
                        display_value = matched_value[:80] + "..." if len(matched_value) > 80 else matched_value

                        secrets.append({
                            "pattern_name": pattern_name,
                            "matched_value": display_value,
                            "line_number": i + 1,
                            "severity": severity,
                            "source_url": source_url,
                            "context": line.strip()[:300],
                        })
            except re.error:
                continue

        # Use additional inline patterns
        for pattern_name, pattern_str in ADDITIONAL_SECRET_PATTERNS.items():
            try:
                regex = re.compile(pattern_str, re.IGNORECASE)
                for i, line in enumerate(lines):
                    matches = regex.finditer(line)
                    for match in matches:
                        matched_value = match.group(0)

                        if self._is_placeholder(matched_value):
                            continue

                        severity = self._classify_secret_severity(pattern_name)
                        display_value = matched_value[:80] + "..." if len(matched_value) > 80 else matched_value

                        secrets.append({
                            "pattern_name": pattern_name,
                            "matched_value": display_value,
                            "line_number": i + 1,
                            "severity": severity,
                            "source_url": source_url,
                            "context": line.strip()[:300],
                        })
            except re.error:
                continue

        # Check for high-entropy strings that might be keys
        entropy_pattern = re.compile(r'["\'`]([A-Za-z0-9+/=_\-]{32,})["\'`]')
        for i, line in enumerate(lines):
            matches = entropy_pattern.finditer(line)
            for match in matches:
                value = match.group(1)
                if self._has_high_entropy(value) and not self._is_placeholder(value):
                    # Check context for key/secret/token indicators
                    context_lower = line.lower()
                    if any(kw in context_lower for kw in ["key", "secret", "token", "auth", "password", "credential"]):
                        secrets.append({
                            "pattern_name": "High-Entropy String (possible key)",
                            "matched_value": value[:60] + "..." if len(value) > 60 else value,
                            "line_number": i + 1,
                            "severity": "MEDIUM",
                            "source_url": source_url,
                            "context": line.strip()[:300],
                        })

        return secrets

    def _is_placeholder(self, value: str) -> bool:
        """Check if a matched value is likely a placeholder or example."""
        placeholder_indicators = [
            "xxx", "yyy", "zzz", "example", "placeholder",
            "your_", "YOUR_", "REPLACE", "INSERT", "CHANGE_ME",
            "todo", "fixme", "temp", "test", "fake", "dummy",
            "sample", "demo", "mock", "<", ">", "${", "{{",
            "undefined", "null", "none", "empty",
        ]
        value_lower = value.lower()
        for indicator in placeholder_indicators:
            if indicator in value_lower:
                return True
        # Check if it's all the same character repeated
        if len(set(value.replace("-", "").replace("_", ""))) <= 3:
            return True
        return False

    def _has_high_entropy(self, value: str) -> bool:
        """Check if a string has high Shannon entropy (likely a key)."""
        import math
        if len(value) < 16:
            return False
        # Calculate Shannon entropy
        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(value)
            if p > 0:
                entropy -= p * math.log2(p)
        # High entropy threshold (random strings typically > 4.0)
        return entropy > 4.0

    def _classify_secret_severity(self, pattern_name: str) -> str:
        """Classify the severity of a detected secret based on pattern name."""
        critical_keywords = [
            "private key", "aws secret", "stripe secret",
            "database", "connection string", "ssh",
        ]
        high_keywords = [
            "access key", "api key", "token", "oauth",
            "webhook", "sendgrid", "twilio", "firebase",
            "github", "gitlab", "slack",
        ]
        medium_keywords = [
            "generic", "bearer", "basic auth", "email",
            "internal ip", "s3 bucket",
        ]

        name_lower = pattern_name.lower()
        for kw in critical_keywords:
            if kw in name_lower:
                return "CRITICAL"
        for kw in high_keywords:
            if kw in name_lower:
                return "HIGH"
        for kw in medium_keywords:
            if kw in name_lower:
                return "MEDIUM"
        return "LOW"

    # =========================================================================
    # DETECT DEPENDENCIES
    # =========================================================================

    def detect_dependencies(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Identify JavaScript libraries and frameworks from code patterns.

        Detects React, Angular, Vue, jQuery, Lodash, Moment.js, Axios,
        Webpack, Bootstrap, D3, Three.js, Socket.IO, and many others.

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of dependency dictionaries with keys:
            - name: Library/framework name
            - version_hint: Detected version (if available)
            - evidence: The code pattern that identified it
            - confidence: high/medium/low
        """
        dependencies = []
        if not js_content:
            return dependencies

        for dep_name, dep_info in DEPENDENCY_SIGNATURES.items():
            detected = False
            evidence_list = []
            version_hint = None

            # Check patterns
            for pattern_str in dep_info.get("patterns", []):
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                    match = pattern.search(js_content)
                    if match:
                        detected = True
                        evidence_list.append(match.group(0)[:100])
                except re.error:
                    continue

            # Try to extract version
            version_pattern = dep_info.get("version_pattern", "")
            if version_pattern and detected:
                try:
                    version_regex = re.compile(version_pattern, re.IGNORECASE)
                    version_match = version_regex.search(js_content)
                    if version_match:
                        version_hint = version_match.group(1)
                except re.error:
                    pass

            if detected:
                confidence = "high" if len(evidence_list) >= 2 else "medium"
                dependencies.append({
                    "name": dep_name,
                    "version_hint": version_hint,
                    "evidence": evidence_list[:3],
                    "confidence": confidence,
                })

        # Check for package.json-style imports
        import_pattern = re.compile(
            r'(?:import|require)\s*\(?\s*["\'`]([a-z@][a-z0-9._\-/]*)["\'`]',
            re.IGNORECASE
        )
        imports = set(import_pattern.findall(js_content))
        for imp in imports:
            # Extract package name (handle scoped packages)
            pkg_name = imp.split("/")[0]
            if imp.startswith("@"):
                parts = imp.split("/")
                pkg_name = "/".join(parts[:2]) if len(parts) > 1 else parts[0]

            # Skip if already detected
            if any(d["name"].lower() == pkg_name.lower() for d in dependencies):
                continue

            # Only add well-known packages
            known_packages = [
                "express", "koa", "hapi", "fastify", "nest",
                "passport", "jsonwebtoken", "bcrypt", "helmet",
                "cors", "morgan", "winston", "bunyan", "pino",
                "mongoose", "sequelize", "knex", "typeorm", "prisma",
                "graphql", "apollo", "relay", "urql",
                "redux", "mobx", "zustand", "recoil", "jotai",
                "formik", "yup", "zod", "joi",
                "dayjs", "date-fns", "luxon",
                "ramda", "immutable", "rxjs",
                "next", "nuxt", "gatsby", "remix",
                "vite", "rollup", "parcel", "esbuild",
                "jest", "mocha", "chai", "cypress", "playwright",
                "storybook", "chromatic",
                "sentry", "datadog", "newrelic",
                "stripe", "paypal", "braintree",
                "aws-sdk", "firebase", "supabase",
                "socket.io-client", "pusher-js", "ably",
            ]
            if pkg_name.lower() in known_packages or pkg_name.startswith("@"):
                dependencies.append({
                    "name": pkg_name,
                    "version_hint": None,
                    "evidence": [f"import/require(\'{imp}\')"],
                    "confidence": "medium",
                })

        return dependencies


    # =========================================================================
    # DETECT DOM SINKS
    # =========================================================================

    def detect_dom_sinks(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Find DOM-based XSS sinks in JavaScript content.

        Detects dangerous DOM manipulation patterns including:
        - innerHTML assignments
        - document.write() calls
        - eval() usage
        - setTimeout/setInterval with string arguments
        - Function() constructor
        - jQuery .html() method
        - Vue v-html directive
        - React dangerouslySetInnerHTML
        - document.location manipulation
        - window.open with user data
        - document.cookie manipulation

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of DOM sink dictionaries with keys:
            - sink_type: Category of the sink
            - code_snippet: The relevant code
            - line_number: Where it was found
            - risk_level: HIGH/MEDIUM/LOW
            - description: What makes this dangerous
        """
        sinks = []
        if not js_content:
            return sinks

        lines = js_content.split("\n")

        # Define sink patterns with their risk levels
        sink_definitions = [
            {
                "sink_type": "innerHTML",
                "pattern": re.compile(r'\.innerHTML\s*[=+]', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Direct innerHTML assignment can lead to DOM-based XSS if user input flows into the value.",
            },
            {
                "sink_type": "outerHTML",
                "pattern": re.compile(r'\.outerHTML\s*[=+]', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "outerHTML assignment replaces the entire element and can execute injected scripts.",
            },
            {
                "sink_type": "document.write",
                "pattern": re.compile(r'document\.write(?:ln)?\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "document.write() injects raw HTML into the page, enabling XSS.",
            },
            {
                "sink_type": "eval",
                "pattern": re.compile(r'(?<!\w)eval\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "eval() executes arbitrary JavaScript code, critical if user input reaches it.",
            },
            {
                "sink_type": "setTimeout_string",
                "pattern": re.compile(r'setTimeout\s*\(\s*["\'`]', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "setTimeout with a string argument acts like eval(), executing the string as code.",
            },
            {
                "sink_type": "setInterval_string",
                "pattern": re.compile(r'setInterval\s*\(\s*["\'`]', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "setInterval with a string argument acts like eval(), executing the string as code.",
            },
            {
                "sink_type": "Function_constructor",
                "pattern": re.compile(r'new\s+Function\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Function constructor creates a function from a string, similar to eval().",
            },
            {
                "sink_type": "jQuery_html",
                "pattern": re.compile(r'\$\([^)]+\)\.html\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "jQuery .html() method sets innerHTML and can execute injected scripts.",
            },
            {
                "sink_type": "jQuery_append_raw",
                "pattern": re.compile(r'\$\([^)]+\)\.(?:append|prepend|after|before|replaceWith)\s*\(', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "jQuery DOM insertion methods can execute scripts if given HTML with script tags.",
            },
            {
                "sink_type": "v-html",
                "pattern": re.compile(r'v-html\s*=', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Vue v-html directive renders raw HTML without escaping, enabling XSS.",
            },
            {
                "sink_type": "dangerouslySetInnerHTML",
                "pattern": re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "React dangerouslySetInnerHTML bypasses React XSS protection.",
            },
            {
                "sink_type": "document.location",
                "pattern": re.compile(r'document\.location\s*=', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Setting document.location can be used for open redirect if user input is used.",
            },
            {
                "sink_type": "window.location.href",
                "pattern": re.compile(r'(?:window\.)?location\.href\s*=', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Setting location.href with user input can lead to open redirect or javascript: URL XSS.",
            },
            {
                "sink_type": "location.assign",
                "pattern": re.compile(r'location\.(?:assign|replace)\s*\(', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "location.assign/replace with user input can lead to open redirect.",
            },
            {
                "sink_type": "insertAdjacentHTML",
                "pattern": re.compile(r'\.insertAdjacentHTML\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "insertAdjacentHTML inserts raw HTML, can execute injected scripts.",
            },
            {
                "sink_type": "document.domain",
                "pattern": re.compile(r'document\.domain\s*=', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Setting document.domain relaxes same-origin policy, potential security issue.",
            },
            {
                "sink_type": "script_src_set",
                "pattern": re.compile(r'\.src\s*=\s*[^;]*(?:location|document|window|url|param|query|hash|search)', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Dynamic script/iframe src assignment with user-controllable data enables XSS.",
            },
            {
                "sink_type": "script_createElement",
                "pattern": re.compile(r'createElement\s*\(\s*["\'`]script["\'`]\s*\)', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Creating script elements dynamically may execute injected code.",
            },
            {
                "sink_type": "window.open",
                "pattern": re.compile(r'window\.open\s*\(\s*[^"\'`)]', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "window.open with dynamic URL can be used for phishing or open redirect.",
            },
            {
                "sink_type": "postMessage_no_origin",
                "pattern": re.compile(r'\.postMessage\s*\([^,]+,\s*["\'`]\*["\'`]', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "postMessage with wildcard origin sends data to any window regardless of origin.",
            },
            {
                "sink_type": "document.cookie_set",
                "pattern": re.compile(r'document\.cookie\s*=', re.IGNORECASE),
                "risk_level": "LOW",
                "description": "JavaScript cookie manipulation may be used for session fixation.",
            },
            {
                "sink_type": "url_hash_usage",
                "pattern": re.compile(r'(?:location\.hash|window\.location\.hash|document\.URL)', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Reading URL hash/fragment without sanitization can lead to DOM XSS.",
            },
            {
                "sink_type": "url_search_params",
                "pattern": re.compile(r'(?:URLSearchParams|location\.search|getParameter)', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Reading URL parameters without sanitization can lead to injection.",
            },
        ]

        for i, line in enumerate(lines):
            for sink_def in sink_definitions:
                if sink_def["pattern"].search(line):
                    sinks.append({
                        "sink_type": sink_def["sink_type"],
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "risk_level": sink_def["risk_level"],
                        "description": sink_def["description"],
                    })

        return sinks

    # =========================================================================
    # DETECT PROTOTYPE POLLUTION
    # =========================================================================

    def detect_prototype_pollution(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Detect potential prototype pollution vectors in JavaScript code.

        Looks for patterns where user-controlled input could be used to
        pollute JavaScript object prototypes:
        - obj[userInput] = value patterns
        - Object.assign with spread from user data
        - Deep merge/extend functions
        - __proto__ references
        - constructor.prototype access
        - Recursive property assignment

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of prototype pollution dictionaries with keys:
            - pattern_type: Category of the pollution vector
            - code_snippet: The relevant code
            - line_number: Where it was found
            - risk_level: HIGH/MEDIUM/LOW
            - description: Explanation of the vulnerability
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern definitions for prototype pollution
        pollution_patterns = [
            {
                "pattern_type": "__proto__",
                "pattern": re.compile(r'__proto__', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Direct __proto__ reference. If user input reaches this, prototype pollution is possible.",
            },
            {
                "pattern_type": "constructor.prototype",
                "pattern": re.compile(r'constructor\s*\.\s*prototype', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "constructor.prototype access can be used to pollute the prototype chain.",
            },
            {
                "pattern_type": "bracket_notation_dynamic",
                "pattern": re.compile(r'\w+\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Nested bracket notation assignment (obj[a][b] = val). If a and b are user-controlled, this enables prototype pollution.",
            },
            {
                "pattern_type": "Object.assign_spread",
                "pattern": re.compile(r'Object\.assign\s*\(\s*(?:\{\}|target|obj|result)', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Object.assign can spread __proto__ from source objects if not filtered.",
            },
            {
                "pattern_type": "deep_merge",
                "pattern": re.compile(r'(?:deepMerge|deep_merge|deepExtend|deep_extend|deepCopy|deep_copy|merge|extend)\s*\(', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "Deep merge/extend functions often recursively assign properties, enabling prototype pollution.",
            },
            {
                "pattern_type": "recursive_assign",
                "pattern": re.compile(r'for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)[^}]*\[\w+\]\s*=', re.IGNORECASE),
                "risk_level": "HIGH",
                "description": "for-in loop with dynamic property assignment can pollute prototypes.",
            },
            {
                "pattern_type": "Object.defineProperty",
                "pattern": re.compile(r'Object\.defineProperty\s*\(\s*\w+\s*,\s*\w+', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Object.defineProperty with dynamic property name could modify prototype properties.",
            },
            {
                "pattern_type": "Reflect.set",
                "pattern": re.compile(r'Reflect\.(?:set|defineProperty)\s*\(', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Reflect.set/defineProperty can be used to set properties on prototypes.",
            },
            {
                "pattern_type": "Object.create_null",
                "pattern": re.compile(r'Object\.create\s*\(\s*null\s*\)', re.IGNORECASE),
                "risk_level": "LOW",
                "description": "Object.create(null) is a defense against prototype pollution (good practice).",
            },
            {
                "pattern_type": "JSON.parse_user_input",
                "pattern": re.compile(r'JSON\.parse\s*\(\s*(?:req|request|body|input|data|params|query|user)', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "JSON.parse of user input may contain __proto__ keys if not sanitized.",
            },
            {
                "pattern_type": "lodash_merge",
                "pattern": re.compile(r'_\.(?:merge|mergeWith|defaults|defaultsDeep|set|setWith)\s*\(', re.IGNORECASE),
                "risk_level": "MEDIUM",
                "description": "Lodash merge/defaults functions may be vulnerable to prototype pollution (CVE-2018-16487).",
            },
            {
                "pattern_type": "spread_operator_merge",
                "pattern": re.compile(r'\{\s*\.\.\.\w+\s*,\s*\.\.\.\w+\s*\}', re.IGNORECASE),
                "risk_level": "LOW",
                "description": "Object spread merging. While safer than deep merge, __proto__ in source can still cause issues.",
            },
        ]

        for i, line in enumerate(lines):
            for pp_def in pollution_patterns:
                if pp_def["pattern"].search(line):
                    results.append({
                        "pattern_type": pp_def["pattern_type"],
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "risk_level": pp_def["risk_level"],
                        "description": pp_def["description"],
                    })

        return results

    # =========================================================================
    # DETECT JSONP ENDPOINTS
    # =========================================================================

    def detect_jsonp_endpoints(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Detect JSONP endpoints and callback patterns in JavaScript code.

        JSONP can be exploited for information leakage if sensitive data
        is returned. Looks for:
        - callback= parameters in URLs
        - JSONP-style function calls
        - Script tag injection patterns
        - Dynamic script loading with callbacks

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of JSONP endpoint dictionaries with keys:
            - url: The JSONP endpoint URL
            - callback_param: The callback parameter name
            - evidence: The code that revealed this
            - risk_level: HIGH/MEDIUM/LOW
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: URLs with callback parameters
        callback_url_patterns = [
            re.compile(r'["\'`]([^"\'`]*[?&](?:callback|jsonp|cb|jsonpcallback|_callback)=[^"\'`]*)["\'`]', re.IGNORECASE),
            re.compile(r'["\'`]([^"\'`]+)["\'`][^;]*[?&]callback', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in callback_url_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    url = match.group(1)
                    results.append({
                        "url": url,
                        "callback_param": "callback",
                        "evidence": line.strip()[:200],
                        "risk_level": "MEDIUM",
                        "line_number": i + 1,
                    })

        # Pattern 2: Dynamic script creation for JSONP
        jsonp_script_pattern = re.compile(
            r'createElement\s*\(\s*["\'`]script["\'`]\s*\)[^;]*\.src\s*=\s*[^;]*(?:callback|jsonp|cb)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = jsonp_script_pattern.search(line)
            if match:
                results.append({
                    "url": "dynamic_script_jsonp",
                    "callback_param": "callback",
                    "evidence": line.strip()[:200],
                    "risk_level": "HIGH",
                    "line_number": i + 1,
                })

        # Pattern 3: JSONP response handling functions
        jsonp_handler_pattern = re.compile(
            r'(?:window\s*\.\s*)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(\s*(?:data|response|json|result)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = jsonp_handler_pattern.search(line)
            if match:
                func_name = match.group(1)
                if func_name not in ("function", "var", "let", "const", "if", "else"):
                    results.append({
                        "url": f"handler:{func_name}",
                        "callback_param": func_name,
                        "evidence": line.strip()[:200],
                        "risk_level": "LOW",
                        "line_number": i + 1,
                    })

        # Pattern 4: jQuery JSONP
        jquery_jsonp_pattern = re.compile(
            r'\$\.(?:ajax|getJSON)\s*\([^)]*dataType\s*:\s*["\'`]jsonp["\'`]',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = jquery_jsonp_pattern.search(line)
            if match:
                results.append({
                    "url": "jquery_jsonp_request",
                    "callback_param": "callback",
                    "evidence": line.strip()[:200],
                    "risk_level": "MEDIUM",
                    "line_number": i + 1,
                })

        return results


    # =========================================================================
    # ANALYZE POSTMESSAGE
    # =========================================================================

    def analyze_postmessage(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Analyze postMessage usage for security issues.

        Checks for:
        - window.postMessage calls (sender analysis)
        - addEventListener('message') handlers (receiver analysis)
        - Origin validation in message handlers
        - Cross-origin communication patterns
        - Wildcard target origins

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of postMessage issue dictionaries with keys:
            - type: "sender" or "receiver"
            - origin_check: Whether origin validation is present
            - code_snippet: The relevant code
            - risk_level: HIGH/MEDIUM/LOW
            - description: Security implications
            - line_number: Where it was found
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: postMessage senders
        sender_pattern = re.compile(
            r'\.postMessage\s*\(([^)]*)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = sender_pattern.search(line)
            if match:
                args = match.group(1)
                # Check if target origin is wildcard
                wildcard_origin = "*" in args and "origin" not in line.lower()
                risk_level = "HIGH" if wildcard_origin else "LOW"
                description = (
                    "postMessage with wildcard (*) target origin sends data to any window."
                    if wildcard_origin
                    else "postMessage call found. Verify target origin is properly restricted."
                )
                results.append({
                    "type": "sender",
                    "origin_check": not wildcard_origin,
                    "code_snippet": line.strip()[:200],
                    "risk_level": risk_level,
                    "description": description,
                    "line_number": i + 1,
                })

        # Pattern 2: message event listeners (receivers)
        receiver_patterns = [
            re.compile(r'addEventListener\s*\(\s*["\'`]message["\'`]', re.IGNORECASE),
            re.compile(r'on(?:message)\s*=\s*function', re.IGNORECASE),
            re.compile(r'window\.onmessage\s*=', re.IGNORECASE),
        ]

        for i, line in enumerate(lines):
            for pattern in receiver_patterns:
                if pattern.search(line):
                    # Look for origin check in nearby lines (within 10 lines)
                    context_start = max(0, i - 2)
                    context_end = min(len(lines), i + 15)
                    context_block = "\n".join(lines[context_start:context_end])

                    origin_checked = bool(re.search(
                        r'(?:event|e|evt|msg)\.origin\s*(?:===|==|!==|!=|\.|indexOf|includes|startsWith|match)',
                        context_block,
                        re.IGNORECASE
                    ))

                    if origin_checked:
                        risk_level = "LOW"
                        description = "Message event listener with origin validation (good practice)."
                    else:
                        risk_level = "HIGH"
                        description = (
                            "Message event listener WITHOUT origin validation. "
                            "Any window can send messages to this handler, "
                            "potentially leading to XSS or data manipulation."
                        )

                    results.append({
                        "type": "receiver",
                        "origin_check": origin_checked,
                        "code_snippet": line.strip()[:200],
                        "risk_level": risk_level,
                        "description": description,
                        "line_number": i + 1,
                    })
                    break

        # Pattern 3: Cross-frame communication
        cross_frame_patterns = [
            re.compile(r'(?:parent|top|opener|frames\[)\s*\.\s*postMessage', re.IGNORECASE),
            re.compile(r'contentWindow\s*\.\s*postMessage', re.IGNORECASE),
        ]
        for i, line in enumerate(lines):
            for pattern in cross_frame_patterns:
                if pattern.search(line):
                    results.append({
                        "type": "cross_frame_sender",
                        "origin_check": False,
                        "code_snippet": line.strip()[:200],
                        "risk_level": "MEDIUM",
                        "description": "Cross-frame postMessage communication detected. Verify origin handling.",
                        "line_number": i + 1,
                    })
                    break

        return results

    # =========================================================================
    # EXTRACT STORAGE KEYS
    # =========================================================================

    def extract_storage_keys(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Extract browser storage operations from JavaScript code.

        Finds usage of:
        - localStorage.setItem/getItem/removeItem
        - sessionStorage operations
        - IndexedDB operations
        - Cookie reads/writes from JavaScript
        - Cache API usage

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of storage key dictionaries with keys:
            - storage_type: localStorage/sessionStorage/cookie/indexedDB/cache
            - key_name: The storage key being used
            - operation: set/get/remove/clear
            - code_snippet: The relevant code
            - line_number: Where it was found
            - sensitivity: HIGH/MEDIUM/LOW (based on key name)
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: localStorage operations
        ls_patterns = [
            (re.compile(r'localStorage\.setItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "set"),
            (re.compile(r'localStorage\.getItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "get"),
            (re.compile(r'localStorage\.removeItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "remove"),
            (re.compile(r'localStorage\[\s*["\'`]([^"\'`]+)["\'`]\s*\]\s*=', re.IGNORECASE), "set"),
            (re.compile(r'localStorage\[\s*["\'`]([^"\'`]+)["\'`]\s*\](?!\s*=)', re.IGNORECASE), "get"),
        ]

        for i, line in enumerate(lines):
            for pattern, operation in ls_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    key_name = match.group(1)
                    sensitivity = self._classify_storage_sensitivity(key_name)
                    results.append({
                        "storage_type": "localStorage",
                        "key_name": key_name,
                        "operation": operation,
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "sensitivity": sensitivity,
                    })

        # Pattern 2: sessionStorage operations
        ss_patterns = [
            (re.compile(r'sessionStorage\.setItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "set"),
            (re.compile(r'sessionStorage\.getItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "get"),
            (re.compile(r'sessionStorage\.removeItem\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "remove"),
            (re.compile(r'sessionStorage\[\s*["\'`]([^"\'`]+)["\'`]\s*\]\s*=', re.IGNORECASE), "set"),
            (re.compile(r'sessionStorage\[\s*["\'`]([^"\'`]+)["\'`]\s*\](?!\s*=)', re.IGNORECASE), "get"),
        ]

        for i, line in enumerate(lines):
            for pattern, operation in ss_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    key_name = match.group(1)
                    sensitivity = self._classify_storage_sensitivity(key_name)
                    results.append({
                        "storage_type": "sessionStorage",
                        "key_name": key_name,
                        "operation": operation,
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "sensitivity": sensitivity,
                    })

        # Pattern 3: Cookie operations
        cookie_patterns = [
            (re.compile(r'document\.cookie\s*=\s*["\'`]?([^=;"\'`]+)', re.IGNORECASE), "set"),
            (re.compile(r'document\.cookie\.(?:match|indexOf|includes|split)\s*\([^)]*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "get"),
            (re.compile(r'(?:getCookie|readCookie|get_cookie)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "get"),
            (re.compile(r'(?:setCookie|createCookie|set_cookie)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "set"),
            (re.compile(r'(?:deleteCookie|removeCookie|eraseCookie|delete_cookie)\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "remove"),
        ]

        for i, line in enumerate(lines):
            for pattern, operation in cookie_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    key_name = match.group(1).strip()
                    if len(key_name) > 2 and not key_name.startswith("{"):
                        sensitivity = self._classify_storage_sensitivity(key_name)
                        results.append({
                            "storage_type": "cookie",
                            "key_name": key_name,
                            "operation": operation,
                            "code_snippet": line.strip()[:200],
                            "line_number": i + 1,
                            "sensitivity": sensitivity,
                        })

        # Pattern 4: IndexedDB operations
        idb_patterns = [
            (re.compile(r'(?:indexedDB|IDBDatabase)\.open\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "open"),
            (re.compile(r'createObjectStore\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "create_store"),
            (re.compile(r'transaction\s*\(\s*(?:\[\s*)?["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "transaction"),
        ]

        for i, line in enumerate(lines):
            for pattern, operation in idb_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    key_name = match.group(1)
                    results.append({
                        "storage_type": "indexedDB",
                        "key_name": key_name,
                        "operation": operation,
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "sensitivity": "MEDIUM",
                    })

        # Pattern 5: Cache API
        cache_patterns = [
            (re.compile(r'caches\.open\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "open"),
            (re.compile(r'cache\.put\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "put"),
            (re.compile(r'cache\.match\s*\(\s*["\'`]([^"\'`]+)["\'`]', re.IGNORECASE), "match"),
        ]

        for i, line in enumerate(lines):
            for pattern, operation in cache_patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    key_name = match.group(1)
                    results.append({
                        "storage_type": "cache_api",
                        "key_name": key_name,
                        "operation": operation,
                        "code_snippet": line.strip()[:200],
                        "line_number": i + 1,
                        "sensitivity": "LOW",
                    })

        return results

    def _classify_storage_sensitivity(self, key_name: str) -> str:
        """Classify sensitivity of a storage key based on its name."""
        high_keywords = [
            "token", "auth", "session", "jwt", "credential",
            "password", "secret", "private", "key", "access",
            "refresh", "bearer", "apikey", "api_key",
        ]
        medium_keywords = [
            "user", "email", "name", "id", "profile",
            "account", "preference", "setting", "config",
            "cart", "order", "payment",
        ]

        key_lower = key_name.lower()
        for kw in high_keywords:
            if kw in key_lower:
                return "HIGH"
        for kw in medium_keywords:
            if kw in key_lower:
                return "MEDIUM"
        return "LOW"

    # =========================================================================
    # ANALYZE SERVICE WORKERS
    # =========================================================================

    def analyze_service_workers(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Analyze service worker registration and features.

        Detects:
        - navigator.serviceWorker.register() calls
        - Service worker scope definition
        - Cached routes
        - Push notification setup
        - Background sync registration
        - Fetch event interception

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of service worker dictionaries with keys:
            - sw_url: The service worker file URL
            - scope: The SW scope
            - features: List of detected features
            - line_number: Where registration was found
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: SW registration
        register_pattern = re.compile(
            r'navigator\.serviceWorker\.register\s*\(\s*["\'`]([^"\'`]+)["\'`](?:\s*,\s*\{[^}]*scope\s*:\s*["\'`]([^"\'`]+)["\'`])?',
            re.IGNORECASE
        )

        for i, line in enumerate(lines):
            match = register_pattern.search(line)
            if match:
                sw_url = match.group(1)
                scope = match.group(2) if match.group(2) else "/"
                features = ["registration"]

                # Look for features in surrounding context
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 20)
                context = "\n".join(lines[context_start:context_end])

                if "pushManager" in context or "PushManager" in context:
                    features.append("push_notifications")
                if "SyncManager" in context or "sync" in context.lower():
                    features.append("background_sync")
                if "cache" in context.lower() or "CacheStorage" in context:
                    features.append("caching")
                if "fetch" in context.lower():
                    features.append("fetch_interception")
                if "notification" in context.lower():
                    features.append("notifications")

                results.append({
                    "sw_url": sw_url,
                    "scope": scope,
                    "features": features,
                    "line_number": i + 1,
                })

        # Pattern 2: SW-related event listeners
        sw_events = [
            ("install", re.compile(r'addEventListener\s*\(\s*["\'`]install["\'`]', re.IGNORECASE)),
            ("activate", re.compile(r'addEventListener\s*\(\s*["\'`]activate["\'`]', re.IGNORECASE)),
            ("fetch", re.compile(r'addEventListener\s*\(\s*["\'`]fetch["\'`]', re.IGNORECASE)),
            ("push", re.compile(r'addEventListener\s*\(\s*["\'`]push["\'`]', re.IGNORECASE)),
            ("sync", re.compile(r'addEventListener\s*\(\s*["\'`]sync["\'`]', re.IGNORECASE)),
            ("notificationclick", re.compile(r'addEventListener\s*\(\s*["\'`]notificationclick["\'`]', re.IGNORECASE)),
        ]

        detected_events = []
        for event_name, pattern in sw_events:
            for i, line in enumerate(lines):
                if pattern.search(line):
                    detected_events.append(event_name)
                    break

        if detected_events and not results:
            results.append({
                "sw_url": "inline_service_worker",
                "scope": "/",
                "features": detected_events,
                "line_number": 0,
            })

        return results


    # =========================================================================
    # DISCOVER WEBPACK CHUNKS
    # =========================================================================

    def discover_webpack_chunks(self, js_content: str, base_url: str) -> List[str]:
        """
        Discover webpack chunk files from JavaScript content.

        Looks for:
        - webpackJsonp patterns
        - __webpack_require__ calls
        - Chunk loading URLs
        - Runtime/manifest references
        - Dynamic imports

        Args:
            js_content: The JavaScript content to analyze.
            base_url: Base URL for resolving chunk paths.

        Returns:
            List of discovered chunk URLs.
        """
        chunks = []
        if not js_content:
            return chunks

        # Pattern 1: webpackJsonp push with chunk IDs
        jsonp_pattern = re.compile(
            r'(?:webpackJsonp|webpackChunk)\w*\.push\s*\(\s*\[\s*\[([\d,\s]+)\]',
            re.IGNORECASE
        )
        match = jsonp_pattern.search(js_content)
        if match:
            chunk_ids = re.findall(r'\d+', match.group(1))
            for chunk_id in chunk_ids[:20]:  # Limit to 20 chunks
                chunk_url = self._resolve_url(base_url, f"/static/js/{chunk_id}.chunk.js")
                chunks.append(chunk_url)
                chunk_url_alt = self._resolve_url(base_url, f"/js/chunk-{chunk_id}.js")
                chunks.append(chunk_url_alt)

        # Pattern 2: Chunk filename patterns in webpack runtime
        chunk_file_pattern = re.compile(
            r'(?:chunkFilename|filename)\s*[=:]\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = chunk_file_pattern.findall(js_content)
        for template in matches:
            if "[" in template:
                # Replace webpack placeholders with common values
                for i in range(5):
                    resolved = template.replace("[name]", f"chunk{i}")
                    resolved = resolved.replace("[id]", str(i))
                    resolved = resolved.replace("[chunkhash]", "abc123")
                    resolved = resolved.replace("[contenthash]", "def456")
                    chunk_url = self._resolve_url(base_url, "/" + resolved)
                    chunks.append(chunk_url)

        # Pattern 3: Static chunk paths
        static_chunk_pattern = re.compile(
            r'["\'`](/(?:static|dist|build|assets)/(?:js|chunks?)/[a-zA-Z0-9._\-]+\.js)["\'`]',
            re.IGNORECASE
        )
        matches = static_chunk_pattern.findall(js_content)
        for path in matches:
            chunk_url = self._resolve_url(base_url, path)
            if chunk_url not in chunks:
                chunks.append(chunk_url)

        # Pattern 4: Dynamic import paths
        dynamic_import_pattern = re.compile(
            r'import\s*\(\s*["\'`]([^"\'`]+)["\'`]\s*\)',
            re.IGNORECASE
        )
        matches = dynamic_import_pattern.findall(js_content)
        for path in matches:
            if path.startswith(".") or path.startswith("/"):
                chunk_url = self._resolve_url(base_url, path)
                if not chunk_url.endswith(".js"):
                    chunk_url += ".js"
                chunks.append(chunk_url)

        # Pattern 5: __webpack_require__.e (chunk loading)
        require_ensure_pattern = re.compile(
            r'__webpack_require__\.e\s*\(\s*(\d+)\s*\)',
            re.IGNORECASE
        )
        chunk_ids_found = require_ensure_pattern.findall(js_content)
        for chunk_id in chunk_ids_found[:15]:
            chunk_url = self._resolve_url(base_url, f"/static/js/{chunk_id}.js")
            chunks.append(chunk_url)

        # Pattern 6: Next.js chunk patterns
        next_chunk_pattern = re.compile(
            r'["\'`](/_next/static/chunks/[a-zA-Z0-9._\-]+\.js)["\'`]',
            re.IGNORECASE
        )
        matches = next_chunk_pattern.findall(js_content)
        for path in matches:
            chunk_url = self._resolve_url(base_url, path)
            chunks.append(chunk_url)

        return list(set(chunks))

    # =========================================================================
    # EXTRACT GRAPHQL
    # =========================================================================

    def extract_graphql(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Extract GraphQL operations from JavaScript content.

        Finds:
        - GraphQL query strings (query { ... })
        - Mutation definitions
        - Subscription definitions
        - Operation names
        - Variable definitions
        - GraphQL endpoint URLs

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of GraphQL operation dictionaries with keys:
            - operation_type: query/mutation/subscription
            - operation_name: Name of the operation (if named)
            - query_snippet: The GraphQL query text (truncated)
            - endpoint_url: Associated endpoint URL (if found)
            - line_number: Where it was found
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: Named GraphQL operations
        named_op_pattern = re.compile(
            r'(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*\{',
            re.MULTILINE
        )
        for match in named_op_pattern.finditer(js_content):
            op_type = "query"
            text_before = js_content[max(0, match.start() - 20):match.start()].lower()
            if "mutation" in text_before or match.group(0).lower().startswith("mutation"):
                op_type = "mutation"
            elif "subscription" in text_before or match.group(0).lower().startswith("subscription"):
                op_type = "subscription"

            # Find line number
            line_num = js_content[:match.start()].count("\n") + 1

            # Get a snippet of the query
            query_end = js_content.find("}", match.end())
            if query_end == -1:
                query_end = match.end() + 200
            snippet = js_content[match.start():min(query_end + 1, match.start() + 300)]

            results.append({
                "operation_type": op_type,
                "operation_name": match.group(1),
                "query_snippet": snippet.strip()[:300],
                "endpoint_url": None,
                "line_number": line_num,
            })

        # Pattern 2: gql tagged template literals
        gql_pattern = re.compile(
            r'(?:gql|graphql)\s*`([^`]{10,})`',
            re.IGNORECASE | re.DOTALL
        )
        for match in gql_pattern.finditer(js_content):
            query_text = match.group(1).strip()
            line_num = js_content[:match.start()].count("\n") + 1

            # Determine operation type
            op_type = "query"
            if query_text.strip().startswith("mutation"):
                op_type = "mutation"
            elif query_text.strip().startswith("subscription"):
                op_type = "subscription"

            # Extract operation name
            op_name_match = re.search(r'(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]*)', query_text)
            op_name = op_name_match.group(1) if op_name_match else "anonymous"

            results.append({
                "operation_type": op_type,
                "operation_name": op_name,
                "query_snippet": query_text[:300],
                "endpoint_url": None,
                "line_number": line_num,
            })

        # Pattern 3: GraphQL endpoint URLs
        gql_url_pattern = re.compile(
            r'["\'`]((?:https?://[^"\'`]+)?/(?:graphql|gql|api/graphql)[^"\'`]*)["\'`]',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = gql_url_pattern.search(line)
            if match:
                endpoint = match.group(1)
                # Associate with existing results or create new
                for result in results:
                    if result["endpoint_url"] is None:
                        result["endpoint_url"] = endpoint
                        break
                else:
                    results.append({
                        "operation_type": "unknown",
                        "operation_name": "endpoint_reference",
                        "query_snippet": "",
                        "endpoint_url": endpoint,
                        "line_number": i + 1,
                    })

        # Pattern 4: Inline query strings
        inline_query_pattern = re.compile(
            r'["\'`]\s*(\{\s*(?:query|mutation|subscription)\s*(?:\{|\())',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = inline_query_pattern.search(line)
            if match:
                results.append({
                    "operation_type": "inline_query",
                    "operation_name": "inline",
                    "query_snippet": line.strip()[:200],
                    "endpoint_url": None,
                    "line_number": i + 1,
                })

        return results

    # =========================================================================
    # EXTRACT WEBSOCKET URLS
    # =========================================================================

    def extract_websocket_urls(self, js_content: str) -> List[str]:
        """
        Extract WebSocket URLs from JavaScript content.

        Finds:
        - ws:// and wss:// URLs
        - WebSocket constructor calls
        - Socket.IO connections
        - SockJS endpoints
        - STOMP connections

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of discovered WebSocket URLs.
        """
        ws_urls = set()
        if not js_content:
            return list(ws_urls)

        # Pattern 1: ws:// and wss:// URLs
        ws_url_pattern = re.compile(
            r'["\'`](wss?://[^"\'`\s]+)["\'`]',
            re.IGNORECASE
        )
        matches = ws_url_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        # Pattern 2: new WebSocket() constructor
        ws_constructor_pattern = re.compile(
            r'new\s+WebSocket\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = ws_constructor_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        # Pattern 3: Socket.IO connections
        socketio_pattern = re.compile(
            r'io\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = socketio_pattern.findall(js_content)
        for url in matches:
            if "://" in url or url.startswith("/"):
                ws_urls.add(url)

        # Pattern 4: Socket.IO with options
        socketio_opts_pattern = re.compile(
            r'io\.connect\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = socketio_opts_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        # Pattern 5: SockJS endpoints
        sockjs_pattern = re.compile(
            r'new\s+SockJS\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = sockjs_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        # Pattern 6: STOMP connections
        stomp_pattern = re.compile(
            r'Stomp\.(?:over|client)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = stomp_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        # Pattern 7: Dynamic WebSocket URL construction
        ws_dynamic_pattern = re.compile(
            r'(?:wsUrl|ws_url|websocketUrl|socket_url|socketUrl)\s*[=:]\s*["\'`]([^"\'`]+)["\'`]',
            re.IGNORECASE
        )
        matches = ws_dynamic_pattern.findall(js_content)
        for url in matches:
            ws_urls.add(url)

        return list(ws_urls)

    # =========================================================================
    # DETECT DEBUG INFO
    # =========================================================================

    def detect_debug_info(self, js_content: str) -> List[Dict[str, Any]]:
        """
        Detect debug/development information left in production JavaScript.

        Finds:
        - console.log/debug/warn with sensitive data
        - Source map references (//# sourceMappingURL)
        - TODO/FIXME comments with auth info
        - Hardcoded credentials in comments
        - Development-only code paths
        - Debug flags and toggles

        Args:
            js_content: The JavaScript content to analyze.

        Returns:
            List of debug info dictionaries with keys:
            - type: Category of debug info
            - content: The relevant content
            - line_number: Where it was found
            - severity: HIGH/MEDIUM/LOW/INFO
        """
        results = []
        if not js_content:
            return results

        lines = js_content.split("\n")

        # Pattern 1: Source map references
        sourcemap_pattern = re.compile(
            r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = sourcemap_pattern.search(line)
            if match:
                results.append({
                    "type": "source_map",
                    "content": match.group(1),
                    "line_number": i + 1,
                    "severity": "MEDIUM",
                })

        # Pattern 2: Console statements with sensitive data
        sensitive_console_pattern = re.compile(
            r'console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|token|secret|key|auth|credential|session|cookie|jwt|bearer)[^)]*\)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = sensitive_console_pattern.search(line)
            if match:
                results.append({
                    "type": "sensitive_console_log",
                    "content": line.strip()[:200],
                    "line_number": i + 1,
                    "severity": "HIGH",
                })

        # Pattern 3: General console.log (info level)
        console_log_pattern = re.compile(r'console\.(?:log|debug)\s*\(', re.IGNORECASE)
        console_count = 0
        for i, line in enumerate(lines):
            if console_log_pattern.search(line):
                console_count += 1
        if console_count > 5:
            results.append({
                "type": "excessive_console_logs",
                "content": f"Found {console_count} console.log/debug statements in production code",
                "line_number": 0,
                "severity": "INFO",
            })

        # Pattern 4: TODO/FIXME with sensitive context
        todo_pattern = re.compile(
            r'(?://|/\*|\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)[^\n]*(?:password|token|secret|auth|credential|key|hack|bypass|workaround)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = todo_pattern.search(line)
            if match:
                results.append({
                    "type": "sensitive_comment",
                    "content": line.strip()[:200],
                    "line_number": i + 1,
                    "severity": "MEDIUM",
                })

        # Pattern 5: Debug/development flags
        debug_flag_pattern = re.compile(
            r'(?:DEBUG|DEVELOPMENT|DEV_MODE|IS_DEV|isDebug|debugMode)\s*[=:]\s*(?:true|1|!0)',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = debug_flag_pattern.search(line)
            if match:
                results.append({
                    "type": "debug_flag_enabled",
                    "content": line.strip()[:200],
                    "line_number": i + 1,
                    "severity": "MEDIUM",
                })

        # Pattern 6: Commented-out credentials
        commented_creds_pattern = re.compile(
            r'(?://|/\*|\*)\s*(?:password|secret|token|key)\s*[=:]\s*["\'`]?[^\s"\'`/]{4,}',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = commented_creds_pattern.search(line)
            if match:
                results.append({
                    "type": "commented_credential",
                    "content": line.strip()[:200],
                    "line_number": i + 1,
                    "severity": "HIGH",
                })

        # Pattern 7: Development/staging URLs
        dev_url_pattern = re.compile(
            r'["\'`]((?:https?://)?(?:localhost|127\.0\.0\.1|dev\.|staging\.|test\.|qa\.)[^"\'`\s]*)["\'`]',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            match = dev_url_pattern.search(line)
            if match:
                results.append({
                    "type": "development_url",
                    "content": match.group(1),
                    "line_number": i + 1,
                    "severity": "LOW",
                })

        # Pattern 8: Stack traces or error details
        stack_trace_pattern = re.compile(
            r'(?:at\s+\w+\s+\(|Error:\s|Traceback|stack\s*:\s*["\'`])',
            re.IGNORECASE
        )
        for i, line in enumerate(lines):
            if stack_trace_pattern.search(line):
                results.append({
                    "type": "error_trace",
                    "content": line.strip()[:200],
                    "line_number": i + 1,
                    "severity": "LOW",
                })
                break  # Only report first occurrence

        return results

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _extract_inline_scripts(self, html_content: str) -> List[str]:
        """
        Extract inline JavaScript from HTML script tags without src attribute.

        Args:
            html_content: The HTML content to parse.

        Returns:
            List of inline script content strings.
        """
        scripts = []
        if not html_content:
            return scripts

        # Match script tags without src
        pattern = re.compile(
            r'<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>',
            re.IGNORECASE | re.DOTALL
        )
        matches = pattern.findall(html_content)
        for script_content in matches:
            content = script_content.strip()
            if content and len(content) > 20:  # Skip tiny scripts
                scripts.append(content)

        return scripts

    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """
        Resolve a relative URL against a base URL.

        Handles:
        - Absolute URLs (returned as-is)
        - Protocol-relative URLs (//example.com)
        - Root-relative URLs (/path)
        - Relative URLs (./path, ../path)
        - Query string and fragment handling

        Args:
            base_url: The base URL to resolve against.
            relative_url: The relative URL to resolve.

        Returns:
            The resolved absolute URL.
        """
        if not relative_url:
            return base_url

        # Already absolute
        if relative_url.startswith(("http://", "https://")):
            return relative_url

        # Protocol-relative
        if relative_url.startswith("//"):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}:{relative_url}"

        # Use urljoin for standard resolution
        try:
            resolved = urljoin(base_url, relative_url)
            return resolved
        except Exception:
            return base_url + "/" + relative_url.lstrip("/")

    def _save_results(self, results: List[JSResults]) -> None:
        """
        Save analysis results to the output directory.

        Creates JSON and text report files for the analysis findings.

        Args:
            results: List of JSResults to save.
        """
        try:
            output_data = {
                "analysis_date": datetime.now().isoformat(),
                "total_targets": len(results),
                "results": [r.to_dict() for r in results],
            }

            # Save JSON report
            json_path = Path(self.output_dir) / "js_analysis.json"
            self.file_manager.save_json(output_data, str(json_path))

            # Save text summary
            summary_path = Path(self.output_dir) / "js_analysis_summary.txt"
            summary_lines = []
            summary_lines.append("=" * 70)
            summary_lines.append("MONSTER JS ANALYSIS REPORT")
            summary_lines.append("=" * 70)
            summary_lines.append(f"Date: {datetime.now().isoformat()}")
            summary_lines.append(f"Targets Analyzed: {len(results)}")
            summary_lines.append("")

            for result in results:
                summary_lines.append("-" * 50)
                summary_lines.append(f"Target: {result.target}")
                summary_lines.append(f"JS Files Found: {result.js_files_found}")
                summary_lines.append(f"Endpoints: {len(result.endpoints)}")
                summary_lines.append(f"Secrets: {len(result.secrets)}")
                summary_lines.append(f"DOM Sinks: {len(result.dom_sinks)}")
                summary_lines.append(f"Dependencies: {len(result.dependencies)}")
                summary_lines.append("")

                if result.secrets:
                    summary_lines.append("  SECRETS FOUND:")
                    for secret in result.secrets[:20]:
                        summary_lines.append(
                            f"    [{secret['severity']}] {secret['pattern_name']}: "
                            f"{secret['matched_value'][:50]}"
                        )
                    summary_lines.append("")

                if result.dom_sinks:
                    summary_lines.append("  DOM SINKS:")
                    for sink in result.dom_sinks[:15]:
                        summary_lines.append(
                            f"    [{sink['risk_level']}] {sink['sink_type']} "
                            f"(line {sink['line_number']})"
                        )
                    summary_lines.append("")

            self.file_manager.write_file(str(summary_path), "\n".join(summary_lines))
            self.color.success(f"  Results saved to {self.output_dir}")

        except Exception as e:
            self.color.error(f"  Error saving results: {str(e)}")
