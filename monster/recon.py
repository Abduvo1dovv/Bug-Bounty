"""
Monster - Full Passive Reconnaissance Engine.

Comprehensive subdomain enumeration, DNS analysis, technology fingerprinting,
port scanning, historical URL discovery, and search query generation.
"""

import json
import os
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from monster.config import (
    COMMON_PORTS,
    GOOGLE_DORK_TEMPLATES,
    MAX_THREADS,
    SHODAN_QUERY_TEMPLATES,
    TECH_SIGNATURES,
    TIMEOUT,
    load_api_keys,
)
from monster.utils import (
    ColorOutput,
    DNSResolver,
    FileManager,
    HTTPClient,
    RateLimiter,
    domain_from_url,
    normalize_url,
)


# ---------------------------------------------------------------------------
# ReconResults Dataclass
# ---------------------------------------------------------------------------

@dataclass
class ReconResults:
    """Container for all reconnaissance results."""

    domain: str
    subdomains: List[dict] = field(default_factory=list)
    dns_records: Dict[str, dict] = field(default_factory=dict)
    wayback_urls: List[str] = field(default_factory=list)
    google_dorks: List[str] = field(default_factory=list)
    shodan_queries: List[str] = field(default_factory=list)
    scan_time: float = 0.0

    def to_dict(self):
        """Convert results to a serializable dictionary."""
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "dns_records": self.dns_records,
            "wayback_urls": self.wayback_urls,
            "google_dorks": self.google_dorks,
            "shodan_queries": self.shodan_queries,
            "scan_time": self.scan_time,
        }


# ---------------------------------------------------------------------------
# ReconEngine
# ---------------------------------------------------------------------------

class ReconEngine:
    """Full passive reconnaissance engine for bug bounty research."""

    def __init__(self, domain: str, output_dir: str, options: dict = None):
        """
        Initialize the ReconEngine.

        Args:
            domain: Target domain to reconnoiter.
            output_dir: Directory to store output files.
            options: Optional dict with keys like 'dry_run', 'max_threads', etc.
        """
        self.domain = domain.lower().strip()
        self.output_dir = output_dir
        self.options = options or {}
        self.dry_run = self.options.get("dry_run", False)

        self.http = HTTPClient(verify_ssl=False)
        self.file_manager = FileManager(output_dir)
        self.api_keys = load_api_keys()
        self.max_threads = self.options.get("max_threads", MAX_THREADS)

        # Wordlist path relative to this module
        self._wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "wordlists",
            "subdomains.txt",
        )

    # -----------------------------------------------------------------------
    # Subdomain Enumeration Sources
    # -----------------------------------------------------------------------

    def enumerate_crtsh(self, domain: str) -> List[str]:
        """
        Query Certificate Transparency logs via crt.sh.

        Args:
            domain: Target domain.

        Returns:
            List of unique subdomains found.
        """
        if self.dry_run:
            ColorOutput.info(f"[DRY RUN] Would query crt.sh for *.{domain}")
            return []

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        ColorOutput.info(f"Querying crt.sh for *.{domain}")

        result = self.http.get(url)
        if result is None:
            ColorOutput.warning("crt.sh query failed")
            return []

        status_code, headers, body = result
        if status_code != 200:
            ColorOutput.warning(f"crt.sh returned status {status_code}")
            return []

        subdomains = set()
        try:
            entries = json.loads(body)
            for entry in entries:
                name_value = entry.get("name_value", "")
                # name_value can contain multiple domains separated by newlines
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and name.endswith(f".{domain}") or name == domain:
                        # Remove wildcard prefix if present
                        name = name.lstrip("*.")
                        if name:
                            subdomains.add(name)
        except (json.JSONDecodeError, TypeError, KeyError):
            ColorOutput.warning("Failed to parse crt.sh response")

        ColorOutput.success(f"crt.sh: found {len(subdomains)} subdomains")
        return list(subdomains)

    def enumerate_bruteforce(self, domain: str) -> List[str]:
        """
        Brute-force subdomain discovery using wordlist and DNS resolution.

        Args:
            domain: Target domain.

        Returns:
            List of subdomains that resolve.
        """
        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would bruteforce subdomains for {domain}"
            )
            return []

        if not os.path.isfile(self._wordlist_path):
            ColorOutput.warning(f"Wordlist not found: {self._wordlist_path}")
            return []

        with open(self._wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]

        ColorOutput.info(
            f"Bruteforcing {len(words)} subdomains for {domain}"
        )

        found = []
        lock = __import__("threading").Lock()

        def _check_subdomain(word):
            fqdn = f"{word}.{domain}"
            try:
                socket.getaddrinfo(fqdn, None, socket.AF_INET)
                with lock:
                    found.append(fqdn)
            except (socket.gaierror, OSError):
                pass

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [
                executor.submit(_check_subdomain, word) for word in words
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        ColorOutput.success(f"Bruteforce: found {len(found)} subdomains")
        return found

    def enumerate_virustotal(self, domain: str) -> List[str]:
        """
        Query VirusTotal passive DNS for subdomains.

        Args:
            domain: Target domain.

        Returns:
            List of subdomains found.
        """
        api_key = self.api_keys.get("virustotal")
        if not api_key:
            ColorOutput.info("VirusTotal: no API key configured, skipping")
            return []

        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would query VirusTotal for {domain}"
            )
            return []

        url = (
            f"https://www.virustotal.com/vtapi/v2/domain/report"
            f"?apikey={api_key}&domain={domain}"
        )
        ColorOutput.info(f"Querying VirusTotal for {domain}")

        result = self.http.get(url)
        if result is None:
            ColorOutput.warning("VirusTotal query failed")
            return []

        status_code, headers, body = result
        if status_code != 200:
            ColorOutput.warning(f"VirusTotal returned status {status_code}")
            return []

        subdomains = set()
        try:
            data = json.loads(body)
            for entry in data.get("subdomains", []):
                sub = entry.strip().lower()
                if sub:
                    subdomains.add(sub)
        except (json.JSONDecodeError, TypeError, KeyError):
            ColorOutput.warning("Failed to parse VirusTotal response")

        ColorOutput.success(
            f"VirusTotal: found {len(subdomains)} subdomains"
        )
        return list(subdomains)

    def enumerate_securitytrails(self, domain: str) -> List[str]:
        """
        Query SecurityTrails API for subdomains.

        Args:
            domain: Target domain.

        Returns:
            List of subdomains found.
        """
        api_key = self.api_keys.get("securitytrails")
        if not api_key:
            ColorOutput.info("SecurityTrails: no API key configured, skipping")
            return []

        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would query SecurityTrails for {domain}"
            )
            return []

        url = (
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        )
        headers = {"apikey": api_key}
        ColorOutput.info(f"Querying SecurityTrails for {domain}")

        result = self.http.get(url, headers=headers)
        if result is None:
            ColorOutput.warning("SecurityTrails query failed")
            return []

        status_code, resp_headers, body = result
        if status_code != 200:
            ColorOutput.warning(
                f"SecurityTrails returned status {status_code}"
            )
            return []

        subdomains = set()
        try:
            data = json.loads(body)
            for sub in data.get("subdomains", []):
                fqdn = f"{sub.strip().lower()}.{domain}"
                subdomains.add(fqdn)
        except (json.JSONDecodeError, TypeError, KeyError):
            ColorOutput.warning("Failed to parse SecurityTrails response")

        ColorOutput.success(
            f"SecurityTrails: found {len(subdomains)} subdomains"
        )
        return list(subdomains)

    def enumerate_wayback(self, domain: str) -> List[str]:
        """
        Extract subdomains from Wayback Machine CDX API.

        Args:
            domain: Target domain.

        Returns:
            List of unique subdomains found in archived URLs.
        """
        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would query Wayback Machine for *.{domain}"
            )
            return []

        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        )
        ColorOutput.info(f"Querying Wayback Machine for *.{domain}")

        result = self.http.get(url)
        if result is None:
            ColorOutput.warning("Wayback Machine query failed")
            return []

        status_code, headers, body = result
        if status_code != 200:
            ColorOutput.warning(f"Wayback Machine returned status {status_code}")
            return []

        subdomains = set()
        try:
            rows = json.loads(body)
            # First row is the header
            for row in rows[1:]:
                if row and row[0]:
                    parsed_url = urllib.parse.urlparse(row[0])
                    host = parsed_url.hostname
                    if host and host.endswith(f".{domain}"):
                        subdomains.add(host.lower())
        except (json.JSONDecodeError, TypeError, IndexError):
            ColorOutput.warning("Failed to parse Wayback Machine response")

        ColorOutput.success(
            f"Wayback Machine: found {len(subdomains)} subdomains"
        )
        return list(subdomains)

    def enumerate_commoncrawl(self, domain: str) -> List[str]:
        """
        Extract subdomains from Common Crawl index.

        Args:
            domain: Target domain.

        Returns:
            List of unique subdomains found.
        """
        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would query Common Crawl for *.{domain}"
            )
            return []

        url = (
            f"http://index.commoncrawl.org/CC-MAIN-2024-10-index"
            f"?url=*.{domain}&output=json"
        )
        ColorOutput.info(f"Querying Common Crawl for *.{domain}")

        result = self.http.get(url)
        if result is None:
            ColorOutput.warning("Common Crawl query failed")
            return []

        status_code, headers, body = result
        if status_code != 200:
            ColorOutput.warning(f"Common Crawl returned status {status_code}")
            return []

        subdomains = set()
        try:
            # Common Crawl returns newline-delimited JSON
            for line in body.strip().split("\n"):
                if not line.strip():
                    continue
                entry = json.loads(line)
                url_str = entry.get("url", "")
                if url_str:
                    parsed = urllib.parse.urlparse(url_str)
                    host = parsed.hostname
                    if host and host.endswith(f".{domain}"):
                        subdomains.add(host.lower())
        except (json.JSONDecodeError, TypeError, KeyError):
            ColorOutput.warning("Failed to parse Common Crawl response")

        ColorOutput.success(
            f"Common Crawl: found {len(subdomains)} subdomains"
        )
        return list(subdomains)

    # -----------------------------------------------------------------------
    # DNS Record Enumeration
    # -----------------------------------------------------------------------

    def resolve_dns(self, subdomain: str) -> dict:
        """
        Resolve all DNS record types for a subdomain.

        Args:
            subdomain: The subdomain to resolve.

        Returns:
            Dict with record types as keys and lists of values.
        """
        if self.dry_run:
            return {}

        records = {}
        for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"):
            result = DNSResolver.resolve(subdomain, rtype)
            if result:
                records[rtype] = result

        return records

    # -----------------------------------------------------------------------
    # Technology Fingerprinting
    # -----------------------------------------------------------------------

    def fingerprint_tech(self, url: str) -> List[str]:
        """
        Fingerprint technologies by analyzing HTTP response.

        Args:
            url: URL to fingerprint.

        Returns:
            List of detected technology names.
        """
        if self.dry_run:
            return []

        result = self.http.get(url)
        if result is None:
            return []

        status_code, headers, body = result
        technologies = set()

        # Check response headers
        header_sigs = TECH_SIGNATURES.get("headers", {})
        for header_name, patterns in header_sigs.items():
            header_value = headers.get(header_name, "").lower()
            if header_value:
                for pattern, tech_name in patterns.items():
                    if pattern.lower() in header_value:
                        technologies.add(tech_name)

        # Check cookies
        cookie_sigs = TECH_SIGNATURES.get("cookies", {})
        set_cookie = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
        for cookie_name, tech_name in cookie_sigs.items():
            if cookie_name.lower() in set_cookie.lower():
                technologies.add(tech_name)

        # Check response body (limited to first 50KB)
        body_sigs = TECH_SIGNATURES.get("body", {})
        body_sample = body[:51200].lower()
        for pattern, tech_name in body_sigs.items():
            if pattern.lower() in body_sample:
                technologies.add(tech_name)

        return list(technologies)

    # -----------------------------------------------------------------------
    # Port Scanning
    # -----------------------------------------------------------------------

    def check_ports(self, host: str) -> List[int]:
        """
        Check common ports on a host using socket.connect_ex.

        Args:
            host: Hostname or IP to scan.

        Returns:
            List of open port numbers.
        """
        if self.dry_run:
            return []

        open_ports = []
        lock = __import__("threading").Lock()

        def _check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    with lock:
                        open_ports.append(port)
            except (socket.error, OSError):
                pass

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [
                executor.submit(_check_port, port) for port in COMMON_PORTS
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        return sorted(open_ports)

    # -----------------------------------------------------------------------
    # HTTP Response Analysis
    # -----------------------------------------------------------------------

    def analyze_http(self, url: str) -> Optional[dict]:
        """
        Analyze HTTP response including redirect chain.

        Args:
            url: URL to analyze.

        Returns:
            Dict with status_code, final_url, redirect_chain, response_size,
            server_header, and interesting_headers. None on failure.
        """
        if self.dry_run:
            return None

        redirect_chain = []
        current_url = url
        max_redirects = 10

        for _ in range(max_redirects):
            result = self.http.get(current_url)
            if result is None:
                break

            status_code, headers, body = result

            redirect_chain.append({
                "url": current_url,
                "status_code": status_code,
            })

            # Check for redirect
            if status_code in (301, 302, 303, 307, 308):
                location = headers.get("Location") or headers.get("location")
                if location:
                    # Handle relative redirects
                    if not location.startswith("http"):
                        parsed = urllib.parse.urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                    continue
            break
        else:
            # Max redirects reached
            pass

        if not redirect_chain:
            return None

        last = redirect_chain[-1]
        interesting_headers = {}
        if result:
            _, final_headers, final_body = result
            for h in (
                "Server", "X-Powered-By", "X-AspNet-Version",
                "X-Generator", "Via", "X-Cache", "X-Frame-Options",
                "Content-Security-Policy", "Strict-Transport-Security",
                "X-Content-Type-Options", "Access-Control-Allow-Origin",
            ):
                val = final_headers.get(h)
                if val:
                    interesting_headers[h] = val

            return {
                "status_code": last["status_code"],
                "final_url": current_url,
                "redirect_chain": redirect_chain if len(redirect_chain) > 1 else [],
                "response_size": len(final_body),
                "server_header": final_headers.get("Server", ""),
                "interesting_headers": interesting_headers,
            }

        return {
            "status_code": last["status_code"],
            "final_url": current_url,
            "redirect_chain": redirect_chain if len(redirect_chain) > 1 else [],
            "response_size": 0,
            "server_header": "",
            "interesting_headers": interesting_headers,
        }

    # -----------------------------------------------------------------------
    # Historical URL Discovery
    # -----------------------------------------------------------------------

    def discover_wayback_urls(self, domain: str) -> dict:
        """
        Discover historical URLs from Wayback Machine CDX API.

        Args:
            domain: Target domain.

        Returns:
            Dict with categorized URLs: api_endpoints, admin_panels,
            interesting_files, all_urls.
        """
        if self.dry_run:
            ColorOutput.info(
                f"[DRY RUN] Would discover Wayback URLs for {domain}"
            )
            return {
                "api_endpoints": [],
                "admin_panels": [],
                "interesting_files": [],
                "all_urls": [],
            }

        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey"
        )
        ColorOutput.info(f"Discovering historical URLs for {domain}")

        result = self.http.get(url)
        if result is None:
            return {
                "api_endpoints": [],
                "admin_panels": [],
                "interesting_files": [],
                "all_urls": [],
            }

        status_code, headers, body = result
        if status_code != 200:
            return {
                "api_endpoints": [],
                "admin_panels": [],
                "interesting_files": [],
                "all_urls": [],
            }

        all_urls = set()
        api_endpoints = set()
        admin_panels = set()
        interesting_files = set()

        interesting_extensions = (
            ".sql", ".bak", ".env", ".log", ".zip", ".tar.gz",
            ".gz", ".rar", ".7z", ".db", ".sqlite", ".dump",
            ".conf", ".cfg", ".ini", ".yaml", ".yml", ".xml",
        )

        admin_keywords = (
            "/admin", "/administrator", "/manage", "/dashboard",
            "/panel", "/console", "/control", "/cpanel", "/wp-admin",
        )

        api_keywords = (
            "/api/", "/api-", "/v1/", "/v2/", "/v3/",
            "/graphql", "/rest/", "/json/", "/endpoint",
        )

        try:
            rows = json.loads(body)
            for row in rows[1:]:
                if not row or not row[0]:
                    continue
                original_url = row[0]
                all_urls.add(original_url)

                url_lower = original_url.lower()

                # Categorize API endpoints
                for keyword in api_keywords:
                    if keyword in url_lower:
                        api_endpoints.add(original_url)
                        break

                # Categorize admin panels
                for keyword in admin_keywords:
                    if keyword in url_lower:
                        admin_panels.add(original_url)
                        break

                # Categorize interesting files
                for ext in interesting_extensions:
                    if url_lower.endswith(ext):
                        interesting_files.add(original_url)
                        break

        except (json.JSONDecodeError, TypeError, IndexError):
            ColorOutput.warning("Failed to parse Wayback CDX response")

        ColorOutput.success(
            f"Wayback URLs: {len(all_urls)} total, "
            f"{len(api_endpoints)} API, "
            f"{len(admin_panels)} admin, "
            f"{len(interesting_files)} interesting files"
        )

        return {
            "api_endpoints": sorted(api_endpoints),
            "admin_panels": sorted(admin_panels),
            "interesting_files": sorted(interesting_files),
            "all_urls": sorted(all_urls),
        }

    # -----------------------------------------------------------------------
    # Google Dorking Query Generator
    # -----------------------------------------------------------------------

    def generate_google_dorks(self) -> List[str]:
        """
        Generate Google dork queries for the target domain.

        Returns:
            List of ready-to-use Google search queries.
        """
        dorks = []
        for template in GOOGLE_DORK_TEMPLATES:
            dorks.append(template.format(domain=self.domain))
        return dorks

    # -----------------------------------------------------------------------
    # Shodan Query Generator
    # -----------------------------------------------------------------------

    def generate_shodan_queries(self) -> List[str]:
        """
        Generate Shodan search queries for the target domain.

        Returns:
            List of Shodan search queries.
        """
        queries = []
        for template in SHODAN_QUERY_TEMPLATES:
            # Handle {org} placeholder with domain name as fallback
            query = template.format(domain=self.domain, org=self.domain)
            queries.append(query)
        return queries

    # -----------------------------------------------------------------------
    # Master Orchestrator
    # -----------------------------------------------------------------------

    def run(self) -> ReconResults:
        """
        Execute the full reconnaissance workflow.

        Returns:
            ReconResults dataclass with all collected data.
        """
        start_time = time.time()
        results = ReconResults(domain=self.domain)

        ColorOutput.banner()
        ColorOutput.info(f"Starting reconnaissance on: {self.domain}")

        if self.dry_run:
            ColorOutput.warning("DRY RUN MODE - no network calls will be made")

        # --- Phase 1: Subdomain Enumeration ---
        ColorOutput.info("Phase 1: Subdomain Enumeration")
        all_subdomains = set()

        sources = [
            ("crt.sh", self.enumerate_crtsh),
            ("bruteforce", self.enumerate_bruteforce),
            ("virustotal", self.enumerate_virustotal),
            ("securitytrails", self.enumerate_securitytrails),
            ("wayback", self.enumerate_wayback),
            ("commoncrawl", self.enumerate_commoncrawl),
        ]

        subdomain_sources = {}  # subdomain -> source name

        for source_name, source_fn in sources:
            try:
                found = source_fn(self.domain)
                for sub in found:
                    sub = sub.lower().strip()
                    if sub and sub not in subdomain_sources:
                        subdomain_sources[sub] = source_name
                    all_subdomains.add(sub)
            except Exception as e:
                ColorOutput.error(
                    f"Error in {source_name} enumeration: {e}"
                )

        ColorOutput.success(
            f"Total unique subdomains found: {len(all_subdomains)}"
        )

        # --- Phase 2: DNS Resolution & Analysis ---
        ColorOutput.info("Phase 2: DNS Resolution & Analysis")
        subdomain_list = sorted(all_subdomains)

        for idx, subdomain in enumerate(subdomain_list, 1):
            if not self.dry_run:
                ColorOutput.progress(
                    idx, len(subdomain_list), f"Resolving {subdomain}"
                )

            dns_data = self.resolve_dns(subdomain)
            if dns_data:
                results.dns_records[subdomain] = dns_data

        # --- Phase 3: HTTP Analysis & Fingerprinting ---
        ColorOutput.info("Phase 3: HTTP Analysis & Technology Fingerprinting")

        for idx, subdomain in enumerate(subdomain_list, 1):
            # Only analyze subdomains that have A or AAAA records
            dns_data = results.dns_records.get(subdomain, {})
            ip_addresses = dns_data.get("A", [])
            cname_records = dns_data.get("CNAME", [])

            if not ip_addresses and not self.dry_run:
                continue

            if not self.dry_run:
                ColorOutput.progress(
                    idx, len(subdomain_list), f"Analyzing {subdomain}"
                )

            url = normalize_url(subdomain)
            technologies = self.fingerprint_tech(url)
            http_info = self.analyze_http(url)
            open_ports = self.check_ports(subdomain)

            subdomain_entry = {
                "name": subdomain,
                "source": subdomain_sources.get(subdomain, "unknown"),
                "ip": ip_addresses[0] if ip_addresses else None,
                "cname": cname_records[0] if cname_records else None,
                "technologies": technologies,
                "open_ports": open_ports,
            }

            if http_info:
                subdomain_entry["http"] = http_info

            results.subdomains.append(subdomain_entry)

        # --- Phase 4: Historical URL Discovery ---
        ColorOutput.info("Phase 4: Historical URL Discovery")
        wayback_data = self.discover_wayback_urls(self.domain)
        results.wayback_urls = wayback_data.get("all_urls", [])

        # --- Phase 5: Search Queries ---
        ColorOutput.info("Phase 5: Generating Search Queries")
        results.google_dorks = self.generate_google_dorks()
        results.shodan_queries = self.generate_shodan_queries()

        # --- Finalize ---
        results.scan_time = time.time() - start_time

        ColorOutput.success(
            f"Reconnaissance complete in {results.scan_time:.1f}s"
        )
        ColorOutput.success(f"  Subdomains: {len(results.subdomains)}")
        ColorOutput.success(
            f"  DNS Records: {len(results.dns_records)} resolved"
        )
        ColorOutput.success(
            f"  Wayback URLs: {len(results.wayback_urls)}"
        )
        ColorOutput.success(
            f"  Google Dorks: {len(results.google_dorks)}"
        )
        ColorOutput.success(
            f"  Shodan Queries: {len(results.shodan_queries)}"
        )

        # Save results to output file
        if not self.dry_run:
            try:
                filepath = self.file_manager.save_json(
                    results.to_dict(), "recon.json"
                )
                ColorOutput.success(f"Results saved to: {filepath}")
            except Exception as e:
                ColorOutput.error(f"Failed to save results: {e}")
        else:
            ColorOutput.info("[DRY RUN] Results would be saved to recon.json")

        return results
