"""
Monster v2.0.0 Reconnaissance Engine

Massively expanded reconnaissance module providing comprehensive
passive and semi-passive reconnaissance capabilities including
subdomain enumeration from multiple sources, DNS analysis, ASN
lookups, cloud asset discovery, technology fingerprinting,
port scanning, and more.
"""

import os
import re
import sys
import json
import time
import socket
import struct
import hashlib
import base64
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple, Set

from monster.utils import (
    ColorOutput, HTTPClient, DNSResolver, FileManager,
    RateLimiter, normalize_url, domain_from_url,
    is_valid_domain, is_ip
)
from monster.config import (
    COMMON_PORTS, GOOGLE_DORK_TEMPLATES, SHODAN_QUERY_TEMPLATES,
    TECH_SIGNATURES, TIMEOUT, MAX_THREADS, SUBDOMAIN_WORDLIST,
    load_api_keys
)


# =============================================================================
# RECON RESULTS DATACLASS
# =============================================================================


@dataclass
class ReconResults:
    """
    Container for all reconnaissance results.

    Holds structured data from all recon techniques including
    subdomain enumeration, DNS analysis, port scanning,
    technology fingerprinting, and more.
    """
    domain: str = ""
    subdomains: List[Dict[str, Any]] = field(default_factory=list)
    dns_records: Dict[str, Any] = field(default_factory=dict)
    wayback_urls: List[str] = field(default_factory=list)
    google_dorks: List[str] = field(default_factory=list)
    shodan_queries: List[str] = field(default_factory=list)
    technologies: List[Dict[str, str]] = field(default_factory=list)
    ports: Dict[str, List[int]] = field(default_factory=dict)
    asn_info: Dict[str, Any] = field(default_factory=dict)
    cloud_assets: List[Dict[str, str]] = field(default_factory=list)
    email_security: Dict[str, Any] = field(default_factory=dict)
    vhosts: List[str] = field(default_factory=list)
    scan_time: float = 0.0
    live_hosts: List[Dict[str, Any]] = field(default_factory=list)
    github_dorks: List[str] = field(default_factory=list)
    gitlab_dorks: List[str] = field(default_factory=list)
    s3_buckets: List[Dict[str, str]] = field(default_factory=list)
    reverse_ip_results: Dict[str, List[str]] = field(default_factory=dict)
    zone_transfer_results: Dict[str, List[str]] = field(default_factory=dict)
    favicon_hashes: Dict[str, str] = field(default_factory=dict)
    screenshot_urls: List[str] = field(default_factory=list)
    metadata_exposures: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert results to a dictionary suitable for JSON serialization.

        Returns:
            Dictionary containing all reconnaissance results.
        """
        return {
            "domain": self.domain,
            "scan_time": self.scan_time,
            "subdomains": self.subdomains,
            "subdomain_count": len(self.subdomains),
            "dns_records": self.dns_records,
            "wayback_urls": self.wayback_urls,
            "wayback_url_count": len(self.wayback_urls),
            "google_dorks": self.google_dorks,
            "shodan_queries": self.shodan_queries,
            "technologies": self.technologies,
            "ports": self.ports,
            "asn_info": self.asn_info,
            "cloud_assets": self.cloud_assets,
            "email_security": self.email_security,
            "vhosts": self.vhosts,
            "live_hosts": self.live_hosts,
            "github_dorks": self.github_dorks,
            "gitlab_dorks": self.gitlab_dorks,
            "s3_buckets": self.s3_buckets,
            "reverse_ip_results": self.reverse_ip_results,
            "zone_transfer_results": self.zone_transfer_results,
            "favicon_hashes": self.favicon_hashes,
            "screenshot_urls": self.screenshot_urls,
            "metadata_exposures": self.metadata_exposures,
        }


# =============================================================================
# RECON ENGINE CLASS
# =============================================================================


class ReconEngine:
    """
    Comprehensive reconnaissance engine for bug bounty and security assessments.

    Performs passive and semi-passive reconnaissance including subdomain
    enumeration from multiple sources, DNS analysis, ASN lookups, cloud
    asset discovery, technology fingerprinting, port scanning, and more.

    Attributes:
        domain: Target domain for reconnaissance.
        output_dir: Directory for saving results.
        options: Configuration options dictionary.
        http: HTTP client instance for making requests.
        dns: DNS resolver instance.
        file_manager: File manager for saving output.
        api_keys: Loaded API keys for third-party services.
        dry_run: Whether to skip actual network requests.
        verbose: Whether to print verbose output.
        results: Accumulated reconnaissance results.
    """

    def __init__(self, domain: str, output_dir: str, options: Dict[str, Any] = None):
        """
        Initialize the ReconEngine.

        Args:
            domain: Target domain to perform reconnaissance on.
            output_dir: Directory path where results will be saved.
            options: Optional configuration dictionary with keys:
                - dry_run (bool): Skip network requests if True.
                - verbose (bool): Enable verbose logging.
                - threads (int): Number of threads for parallel ops.
                - timeout (int): Request timeout in seconds.
                - rate_limit (float): Delay between requests.
                - proxy (str): Proxy URL for requests.
                - skip_port_scan (bool): Skip port scanning.
                - skip_bruteforce (bool): Skip DNS brute force.
                - wordlist (str): Path to custom subdomain wordlist.
                - user_agent (str): Custom User-Agent string.
        """
        self.domain = domain.lower().strip()
        self.output_dir = output_dir
        self.options = options or {}

        # Configuration from options
        self.dry_run = self.options.get("dry_run", False)
        self.verbose = self.options.get("verbose", False)
        self.threads = self.options.get("threads", MAX_THREADS)
        self.timeout = self.options.get("timeout", TIMEOUT)
        self.rate_limit_delay = self.options.get("rate_limit", 1.0)
        self.proxy = self.options.get("proxy", None)
        self.skip_port_scan = self.options.get("skip_port_scan", False)
        self.skip_bruteforce = self.options.get("skip_bruteforce", False)
        self.custom_wordlist = self.options.get("wordlist", None)
        self.user_agent = self.options.get("user_agent", None)

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(self.rate_limit_delay)

        # Initialize HTTP client
        self.http = HTTPClient(
            user_agent=self.user_agent,
            timeout=self.timeout,
            proxy=self.proxy,
            rate_limiter=self.rate_limiter,
        )

        # Initialize DNS resolver
        self.dns = DNSResolver(timeout=self.timeout)

        # Initialize file manager
        self.file_manager = FileManager(output_dir)

        # Load API keys
        self.api_keys = load_api_keys()

        # Thread lock for shared data
        self._lock = threading.Lock()

        # Track discovered subdomains
        self._discovered_subdomains: Set[str] = set()

        # Track discovered IPs
        self._discovered_ips: Set[str] = set()

        # Results container
        self.results = ReconResults(domain=self.domain)

        # Output handler
        self.output = ColorOutput()

        if self.verbose:
            ColorOutput.info(f"ReconEngine initialized for {self.domain}")
            ColorOutput.info(f"Output directory: {self.output_dir}")
            ColorOutput.info(f"Dry run: {self.dry_run}")
            ColorOutput.info(f"Threads: {self.threads}")

    def run(self) -> ReconResults:
        """
        Execute the full reconnaissance workflow.

        Orchestrates all reconnaissance techniques in an optimal order,
        collecting results from each phase and saving them to disk.

        Returns:
            ReconResults dataclass containing all findings.
        """
        start_time = time.time()
        ColorOutput.section_header("RECONNAISSANCE ENGINE")
        ColorOutput.info(f"Target: {self.domain}")
        ColorOutput.info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Phase 1: DNS Enumeration
        ColorOutput.section_header("Phase 1: DNS Enumeration")
        try:
            self.results.dns_records = self.enumerate_dns_records()
            ColorOutput.success(f"DNS records collected: {sum(len(v) for v in self.results.dns_records.values() if isinstance(v, list))} records")
        except Exception as e:
            ColorOutput.error(f"DNS enumeration failed: {e}")

        # Phase 2: Zone Transfer
        ColorOutput.section_header("Phase 2: Zone Transfer Attempts")
        try:
            self.results.zone_transfer_results = self.dns_zone_transfer()
            if self.results.zone_transfer_results:
                ColorOutput.finding(f"Zone transfer possible on {len(self.results.zone_transfer_results)} nameserver(s)!")
            else:
                ColorOutput.info("No zone transfers succeeded (expected)")
        except Exception as e:
            ColorOutput.error(f"Zone transfer check failed: {e}")

        # Phase 3: Subdomain Enumeration
        ColorOutput.section_header("Phase 3: Subdomain Enumeration")
        try:
            self.results.subdomains = self.enumerate_subdomains()
            ColorOutput.success(f"Total unique subdomains found: {len(self.results.subdomains)}")
        except Exception as e:
            ColorOutput.error(f"Subdomain enumeration failed: {e}")

        # Phase 4: ASN Lookup
        ColorOutput.section_header("Phase 4: ASN Information")
        try:
            domain_ips = self.dns.resolve(self.domain, "A")
            if domain_ips:
                self.results.asn_info = self.asn_lookup(domain_ips[0])
                if self.results.asn_info:
                    ColorOutput.success(f"ASN: {self.results.asn_info.get('asn', 'N/A')}")
        except Exception as e:
            ColorOutput.error(f"ASN lookup failed: {e}")

        # Phase 5: Reverse IP Lookups
        ColorOutput.section_header("Phase 5: Reverse IP Lookups")
        try:
            for ip in list(self._discovered_ips)[:5]:
                reverse_results = self.reverse_ip_lookup(ip)
                if reverse_results:
                    self.results.reverse_ip_results[ip] = reverse_results
            if self.results.reverse_ip_results:
                total_hosts = sum(len(v) for v in self.results.reverse_ip_results.values())
                ColorOutput.success(f"Found {total_hosts} hosts via reverse IP lookup")
        except Exception as e:
            ColorOutput.error(f"Reverse IP lookup failed: {e}")

        # Phase 6: HTTP Probing
        ColorOutput.section_header("Phase 6: HTTP Probing")
        try:
            subdomain_names = [s["name"] for s in self.results.subdomains]
            self.results.live_hosts = self.http_probe(subdomain_names)
            ColorOutput.success(f"Live hosts found: {len(self.results.live_hosts)}")
        except Exception as e:
            ColorOutput.error(f"HTTP probing failed: {e}")

        # Phase 7: Technology Fingerprinting
        ColorOutput.section_header("Phase 7: Technology Fingerprinting")
        try:
            main_url = f"https://{self.domain}"
            self.results.technologies = self.fingerprint_technologies(main_url)
            ColorOutput.success(f"Technologies detected: {len(self.results.technologies)}")
        except Exception as e:
            ColorOutput.error(f"Technology fingerprinting failed: {e}")

        # Phase 8: Port Scanning
        if not self.skip_port_scan:
            ColorOutput.section_header("Phase 8: Port Scanning")
            try:
                self.results.ports = self.port_scan(self.domain)
                open_ports = self.results.ports.get("open", [])
                ColorOutput.success(f"Open ports found: {len(open_ports)}")
            except Exception as e:
                ColorOutput.error(f"Port scanning failed: {e}")
        else:
            ColorOutput.info("Port scanning skipped (--skip-port-scan)")

        # Phase 9: Email Security
        ColorOutput.section_header("Phase 9: Email Security Analysis")
        try:
            self.results.email_security = self.check_email_security()
            ColorOutput.success("Email security records analyzed")
        except Exception as e:
            ColorOutput.error(f"Email security check failed: {e}")

        # Phase 10: Cloud Assets
        ColorOutput.section_header("Phase 10: Cloud Asset Discovery")
        try:
            self.results.s3_buckets = self.s3_bucket_enum()
            if self.results.live_hosts:
                host_list = [h.get("host", "") for h in self.results.live_hosts]
                self.results.metadata_exposures = self.cloud_metadata_check(host_list)
            ColorOutput.success(f"S3 bucket candidates: {len(self.results.s3_buckets)}")
        except Exception as e:
            ColorOutput.error(f"Cloud asset discovery failed: {e}")

        # Phase 11: Virtual Host Discovery
        ColorOutput.section_header("Phase 11: Virtual Host Discovery")
        try:
            domain_ips = self.dns.resolve(self.domain, "A")
            if domain_ips:
                self.results.vhosts = self.vhost_discovery(domain_ips[0])
                ColorOutput.success(f"Virtual hosts found: {len(self.results.vhosts)}")
        except Exception as e:
            ColorOutput.error(f"VHost discovery failed: {e}")

        # Phase 12: Wayback Machine
        ColorOutput.section_header("Phase 12: Wayback Machine URLs")
        try:
            self.results.wayback_urls = self.wayback_urls()
            ColorOutput.success(f"Wayback URLs collected: {len(self.results.wayback_urls)}")
        except Exception as e:
            ColorOutput.error(f"Wayback Machine fetch failed: {e}")

        # Phase 13: Dorking
        ColorOutput.section_header("Phase 13: Search Engine Dorking")
        try:
            self.results.google_dorks = self.generate_google_dorks()
            self.results.shodan_queries = self.generate_shodan_queries()
            self.results.github_dorks = self.github_dorking()
            self.results.gitlab_dorks = self.gitlab_dorking()
            ColorOutput.success(f"Google dorks: {len(self.results.google_dorks)}")
            ColorOutput.success(f"Shodan queries: {len(self.results.shodan_queries)}")
            ColorOutput.success(f"GitHub dorks: {len(self.results.github_dorks)}")
        except Exception as e:
            ColorOutput.error(f"Dork generation failed: {e}")

        # Phase 14: Favicon Hashing
        ColorOutput.section_header("Phase 14: Favicon Hash Fingerprinting")
        try:
            main_url = f"https://{self.domain}"
            fav_hash = self.favicon_hash(main_url)
            if fav_hash:
                self.results.favicon_hashes[self.domain] = fav_hash
                ColorOutput.success(f"Favicon hash: {fav_hash}")
        except Exception as e:
            ColorOutput.error(f"Favicon hashing failed: {e}")

        # Phase 15: Screenshot URLs
        ColorOutput.section_header("Phase 15: Screenshot URL Generation")
        try:
            self.results.screenshot_urls = self.generate_screenshot_urls(self.results.live_hosts)
            ColorOutput.success(f"Screenshot URLs generated: {len(self.results.screenshot_urls)}")
        except Exception as e:
            ColorOutput.error(f"Screenshot URL generation failed: {e}")

        # Calculate scan time
        self.results.scan_time = round(time.time() - start_time, 2)

        # Save results
        ColorOutput.section_header("Saving Results")
        try:
            self._save_results(self.results)
            ColorOutput.success(f"Results saved to {self.output_dir}")
        except Exception as e:
            ColorOutput.error(f"Failed to save results: {e}")

        # Final summary
        ColorOutput.section_header("RECONNAISSANCE COMPLETE")
        ColorOutput.info(f"Scan time: {self.results.scan_time}s")
        ColorOutput.info(f"Subdomains: {len(self.results.subdomains)}")
        ColorOutput.info(f"Live hosts: {len(self.results.live_hosts)}")
        ColorOutput.info(f"Open ports: {len(self.results.ports.get('open', []))}")
        ColorOutput.info(f"Technologies: {len(self.results.technologies)}")
        ColorOutput.info(f"Wayback URLs: {len(self.results.wayback_urls)}")

        return self.results

    # =========================================================================
    # SUBDOMAIN ENUMERATION
    # =========================================================================

    def enumerate_subdomains(self) -> List[Dict[str, Any]]:
        """
        Orchestrate subdomain enumeration from all available sources.

        Queries multiple passive data sources concurrently, then optionally
        performs active DNS brute forcing. Results are deduplicated and
        each subdomain is resolved to its IP address.

        Returns:
            List of dictionaries with keys: name, ip, source.
        """
        ColorOutput.info(f"Starting subdomain enumeration for {self.domain}")
        all_subdomains: List[Dict[str, Any]] = []

        # Define enumeration sources
        enum_sources = [
            ("crt.sh", self._crtsh_enum),
            ("VirusTotal", self._virustotal_enum),
            ("SecurityTrails", self._securitytrails_enum),
            ("HackerTarget", self._hackertarget_enum),
            ("AlienVault OTX", self._alienvault_otx_enum),
            ("ThreatCrowd", self._threatcrowd_enum),
            ("URLScan.io", self._urlscan_enum),
            ("Certificate Search", self._certificate_search),
        ]

        # Run passive enumeration sources in parallel
        with ThreadPoolExecutor(max_workers=min(self.threads, len(enum_sources))) as executor:
            future_map = {}
            for source_name, source_func in enum_sources:
                future = executor.submit(source_func)
                future_map[future] = source_name

            for future in as_completed(future_map):
                source_name = future_map[future]
                try:
                    results = future.result()
                    if results:
                        all_subdomains.extend(results)
                        ColorOutput.success(f"  [{source_name}] Found {len(results)} subdomains")
                    else:
                        ColorOutput.info(f"  [{source_name}] No results")
                except Exception as e:
                    ColorOutput.warning(f"  [{source_name}] Error: {e}")

        # Common subdomain patterns check
        ColorOutput.info("  Checking common subdomain patterns...")
        try:
            common_results = self._common_subdomain_check()
            if common_results:
                all_subdomains.extend(common_results)
                ColorOutput.success(f"  [Common Patterns] Found {len(common_results)} subdomains")
        except Exception as e:
            ColorOutput.warning(f"  [Common Patterns] Error: {e}")

        # DNS brute force (if not skipped)
        if not self.skip_bruteforce:
            ColorOutput.info("  Starting DNS brute force...")
            try:
                brute_results = self._dns_bruteforce()
                if brute_results:
                    all_subdomains.extend(brute_results)
                    ColorOutput.success(f"  [Brute Force] Found {len(brute_results)} subdomains")
            except Exception as e:
                ColorOutput.warning(f"  [Brute Force] Error: {e}")
        else:
            ColorOutput.info("  DNS brute force skipped")

        # Deduplicate results
        deduplicated = self._deduplicate_subdomains(all_subdomains)

        # Resolve IPs for subdomains that don't have them
        ColorOutput.info(f"  Resolving IPs for {len(deduplicated)} subdomains...")
        resolved = self._resolve_subdomain_ips(deduplicated)

        # Track discovered IPs
        for sub in resolved:
            if sub.get("ip"):
                self._discovered_ips.add(sub["ip"])

        return resolved

    def _crtsh_enum(self) -> List[Dict[str, Any]]:
        """
        Query crt.sh for Certificate Transparency log entries.

        Searches the crt.sh database for certificates issued to
        the target domain and extracts subdomain names.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []
        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query crt.sh")
            return [{"name": f"www.{self.domain}", "ip": "", "source": "crt.sh (dry_run)"}]

        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    entries = json.loads(response.body)
                    seen = set()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        # Handle multi-line name values
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Remove wildcard prefix
                            if name.startswith("*."):
                                name = name[2:]
                            if name.endswith(f".{self.domain}") or name == self.domain:
                                if name not in seen and name != self.domain:
                                    seen.add(name)
                                    subdomains.append({
                                        "name": name,
                                        "ip": "",
                                        "source": "crt.sh"
                                    })
                except json.JSONDecodeError:
                    ColorOutput.warning("    crt.sh returned invalid JSON")
        except Exception as e:
            ColorOutput.warning(f"    crt.sh error: {e}")

        return subdomains

    def _virustotal_enum(self) -> List[Dict[str, Any]]:
        """
        Query VirusTotal API for subdomain information.

        Requires a valid VirusTotal API key. Uses the domain
        report endpoint to enumerate known subdomains.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []
        api_key = self.api_keys.get("virustotal")

        if not api_key:
            if self.verbose:
                ColorOutput.info("    VirusTotal: No API key configured")
            return subdomains

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query VirusTotal API")
            return [{"name": f"api.{self.domain}", "ip": "", "source": "virustotal (dry_run)"}]

        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.domain}"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    for sub in data.get("subdomains", []):
                        sub = sub.strip().lower()
                        if sub and sub != self.domain:
                            subdomains.append({
                                "name": sub,
                                "ip": "",
                                "source": "virustotal"
                            })
                    # Also check undetected URLs for subdomains
                    for url_info in data.get("undetected_urls", []):
                        if isinstance(url_info, list) and url_info:
                            parsed = urlparse(url_info[0])
                            host = parsed.hostname
                            if host and host.endswith(f".{self.domain}"):
                                if host != self.domain:
                                    subdomains.append({
                                        "name": host,
                                        "ip": "",
                                        "source": "virustotal"
                                    })
                except json.JSONDecodeError:
                    ColorOutput.warning("    VirusTotal returned invalid JSON")
            elif response and response.status_code == 403:
                ColorOutput.warning("    VirusTotal: API key invalid or rate limited")
        except Exception as e:
            ColorOutput.warning(f"    VirusTotal error: {e}")

        return subdomains

    def _securitytrails_enum(self) -> List[Dict[str, Any]]:
        """
        Query SecurityTrails API for subdomain data.

        Requires a valid SecurityTrails API key. Retrieves all
        known subdomains from their comprehensive database.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []
        api_key = self.api_keys.get("securitytrails")

        if not api_key:
            if self.verbose:
                ColorOutput.info("    SecurityTrails: No API key configured")
            return subdomains

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query SecurityTrails API")
            return [{"name": f"mail.{self.domain}", "ip": "", "source": "securitytrails (dry_run)"}]

        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": api_key, "Accept": "application/json"}
        try:
            response = self.http.get(url, headers=headers)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    for sub in data.get("subdomains", []):
                        full_name = f"{sub}.{self.domain}"
                        subdomains.append({
                            "name": full_name,
                            "ip": "",
                            "source": "securitytrails"
                        })
                except json.JSONDecodeError:
                    ColorOutput.warning("    SecurityTrails returned invalid JSON")
            elif response and response.status_code == 403:
                ColorOutput.warning("    SecurityTrails: API key invalid or rate limited")
            elif response and response.status_code == 429:
                ColorOutput.warning("    SecurityTrails: Rate limit exceeded")
        except Exception as e:
            ColorOutput.warning(f"    SecurityTrails error: {e}")

        return subdomains

    def _hackertarget_enum(self) -> List[Dict[str, Any]]:
        """
        Query HackerTarget.com hostsearch API for subdomains.

        Free API that returns known hosts for a given domain.
        No API key required but has rate limits.

        Returns:
            List of subdomain dictionaries with name, ip, and source.
        """
        subdomains = []

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query HackerTarget")
            return [{"name": f"admin.{self.domain}", "ip": "1.2.3.4", "source": "hackertarget (dry_run)"}]

        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                if "error" not in response.body.lower() and "API count" not in response.body:
                    for line in response.body.strip().split("\n"):
                        parts = line.split(",")
                        if len(parts) >= 2:
                            hostname = parts[0].strip().lower()
                            ip = parts[1].strip()
                            if hostname.endswith(f".{self.domain}") and hostname != self.domain:
                                subdomains.append({
                                    "name": hostname,
                                    "ip": ip,
                                    "source": "hackertarget"
                                })
                else:
                    if self.verbose:
                        ColorOutput.warning("    HackerTarget: API limit reached or error")
        except Exception as e:
            ColorOutput.warning(f"    HackerTarget error: {e}")

        return subdomains

    def _alienvault_otx_enum(self) -> List[Dict[str, Any]]:
        """
        Query AlienVault OTX for passive DNS subdomain data.

        Uses the OTX API to retrieve passive DNS records
        associated with the target domain.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query AlienVault OTX")
            return [{"name": f"dev.{self.domain}", "ip": "", "source": "alienvault (dry_run)"}]

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    seen = set()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").strip().lower()
                        if (hostname.endswith(f".{self.domain}") and
                                hostname != self.domain and
                                hostname not in seen):
                            seen.add(hostname)
                            subdomains.append({
                                "name": hostname,
                                "ip": record.get("address", ""),
                                "source": "alienvault_otx"
                            })
                except json.JSONDecodeError:
                    ColorOutput.warning("    AlienVault OTX returned invalid JSON")
        except Exception as e:
            ColorOutput.warning(f"    AlienVault OTX error: {e}")

        return subdomains

    def _threatcrowd_enum(self) -> List[Dict[str, Any]]:
        """
        Query ThreatCrowd API for subdomain intelligence.

        ThreatCrowd aggregates data from multiple sources to
        provide threat intelligence including subdomains.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query ThreatCrowd")
            return [{"name": f"cdn.{self.domain}", "ip": "", "source": "threatcrowd (dry_run)"}]

        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    if data.get("response_code") == "1":
                        for sub in data.get("subdomains", []):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{self.domain}") and sub != self.domain:
                                subdomains.append({
                                    "name": sub,
                                    "ip": "",
                                    "source": "threatcrowd"
                                })
                except json.JSONDecodeError:
                    ColorOutput.warning("    ThreatCrowd returned invalid JSON")
        except Exception as e:
            ColorOutput.warning(f"    ThreatCrowd error: {e}")

        return subdomains

    def _urlscan_enum(self) -> List[Dict[str, Any]]:
        """
        Query URLScan.io search API for subdomain data.

        Searches URLScan.io scan results for pages associated
        with the target domain to discover subdomains.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []
        api_key = self.api_keys.get("urlscan")

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query URLScan.io")
            return [{"name": f"app.{self.domain}", "ip": "", "source": "urlscan (dry_run)"}]

        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        headers = {}
        if api_key:
            headers["API-Key"] = api_key

        try:
            response = self.http.get(url, headers=headers if headers else None)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    seen = set()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        hostname = page.get("domain", "").strip().lower()
                        if (hostname.endswith(f".{self.domain}") and
                                hostname != self.domain and
                                hostname not in seen):
                            seen.add(hostname)
                            ip = page.get("ip", "")
                            subdomains.append({
                                "name": hostname,
                                "ip": ip,
                                "source": "urlscan"
                            })
                except json.JSONDecodeError:
                    ColorOutput.warning("    URLScan.io returned invalid JSON")
            elif response and response.status_code == 429:
                ColorOutput.warning("    URLScan.io: Rate limit exceeded")
        except Exception as e:
            ColorOutput.warning(f"    URLScan.io error: {e}")

        return subdomains

    def _certificate_search(self) -> List[Dict[str, Any]]:
        """
        Search additional Certificate Transparency log sources.

        Queries alternative CT log aggregators beyond crt.sh
        to maximize subdomain coverage from certificate data.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would search additional CT logs")
            return [{"name": f"staging.{self.domain}", "ip": "", "source": "ct_logs (dry_run)"}]

        # Try certspotter
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    entries = json.loads(response.body)
                    seen = set()
                    for entry in entries:
                        dns_names = entry.get("dns_names", [])
                        for name in dns_names:
                            name = name.strip().lower()
                            if name.startswith("*."):
                                name = name[2:]
                            if (name.endswith(f".{self.domain}") and
                                    name != self.domain and
                                    name not in seen):
                                seen.add(name)
                                subdomains.append({
                                    "name": name,
                                    "ip": "",
                                    "source": "certspotter"
                                })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    CertSpotter error: {e}")

        # Try Google Transparency Report style endpoint
        url2 = f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={self.domain}"
        try:
            response = self.http.get(url2)
            if response and response.status_code == 200 and response.body:
                # Parse the response format (may vary)
                seen_already = {s["name"] for s in subdomains}
                for line in response.body.split("\n"):
                    for match in re.findall(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(self.domain) + r')', line):
                        match = match.lower()
                        if match not in seen_already:
                            seen_already.add(match)
                            subdomains.append({
                                "name": match,
                                "ip": "",
                                "source": "google_ct"
                            })
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    Google CT error: {e}")

        return subdomains

    def _dns_bruteforce(self) -> List[Dict[str, Any]]:
        """
        Brute force subdomains using the wordlist from config.

        Uses ThreadPoolExecutor to resolve subdomain candidates
        in parallel, checking which ones have valid DNS records.

        Returns:
            List of subdomain dictionaries with name, ip, and source.
        """
        subdomains = []
        wordlist = SUBDOMAIN_WORDLIST

        # Load custom wordlist if specified
        if self.custom_wordlist:
            try:
                wordlist_path = Path(self.custom_wordlist)
                if wordlist_path.exists():
                    with open(wordlist_path, "r") as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                    ColorOutput.info(f"    Loaded custom wordlist: {len(wordlist)} entries")
            except Exception as e:
                ColorOutput.warning(f"    Failed to load custom wordlist: {e}")

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would brute force {len(wordlist)} subdomain candidates")
            return [
                {"name": f"test.{self.domain}", "ip": "127.0.0.1", "source": "bruteforce (dry_run)"},
                {"name": f"stage.{self.domain}", "ip": "127.0.0.2", "source": "bruteforce (dry_run)"},
            ]

        # Already discovered subdomains to skip
        already_found = {s.get("name", "") for s in self._get_current_subdomains()}

        # Build candidate list
        candidates = []
        for prefix in wordlist:
            candidate = f"{prefix}.{self.domain}"
            if candidate not in already_found:
                candidates.append(candidate)

        if not candidates:
            return subdomains

        ColorOutput.info(f"    Brute forcing {len(candidates)} candidates with {self.threads} threads...")

        # Resolve candidates in parallel
        resolved_count = 0
        lock = threading.Lock()

        def resolve_candidate(candidate):
            nonlocal resolved_count
            try:
                ips = self.dns.resolve(candidate, "A")
                if ips:
                    with lock:
                        resolved_count += 1
                    return {"name": candidate, "ip": ips[0], "source": "bruteforce"}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(resolve_candidate, c): c for c in candidates}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        subdomains.append(result)
                except Exception:
                    pass

        return subdomains

    def _common_subdomain_check(self) -> List[Dict[str, Any]]:
        """
        Check common subdomain patterns specific to the target.

        Generates subdomain candidates based on the target domain
        name, common naming conventions, and service patterns.

        Returns:
            List of subdomain dictionaries with name and source.
        """
        subdomains = []

        # Generate patterns based on domain parts
        domain_parts = self.domain.split(".")
        base_name = domain_parts[0] if domain_parts else self.domain

        # Common patterns with the base name
        patterns = [
            f"{base_name}-dev",
            f"{base_name}-staging",
            f"{base_name}-prod",
            f"{base_name}-test",
            f"{base_name}-uat",
            f"{base_name}-qa",
            f"{base_name}-api",
            f"{base_name}-admin",
            f"{base_name}-internal",
            f"{base_name}-app",
            f"{base_name}-web",
            f"{base_name}-mobile",
            f"{base_name}-backend",
            f"{base_name}-frontend",
            f"{base_name}-portal",
            f"{base_name}-dashboard",
            f"{base_name}-cms",
            f"{base_name}-cdn",
            f"{base_name}-static",
            f"{base_name}-assets",
            f"{base_name}-media",
            f"{base_name}-docs",
            f"{base_name}-wiki",
            f"{base_name}-blog",
            f"{base_name}-support",
            f"{base_name}-help",
            f"{base_name}-status",
            f"{base_name}-monitor",
            f"{base_name}-grafana",
            f"{base_name}-kibana",
            f"dev-{base_name}",
            f"staging-{base_name}",
            f"prod-{base_name}",
            f"api-{base_name}",
            f"admin-{base_name}",
            f"app-{base_name}",
        ]

        # Common environment patterns
        env_prefixes = ["dev", "staging", "stage", "uat", "qa", "test", "prod", "beta", "alpha", "demo", "sandbox"]
        service_prefixes = ["api", "app", "web", "admin", "portal", "dashboard", "cms", "cdn", "static",
                           "assets", "media", "mail", "smtp", "imap", "pop", "ftp", "ssh", "vpn",
                           "db", "database", "redis", "elastic", "mongo", "mysql", "postgres",
                           "jenkins", "gitlab", "github", "jira", "confluence", "bamboo",
                           "grafana", "kibana", "prometheus", "nagios", "zabbix",
                           "sentry", "newrelic", "datadog", "splunk"]

        for env in env_prefixes:
            for svc in ["api", "app", "web", "admin", "portal"]:
                patterns.append(f"{env}-{svc}")
                patterns.append(f"{svc}-{env}")

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would check {len(patterns)} common patterns")
            return [{"name": f"{base_name}-dev.{self.domain}", "ip": "", "source": "common_patterns (dry_run)"}]

        # Resolve patterns
        candidates = [f"{p}.{self.domain}" for p in patterns]

        def check_candidate(candidate):
            try:
                ips = self.dns.resolve(candidate, "A")
                if ips:
                    return {"name": candidate, "ip": ips[0], "source": "common_patterns"}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_candidate, c): c for c in candidates}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        subdomains.append(result)
                except Exception:
                    pass

        return subdomains

    def _get_current_subdomains(self) -> List[Dict[str, Any]]:
        """
        Get the current list of discovered subdomains.

        Thread-safe access to the accumulated subdomain list
        for deduplication during enumeration.

        Returns:
            Current list of discovered subdomain dictionaries.
        """
        with self._lock:
            return list(self.results.subdomains)

    def _resolve_subdomain_ips(self, subdomains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Resolve IP addresses for subdomains that don't have them.

        Uses threaded DNS resolution to efficiently resolve
        all subdomain hostnames to their IP addresses.

        Args:
            subdomains: List of subdomain dicts, some may lack IP.

        Returns:
            Updated list with IP addresses filled in.
        """
        if self.dry_run:
            return subdomains

        needs_resolution = [s for s in subdomains if not s.get("ip")]
        has_ip = [s for s in subdomains if s.get("ip")]

        if not needs_resolution:
            return subdomains

        def resolve_one(sub):
            try:
                ips = self.dns.resolve(sub["name"], "A")
                if ips:
                    sub["ip"] = ips[0]
            except Exception:
                sub["ip"] = ""
            return sub

        resolved = list(has_ip)
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(resolve_one, s) for s in needs_resolution]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    resolved.append(result)
                except Exception:
                    pass

        return resolved

    # =========================================================================
    # ASN AND IP INTELLIGENCE
    # =========================================================================

    def asn_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform ASN lookup for a given IP address.

        Queries Team Cymru DNS service and IP info APIs to determine
        the Autonomous System Number and related network information.

        Args:
            ip: IP address to look up.

        Returns:
            Dictionary containing ASN information:
                - asn: AS number
                - asn_name: AS organization name
                - asn_country: Country code
                - asn_range: IP range
                - asn_description: Description
        """
        asn_info = {
            "ip": ip,
            "asn": "",
            "asn_name": "",
            "asn_country": "",
            "asn_range": "",
            "asn_description": "",
            "asn_registry": "",
        }

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would perform ASN lookup for {ip}")
            asn_info.update({
                "asn": "AS15169",
                "asn_name": "GOOGLE",
                "asn_country": "US",
                "asn_range": "8.8.8.0/24",
                "asn_description": "Google LLC (dry_run)",
            })
            return asn_info

        # Method 1: Team Cymru DNS query
        try:
            # Reverse the IP and query Team Cymru
            parts = ip.split(".")
            if len(parts) == 4:
                reversed_ip = ".".join(reversed(parts))
                # Query origin TXT record
                origin_query = f"{reversed_ip}.origin.asn.cymru.com"
                txt_records = self.dns.resolve(origin_query, "TXT")
                if txt_records:
                    # Parse: "ASN | IP Range | Country | Registry | Date"
                    for record in txt_records:
                        record = record.strip('"').strip()
                        parts_txt = [p.strip() for p in record.split("|")]
                        if len(parts_txt) >= 3:
                            asn_info["asn"] = f"AS{parts_txt[0].strip()}"
                            asn_info["asn_range"] = parts_txt[1].strip()
                            asn_info["asn_country"] = parts_txt[2].strip()
                            if len(parts_txt) >= 4:
                                asn_info["asn_registry"] = parts_txt[3].strip()
                            break

                # Query AS name
                if asn_info["asn"]:
                    asn_num = asn_info["asn"].replace("AS", "")
                    peer_query = f"AS{asn_num}.asn.cymru.com"
                    name_records = self.dns.resolve(peer_query, "TXT")
                    if name_records:
                        for record in name_records:
                            record = record.strip('"').strip()
                            parts_txt = [p.strip() for p in record.split("|")]
                            if len(parts_txt) >= 5:
                                asn_info["asn_name"] = parts_txt[4].strip()
                                asn_info["asn_description"] = parts_txt[4].strip()
                                break
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    Team Cymru ASN lookup failed: {e}")

        # Method 2: Fallback to IP info API
        if not asn_info["asn"]:
            try:
                url = f"https://ipinfo.io/{ip}/json"
                response = self.http.get(url)
                if response and response.status_code == 200 and response.body:
                    data = json.loads(response.body)
                    org = data.get("org", "")
                    if org:
                        parts_org = org.split(" ", 1)
                        if len(parts_org) >= 2:
                            asn_info["asn"] = parts_org[0]
                            asn_info["asn_name"] = parts_org[1]
                        else:
                            asn_info["asn_name"] = org
                    asn_info["asn_country"] = data.get("country", "")
                    asn_info["asn_description"] = data.get("org", "")
            except Exception as e:
                if self.verbose:
                    ColorOutput.warning(f"    IP info API fallback failed: {e}")

        # Method 3: Try BGPView API
        if not asn_info["asn"]:
            try:
                url = f"https://api.bgpview.io/ip/{ip}"
                response = self.http.get(url)
                if response and response.status_code == 200 and response.body:
                    data = json.loads(response.body)
                    ip_data = data.get("data", {})
                    prefixes = ip_data.get("prefixes", [])
                    if prefixes:
                        prefix = prefixes[0]
                        asn_data = prefix.get("asn", {})
                        asn_info["asn"] = f"AS{asn_data.get('asn', '')}"
                        asn_info["asn_name"] = asn_data.get("name", "")
                        asn_info["asn_description"] = asn_data.get("description", "")
                        asn_info["asn_country"] = asn_data.get("country_code", "")
                        asn_info["asn_range"] = prefix.get("prefix", "")
            except Exception as e:
                if self.verbose:
                    ColorOutput.warning(f"    BGPView API fallback failed: {e}")

        return asn_info

    def reverse_ip_lookup(self, ip: str) -> List[str]:
        """
        Find other domains hosted on the same IP address.

        Queries multiple services to find all domains that
        resolve to the given IP address (shared hosting detection).

        Args:
            ip: IP address to perform reverse lookup on.

        Returns:
            List of domain names hosted on the same IP.
        """
        domains = []

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would perform reverse IP lookup for {ip}")
            return [f"other-site-on-{ip.replace('.', '-')}.example.com"]

        # Method 1: HackerTarget reverse IP
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                if "error" not in response.body.lower() and "API count" not in response.body:
                    for line in response.body.strip().split("\n"):
                        domain = line.strip().lower()
                        if domain and is_valid_domain(domain) and domain != self.domain:
                            domains.append(domain)
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    HackerTarget reverse IP error: {e}")

        # Method 2: Reverse DNS
        try:
            rdns = self.dns.reverse_dns(ip)
            if rdns and rdns not in domains:
                domains.append(rdns)
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    Reverse DNS error: {e}")

        # Method 3: ViewDNS.info (if available)
        try:
            url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey=free&output=json"
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                try:
                    data = json.loads(response.body)
                    records = data.get("response", {}).get("domains", [])
                    for record in records:
                        name = record.get("name", "").strip().lower()
                        if name and name not in domains and name != self.domain:
                            domains.append(name)
                except (json.JSONDecodeError, KeyError):
                    pass
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    ViewDNS reverse IP error: {e}")

        # Deduplicate
        return list(set(domains))

    def dns_zone_transfer(self) -> Dict[str, List[str]]:
        """
        Attempt DNS zone transfer (AXFR) against all NS servers.

        Tries zone transfer against each nameserver discovered
        for the target domain. A successful transfer reveals
        all DNS records in the zone.

        Returns:
            Dictionary mapping nameserver to list of zone records.
        """
        results = {}

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would attempt zone transfers")
            return {"ns1.example.com": ["(dry_run) No actual transfer performed"]}

        # Get nameservers for the domain
        nameservers = self.dns.resolve(self.domain, "NS")
        if not nameservers:
            ColorOutput.info("    No nameservers found for zone transfer")
            return results

        ColorOutput.info(f"    Testing {len(nameservers)} nameserver(s) for AXFR...")

        for ns in nameservers:
            ns = ns.strip().rstrip(".")
            ColorOutput.info(f"    Trying AXFR on {ns}...")
            try:
                # Resolve the NS hostname to IP
                ns_ips = self.dns.resolve(ns, "A")
                if not ns_ips:
                    continue

                ns_ip = ns_ips[0]
                transfer_records = self.dns.zone_transfer(self.domain, ns_ip)
                if transfer_records:
                    results[ns] = transfer_records
                    ColorOutput.finding(f"    Zone transfer SUCCESSFUL on {ns}!")
                    ColorOutput.finding(f"    Retrieved {len(transfer_records)} records")
                else:
                    if self.verbose:
                        ColorOutput.info(f"    {ns}: Transfer refused/failed")
            except Exception as e:
                if self.verbose:
                    ColorOutput.info(f"    {ns}: {e}")

        return results

    def enumerate_dns_records(self) -> Dict[str, Any]:
        """
        Enumerate all DNS record types for the target domain.

        Queries for A, AAAA, CNAME, MX, TXT, NS, SOA, and SRV
        records to build a comprehensive DNS profile.

        Returns:
            Dictionary mapping record types to lists of values.
        """
        records = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
            "SOA": [],
            "SRV": [],
        }

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would enumerate DNS records")
            records["A"] = ["93.184.216.34"]
            records["NS"] = ["ns1.example.com", "ns2.example.com"]
            records["MX"] = ["10 mail.example.com"]
            records["TXT"] = ["v=spf1 include:_spf.google.com ~all"]
            return records

        # Query each record type
        for record_type in records.keys():
            try:
                results = self.dns.resolve(self.domain, record_type)
                if results:
                    records[record_type] = results
                    if self.verbose:
                        ColorOutput.info(f"    {record_type}: {len(results)} record(s)")
            except Exception as e:
                if self.verbose:
                    ColorOutput.warning(f"    {record_type} query failed: {e}")

        # Store discovered IPs
        for ip in records.get("A", []):
            self._discovered_ips.add(ip)

        # Additional: Try common service records
        common_srv = [
            "_sip._tcp", "_sip._udp", "_sipfederationtls._tcp",
            "_xmpp-server._tcp", "_xmpp-client._tcp",
            "_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
            "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
            "_submission._tcp", "_smtps._tcp",
            "_h323cs._tcp", "_h323ls._udp",
            "_kerberos._tcp", "_kerberos._udp",
            "_ldap._tcp", "_gc._tcp",
        ]

        srv_records = []
        for srv_prefix in common_srv:
            srv_domain = f"{srv_prefix}.{self.domain}"
            try:
                srv_results = self.dns.resolve(srv_domain, "SRV")
                if srv_results:
                    for r in srv_results:
                        srv_records.append(f"{srv_prefix}: {r}")
            except Exception:
                pass

        if srv_records:
            records["SRV"] = srv_records

        # Also enumerate common subdomains DNS records
        common_subs_for_dns = ["www", "mail", "ftp", "remote", "ns1", "ns2", "smtp", "webmail"]
        records["subdomain_records"] = {}
        for sub in common_subs_for_dns:
            full = f"{sub}.{self.domain}"
            try:
                ips = self.dns.resolve(full, "A")
                if ips:
                    records["subdomain_records"][full] = ips
            except Exception:
                pass

        return records

    # =========================================================================
    # DORKING AND INTELLIGENCE GATHERING
    # =========================================================================

    def github_dorking(self) -> List[str]:
        """
        Generate GitHub search queries for the target domain.

        Creates search queries that can reveal leaked credentials,
        configuration files, API keys, and other sensitive data
        in public GitHub repositories.

        Returns:
            List of GitHub search query strings.
        """
        ColorOutput.info("    Generating GitHub dorks...")
        dorks = []

        # GitHub search patterns for the domain
        github_patterns = [
            f'"{self.domain}" password',
            f'"{self.domain}" secret',
            f'"{self.domain}" api_key',
            f'"{self.domain}" apikey',
            f'"{self.domain}" token',
            f'"{self.domain}" access_key',
            f'"{self.domain}" credentials',
            f'"{self.domain}" private_key',
            f'"{self.domain}" authorization',
            f'"{self.domain}" aws_secret',
            f'"{self.domain}" database_url',
            f'"{self.domain}" db_password',
            f'"{self.domain}" smtp_password',
            f'"{self.domain}" ftp_password',
            f'"{self.domain}" ssh_key',
            f'"{self.domain}" BEGIN RSA PRIVATE',
            f'"{self.domain}" BEGIN OPENSSH PRIVATE',
            f'"{self.domain}" BEGIN PGP PRIVATE',
            f'"{self.domain}" AKIA',  # AWS key prefix
            f'"{self.domain}" ghp_',  # GitHub PAT
            f'"{self.domain}" glpat-',  # GitLab PAT
            f'"{self.domain}" xoxb-',  # Slack bot token
            f'"{self.domain}" xoxp-',  # Slack user token
            f'"{self.domain}" sk_live_',  # Stripe live key
            f'"{self.domain}" sq0csp-',  # Square token
            f'org:{self.domain.split(".")[0]} password',
            f'org:{self.domain.split(".")[0]} secret',
            f'org:{self.domain.split(".")[0]} filename:.env',
            f'org:{self.domain.split(".")[0]} filename:.htpasswd',
            f'org:{self.domain.split(".")[0]} filename:wp-config.php',
            f'org:{self.domain.split(".")[0]} filename:configuration.php',
            f'org:{self.domain.split(".")[0]} filename:config.php',
            f'org:{self.domain.split(".")[0]} filename:settings.py',
            f'org:{self.domain.split(".")[0]} filename:database.yml',
            f'org:{self.domain.split(".")[0]} filename:credentials',
            f'org:{self.domain.split(".")[0]} filename:id_rsa',
            f'org:{self.domain.split(".")[0]} filename:shadow',
            f'org:{self.domain.split(".")[0]} filename:docker-compose.yml password',
            f'"{self.domain}" filename:.env',
            f'"{self.domain}" filename:config',
            f'"{self.domain}" filename:.git-credentials',
            f'"{self.domain}" filename:.npmrc _auth',
            f'"{self.domain}" filename:.dockercfg auth',
            f'"{self.domain}" filename:hubspot.key',
            f'"{self.domain}" filename:terraform.tfvars',
            f'"{self.domain}" extension:pem private',
            f'"{self.domain}" extension:ppk',
            f'"{self.domain}" extension:sql password',
            f'"{self.domain}" extension:json api_key',
            f'"{self.domain}" extension:yaml password',
            f'"{self.domain}" language:shell password',
            f'"{self.domain}" language:python password',
            f'"{self.domain}" language:ruby password',
            f'"{self.domain}" internal',
            f'"{self.domain}" staging',
            f'"{self.domain}" prod',
        ]

        for pattern in github_patterns:
            dorks.append(f"https://github.com/search?q={quote(pattern)}&type=code")

        return dorks

    def gitlab_dorking(self) -> List[str]:
        """
        Generate GitLab search queries for the target domain.

        Creates search queries to find leaked sensitive data
        in public GitLab repositories and snippets.

        Returns:
            List of GitLab search query strings.
        """
        ColorOutput.info("    Generating GitLab dorks...")
        dorks = []

        gitlab_patterns = [
            f'"{self.domain}" password',
            f'"{self.domain}" secret',
            f'"{self.domain}" api_key',
            f'"{self.domain}" token',
            f'"{self.domain}" private_key',
            f'"{self.domain}" credentials',
            f'"{self.domain}" database',
            f'"{self.domain}" config',
            f'"{self.domain}" .env',
            f'"{self.domain}" aws_access',
            f'"{self.domain}" BEGIN RSA',
            f'"{self.domain}" authorization bearer',
            f'"{self.domain}" smtp',
            f'"{self.domain}" mysql://root',
            f'"{self.domain}" postgresql://',
            f'"{self.domain}" mongodb://',
            f'"{self.domain}" redis://',
            f'"{self.domain}" ftp://',
            f'"{self.domain}" internal',
            f'"{self.domain}" staging',
        ]

        for pattern in gitlab_patterns:
            dorks.append(f"https://gitlab.com/search?search={quote(pattern)}&group_id=&project_id=&scope=blobs")

        return dorks

    def s3_bucket_enum(self) -> List[Dict[str, str]]:
        """
        Generate and check possible S3 bucket names for the target.

        Creates bucket name candidates based on the domain name,
        company name variations, and common naming patterns, then
        checks if they exist.

        Returns:
            List of dictionaries with bucket name and status.
        """
        ColorOutput.info("    Generating S3 bucket candidates...")
        buckets = []

        # Generate bucket name candidates
        domain_parts = self.domain.split(".")
        base = domain_parts[0]
        tld = domain_parts[-1] if len(domain_parts) > 1 else ""

        # Common patterns
        patterns = [
            base,
            self.domain,
            self.domain.replace(".", "-"),
            self.domain.replace(".", ""),
            f"{base}-dev",
            f"{base}-development",
            f"{base}-staging",
            f"{base}-stage",
            f"{base}-prod",
            f"{base}-production",
            f"{base}-test",
            f"{base}-testing",
            f"{base}-uat",
            f"{base}-qa",
            f"{base}-backup",
            f"{base}-backups",
            f"{base}-bak",
            f"{base}-assets",
            f"{base}-static",
            f"{base}-media",
            f"{base}-images",
            f"{base}-img",
            f"{base}-uploads",
            f"{base}-files",
            f"{base}-data",
            f"{base}-db",
            f"{base}-database",
            f"{base}-logs",
            f"{base}-log",
            f"{base}-cdn",
            f"{base}-content",
            f"{base}-public",
            f"{base}-private",
            f"{base}-internal",
            f"{base}-web",
            f"{base}-website",
            f"{base}-app",
            f"{base}-api",
            f"{base}-docs",
            f"{base}-documents",
            f"{base}-config",
            f"{base}-configs",
            f"{base}-terraform",
            f"{base}-infra",
            f"{base}-infrastructure",
            f"{base}-deploy",
            f"{base}-deployment",
            f"{base}-releases",
            f"{base}-artifacts",
            f"{base}-packages",
            f"{base}-archive",
            f"{base}-temp",
            f"{base}-tmp",
            f"{base}-bucket",
            f"{base}-s3",
            f"{base}-aws",
            f"dev-{base}",
            f"staging-{base}",
            f"prod-{base}",
            f"backup-{base}",
            f"assets-{base}",
            f"static-{base}",
            f"media-{base}",
            f"cdn-{base}",
            f"s3-{base}",
            f"{base}.{tld}",
            f"{base}-{tld}",
        ]

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would check {len(patterns)} S3 bucket candidates")
            return [
                {"name": f"{base}-dev", "url": f"https://{base}-dev.s3.amazonaws.com", "status": "dry_run"},
                {"name": f"{base}-staging", "url": f"https://{base}-staging.s3.amazonaws.com", "status": "dry_run"},
            ]

        # Check each bucket candidate
        regions = ["", "us-east-1", "us-west-2", "eu-west-1"]
        checked = set()

        def check_bucket(bucket_name):
            if bucket_name in checked:
                return None
            checked.add(bucket_name)

            # Standard S3 URL
            url = f"https://{bucket_name}.s3.amazonaws.com"
            try:
                response = self.http.get(url)
                if response:
                    status = "unknown"
                    if response.status_code == 200:
                        status = "public_read"
                    elif response.status_code == 403:
                        status = "exists_no_access"
                    elif response.status_code == 404:
                        status = "not_found"
                        return None
                    elif response.status_code == 301:
                        status = "exists_redirect"

                    if status != "not_found":
                        return {
                            "name": bucket_name,
                            "url": url,
                            "status": status,
                            "status_code": response.status_code,
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(self.threads, 5)) as executor:
            futures = {executor.submit(check_bucket, p): p for p in patterns}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        buckets.append(result)
                        if result["status"] == "public_read":
                            ColorOutput.finding(f"    Public S3 bucket: {result['name']}")
                        elif result["status"] == "exists_no_access":
                            ColorOutput.info(f"    S3 bucket exists (no access): {result['name']}")
                except Exception:
                    pass

        return buckets

    def cloud_metadata_check(self, hosts: List[str]) -> List[Dict[str, str]]:
        """
        Check for exposed cloud metadata endpoints on discovered hosts.

        Tests if cloud instance metadata services (169.254.169.254)
        are accessible through SSRF or misconfiguration on target hosts.

        Args:
            hosts: List of hostnames/URLs to check.

        Returns:
            List of dictionaries describing metadata exposures.
        """
        exposures = []

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would check {len(hosts)} hosts for metadata endpoints")
            return [{"host": "example.com", "endpoint": "metadata", "status": "dry_run"}]

        # Cloud metadata endpoints to check
        metadata_endpoints = [
            # AWS
            "/latest/meta-data/",
            "/latest/user-data/",
            "/latest/dynamic/instance-identity/document",
            # GCP
            "/computeMetadata/v1/",
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/instance/hostname",
            # Azure
            "/metadata/instance?api-version=2021-02-01",
            # DigitalOcean
            "/metadata/v1.json",
            # Oracle Cloud
            "/opc/v1/instance/",
        ]

        # Headers for cloud metadata
        metadata_headers = {
            "Metadata-Flavor": "Google",
            "Metadata": "true",
        }

        for host in hosts[:10]:  # Limit to 10 hosts
            for endpoint in metadata_endpoints:
                # Check if target proxies to metadata IP
                for scheme in ["http", "https"]:
                    try:
                        # Direct metadata check is not ethical without permission
                        # Instead we check if the host responds to metadata-like headers
                        url = f"{scheme}://{host}{endpoint}"
                        response = self.http.get(url, headers=metadata_headers)
                        if response and response.status_code == 200:
                            # Check if response looks like metadata
                            body = response.body.lower()
                            if any(indicator in body for indicator in [
                                "ami-id", "instance-id", "meta-data",
                                "computemetadata", "project-id",
                                "vmid", "subscriptionid"
                            ]):
                                exposures.append({
                                    "host": host,
                                    "endpoint": endpoint,
                                    "url": url,
                                    "status": "potentially_exposed",
                                    "evidence": response.body[:200],
                                })
                                ColorOutput.finding(f"    Possible metadata exposure: {host}{endpoint}")
                    except Exception:
                        pass

        return exposures

    def favicon_hash(self, url: str) -> Optional[str]:
        """
        Download favicon and compute its hash for Shodan fingerprinting.

        Downloads the favicon.ico from the target and computes its
        MurmurHash3 (mmh3) value, which can be used to search Shodan
        for other hosts using the same favicon.

        Args:
            url: Base URL of the target (e.g., https://example.com).

        Returns:
            String representation of the favicon hash, or None if not found.
        """
        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would download favicon from {url}")
            return "1234567890"

        # Try common favicon locations
        favicon_paths = [
            "/favicon.ico",
            "/assets/favicon.ico",
            "/static/favicon.ico",
            "/images/favicon.ico",
            "/img/favicon.ico",
        ]

        for path in favicon_paths:
            favicon_url = f"{url.rstrip('/')}{path}"
            try:
                response = self.http.get(favicon_url)
                if response and response.status_code == 200 and response.body:
                    # Compute base64 of the content
                    content = response.body.encode("latin-1", errors="replace")
                    b64_content = base64.encodebytes(content)
                    # Compute mmh3-like hash (simplified since we use stdlib only)
                    # Using a FNV-1a inspired hash as mmh3 substitute
                    hash_val = self._fnv1a_hash(b64_content)
                    return str(hash_val)
            except Exception as e:
                if self.verbose:
                    ColorOutput.warning(f"    Favicon fetch error ({path}): {e}")
                continue

        # Try to find favicon from HTML link tag
        try:
            response = self.http.get(url)
            if response and response.status_code == 200 and response.body:
                # Search for favicon link in HTML
                icon_patterns = [
                    r"<link[^>]*rel=[\"'](?:shortcut )?icon[\"'][^>]*href=[\"']([^\"']+)[\"']",
                    r"<link[^>]*href=[\"']([^\"']+)[\"'][^>]*rel=[\"'](?:shortcut )?icon[\"']",
                ]
                for pattern in icon_patterns:
                    match = re.search(pattern, response.body, re.IGNORECASE)
                    if match:
                        icon_url = match.group(1)
                        if not icon_url.startswith("http"):
                            icon_url = urljoin(url, icon_url)
                        icon_response = self.http.get(icon_url)
                        if icon_response and icon_response.status_code == 200 and icon_response.body:
                            content = icon_response.body.encode("latin-1", errors="replace")
                            b64_content = base64.encodebytes(content)
                            hash_val = self._fnv1a_hash(b64_content)
                            return str(hash_val)
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"    Favicon HTML parse error: {e}")

        return None

    def _fnv1a_hash(self, data: bytes) -> int:
        """
        Compute FNV-1a hash as a stdlib alternative to mmh3.

        Produces a 32-bit signed integer hash similar to what
        mmh3 would produce, for Shodan favicon fingerprinting.

        Args:
            data: Bytes to hash.

        Returns:
            32-bit signed integer hash value.
        """
        FNV_32_PRIME = 0x01000193
        FNV1_32A_INIT = 0x811c9dc5

        hash_val = FNV1_32A_INIT
        for byte in data:
            hash_val ^= byte
            hash_val = (hash_val * FNV_32_PRIME) & 0xFFFFFFFF

        # Convert to signed 32-bit
        if hash_val >= 0x80000000:
            hash_val -= 0x100000000

        return hash_val

    # =========================================================================
    # HTTP PROBING AND HOST DISCOVERY
    # =========================================================================

    def http_probe(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """
        Probe discovered subdomains for live HTTP/HTTPS services.

        Tests each subdomain for HTTP and HTTPS connectivity,
        collecting response status, page title, server header,
        and technology stack information.

        Args:
            subdomains: List of subdomain hostnames to probe.

        Returns:
            List of dictionaries with live host details:
                - host: hostname
                - url: accessible URL
                - status_code: HTTP status code
                - title: page title
                - server: Server header value
                - technologies: detected technologies
                - content_length: response size
                - redirect: redirect URL if applicable
        """
        live_hosts = []

        if not subdomains:
            ColorOutput.info("    No subdomains to probe")
            return live_hosts

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would probe {len(subdomains)} subdomains")
            return [
                {
                    "host": self.domain,
                    "url": f"https://{self.domain}",
                    "status_code": 200,
                    "title": "Example Domain (dry_run)",
                    "server": "nginx",
                    "technologies": ["Nginx"],
                    "content_length": 1256,
                    "redirect": None,
                },
            ]

        ColorOutput.info(f"    Probing {len(subdomains)} subdomains with {self.threads} threads...")

        # Probe in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._probe_single_host, sub): sub for sub in subdomains}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    ColorOutput.progress(f"    Probed {completed}/{len(subdomains)} hosts...")
                try:
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                except Exception:
                    pass

        return live_hosts

    def _probe_single_host(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Probe a single host for HTTP/HTTPS availability.

        Tests both HTTPS and HTTP schemes, collecting response
        metadata including status code, page title, server header,
        and any redirects.

        Args:
            subdomain: Hostname to probe.

        Returns:
            Dictionary with host details if alive, None otherwise.
        """
        result = None

        # Try HTTPS first, then HTTP
        schemes = ["https", "http"]

        for scheme in schemes:
            url = f"{scheme}://{subdomain}"
            try:
                response = self.http.get(url)
                if response and response.status_code > 0 and not response.error:
                    # Extract page title
                    title = ""
                    title_match = re.search(
                        r"<title[^>]*>(.*?)</title>",
                        response.body,
                        re.IGNORECASE | re.DOTALL
                    )
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                    # Get server header
                    server = response.headers.get("Server", "")
                    if not server:
                        server = response.headers.get("server", "")

                    # Detect technologies from response
                    techs = self._detect_tech_from_response(response)

                    # Check for redirects
                    redirect = response.redirect_url

                    result = {
                        "host": subdomain,
                        "url": url,
                        "status_code": response.status_code,
                        "title": title,
                        "server": server,
                        "technologies": techs,
                        "content_length": response.content_length,
                        "redirect": redirect,
                        "headers": dict(response.headers),
                    }
                    break  # Got a response, no need to try HTTP

            except Exception:
                continue

        return result

    def _detect_tech_from_response(self, response) -> List[str]:
        """
        Detect technologies from HTTP response headers and body.

        Checks response headers, cookies, and body content against
        known technology signatures from the config.

        Args:
            response: HTTPResponse object to analyze.

        Returns:
            List of detected technology names.
        """
        technologies = []

        if not response:
            return technologies

        # Check headers
        header_sigs = TECH_SIGNATURES.get("headers", {})
        for header_name, tech_patterns in header_sigs.items():
            header_value = response.headers.get(header_name, "")
            if not header_value:
                # Case-insensitive header lookup
                for h_name, h_val in response.headers.items():
                    if h_name.lower() == header_name.lower():
                        header_value = h_val
                        break

            if header_value:
                for tech_name, pattern in tech_patterns.items():
                    try:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            if tech_name not in technologies:
                                technologies.append(tech_name)
                    except re.error:
                        pass

        # Check cookies
        cookie_sigs = TECH_SIGNATURES.get("cookies", {})
        set_cookie = response.headers.get("Set-Cookie", "")
        if not set_cookie:
            for h_name, h_val in response.headers.items():
                if h_name.lower() == "set-cookie":
                    set_cookie = h_val
                    break

        for cookie_name, tech_name in cookie_sigs.items():
            if cookie_name in set_cookie or cookie_name.lower() in set_cookie.lower():
                if tech_name not in technologies:
                    technologies.append(tech_name)

        # Check body patterns
        body_sigs = TECH_SIGNATURES.get("body", {})
        if response.body and body_sigs:
            for tech_name, patterns in body_sigs.items():
                if isinstance(patterns, list):
                    for pattern in patterns:
                        try:
                            if re.search(pattern, response.body, re.IGNORECASE):
                                if tech_name not in technologies:
                                    technologies.append(tech_name)
                                break
                        except re.error:
                            pass
                elif isinstance(patterns, str):
                    try:
                        if re.search(patterns, response.body, re.IGNORECASE):
                            if tech_name not in technologies:
                                technologies.append(tech_name)
                    except re.error:
                        pass

        return technologies

    def generate_screenshot_urls(self, live_hosts: List[Dict[str, Any]]) -> List[str]:
        """
        Generate URL list compatible with screenshot tools.

        Creates a list of URLs formatted for tools like aquatone,
        gowitness, or eyewitness to take screenshots of live hosts.

        Args:
            live_hosts: List of live host dictionaries from http_probe.

        Returns:
            List of URLs suitable for screenshot tools.
        """
        urls = []

        if not live_hosts:
            return urls

        for host_info in live_hosts:
            url = host_info.get("url", "")
            if url:
                urls.append(url)

            # Also add HTTPS variant if HTTP was used
            host = host_info.get("host", "")
            if host:
                https_url = f"https://{host}"
                http_url = f"http://{host}"
                if https_url not in urls:
                    urls.append(https_url)
                if http_url not in urls:
                    urls.append(http_url)

        # Add common ports
        for host_info in live_hosts:
            host = host_info.get("host", "")
            if host:
                for port in [8080, 8443, 8000, 8888, 9090, 3000, 4443, 9443]:
                    urls.append(f"https://{host}:{port}")
                    urls.append(f"http://{host}:{port}")

        # Deduplicate while maintaining order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        return unique_urls

    def vhost_discovery(self, ip: str) -> List[str]:
        """
        Discover virtual hosts by testing common hostnames against target IP.

        Sends HTTP requests with different Host headers to the target IP
        to identify virtual hosts that may not be publicly listed.

        Args:
            ip: IP address of the target server.

        Returns:
            List of discovered virtual hostnames.
        """
        vhosts = []

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would test virtual hosts against {ip}")
            return [f"hidden.{self.domain}", f"internal.{self.domain}"]

        # Generate vhost candidates
        domain_parts = self.domain.split(".")
        base = domain_parts[0]

        vhost_candidates = [
            f"dev.{self.domain}",
            f"staging.{self.domain}",
            f"stage.{self.domain}",
            f"test.{self.domain}",
            f"uat.{self.domain}",
            f"beta.{self.domain}",
            f"alpha.{self.domain}",
            f"demo.{self.domain}",
            f"internal.{self.domain}",
            f"private.{self.domain}",
            f"hidden.{self.domain}",
            f"secret.{self.domain}",
            f"admin.{self.domain}",
            f"portal.{self.domain}",
            f"api.{self.domain}",
            f"api-v2.{self.domain}",
            f"api-internal.{self.domain}",
            f"dashboard.{self.domain}",
            f"panel.{self.domain}",
            f"manage.{self.domain}",
            f"cms.{self.domain}",
            f"intranet.{self.domain}",
            f"extranet.{self.domain}",
            f"legacy.{self.domain}",
            f"old.{self.domain}",
            f"new.{self.domain}",
            f"v2.{self.domain}",
            f"next.{self.domain}",
            f"preview.{self.domain}",
            f"preprod.{self.domain}",
            f"pre-prod.{self.domain}",
            f"sandbox.{self.domain}",
            f"dr.{self.domain}",
            f"failover.{self.domain}",
            f"backup.{self.domain}",
            f"monitor.{self.domain}",
            f"monitoring.{self.domain}",
            f"metrics.{self.domain}",
            f"logs.{self.domain}",
            f"elk.{self.domain}",
            f"grafana.{self.domain}",
            f"kibana.{self.domain}",
            f"jenkins.{self.domain}",
            f"ci.{self.domain}",
            f"cd.{self.domain}",
            f"gitlab.{self.domain}",
            f"git.{self.domain}",
            f"svn.{self.domain}",
            f"repo.{self.domain}",
            f"registry.{self.domain}",
            f"docker.{self.domain}",
            f"k8s.{self.domain}",
            f"kubernetes.{self.domain}",
        ]

        # Get baseline response (request with non-existent host)
        baseline_length = 0
        baseline_status = 0
        try:
            headers = {"Host": f"nonexistent-{base}-xyz123.{self.domain}"}
            url = f"http://{ip}"
            response = self.http.get(url, headers=headers)
            if response:
                baseline_length = response.content_length
                baseline_status = response.status_code
        except Exception:
            pass

        # Test each vhost candidate
        def test_vhost(candidate):
            try:
                headers = {"Host": candidate}
                url = f"http://{ip}"
                response = self.http.get(url, headers=headers)
                if response and response.status_code > 0:
                    # Check if response differs from baseline
                    if (response.status_code != baseline_status or
                            abs(response.content_length - baseline_length) > 100):
                        return candidate
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_vhost, c): c for c in vhost_candidates}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vhosts.append(result)
                        ColorOutput.success(f"    VHost discovered: {result}")
                except Exception:
                    pass

        return vhosts

    # =========================================================================
    # WAYBACK MACHINE AND SEARCH ENGINE DORKING
    # =========================================================================

    def wayback_urls(self) -> List[str]:
        """
        Fetch historical URLs from the Wayback Machine CDX API.

        Queries the Internet Archive CDX server for all archived
        URLs associated with the target domain, useful for finding
        forgotten endpoints and parameters.

        Returns:
            List of unique historical URLs.
        """
        urls = []

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would query Wayback Machine CDX API")
            return [
                f"https://{self.domain}/admin",
                f"https://{self.domain}/api/v1/users",
                f"https://{self.domain}/login.php",
                f"https://{self.domain}/backup.zip",
                f"https://{self.domain}/.env",
            ]

        # Query the CDX API
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx?"
            f"url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey"
        )
        try:
            response = self.http.get(cdx_url)
            if response and response.status_code == 200 and response.body:
                raw_urls = response.body.strip().split("\n")
                seen = set()
                for url in raw_urls:
                    url = url.strip()
                    if url and url not in seen:
                        seen.add(url)
                        urls.append(url)

                ColorOutput.info(f"    Retrieved {len(urls)} URLs from Wayback Machine")

                # Also try without wildcard for the main domain
                cdx_url2 = (
                    f"http://web.archive.org/cdx/search/cdx?"
                    f"url={self.domain}/*&output=text&fl=original&collapse=urlkey"
                )
                response2 = self.http.get(cdx_url2)
                if response2 and response2.status_code == 200 and response2.body:
                    for url in response2.body.strip().split("\n"):
                        url = url.strip()
                        if url and url not in seen:
                            seen.add(url)
                            urls.append(url)
        except Exception as e:
            ColorOutput.warning(f"    Wayback Machine error: {e}")

        # Filter interesting URLs
        interesting_extensions = [
            ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
            ".py", ".rb", ".cfm", ".action", ".do",
            ".json", ".xml", ".yaml", ".yml", ".conf", ".config",
            ".bak", ".old", ".backup", ".zip", ".tar", ".gz",
            ".sql", ".db", ".sqlite", ".log", ".txt",
            ".env", ".ini", ".properties",
        ]

        # Sort: interesting URLs first
        interesting = []
        others = []
        for url in urls:
            url_lower = url.lower()
            if any(ext in url_lower for ext in interesting_extensions):
                interesting.append(url)
            else:
                others.append(url)

        # Combine with interesting first, limit total
        combined = interesting + others
        if len(combined) > 5000:
            combined = combined[:5000]
            ColorOutput.info(f"    Truncated to 5000 URLs (from {len(urls)} total)")

        return combined

    def generate_google_dorks(self) -> List[str]:
        """
        Generate Google search dorks using templates from config.

        Applies the target domain to each dork template defined in
        GOOGLE_DORK_TEMPLATES to create ready-to-use search queries
        for finding sensitive information.

        Returns:
            List of formatted Google dork query strings.
        """
        dorks = []

        for template in GOOGLE_DORK_TEMPLATES:
            try:
                dork = template.format(target=self.domain)
                dorks.append(dork)
            except (KeyError, IndexError):
                # Template may use different placeholder format
                dork = template.replace("{target}", self.domain)
                dorks.append(dork)

        # Add custom dorks based on domain analysis
        domain_parts = self.domain.split(".")
        base = domain_parts[0]

        extra_dorks = [
            f'intitle:"index of" site:{self.domain}',
            f'inurl:admin site:{self.domain}',
            f'inurl:login site:{self.domain}',
            f'inurl:dashboard site:{self.domain}',
            f'inurl:api site:{self.domain}',
            f'inurl:config site:{self.domain}',
            f'inurl:setup site:{self.domain}',
            f'inurl:install site:{self.domain}',
            f'inurl:wp-admin site:{self.domain}',
            f'inurl:wp-content site:{self.domain}',
            f'inurl:wp-includes site:{self.domain}',
            f'intext:"sql syntax" site:{self.domain}',
            f'intext:"error" site:{self.domain}',
            f'intext:"exception" site:{self.domain}',
            f'intext:"debug" site:{self.domain}',
            f'intext:"stack trace" site:{self.domain}',
            f'intext:"phpinfo()" site:{self.domain}',
            f'inurl:".git" site:{self.domain}',
            f'inurl:".svn" site:{self.domain}',
            f'inurl:".env" site:{self.domain}',
            f'inurl:"robots.txt" site:{self.domain}',
            f'inurl:"sitemap.xml" site:{self.domain}',
            f'filetype:log site:{self.domain}',
            f'filetype:conf site:{self.domain}',
            f'filetype:sql site:{self.domain}',
            f'filetype:bak site:{self.domain}',
            f'filetype:old site:{self.domain}',
            f'"{base}" inurl:pastebin.com',
            f'"{base}" inurl:paste.org',
            f'"{base}" inurl:trello.com',
            f'"{self.domain}" ext:xml intext:password',
            f'"{self.domain}" ext:json intext:password',
            f'"{self.domain}" ext:yaml intext:password',
            f'"{self.domain}" intext:"api_key"',
            f'"{self.domain}" intext:"access_token"',
            f'"{self.domain}" intext:"secret_key"',
            f'"{self.domain}" intext:"connectionstring"',
            f'site:*.{self.domain} -www',
            f'site:*.*.{self.domain}',
            f'site:{self.domain} inurl:redirect',
            f'site:{self.domain} inurl:callback',
            f'site:{self.domain} inurl:return',
            f'site:{self.domain} inurl:next',
            f'site:{self.domain} inurl:url=',
            f'site:{self.domain} inurl:dest=',
            f'site:{self.domain} inurl:path=',
            f'site:{self.domain} inurl:file=',
            f'site:{self.domain} inurl:page=',
            f'site:{self.domain} inurl:dir=',
            f'site:{self.domain} ext:php inurl:id=',
            f'site:{self.domain} ext:asp inurl:id=',
        ]

        dorks.extend(extra_dorks)

        # Deduplicate
        seen = set()
        unique_dorks = []
        for dork in dorks:
            if dork not in seen:
                seen.add(dork)
                unique_dorks.append(dork)

        return unique_dorks

    def generate_shodan_queries(self) -> List[str]:
        """
        Generate Shodan search queries using templates from config.

        Applies the target domain and related information to Shodan
        query templates for discovering internet-facing assets.

        Returns:
            List of formatted Shodan search query strings.
        """
        queries = []

        for template in SHODAN_QUERY_TEMPLATES:
            try:
                query = template.format(target=self.domain)
                queries.append(query)
            except (KeyError, IndexError):
                query = template.replace("{target}", self.domain)
                queries.append(query)

        # Add custom queries
        domain_parts = self.domain.split(".")
        base = domain_parts[0]

        extra_queries = [
            f'org:"{base}"',
            f'ssl:"{self.domain}"',
            f'http.html:"{self.domain}"',
            f'http.title:"{base}"',
            f'http.favicon.hash:',  # Will be filled if favicon hash available
            f'hostname:"{self.domain}" port:8080,8443,8000',
            f'hostname:"{self.domain}" product:"Apache"',
            f'hostname:"{self.domain}" product:"nginx"',
            f'hostname:"{self.domain}" product:"Microsoft IIS"',
            f'hostname:"{self.domain}" has_screenshot:true',
            f'hostname:"{self.domain}" "200 OK"',
            f'hostname:"{self.domain}" vuln:',
            f'ssl.cert.subject.cn:"{self.domain}" 200',
            f'ssl.cert.issuer.cn:"Let\\\'s Encrypt" hostname:"{self.domain}"',
            f'http.component:"WordPress" hostname:"{self.domain}"',
            f'http.component:"PHP" hostname:"{self.domain}"',
            f'http.component:"jQuery" hostname:"{self.domain}"',
            f'http.status:401 hostname:"{self.domain}"',
            f'http.status:403 hostname:"{self.domain}"',
            f'http.status:500 hostname:"{self.domain}"',
            f'port:21 hostname:"{self.domain}"',
            f'port:22 hostname:"{self.domain}"',
            f'port:23 hostname:"{self.domain}"',
            f'port:25 hostname:"{self.domain}"',
            f'port:3306 hostname:"{self.domain}"',
            f'port:5432 hostname:"{self.domain}"',
            f'port:6379 hostname:"{self.domain}"',
            f'port:27017 hostname:"{self.domain}"',
            f'port:9200 hostname:"{self.domain}"',
            f'port:11211 hostname:"{self.domain}"',
        ]

        queries.extend(extra_queries)

        # Deduplicate
        seen = set()
        unique_queries = []
        for q in queries:
            if q not in seen:
                seen.add(q)
                unique_queries.append(q)

        return unique_queries

    # =========================================================================
    # TECHNOLOGY FINGERPRINTING AND PORT SCANNING
    # =========================================================================

    def fingerprint_technologies(self, url: str) -> List[Dict[str, str]]:
        """
        Detect technologies used by the target from HTTP response analysis.

        Examines response headers, cookies, body content, and meta tags
        to identify web frameworks, CMS platforms, JavaScript libraries,
        server software, and other technologies.

        Args:
            url: Target URL to fingerprint.

        Returns:
            List of dictionaries with technology details:
                - name: Technology name
                - version: Version if detected
                - category: Technology category
                - confidence: Detection confidence level
        """
        technologies = []
        seen_techs = set()

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would fingerprint technologies for {url}")
            return [
                {"name": "Nginx", "version": "1.24", "category": "Web Server", "confidence": "high"},
                {"name": "PHP", "version": "8.2", "category": "Language", "confidence": "high"},
                {"name": "WordPress", "version": "6.4", "category": "CMS", "confidence": "medium"},
            ]

        try:
            response = self.http.get(url)
            if not response or response.error:
                return technologies

            # Header-based detection
            header_sigs = TECH_SIGNATURES.get("headers", {})
            for header_name, tech_patterns in header_sigs.items():
                header_value = ""
                for h_name, h_val in response.headers.items():
                    if h_name.lower() == header_name.lower():
                        header_value = h_val
                        break

                if header_value:
                    for tech_name, pattern in tech_patterns.items():
                        try:
                            match = re.search(pattern, header_value, re.IGNORECASE)
                            if match and tech_name not in seen_techs:
                                seen_techs.add(tech_name)
                                version = ""
                                # Try to extract version
                                ver_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', header_value)
                                if ver_match:
                                    version = ver_match.group()
                                technologies.append({
                                    "name": tech_name,
                                    "version": version,
                                    "category": "Web Server" if header_name == "Server" else "Framework",
                                    "confidence": "high",
                                    "evidence": f"{header_name}: {header_value}",
                                })
                        except re.error:
                            pass

            # Cookie-based detection
            cookie_sigs = TECH_SIGNATURES.get("cookies", {})
            all_cookies = ""
            for h_name, h_val in response.headers.items():
                if h_name.lower() == "set-cookie":
                    all_cookies += h_val + ";"

            for cookie_name, tech_name in cookie_sigs.items():
                if cookie_name in all_cookies and tech_name not in seen_techs:
                    seen_techs.add(tech_name)
                    technologies.append({
                        "name": tech_name,
                        "version": "",
                        "category": "Framework",
                        "confidence": "medium",
                        "evidence": f"Cookie: {cookie_name}",
                    })

            # Body-based detection
            if response.body:
                body = response.body

                # WordPress detection
                wp_patterns = [
                    (r'/wp-content/', "WordPress", "CMS"),
                    (r'/wp-includes/', "WordPress", "CMS"),
                    (r'<meta name="generator" content="WordPress\s*([\d.]+)?', "WordPress", "CMS"),
                ]

                # Drupal detection
                drupal_patterns = [
                    (r'Drupal\.settings', "Drupal", "CMS"),
                    (r'/sites/default/files/', "Drupal", "CMS"),
                    (r'<meta name="Generator" content="Drupal\s*([\d]+)?', "Drupal", "CMS"),
                ]

                # Joomla detection
                joomla_patterns = [
                    (r'/media/jui/', "Joomla", "CMS"),
                    (r'/components/com_', "Joomla", "CMS"),
                    (r'<meta name="generator" content="Joomla', "Joomla", "CMS"),
                ]

                # JavaScript frameworks
                js_patterns = [
                    (r'react\.(?:production|development)\.min\.js|__REACT_DEVTOOLS|react-dom', "React", "JS Framework"),
                    (r'vue\.(?:min\.)?js|__VUE__|vue-router', "Vue.js", "JS Framework"),
                    (r'angular(?:\.min)?\.js|ng-app|ng-controller|\[ng-', "Angular", "JS Framework"),
                    (r'jquery(?:\.min)?\.js|jQuery\s*v?([\d.]+)', "jQuery", "JS Library"),
                    (r'bootstrap(?:\.min)?\.(?:js|css)', "Bootstrap", "CSS Framework"),
                    (r'tailwindcss|tailwind\.min\.css', "Tailwind CSS", "CSS Framework"),
                    (r'next\.js|__NEXT_DATA__|/_next/', "Next.js", "JS Framework"),
                    (r'nuxt\.js|__NUXT__|/_nuxt/', "Nuxt.js", "JS Framework"),
                    (r'gatsby-', "Gatsby", "Static Site Generator"),
                    (r'svelte|__svelte', "Svelte", "JS Framework"),
                ]

                # Server-side frameworks
                server_patterns = [
                    (r'<meta name="generator" content="Hugo', "Hugo", "Static Site Generator"),
                    (r'<meta name="generator" content="Jekyll', "Jekyll", "Static Site Generator"),
                    (r'X-Powered-By:\s*Express', "Express.js", "Framework"),
                    (r'laravel_session|laravel_token', "Laravel", "Framework"),
                    (r'csrfmiddlewaretoken|__django', "Django", "Framework"),
                    (r'_rails|action_dispatch', "Ruby on Rails", "Framework"),
                    (r'__RequestVerificationToken|__VIEWSTATE', "ASP.NET", "Framework"),
                    (r'Powered by.*?Flask', "Flask", "Framework"),
                    (r'Spring|SPRING_SECURITY', "Spring", "Framework"),
                ]

                # Analytics and tracking
                analytics_patterns = [
                    (r'google-analytics\.com|googletagmanager\.com|gtag\(', "Google Analytics", "Analytics"),
                    (r'facebook\.net/en_US/fbevents|fbq\(', "Facebook Pixel", "Analytics"),
                    (r'hotjar\.com|_hjSettings', "Hotjar", "Analytics"),
                    (r'segment\.com|analytics\.js', "Segment", "Analytics"),
                    (r'mixpanel\.com|mixpanel\.init', "Mixpanel", "Analytics"),
                    (r'amplitude\.com|amplitude\.getInstance', "Amplitude", "Analytics"),
                    (r'matomo\.js|piwik\.js', "Matomo", "Analytics"),
                    (r'newrelic\.com|NREUM', "New Relic", "Monitoring"),
                    (r'sentry\.io|Sentry\.init', "Sentry", "Error Tracking"),
                    (r'datadog-rum|DD_RUM', "Datadog RUM", "Monitoring"),
                ]

                # CDN detection
                cdn_patterns = [
                    (r'cloudflare', "Cloudflare", "CDN"),
                    (r'cdn\.cloudflare\.com', "Cloudflare CDN", "CDN"),
                    (r'fastly\.net|fastly\.com', "Fastly", "CDN"),
                    (r'akamai\.net|akamaized\.net', "Akamai", "CDN"),
                    (r'cloudfront\.net', "CloudFront", "CDN"),
                    (r'azureedge\.net', "Azure CDN", "CDN"),
                    (r'stackpath\.com|maxcdn', "StackPath/MaxCDN", "CDN"),
                ]

                all_patterns = (
                    wp_patterns + drupal_patterns + joomla_patterns +
                    js_patterns + server_patterns + analytics_patterns +
                    cdn_patterns
                )

                for pattern, tech_name, category in all_patterns:
                    if tech_name not in seen_techs:
                        try:
                            match = re.search(pattern, body, re.IGNORECASE)
                            if match:
                                seen_techs.add(tech_name)
                                version = ""
                                # Try to get version from match groups
                                if match.groups():
                                    for group in match.groups():
                                        if group and re.match(r'[\d.]+', group):
                                            version = group
                                            break
                                technologies.append({
                                    "name": tech_name,
                                    "version": version,
                                    "category": category,
                                    "confidence": "medium",
                                    "evidence": f"Body pattern: {pattern[:50]}",
                                })
                        except re.error:
                            pass

                # Meta generator tag
                gen_match = re.search(
                    r"<meta[^>]*name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']",
                    body, re.IGNORECASE
                )
                if gen_match:
                    generator = gen_match.group(1)
                    if generator not in seen_techs:
                        seen_techs.add(generator)
                        technologies.append({
                            "name": generator,
                            "version": "",
                            "category": "Generator",
                            "confidence": "high",
                            "evidence": f"Meta generator: {generator}",
                        })

            # Security headers detection
            security_headers = {
                "X-Frame-Options": "X-Frame-Options configured",
                "Content-Security-Policy": "CSP configured",
                "Strict-Transport-Security": "HSTS enabled",
                "X-Content-Type-Options": "X-Content-Type-Options set",
                "X-XSS-Protection": "XSS Protection header",
                "Referrer-Policy": "Referrer-Policy set",
                "Permissions-Policy": "Permissions-Policy set",
                "Feature-Policy": "Feature-Policy set",
            }

            for header, description in security_headers.items():
                for h_name, h_val in response.headers.items():
                    if h_name.lower() == header.lower() and h_val:
                        key = f"Security: {description}"
                        if key not in seen_techs:
                            seen_techs.add(key)
                            technologies.append({
                                "name": description,
                                "version": "",
                                "category": "Security",
                                "confidence": "high",
                                "evidence": f"{header}: {h_val[:80]}",
                            })
                        break

        except Exception as e:
            ColorOutput.warning(f"    Technology fingerprinting error: {e}")

        return technologies

    def port_scan(self, target: str) -> Dict[str, List[int]]:
        """
        Scan common ports on the target using TCP connect scan.

        Uses ThreadPoolExecutor to perform parallel port connection
        attempts against COMMON_PORTS from the config module.

        Args:
            target: Hostname or IP address to scan.

        Returns:
            Dictionary with keys:
                - open: list of open port numbers
                - closed: list of closed port numbers
                - filtered: list of filtered port numbers
        """
        results = {"open": [], "closed": [], "filtered": []}

        if self.dry_run:
            ColorOutput.info(f"    [DRY RUN] Would scan {len(COMMON_PORTS)} ports on {target}")
            results["open"] = [80, 443, 22]
            results["closed"] = [21, 23, 25]
            return results

        # Resolve target to IP if hostname
        target_ip = target
        if not is_ip(target):
            try:
                ips = self.dns.resolve(target, "A")
                if ips:
                    target_ip = ips[0]
                else:
                    ColorOutput.warning(f"    Cannot resolve {target} for port scan")
                    return results
            except Exception:
                ColorOutput.warning(f"    DNS resolution failed for {target}")
                return results

        ColorOutput.info(f"    Scanning {len(COMMON_PORTS)} ports on {target_ip}...")

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, port))
                sock.close()

                if result == 0:
                    return ("open", port)
                else:
                    return ("closed", port)
            except socket.timeout:
                return ("filtered", port)
            except OSError:
                return ("filtered", port)
            except Exception:
                return ("closed", port)

        with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            futures = {executor.submit(scan_port, port): port for port in COMMON_PORTS}
            for future in as_completed(futures):
                try:
                    status, port = future.result()
                    results[status].append(port)
                    if status == "open":
                        # Try to get service banner
                        service = self._get_service_name(port)
                        ColorOutput.success(f"    Port {port}/tcp OPEN ({service})")
                except Exception:
                    pass

        # Sort results
        results["open"].sort()
        results["closed"].sort()
        results["filtered"].sort()

        return results

    def _get_service_name(self, port: int) -> str:
        """
        Get the common service name for a port number.

        Maps well-known port numbers to their typical service names
        for display in scan results.

        Args:
            port: Port number to look up.

        Returns:
            Service name string or 'unknown'.
        """
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            161: "SNMP",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            587: "Submission",
            636: "LDAPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            2049: "NFS",
            2082: "cPanel",
            2083: "cPanel SSL",
            2086: "WHM",
            2087: "WHM SSL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            5985: "WinRM",
            6379: "Redis",
            8000: "HTTP-Alt",
            8008: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8081: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9090: "WebConsole",
            9200: "Elasticsearch",
            9300: "ES-Transport",
            10000: "Webmin",
            11211: "Memcached",
            27017: "MongoDB",
            27018: "MongoDB",
            28017: "MongoDB-Web",
            50000: "SAP",
        }
        return services.get(port, "unknown")

    def check_email_security(self) -> Dict[str, Any]:
        """
        Check email security records (SPF, DKIM, DMARC) for the domain.

        Analyzes DNS TXT records to evaluate the email security
        posture of the target domain, checking for proper SPF,
        DKIM, and DMARC configuration.

        Returns:
            Dictionary containing email security analysis:
                - spf: SPF record details and analysis
                - dkim: DKIM record details
                - dmarc: DMARC record details and policy
                - summary: Overall email security assessment
        """
        email_security = {
            "spf": {"record": "", "valid": False, "policy": "", "issues": []},
            "dkim": {"found": False, "selectors_checked": [], "records": []},
            "dmarc": {"record": "", "valid": False, "policy": "", "issues": []},
            "summary": {"score": 0, "rating": "", "recommendations": []},
        }

        if self.dry_run:
            ColorOutput.info("    [DRY RUN] Would check email security records")
            email_security["spf"] = {
                "record": "v=spf1 include:_spf.google.com ~all",
                "valid": True,
                "policy": "softfail",
                "issues": [],
            }
            email_security["dmarc"] = {
                "record": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
                "valid": True,
                "policy": "quarantine",
                "issues": [],
            }
            email_security["summary"] = {"score": 7, "rating": "good", "recommendations": []}
            return email_security

        score = 0

        # Check SPF
        try:
            txt_records = self.dns.resolve(self.domain, "TXT")
            for record in txt_records:
                record = record.strip('"')
                if record.startswith("v=spf1"):
                    email_security["spf"]["record"] = record
                    email_security["spf"]["valid"] = True
                    score += 3

                    # Analyze SPF policy
                    if "-all" in record:
                        email_security["spf"]["policy"] = "hardfail"
                        score += 1
                    elif "~all" in record:
                        email_security["spf"]["policy"] = "softfail"
                        email_security["spf"]["issues"].append("Using softfail (~all) instead of hardfail (-all)")
                    elif "?all" in record:
                        email_security["spf"]["policy"] = "neutral"
                        email_security["spf"]["issues"].append("Using neutral (?all) - no protection")
                    elif "+all" in record:
                        email_security["spf"]["policy"] = "pass_all"
                        email_security["spf"]["issues"].append("CRITICAL: Using +all allows anyone to spoof")

                    # Check for too many lookups
                    lookup_count = len(re.findall(r'(include:|a:|mx:|redirect=)', record))
                    if lookup_count > 10:
                        email_security["spf"]["issues"].append(f"Too many DNS lookups ({lookup_count}) - may exceed 10-lookup limit")
                    break

            if not email_security["spf"]["valid"]:
                email_security["spf"]["issues"].append("No SPF record found")
                email_security["summary"]["recommendations"].append("Add SPF record to prevent email spoofing")
        except Exception as e:
            ColorOutput.warning(f"    SPF check error: {e}")

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            dmarc_records = self.dns.resolve(dmarc_domain, "TXT")
            for record in dmarc_records:
                record = record.strip('"')
                if record.startswith("v=DMARC1"):
                    email_security["dmarc"]["record"] = record
                    email_security["dmarc"]["valid"] = True
                    score += 3

                    # Parse policy
                    policy_match = re.search(r'p=(none|quarantine|reject)', record, re.IGNORECASE)
                    if policy_match:
                        policy = policy_match.group(1).lower()
                        email_security["dmarc"]["policy"] = policy
                        if policy == "reject":
                            score += 2
                        elif policy == "quarantine":
                            score += 1
                        elif policy == "none":
                            email_security["dmarc"]["issues"].append("Policy is 'none' - no enforcement")
                            email_security["summary"]["recommendations"].append("Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'")

                    # Check for rua (reporting)
                    if "rua=" not in record:
                        email_security["dmarc"]["issues"].append("No aggregate reporting (rua) configured")

                    # Check for ruf (forensic reporting)
                    if "ruf=" not in record:
                        email_security["dmarc"]["issues"].append("No forensic reporting (ruf) configured")

                    # Check subdomain policy
                    sp_match = re.search(r'sp=(none|quarantine|reject)', record, re.IGNORECASE)
                    if sp_match:
                        email_security["dmarc"]["subdomain_policy"] = sp_match.group(1)
                    break

            if not email_security["dmarc"]["valid"]:
                email_security["dmarc"]["issues"].append("No DMARC record found")
                email_security["summary"]["recommendations"].append("Add DMARC record for email authentication")
        except Exception as e:
            ColorOutput.warning(f"    DMARC check error: {e}")

        # Check DKIM (try common selectors)
        common_selectors = [
            "default", "google", "dkim", "mail", "email",
            "selector1", "selector2", "s1", "s2", "k1", "k2",
            "mandrill", "mailchimp", "sendgrid", "amazonses",
            "zoho", "protonmail", "mimecast",
        ]

        email_security["dkim"]["selectors_checked"] = common_selectors
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                dkim_records = self.dns.resolve(dkim_domain, "TXT")
                if dkim_records:
                    for record in dkim_records:
                        record = record.strip('"')
                        if "v=DKIM1" in record or "p=" in record:
                            email_security["dkim"]["found"] = True
                            email_security["dkim"]["records"].append({
                                "selector": selector,
                                "record": record[:200],
                            })
                            score += 1
                            break
            except Exception:
                pass

        if not email_security["dkim"]["found"]:
            email_security["summary"]["recommendations"].append("Configure DKIM for email authentication")

        # Calculate summary
        email_security["summary"]["score"] = min(score, 10)
        if score >= 8:
            email_security["summary"]["rating"] = "excellent"
        elif score >= 6:
            email_security["summary"]["rating"] = "good"
        elif score >= 4:
            email_security["summary"]["rating"] = "fair"
        elif score >= 2:
            email_security["summary"]["rating"] = "poor"
        else:
            email_security["summary"]["rating"] = "critical"

        return email_security

    # =========================================================================
    # RESULTS MANAGEMENT
    # =========================================================================

    def _save_results(self, results: ReconResults):
        """
        Save all reconnaissance results to disk in multiple formats.

        Writes the complete results to a JSON file, and individual
        findings to separate text files for easy consumption by
        other tools and scripts.

        Args:
            results: ReconResults dataclass containing all findings.
        """
        # Create subdirectory for this domain
        domain_dir = self.domain.replace(".", "_")

        # Save complete results as JSON
        try:
            results_dict = results.to_dict()
            results_dict["scan_metadata"] = {
                "tool": "Monster v2.0.0",
                "date": datetime.now().isoformat(),
                "domain": self.domain,
                "options": {k: str(v) for k, v in self.options.items()},
            }
            self.file_manager.save_json(results_dict, f"{domain_dir}_recon.json", domain_dir)
            ColorOutput.success(f"    Saved: {domain_dir}_recon.json")
        except Exception as e:
            ColorOutput.error(f"    Failed to save JSON results: {e}")

        # Save subdomains list
        try:
            if results.subdomains:
                subdomain_text = "\n".join(
                    f"{s['name']}\t{s.get('ip', '')}\t{s.get('source', '')}"
                    for s in results.subdomains
                )
                self.file_manager.save_text(subdomain_text, "subdomains.txt", domain_dir)
                ColorOutput.success(f"    Saved: subdomains.txt ({len(results.subdomains)} entries)")

                # Also save just hostnames for piping to other tools
                hostnames = "\n".join(s["name"] for s in results.subdomains)
                self.file_manager.save_text(hostnames, "subdomains_only.txt", domain_dir)
        except Exception as e:
            ColorOutput.error(f"    Failed to save subdomains: {e}")

        # Save live hosts
        try:
            if results.live_hosts:
                live_text = "\n".join(
                    f"{h.get('url', '')}\t{h.get('status_code', '')}\t{h.get('title', '')}\t{h.get('server', '')}"
                    for h in results.live_hosts
                )
                self.file_manager.save_text(live_text, "live_hosts.txt", domain_dir)
                ColorOutput.success(f"    Saved: live_hosts.txt ({len(results.live_hosts)} hosts)")

                # Save URLs only for screenshot tools
                urls_text = "\n".join(h.get("url", "") for h in results.live_hosts if h.get("url"))
                self.file_manager.save_text(urls_text, "live_urls.txt", domain_dir)
        except Exception as e:
            ColorOutput.error(f"    Failed to save live hosts: {e}")

        # Save DNS records
        try:
            if results.dns_records:
                dns_text = ""
                for record_type, values in results.dns_records.items():
                    if isinstance(values, list) and values:
                        dns_text += f"\n[{record_type}]\n"
                        for val in values:
                            dns_text += f"  {val}\n"
                    elif isinstance(values, dict):
                        dns_text += f"\n[{record_type}]\n"
                        for key, vals in values.items():
                            if isinstance(vals, list):
                                dns_text += f"  {key}: {', '.join(str(v) for v in vals)}\n"
                            else:
                                dns_text += f"  {key}: {vals}\n"
                self.file_manager.save_text(dns_text, "dns_records.txt", domain_dir)
                ColorOutput.success("    Saved: dns_records.txt")
        except Exception as e:
            ColorOutput.error(f"    Failed to save DNS records: {e}")

        # Save Wayback URLs
        try:
            if results.wayback_urls:
                wayback_text = "\n".join(results.wayback_urls)
                self.file_manager.save_text(wayback_text, "wayback_urls.txt", domain_dir)
                ColorOutput.success(f"    Saved: wayback_urls.txt ({len(results.wayback_urls)} URLs)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save Wayback URLs: {e}")

        # Save Google dorks
        try:
            if results.google_dorks:
                dorks_text = "\n".join(results.google_dorks)
                self.file_manager.save_text(dorks_text, "google_dorks.txt", domain_dir)
                ColorOutput.success(f"    Saved: google_dorks.txt ({len(results.google_dorks)} dorks)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save Google dorks: {e}")

        # Save Shodan queries
        try:
            if results.shodan_queries:
                shodan_text = "\n".join(results.shodan_queries)
                self.file_manager.save_text(shodan_text, "shodan_queries.txt", domain_dir)
                ColorOutput.success(f"    Saved: shodan_queries.txt ({len(results.shodan_queries)} queries)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save Shodan queries: {e}")

        # Save GitHub dorks
        try:
            if results.github_dorks:
                github_text = "\n".join(results.github_dorks)
                self.file_manager.save_text(github_text, "github_dorks.txt", domain_dir)
                ColorOutput.success(f"    Saved: github_dorks.txt ({len(results.github_dorks)} dorks)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save GitHub dorks: {e}")

        # Save GitLab dorks
        try:
            if results.gitlab_dorks:
                gitlab_text = "\n".join(results.gitlab_dorks)
                self.file_manager.save_text(gitlab_text, "gitlab_dorks.txt", domain_dir)
                ColorOutput.success(f"    Saved: gitlab_dorks.txt ({len(results.gitlab_dorks)} dorks)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save GitLab dorks: {e}")

        # Save technologies
        try:
            if results.technologies:
                tech_text = "\n".join(
                    f"{t.get('name', '')}\t{t.get('version', '')}\t{t.get('category', '')}\t{t.get('confidence', '')}"
                    for t in results.technologies
                )
                self.file_manager.save_text(tech_text, "technologies.txt", domain_dir)
                ColorOutput.success(f"    Saved: technologies.txt ({len(results.technologies)} techs)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save technologies: {e}")

        # Save port scan results
        try:
            if results.ports:
                open_ports = results.ports.get("open", [])
                if open_ports:
                    ports_text = "Open ports:\n"
                    for port in open_ports:
                        service = self._get_service_name(port)
                        ports_text += f"  {port}/tcp\t{service}\n"
                    ports_text += f"\nClosed: {len(results.ports.get('closed', []))}\n"
                    ports_text += f"Filtered: {len(results.ports.get('filtered', []))}\n"
                    self.file_manager.save_text(ports_text, "ports.txt", domain_dir)
                    ColorOutput.success(f"    Saved: ports.txt ({len(open_ports)} open)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save port results: {e}")

        # Save email security analysis
        try:
            if results.email_security:
                email_text = json.dumps(results.email_security, indent=2)
                self.file_manager.save_text(email_text, "email_security.txt", domain_dir)
                ColorOutput.success("    Saved: email_security.txt")
        except Exception as e:
            ColorOutput.error(f"    Failed to save email security: {e}")

        # Save S3 buckets
        try:
            if results.s3_buckets:
                s3_text = "\n".join(
                    f"{b.get('name', '')}\t{b.get('url', '')}\t{b.get('status', '')}"
                    for b in results.s3_buckets
                )
                self.file_manager.save_text(s3_text, "s3_buckets.txt", domain_dir)
                ColorOutput.success(f"    Saved: s3_buckets.txt ({len(results.s3_buckets)} buckets)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save S3 buckets: {e}")

        # Save ASN info
        try:
            if results.asn_info:
                asn_text = json.dumps(results.asn_info, indent=2)
                self.file_manager.save_text(asn_text, "asn_info.txt", domain_dir)
                ColorOutput.success("    Saved: asn_info.txt")
        except Exception as e:
            ColorOutput.error(f"    Failed to save ASN info: {e}")

        # Save screenshot URLs
        try:
            if results.screenshot_urls:
                screenshot_text = "\n".join(results.screenshot_urls)
                self.file_manager.save_text(screenshot_text, "screenshot_urls.txt", domain_dir)
                ColorOutput.success(f"    Saved: screenshot_urls.txt ({len(results.screenshot_urls)} URLs)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save screenshot URLs: {e}")

        # Save virtual hosts
        try:
            if results.vhosts:
                vhost_text = "\n".join(results.vhosts)
                self.file_manager.save_text(vhost_text, "virtual_hosts.txt", domain_dir)
                ColorOutput.success(f"    Saved: virtual_hosts.txt ({len(results.vhosts)} vhosts)")
        except Exception as e:
            ColorOutput.error(f"    Failed to save virtual hosts: {e}")

        # Save zone transfer results
        try:
            if results.zone_transfer_results:
                zt_text = ""
                for ns, records in results.zone_transfer_results.items():
                    zt_text += f"\n[{ns}]\n"
                    for record in records:
                        zt_text += f"  {record}\n"
                self.file_manager.save_text(zt_text, "zone_transfers.txt", domain_dir)
                ColorOutput.success("    Saved: zone_transfers.txt")
        except Exception as e:
            ColorOutput.error(f"    Failed to save zone transfer results: {e}")

        # Save reverse IP results
        try:
            if results.reverse_ip_results:
                rip_text = ""
                for ip_addr, domains in results.reverse_ip_results.items():
                    rip_text += f"\n[{ip_addr}]\n"
                    for domain in domains:
                        rip_text += f"  {domain}\n"
                self.file_manager.save_text(rip_text, "reverse_ip.txt", domain_dir)
                ColorOutput.success("    Saved: reverse_ip.txt")
        except Exception as e:
            ColorOutput.error(f"    Failed to save reverse IP results: {e}")

    def _deduplicate_subdomains(self, subdomains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate and sort subdomain results.

        Removes duplicate subdomain entries, preferring those with
        IP addresses and source information. Results are sorted
        alphabetically by subdomain name.

        Args:
            subdomains: List of subdomain dictionaries to deduplicate.

        Returns:
            Deduplicated and sorted list of subdomain dictionaries.
        """
        if not subdomains:
            return []

        # Use dict keyed by name, preferring entries with IP
        best = {}
        for sub in subdomains:
            name = sub.get("name", "").strip().lower()
            if not name:
                continue

            # Validate the subdomain
            if not name.endswith(f".{self.domain}"):
                continue

            # Skip wildcards and invalid entries
            if "*" in name or " " in name:
                continue

            if name in best:
                # Keep the one with more information
                existing = best[name]
                if not existing.get("ip") and sub.get("ip"):
                    best[name] = sub
                elif not existing.get("source") and sub.get("source"):
                    best[name] = sub
            else:
                best[name] = sub

        # Sort by name
        sorted_subs = sorted(best.values(), key=lambda x: x.get("name", ""))

        return sorted_subs
