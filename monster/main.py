"""
Monster - Master Controller.

Orchestrates all modules: reconnaissance, JavaScript analysis, vulnerability
scanning, and report generation. Provides CLI interface and manages concurrency.
"""

import argparse
import json
import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from monster import VERSION
from monster.config import RATE_LIMIT_DELAY, MAX_THREADS, TIMEOUT
from monster.utils import (
    ColorOutput,
    FileManager,
    HTTPClient,
    RateLimiter,
    domain_from_url,
    is_valid_domain,
    normalize_url,
)


# ---------------------------------------------------------------------------
# Monster Master Controller
# ---------------------------------------------------------------------------

class Monster:
    """Master controller that orchestrates all Monster modules."""

    def __init__(self, args):
        self.targets = []
        self.output_dir = args.output
        self.module = args.module
        self.delay = args.delay
        self.threads = args.threads
        self.timeout = args.timeout
        self.dry_run = args.dry_run
        self.verbose = args.verbose
        self.no_color = args.no_color
        self.resume = args.resume
        self.scan_results = {}
        self.start_time = None

        # Load targets
        if args.target:
            self.targets = [args.target]
        elif args.scope:
            self.targets = self._load_scope_file(args.scope)
        elif args.apk:
            self.targets = self._extract_from_apk(args.apk)

    def run(self):
        """Execute the full scan pipeline."""
        if not self.targets:
            ColorOutput.error("No targets specified. Use --target, --scope, or --apk.")
            return 1

        self.start_time = time.time()

        if not self.no_color:
            ColorOutput.banner()

        ColorOutput.info(f"Scope: {len(self.targets)} target(s)")
        ColorOutput.info(f"Output: {self.output_dir}")
        ColorOutput.info(f"Rate limit: {self.delay}s delay")
        ColorOutput.info(f"Threads: {self.threads}")
        ColorOutput.info(f"Module: {self.module}")

        if self.dry_run:
            ColorOutput.warning("DRY-RUN mode enabled - no network calls")

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

        # Run selected modules
        if self.module in ("all", "recon"):
            self._run_recon()

        if self.module in ("all", "js"):
            self._run_js_analysis()

        if self.module in ("all", "vuln"):
            self._run_vuln_scan()

        if self.module in ("all", "report"):
            self._run_report()

        # Print final summary
        self._print_final_summary()
        return 0

    # -------------------------------------------------------------------
    # Module Runners
    # -------------------------------------------------------------------

    def _run_recon(self):
        """Run the reconnaissance module."""
        self._print_phase_header("PHASE 1: RECONNAISSANCE")

        try:
            from monster.recon import ReconEngine
        except ImportError as e:
            ColorOutput.error(f"Could not load recon module: {e}")
            return

        all_subdomains = []
        all_urls = []

        for target in self.targets:
            domain = domain_from_url(target)
            target_dir = os.path.join(self.output_dir, domain)

            # Resume check
            if self.resume and os.path.exists(os.path.join(target_dir, "recon.json")):
                ColorOutput.info(f"[SKIP] {domain} - already scanned (--resume)")
                continue

            options = {
                "dry_run": self.dry_run,
                "max_threads": self.threads,
            }
            engine = ReconEngine(domain, target_dir, options=options)
            results = engine.run()

            if results:
                # results.subdomains is a list of dicts with 'name' key
                for sub in results.subdomains:
                    name = sub.get("name", "") if isinstance(sub, dict) else str(sub)
                    if name:
                        all_subdomains.append(name)
                all_urls.extend(results.wayback_urls)

        # Save combined subdomain list
        if all_subdomains:
            unique_subs = sorted(set(all_subdomains))
            fm = FileManager(self.output_dir)
            fm.save_text("\n".join(unique_subs), "subdomains.txt")
            ColorOutput.success(f"Total unique subdomains: {len(unique_subs)}")

        self.scan_results["recon"] = {
            "subdomains": list(set(all_subdomains)),
            "wayback_urls": all_urls,
        }

    def _run_js_analysis(self):
        """Run the JavaScript analysis module."""
        self._print_phase_header("PHASE 2: JAVASCRIPT ANALYSIS")

        try:
            from monster.js_analyzer import JSAnalyzer
        except ImportError as e:
            ColorOutput.error(f"Could not load js_analyzer module: {e}")
            return

        # Build URL list from targets and discovered subdomains
        urls_to_scan = [normalize_url(t) for t in self.targets]
        recon_subs = self.scan_results.get("recon", {}).get("subdomains", [])
        for sub in recon_subs[:50]:  # Limit to avoid excessive scanning
            urls_to_scan.append(normalize_url(sub))

        js_dir = os.path.join(self.output_dir, "js_analysis")
        options = {"dry_run": self.dry_run}
        analyzer = JSAnalyzer(urls_to_scan, js_dir, options=options)
        results = analyzer.run()

        # Save endpoints
        all_endpoints = []
        if results:
            for r in results:
                all_endpoints.extend(r.endpoints if hasattr(r, 'endpoints') else [])
        if all_endpoints:
            fm = FileManager(self.output_dir)
            fm.save_text("\n".join(all_endpoints), "js_endpoints.txt")
            ColorOutput.success(f"API endpoints found: {len(all_endpoints)}")

        self.scan_results["js_analysis"] = {
            "endpoints": all_endpoints,
            "js_files": [],
        }

    def _run_vuln_scan(self):
        """Run the vulnerability scanning module."""
        self._print_phase_header("PHASE 3: VULNERABILITY SCAN")

        try:
            from monster.vuln_scanner import VulnScanner
        except ImportError as e:
            ColorOutput.error(f"Could not load vuln_scanner module: {e}")
            return

        # Build target list
        urls_to_scan = [normalize_url(t) for t in self.targets]

        # Include discovered subdomains if available
        recon_subs = self.scan_results.get("recon", {}).get("subdomains", [])
        subdomains_data = {}
        for sub in recon_subs[:30]:
            subdomains_data[sub] = []

        vuln_dir = os.path.join(self.output_dir, "vulnerabilities")
        scanner = VulnScanner(
            urls_to_scan,
            subdomains_data,
            vuln_dir,
            rate_limit=self.delay,
            timeout=self.timeout,
            dry_run=self.dry_run,
        )
        findings = scanner.run()

        self.scan_results["vulnerabilities"] = {
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    def _run_report(self):
        """Run the report generation module."""
        self._print_phase_header("PHASE 4: REPORT GENERATION")

        try:
            from monster.report_generator import ReportGenerator
        except ImportError as e:
            ColorOutput.error(f"Could not load report_generator module: {e}")
            return

        duration = time.time() - self.start_time if self.start_time else 0
        metadata = {
            "target": ", ".join(self.targets[:5]),
            "duration": round(duration, 1),
            "modules": [self.module] if self.module != "all" else ["recon", "js", "vuln"],
        }

        generator = ReportGenerator(self.output_dir)
        generator.generate_full_report(self.scan_results, metadata)

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _load_scope_file(self, filepath):
        """Load targets from a scope file (one domain per line)."""
        if not os.path.isfile(filepath):
            ColorOutput.error(f"Scope file not found: {filepath}")
            return []

        targets = []
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        ColorOutput.info(f"Loaded {len(targets)} targets from {filepath}")
        return targets

    def _extract_from_apk(self, apk_path):
        """Extract URLs/domains from an APK file using apk_analyzer."""
        if not os.path.isfile(apk_path):
            ColorOutput.error(f"APK file not found: {apk_path}")
            return []

        ColorOutput.info(f"Extracting targets from APK: {apk_path}")

        # Try using the apk_analyzer module
        try:
            analyzer_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "apk_analyzer", "analyze.py"
            )
            if os.path.isfile(analyzer_path):
                import subprocess
                result = subprocess.run(
                    [sys.executable, analyzer_path, apk_path],
                    capture_output=True, text=True, timeout=120
                )
                # Parse domains from output
                domains = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if is_valid_domain(line):
                        domains.append(line)
                if domains:
                    ColorOutput.success(f"Extracted {len(domains)} domains from APK")
                    return domains
        except Exception as e:
            ColorOutput.warning(f"APK analysis error: {e}")

        return []

    @staticmethod
    def _print_phase_header(title):
        """Print a phase separator header."""
        print()
        print(f"\033[36m{'=' * 60}\033[0m")
        print(f"\033[36m  {title}\033[0m")
        print(f"\033[36m{'=' * 60}\033[0m")
        print()

    def _print_final_summary(self):
        """Print final scan summary."""
        duration = time.time() - self.start_time if self.start_time else 0
        minutes = int(duration // 60)
        seconds = int(duration % 60)

        vulns = self.scan_results.get("vulnerabilities", {})
        total_findings = vulns.get("total_findings", 0) if isinstance(vulns, dict) else 0
        recon = self.scan_results.get("recon", {})
        total_subs = len(recon.get("subdomains", [])) if isinstance(recon, dict) else 0

        print()
        print(f"\033[36m{'=' * 60}\033[0m")
        print(f"\033[36m  SCAN COMPLETE\033[0m")
        print(f"\033[36m  Duration: {minutes}m {seconds}s | Targets: {len(self.targets)} | Findings: {total_findings}\033[0m")
        if total_subs:
            print(f"\033[36m  Subdomains: {total_subs}\033[0m")
        print(f"\033[36m{'=' * 60}\033[0m")
        print()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for Monster."""
    parser = argparse.ArgumentParser(
        prog="monster",
        description=f"Monster - Bug Bounty Intelligence Platform v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python -m monster --target example.com
  python -m monster --scope targets.txt --module recon
  python -m monster --target example.com --module vuln -o ./results
  python -m monster --target example.com --dry-run
""",
    )

    parser.add_argument(
        "--target", "-t",
        help="Single target domain to scan",
    )
    parser.add_argument(
        "--scope", "-s",
        help="File with list of target domains (one per line)",
    )
    parser.add_argument(
        "--apk",
        help="APK file path to extract URLs/domains from",
    )
    parser.add_argument(
        "--module", "-m",
        choices=["all", "recon", "js", "vuln", "report"],
        default="all",
        help="Module to run (default: all)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./monster_output",
        help="Output directory (default: ./monster_output)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=RATE_LIMIT_DELAY,
        help=f"Delay between requests in seconds (default: {RATE_LIMIT_DELAY})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=MAX_THREADS,
        help=f"Max concurrent threads (default: {MAX_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT,
        help=f"Request timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making network calls",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip already-scanned targets (check existing results)",
    )

    args = parser.parse_args()

    # Validate at least one target source
    if not args.target and not args.scope and not args.apk:
        parser.print_help()
        return 1

    try:
        monster = Monster(args)
        return monster.run()
    except KeyboardInterrupt:
        ColorOutput.warning("Scan interrupted by user.")
        return 130
    except Exception as e:
        ColorOutput.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
