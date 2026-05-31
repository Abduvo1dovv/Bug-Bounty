"""
Monster v2.0.0 Main Module - CLI Orchestration

Main entry point and orchestrator for the Monster security assessment
toolkit. Handles argument parsing, configuration loading, module
coordination, signal handling, and output formatting.

Usage:
    python -m monster --target example.com
    python -m monster --target example.com --dry-run
    python -m monster --scope targets.txt --module all --profile deep
    python -m monster --interactive
"""

import os
import re
import sys
import json
import time
import signal
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse

from monster import VERSION
from monster.utils import (
    ColorOutput, HTTPClient, FileManager, RateLimiter,
    ProxyManager, normalize_url, domain_from_url,
    is_valid_domain
)
from monster.config import (
    DEFAULT_USER_AGENT, RATE_LIMIT_DELAY,
    MAX_THREADS, TIMEOUT
)


# =============================================================================
# SCAN PROFILES
# =============================================================================

SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast reconnaissance only. Good for initial target assessment.",
        "modules": ["recon"],
        "threads": 5,
        "delay": 0.5,
        "timeout": 10,
        "verbose": False,
    },
    "normal": {
        "name": "Normal Scan",
        "description": "Balanced scan with recon, JS analysis, and vulnerability checks.",
        "modules": ["recon", "js", "vuln"],
        "threads": 10,
        "delay": 1.0,
        "timeout": 15,
        "verbose": False,
    },
    "deep": {
        "name": "Deep Scan",
        "description": "Thorough analysis with all modules. Slower but more comprehensive.",
        "modules": ["recon", "js", "vuln", "param", "cookie"],
        "threads": 5,
        "delay": 2.0,
        "timeout": 20,
        "verbose": True,
    },
    "aggressive": {
        "name": "Aggressive Scan",
        "description": "Fast full scan with all modules. Noisy but quick.",
        "modules": ["recon", "js", "vuln", "param", "cookie"],
        "threads": 20,
        "delay": 0.2,
        "timeout": 10,
        "verbose": True,
    },
}


# =============================================================================
# BANNER
# =============================================================================

MONSTER_BANNER = f"""
{chr(27)}[36m{chr(27)}[1m
  __  __  ___  _  _ ___ _____ ___ ___
 |  \\/  |/ _ \\| \\| / __|_   _| __| _ \\
 | |\\/| | (_) | .` \\__ \\ | | | _||   /
 |_|  |_|\\___/|_|\\_|___/ |_| |___|_|_\\

{chr(27)}[0m{chr(27)}[35m  Bug Bounty Recon & Vulnerability Assessment Toolkit{chr(27)}[0m
{chr(27)}[90m  Version {VERSION} | github.com/monster-security{chr(27)}[0m
"""


# =============================================================================
# MONSTER CLASS
# =============================================================================


class Monster:
    """
    Main orchestrator for Monster security assessment toolkit.

    Coordinates all scanning modules (recon, JS analysis, vulnerability
    scanning, parameter mining, cookie analysis) and manages the overall
    assessment workflow including configuration, progress tracking, and
    report generation.

    Attributes:
        args: Parsed command-line arguments.
        target: Primary target domain or URL.
        targets: List of all targets to scan.
        output_dir: Output directory for results.
        dry_run: If True, skip network requests.
        verbose: If True, show detailed output.
        modules_to_run: List of module names to execute.
        findings: Collected vulnerability findings.
        scan_metadata: Metadata about the current scan.
        shutdown_requested: Flag for graceful shutdown.
    """

    def __init__(self, args: argparse.Namespace):
        """
        Initialize the Monster scanner with parsed arguments.

        Sets up all configuration from CLI args, config file, and
        scan profile. Initializes module runners and output handlers.

        Args:
            args: Parsed argparse.Namespace with all CLI options.
        """
        self.args = args
        self.shutdown_requested = False
        self.findings: List[Any] = []
        self.scan_metadata: Dict[str, Any] = {}
        self.scan_results: Dict[str, Any] = {}
        self._lock = threading.Lock()

        # Load config file if specified or default
        self.config = self._load_config_file()

        # Apply profile settings first (lowest priority)
        profile_name = getattr(args, "profile", None) or self.config.get("profile", "normal")
        profile = self._get_scan_profile(profile_name)

        # Determine settings with priority: CLI > config > profile > defaults
        self.output_dir = (
            getattr(args, "output", None)
            or self.config.get("output", None)
            or "./monster_output"
        )
        self.dry_run = getattr(args, "dry_run", False) or self.config.get("dry_run", False)
        self.verbose = getattr(args, "verbose", False) or self.config.get("verbose", False)
        self.no_color = getattr(args, "no_color", False) or self.config.get("no_color", False)
        self.delay = (
            getattr(args, "delay", None)
            or self.config.get("delay", None)
            or profile.get("delay", RATE_LIMIT_DELAY)
        )
        self.threads = (
            getattr(args, "threads", None)
            or self.config.get("threads", None)
            or profile.get("threads", MAX_THREADS)
        )
        self.timeout = (
            getattr(args, "timeout", None)
            or self.config.get("timeout", None)
            or profile.get("timeout", TIMEOUT)
        )
        self.proxy = getattr(args, "proxy", None) or self.config.get("proxy", None)
        self.webhook_url = getattr(args, "webhook", None) or self.config.get("webhook", None)
        self.resume = getattr(args, "resume", False)
        self.report_format = (
            getattr(args, "format", None)
            or self.config.get("format", "all")
        )
        self.exclude_patterns = []
        exclude_str = getattr(args, "exclude", None) or self.config.get("exclude", "")
        if exclude_str:
            self.exclude_patterns = [p.strip() for p in exclude_str.split(",") if p.strip()]

        # Cookie configuration
        self.cookies_file = getattr(args, "cookies", None) or self.config.get("cookies", None)
        self.cookie_jar_path = getattr(args, "cookie_jar", None) or self.config.get("cookie_jar", None)

        # Determine modules to run
        module_arg = getattr(args, "module", None) or self.config.get("module", "all")
        if module_arg == "all":
            self.modules_to_run = profile.get("modules", ["recon", "js", "vuln", "param", "cookie"])
        else:
            self.modules_to_run = [m.strip() for m in module_arg.split(",")]

        # Always include report generation
        if "report" not in self.modules_to_run:
            self.modules_to_run.append("report")

        # Load targets
        self.targets = self._load_targets()
        self.target = self.targets[0] if self.targets else ""

        # Setup output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # Setup signal handlers
        self._setup_signal_handlers()

        # Cookie manager (lazy-loaded)
        self._cookie_manager = None
        self._authenticated_client = None

    def run(self) -> int:
        """
        Execute the full scanning workflow.

        Runs all configured modules in sequence, collects results,
        generates reports, and prints a final summary.

        Returns:
            Exit code (0 for success, 1 for errors, 130 for interrupt).
        """
        start_time = time.time()
        self.scan_metadata["start_time"] = datetime.now().isoformat()
        self.scan_metadata["target"] = self.target
        self.scan_metadata["modules_run"] = []
        self.scan_metadata["version"] = VERSION
        self.scan_metadata["timeline"] = []

        # Print banner
        if not self.no_color:
            print(MONSTER_BANNER)
        else:
            print(f"\n  MONSTER v{VERSION} - Bug Bounty Toolkit\n")

        # Validate we have targets
        if not self.targets:
            ColorOutput.error("No targets specified. Use --target or --scope.")
            return 1

        # Print scan configuration
        self._print_scan_config()

        # Track timeline
        self.scan_metadata["timeline"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "event": "Scan started",
        })

        try:
            # Run modules
            if "recon" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("RECONNAISSANCE")
                self._run_recon()
                self.scan_metadata["modules_run"].append("recon")
                self.scan_metadata["timeline"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": "Reconnaissance completed",
                })

            if "js" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("JAVASCRIPT ANALYSIS")
                self._run_js_analysis()
                self.scan_metadata["modules_run"].append("js")
                self.scan_metadata["timeline"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": "JavaScript analysis completed",
                })

            if "vuln" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("VULNERABILITY SCANNING")
                self._run_vuln_scan()
                self.scan_metadata["modules_run"].append("vuln")
                self.scan_metadata["timeline"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": "Vulnerability scanning completed",
                })

            if "param" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("PARAMETER MINING")
                self._run_param_mining()
                self.scan_metadata["modules_run"].append("param")
                self.scan_metadata["timeline"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": "Parameter mining completed",
                })

            if "cookie" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("COOKIE ANALYSIS")
                self._run_cookie_analysis()
                self.scan_metadata["modules_run"].append("cookie")
                self.scan_metadata["timeline"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "event": "Cookie analysis completed",
                })

            # Generate reports
            if "report" in self.modules_to_run and not self.shutdown_requested:
                self._print_phase_header("REPORT GENERATION")
                self._run_report()
                self.scan_metadata["modules_run"].append("report")

        except KeyboardInterrupt:
            ColorOutput.warning("\nScan interrupted by user. Saving partial results...")
            self.shutdown_requested = True
        except Exception as e:
            ColorOutput.error(f"Scan error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        # Finalize
        end_time = time.time()
        duration = end_time - start_time
        self.scan_metadata["end_time"] = datetime.now().isoformat()
        self.scan_metadata["duration"] = f"{duration:.1f}s"
        self.scan_metadata["timeline"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "event": f"Scan completed in {duration:.1f}s",
        })

        # Print summary
        self._print_final_summary()

        if self.shutdown_requested:
            return 130
        return 0

    def _run_recon(self):
        """
        Execute reconnaissance module.

        Runs the ReconEngine against all targets and collects
        subdomain, DNS, technology, and port scanning results.
        """
        if self.dry_run:
            ColorOutput.info("[DRY RUN] Skipping reconnaissance (no network calls)")
            self.scan_results["recon"] = {"status": "skipped (dry-run)", "targets": self.targets}
            return

        try:
            from monster.recon import ReconEngine, ReconResults

            for target in self.targets:
                if self.shutdown_requested:
                    break

                domain = domain_from_url(target) if "://" in target else target
                ColorOutput.info(f"Running recon on: {domain}")

                options = {
                    "dry_run": self.dry_run,
                    "verbose": self.verbose,
                    "threads": self.threads,
                    "timeout": self.timeout,
                }

                engine = ReconEngine(domain, self.output_dir, options=options)
                results = engine.run()

                if hasattr(results, "to_dict"):
                    self.scan_results["recon"] = results.to_dict()
                else:
                    self.scan_results["recon"] = {"domain": domain}

        except ImportError as e:
            ColorOutput.error(f"Failed to load recon module: {e}")
            self.scan_results["recon"] = {"error": str(e)}
        except Exception as e:
            ColorOutput.error(f"Recon failed: {e}")
            self.scan_results["recon"] = {"error": str(e)}
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _run_js_analysis(self):
        """
        Execute JavaScript analysis module.

        Discovers and analyzes JavaScript files for endpoints,
        secrets, vulnerabilities, and other security-relevant data.
        """
        if self.dry_run:
            ColorOutput.info("[DRY RUN] Skipping JS analysis (no network calls)")
            self.scan_results["js_analysis"] = {"status": "skipped (dry-run)", "targets": self.targets}
            return

        try:
            from monster.js_analyzer import JSAnalyzer, JSResults

            urls = []
            for target in self.targets:
                if "://" not in target:
                    urls.append(f"https://{target}")
                else:
                    urls.append(target)

            options = {
                "dry_run": self.dry_run,
                "rate_limit": self.delay,
                "timeout": self.timeout,
            }

            analyzer = JSAnalyzer(urls, output_dir=self.output_dir, options=options)
            results = analyzer.run()

            js_summary = []
            for r in results:
                if hasattr(r, "to_dict"):
                    js_summary.append(r.to_dict())

            self.scan_results["js_analysis"] = {
                "targets_analyzed": len(urls),
                "results": js_summary,
            }

        except ImportError as e:
            ColorOutput.error(f"Failed to load JS analyzer: {e}")
            self.scan_results["js_analysis"] = {"error": str(e)}
        except Exception as e:
            ColorOutput.error(f"JS analysis failed: {e}")
            self.scan_results["js_analysis"] = {"error": str(e)}
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _run_vuln_scan(self):
        """
        Execute vulnerability scanning module.

        Runs comprehensive security checks against target URLs
        and collects all findings. Integrates cookie manager if loaded.
        """
        if self.dry_run:
            ColorOutput.info("[DRY RUN] Skipping vulnerability scan (no network calls)")
            self.scan_results["vuln_scan"] = {"status": "skipped (dry-run)", "targets": self.targets}
            return

        try:
            from monster.vuln_scanner import VulnScanner, Finding

            urls = []
            for target in self.targets:
                if "://" not in target:
                    urls.append(f"https://{target}")
                else:
                    urls.append(target)

            scanner = VulnScanner(
                targets=urls,
                output_dir=self.output_dir,
                rate_limit=self.delay,
                timeout=self.timeout,
                dry_run=self.dry_run,
            )

            findings = scanner.run()
            self.findings.extend(findings)

            self.scan_results["vuln_scan"] = {
                "targets_scanned": len(urls),
                "findings_count": len(findings),
            }

            # Send webhooks for critical findings
            if self.webhook_url:
                for finding in findings:
                    if hasattr(finding, "severity") and finding.severity.upper() in ("CRITICAL", "HIGH"):
                        self._send_notification(finding)

        except ImportError as e:
            ColorOutput.error(f"Failed to load vuln scanner: {e}")
            self.scan_results["vuln_scan"] = {"error": str(e)}
        except Exception as e:
            ColorOutput.error(f"Vulnerability scan failed: {e}")
            self.scan_results["vuln_scan"] = {"error": str(e)}
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _run_param_mining(self):
        """
        Execute parameter mining module.

        Discovers hidden parameters, tests for reflection,
        maps input vectors, and extracts forms from targets.
        """
        if self.dry_run:
            ColorOutput.info("[DRY RUN] Skipping parameter mining (no network calls)")
            self.scan_results["param_mining"] = {"status": "skipped (dry-run)", "targets": self.targets}
            return

        try:
            from monster.param_miner import ParamMiner

            urls = []
            for target in self.targets:
                if "://" not in target:
                    urls.append(f"https://{target}")
                else:
                    urls.append(target)

            options = {
                "delay": self.delay,
                "timeout": self.timeout,
                "proxy": self.proxy,
            }

            miner = ParamMiner(targets=urls, output_dir=self.output_dir, options=options)
            results = miner.run()

            self.scan_results["param_mining"] = {
                "targets_analyzed": len(urls),
                "results": results if isinstance(results, dict) else {},
            }

        except ImportError as e:
            ColorOutput.error(f"Failed to load param miner: {e}")
            self.scan_results["param_mining"] = {"error": str(e)}
        except Exception as e:
            ColorOutput.error(f"Parameter mining failed: {e}")
            self.scan_results["param_mining"] = {"error": str(e)}
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _run_cookie_analysis(self):
        """
        Execute cookie analysis module.

        Analyzes cookie security properties, JWT tokens, and
        session management. Uses loaded cookie file if provided.
        """
        if self.dry_run:
            ColorOutput.info("[DRY RUN] Skipping cookie analysis (no network calls)")
            self.scan_results["cookie_analysis"] = {"status": "skipped (dry-run)", "targets": self.targets}
            return

        try:
            from monster.cookie_manager import CookieSecurityAnalyzer

            analyzer = CookieSecurityAnalyzer()

            # If cookies file was provided, load and analyze them
            if self.cookies_file and os.path.exists(self.cookies_file):
                ColorOutput.info(f"Loading cookies from: {self.cookies_file}")
                try:
                    with open(self.cookies_file, "r") as f:
                        cookie_data = f.read()
                    # Try JSON format first
                    try:
                        cookies = json.loads(cookie_data)
                        if isinstance(cookies, list):
                            for cookie in cookies:
                                issues = analyzer.analyze_cookie(cookie)
                                if issues:
                                    self.scan_results.setdefault("cookie_analysis", {})
                                    self.scan_results["cookie_analysis"]["issues"] = issues
                    except json.JSONDecodeError:
                        # Try Netscape format
                        ColorOutput.info("Parsing cookies in Netscape format")
                except Exception as e:
                    ColorOutput.warning(f"Failed to load cookies file: {e}")

            self.scan_results["cookie_analysis"] = {
                "status": "completed",
                "cookies_file": self.cookies_file,
            }

        except ImportError as e:
            ColorOutput.error(f"Failed to load cookie manager: {e}")
            self.scan_results["cookie_analysis"] = {"error": str(e)}
        except Exception as e:
            ColorOutput.error(f"Cookie analysis failed: {e}")
            self.scan_results["cookie_analysis"] = {"error": str(e)}
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _run_report(self):
        """
        Execute report generation module.

        Generates reports in configured formats from all collected
        scan results and findings.
        """
        try:
            from monster.report_generator import ReportGenerator

            generator = ReportGenerator(output_dir=self.output_dir)

            # Prepare scan results
            report_data = {
                "findings": self.findings,
                "recon": self.scan_results.get("recon", {}),
                "js_analysis": self.scan_results.get("js_analysis", {}),
                "param_mining": self.scan_results.get("param_mining", {}),
                "cookie_analysis": self.scan_results.get("cookie_analysis", {}),
                "target": self.target,
            }

            # Generate reports based on format preference
            if self.report_format == "all":
                generator.generate_full_report(report_data, self.scan_metadata)
            elif self.report_format == "json":
                generator.generate_json_report(report_data, self.scan_metadata)
            elif self.report_format == "md":
                generator.generate_markdown_report(report_data, self.scan_metadata)
            elif self.report_format == "html":
                generator.generate_html_report(report_data, self.scan_metadata)
            else:
                generator.generate_full_report(report_data, self.scan_metadata)

        except ImportError as e:
            ColorOutput.error(f"Failed to load report generator: {e}")
        except Exception as e:
            ColorOutput.error(f"Report generation failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()

    def _load_targets(self) -> List[str]:
        """
        Load targets from CLI arguments, scope file, or interactive input.

        Priority: --target > --scope file > interactive prompt

        Returns:
            List of target domains/URLs to scan.
        """
        targets = []

        # Single target from --target flag
        target_arg = getattr(self.args, "target", None)
        if target_arg:
            targets.append(target_arg)

        # Multiple targets from scope file
        scope_file = getattr(self.args, "scope", None) or self.config.get("scope", None)
        if scope_file:
            scope_targets = self._load_scope_file(scope_file)
            targets.extend(scope_targets)

        # Apply exclusion patterns
        if self.exclude_patterns and targets:
            targets = self._apply_exclusions(targets)

        return targets

    def _load_scope_file(self, filepath: str) -> List[str]:
        """
        Load targets from a scope file.

        Supports one target per line. Lines starting with # are
        treated as comments and ignored. Empty lines are skipped.

        Args:
            filepath: Path to the scope file.

        Returns:
            List of targets from the file.
        """
        targets = []
        filepath = os.path.expanduser(filepath)

        if not os.path.exists(filepath):
            ColorOutput.error(f"Scope file not found: {filepath}")
            return targets

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
            ColorOutput.info(f"Loaded {len(targets)} targets from {filepath}")
        except Exception as e:
            ColorOutput.error(f"Failed to read scope file: {e}")

        return targets

    def _load_config_file(self) -> Dict[str, Any]:
        """
        Load configuration from .monsterrc file.

        Searches for configuration in this order:
        1. Path specified by --config CLI flag
        2. .monsterrc in current working directory
        3. .monsterrc in user home directory

        Returns:
            Configuration dictionary (empty dict if no config found).
        """
        config = {}

        # Check CLI-specified config path
        config_path = getattr(self.args, "config", None)

        if config_path:
            if os.path.exists(config_path):
                return self._read_config(config_path)
            else:
                ColorOutput.warning(f"Config file not found: {config_path}")
                return config

        # Check current directory
        cwd_config = os.path.join(os.getcwd(), ".monsterrc")
        if os.path.exists(cwd_config):
            return self._read_config(cwd_config)

        # Check home directory
        home_config = os.path.join(Path.home(), ".monsterrc")
        if os.path.exists(home_config):
            return self._read_config(home_config)

        return config

    def _read_config(self, path: str) -> Dict[str, Any]:
        """
        Read and parse a JSON config file.

        Args:
            path: Path to the config file.

        Returns:
            Parsed configuration dictionary.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
            if self.verbose:
                ColorOutput.info(f"Loaded config from: {path}")
            return config
        except json.JSONDecodeError as e:
            ColorOutput.warning(f"Invalid JSON in config file {path}: {e}")
        except Exception as e:
            ColorOutput.warning(f"Failed to read config file: {e}")
        return {}

    def _setup_signal_handlers(self):
        """
        Set up signal handlers for graceful shutdown.

        Catches SIGINT (Ctrl+C) and SIGTERM to allow saving partial
        results before exiting.
        """
        def signal_handler(signum, frame):
            if self.shutdown_requested:
                # Second signal: force exit
                ColorOutput.error("Forced shutdown. Exiting immediately.")
                sys.exit(1)
            self.shutdown_requested = True
            ColorOutput.warning("\nShutdown requested. Finishing current operation...")

        signal.signal(signal.SIGINT, signal_handler)
        # SIGTERM may not be available on all platforms
        try:
            signal.signal(signal.SIGTERM, signal_handler)
        except (OSError, AttributeError):
            pass

    def _send_notification(self, finding: Any):
        """
        Send a webhook notification for a finding.

        POSTs finding data to the configured webhook URL for
        real-time alerting on critical discoveries.

        Args:
            finding: The Finding object to notify about.
        """
        if not self.webhook_url:
            return

        try:
            import urllib.request

            if hasattr(finding, "to_dict"):
                payload = finding.to_dict()
            elif isinstance(finding, dict):
                payload = finding
            else:
                payload = {"message": str(finding)}

            payload["timestamp"] = datetime.now().isoformat()
            payload["scanner"] = f"Monster v{VERSION}"

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=5) as resp:
                if self.verbose:
                    ColorOutput.info(f"Webhook notification sent: {resp.status}")
        except Exception as e:
            if self.verbose:
                ColorOutput.warning(f"Webhook notification failed: {e}")

    def _apply_exclusions(self, targets: List[str]) -> List[str]:
        """
        Filter targets based on exclusion patterns.

        Args:
            targets: List of targets to filter.

        Returns:
            Filtered list with excluded patterns removed.
        """
        filtered = []
        for target in targets:
            excluded = False
            for pattern in self.exclude_patterns:
                if pattern in target:
                    excluded = True
                    break
                # Support simple wildcard matching
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, target):
                        excluded = True
                        break
            if not excluded:
                filtered.append(target)

        excluded_count = len(targets) - len(filtered)
        if excluded_count > 0:
            ColorOutput.info(f"Excluded {excluded_count} targets based on patterns")

        return filtered

    def _print_phase_header(self, title: str):
        """
        Print a formatted phase header to terminal.

        Args:
            title: The phase name to display.
        """
        ColorOutput.section_header(title)

    def _print_scan_config(self):
        """Print the current scan configuration summary."""
        ColorOutput.info(f"Target(s): {', '.join(self.targets[:5])}")
        if len(self.targets) > 5:
            ColorOutput.info(f"  ... and {len(self.targets) - 5} more")
        ColorOutput.info(f"Modules: {', '.join(self.modules_to_run)}")
        ColorOutput.info(f"Output: {self.output_dir}")
        ColorOutput.info(f"Threads: {self.threads} | Delay: {self.delay}s | Timeout: {self.timeout}s")
        if self.dry_run:
            ColorOutput.warning("DRY RUN MODE - No network requests will be made")
        if self.proxy:
            ColorOutput.info(f"Proxy: {self.proxy}")
        if self.cookies_file:
            ColorOutput.info(f"Cookies: {self.cookies_file}")
        print()

    def _print_final_summary(self):
        """Print the final scan summary with statistics."""
        ColorOutput.section_header("SCAN COMPLETE")

        duration = self.scan_metadata.get("duration", "N/A")
        modules_run = self.scan_metadata.get("modules_run", [])

        ColorOutput.info(f"Duration: {duration}")
        ColorOutput.info(f"Modules executed: {', '.join(modules_run)}")
        ColorOutput.info(f"Total findings: {len(self.findings)}")

        if self.findings:
            # Count by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in self.findings:
                sev = (f.severity if hasattr(f, "severity") else f.get("severity", "INFO")).upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            ColorOutput.info(
                f"  Critical: {severity_counts['CRITICAL']} | "
                f"High: {severity_counts['HIGH']} | "
                f"Medium: {severity_counts['MEDIUM']} | "
                f"Low: {severity_counts['LOW']} | "
                f"Info: {severity_counts['INFO']}"
            )

        ColorOutput.info(f"Output directory: {self.output_dir}")

        if self.shutdown_requested:
            ColorOutput.warning("Scan was interrupted - partial results saved")

        print()

    def _get_scan_profile(self, name: str) -> Dict[str, Any]:
        """
        Get scan profile configuration by name.

        Args:
            name: Profile name (quick, normal, deep, aggressive).

        Returns:
            Profile configuration dictionary.
        """
        return SCAN_PROFILES.get(name, SCAN_PROFILES["normal"])


# =============================================================================
# INTERACTIVE MODE
# =============================================================================


def interactive_mode() -> argparse.Namespace:
    """
    Run Monster in interactive mode.

    Prompts the user for target and module selection when no
    arguments are provided. Provides a guided experience for
    new users.

    Returns:
        argparse.Namespace with user-selected options.
    """
    print(MONSTER_BANNER)
    print("  Welcome to Monster Interactive Mode!")
    print("  " + "=" * 50)
    print()

    # Get target
    target = ""
    while not target:
        try:
            target = input("  Enter target domain or URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            sys.exit(0)
        if not target:
            print("  Please enter a valid target.")

    # Module selection
    print()
    print("  Available modules:")
    print("    1. all     - Run all modules (recommended)")
    print("    2. recon   - Reconnaissance only")
    print("    3. js      - JavaScript analysis only")
    print("    4. vuln    - Vulnerability scanning only")
    print("    5. param   - Parameter mining only")
    print("    6. cookie  - Cookie analysis only")
    print("    7. report  - Generate reports from previous data")
    print()

    try:
        module_input = input("  Select module [1-7, default=1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Using defaults.")
        module_input = "1"

    module_map = {
        "1": "all", "2": "recon", "3": "js", "4": "vuln",
        "5": "param", "6": "cookie", "7": "report",
        "all": "all", "recon": "recon", "js": "js", "vuln": "vuln",
        "param": "param", "cookie": "cookie", "report": "report",
    }
    module = module_map.get(module_input, "all")

    # Profile selection
    print()
    print("  Scan profiles:")
    print("    1. quick      - Fast recon only (5 threads, 0.5s delay)")
    print("    2. normal     - Balanced scan (10 threads, 1s delay)")
    print("    3. deep       - Thorough scan (5 threads, 2s delay)")
    print("    4. aggressive - Fast full scan (20 threads, 0.2s delay)")
    print()

    try:
        profile_input = input("  Select profile [1-4, default=2]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Using defaults.")
        profile_input = "2"

    profile_map = {
        "1": "quick", "2": "normal", "3": "deep", "4": "aggressive",
        "quick": "quick", "normal": "normal", "deep": "deep",
        "aggressive": "aggressive",
    }
    profile = profile_map.get(profile_input, "normal")

    # Output directory
    print()
    try:
        output = input("  Output directory [./monster_output]: ").strip()
    except (EOFError, KeyboardInterrupt):
        output = ""
    if not output:
        output = "./monster_output"

    # Dry run option
    print()
    try:
        dry_run_input = input("  Dry run (no network calls)? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        dry_run_input = "n"
    dry_run = dry_run_input in ("y", "yes")

    print()
    print("  " + "=" * 50)
    print(f"  Starting scan: {target} | Module: {module} | Profile: {profile}")
    print("  " + "=" * 50)
    print()

    # Build namespace
    args = argparse.Namespace(
        target=target,
        scope=None,
        apk=None,
        module=module,
        output=output,
        delay=None,
        threads=None,
        timeout=None,
        dry_run=dry_run,
        verbose=False,
        no_color=False,
        resume=False,
        cookies=None,
        cookie_jar=None,
        proxy=None,
        format="all",
        exclude=None,
        profile=profile,
        webhook=None,
        config=None,
        interactive=True,
        version=False,
    )

    return args


# =============================================================================
# ARGPARSE AND MAIN FUNCTION
# =============================================================================


def create_parser() -> argparse.ArgumentParser:
    """
    Create the argument parser with all CLI options.

    Returns:
        Configured argparse.ArgumentParser instance.
    """
    epilog = """
Examples:
  # Quick scan of a single target
  python -m monster --target example.com --profile quick

  # Full assessment with all modules
  python -m monster --target https://example.com --module all --profile deep

  # Scan multiple targets from a file
  python -m monster --scope targets.txt --output ./results

  # Dry run (no network calls) to test configuration
  python -m monster --target example.com --dry-run

  # Scan with proxy and cookies
  python -m monster --target example.com --proxy http://127.0.0.1:8080 --cookies cookies.txt

  # Generate only HTML report
  python -m monster --target example.com --format html

  # Aggressive scan with webhook alerts
  python -m monster --target example.com --profile aggressive --webhook https://hooks.example.com/alert

  # Use config file for defaults
  python -m monster --target example.com --config ~/.monsterrc

  # Interactive mode
  python -m monster --interactive

Config file (.monsterrc) example:
  {
    "module": "all",
    "profile": "normal",
    "output": "./monster_output",
    "delay": 1.0,
    "threads": 10,
    "timeout": 15,
    "verbose": false,
    "format": "all"
  }
"""

    parser = argparse.ArgumentParser(
        prog="monster",
        description=(
            "Monster v{} - Bug Bounty Reconnaissance & Vulnerability Assessment Toolkit. "
            "A comprehensive passive/semi-passive security assessment tool for "
            "bug bounty hunters and security researchers."
        ).format(VERSION),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Single target domain or URL (e.g., example.com or https://example.com)",
    )
    target_group.add_argument(
        "--scope", "-s",
        metavar="FILE",
        help="File containing list of targets (one per line)",
    )
    target_group.add_argument(
        "--apk",
        metavar="FILE",
        help="APK file path for mobile app analysis",
    )

    # Module options
    module_group = parser.add_argument_group("Module Options")
    module_group.add_argument(
        "--module", "-m",
        metavar="MODULE",
        default="all",
        help="Modules to run: all, recon, js, vuln, param, cookie, report (default: all)",
    )
    module_group.add_argument(
        "--profile",
        metavar="PROFILE",
        choices=["quick", "normal", "deep", "aggressive"],
        help="Scan profile: quick, normal, deep, aggressive (default: normal)",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Output directory for results (default: ./monster_output)",
    )
    output_group.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["json", "md", "html", "all"],
        default="all",
        help="Report format: json, md, html, all (default: all)",
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output with detailed progress",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output",
    )

    # Performance options
    perf_group = parser.add_argument_group("Performance Options")
    perf_group.add_argument(
        "--delay",
        metavar="SECONDS",
        type=float,
        help=f"Rate limit delay between requests in seconds (default: {RATE_LIMIT_DELAY})",
    )
    perf_group.add_argument(
        "--threads",
        metavar="N",
        type=int,
        help=f"Maximum concurrent threads (default: {MAX_THREADS})",
    )
    perf_group.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=int,
        help=f"HTTP request timeout in seconds (default: {TIMEOUT})",
    )

    # Network options
    net_group = parser.add_argument_group("Network Options")
    net_group.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/SOCKS proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)",
    )
    net_group.add_argument(
        "--cookies",
        metavar="FILE",
        help="Load cookies from file (Netscape or JSON format)",
    )
    net_group.add_argument(
        "--cookie-jar",
        metavar="FILE",
        help="Save and load cookies between scan runs",
    )

    # Scan behavior options
    scan_group = parser.add_argument_group("Scan Behavior")
    scan_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate scan without making network requests",
    )
    scan_group.add_argument(
        "--resume",
        action="store_true",
        help="Skip already-scanned targets from previous runs",
    )
    scan_group.add_argument(
        "--exclude",
        metavar="PATTERNS",
        help="Comma-separated patterns to exclude from scanning",
    )

    # Notification options
    notify_group = parser.add_argument_group("Notifications")
    notify_group.add_argument(
        "--webhook",
        metavar="URL",
        help="Webhook URL for real-time finding notifications (POST)",
    )

    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        metavar="FILE",
        help="Path to config file (default: .monsterrc in cwd or home)",
    )
    config_group.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode with guided prompts",
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"Monster v{VERSION}",
    )

    return parser


def main() -> int:
    """
    Main entry point for the Monster toolkit.

    Parses command-line arguments, initializes the scanner,
    and executes the scanning workflow.

    Returns:
        Exit code (0 for success, 1 for errors, 130 for interrupt).
    """
    parser = create_parser()
    args = parser.parse_args()

    # Handle interactive mode
    if getattr(args, "interactive", False) or (
        not getattr(args, "target", None)
        and not getattr(args, "scope", None)
        and not getattr(args, "apk", None)
        and sys.stdin.isatty()
        and len(sys.argv) <= 1
    ):
        try:
            args = interactive_mode()
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting.")
            return 0

    # Validate that we have at least one target source
    if (
        not getattr(args, "target", None)
        and not getattr(args, "scope", None)
        and not getattr(args, "apk", None)
    ):
        parser.print_help()
        return 1

    # Run the scanner
    try:
        scanner = Monster(args)
        return scanner.run()
    except KeyboardInterrupt:
        ColorOutput.warning("\nInterrupted by user.")
        return 130
    except Exception as e:
        ColorOutput.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
