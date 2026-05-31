"""
Super Monster v2.0 - Main CLI Orchestrator

Wires together: DomainClassifier -> SmartScanner -> Verifier -> SmartCorrelator -> Reporter
"""

import argparse
import sys
import time
import os
import json
from pathlib import Path

from super_monster import VERSION
from super_monster.config import (
    Colors,
    BANNER,
    MAX_THREADS,
    REQUEST_TIMEOUT,
    OUTPUT_DIR,
    SCAN_TESTS_PER_TYPE,
    DOMAIN_TYPES,
)
from super_monster.domain_classifier import DomainClassifier
from super_monster.smart_scanner import SmartScanner, Finding
from super_monster.verifier import Verifier
from super_monster.correlator import SmartCorrelator
from super_monster.reporter import Reporter


# =============================================================================
# TEST DESCRIPTIONS (for --dry-run display)
# =============================================================================

TEST_DESCRIPTIONS = {
    "cors": "Check CORS misconfiguration",
    "csp": "Check Content-Security-Policy",
    "hsts": "Check Strict-Transport-Security",
    "cookie_security": "Check session cookie flags",
    "clickjacking": "Check X-Frame-Options",
    "api_exposure": "Check exposed API documentation",
    "graphql": "Check GraphQL introspection",
    "server_disclosure": "Check server version headers",
    "open_redirect": "Check open redirect parameters",
    "subdomain_takeover": "Check CNAME takeover",
    "default_creds_hints": "Check default credential hints",
    "session_fixation": "Check session fixation",
}


# =============================================================================
# SCAN SUBCOMMAND
# =============================================================================


def cmd_scan(args) -> int:
    """Execute the scan subcommand."""
    c = Colors

    # Print banner
    print(BANNER)

    # Load targets
    targets = _load_targets(args)
    if not targets:
        print(f"{c.ERROR}[!] No targets specified. Use --target or --scope.{c.RESET}")
        return 1

    print(f"{c.HEADER}[*] Targets loaded: {len(targets)} domain(s){c.RESET}")

    if args.verbose:
        for t in targets:
            print(f"    {c.DIM}{t}{c.RESET}")
        print()

    # Classify domains
    classifier = DomainClassifier()
    classified = classifier.classify_domains(targets)
    summary = classifier.summarize_classification(classified)

    # Print classification summary
    print(f"{c.HEADER}[*] Domain Classification:{c.RESET}")
    for dtype, domains in sorted(summary.items()):
        color = c.domain_color(dtype)
        print(f"  {color}{dtype}{c.RESET} ({len(domains)}): {', '.join(domains[:5])}", end="")
        if len(domains) > 5:
            print(f" ... +{len(domains) - 5} more", end="")
        print()
    print()

    # Dry run mode
    if args.dry_run:
        return _handle_dry_run(classified, classifier, targets, c)

    # Start timing
    start_time = time.time()

    # Scan
    print(f"{c.PROGRESS}[*] Starting adaptive scan...{c.RESET}")
    print(f"    Threads: {args.threads} | Timeout: {args.timeout}s")
    print()

    scanner = SmartScanner()
    raw_findings = scanner.scan_all_domains(classified, dry_run=False)

    raw_count = len(raw_findings)
    print(f"{c.SUBHEADER}[*] Raw findings: {raw_count}{c.RESET}")

    # Verify
    print(f"{c.PROGRESS}[*] Verifying findings (eliminating false positives)...{c.RESET}")
    verifier = Verifier()
    verified_findings = verifier.verify_all(raw_findings)

    false_positives_filtered = raw_count - len(verified_findings)
    print(
        f"{c.SUBHEADER}[*] Verified: {len(verified_findings)} | "
        f"False positives filtered: {false_positives_filtered}{c.RESET}"
    )
    print()

    # Correlate
    print(f"{c.PROGRESS}[*] Correlating findings into attack chains...{c.RESET}")
    correlator = SmartCorrelator()
    chains = correlator.correlate(verified_findings)
    print(f"{c.SUBHEADER}[*] Attack chains found: {len(chains)}{c.RESET}")
    print()

    # Build scan stats
    duration = time.time() - start_time
    scan_stats = {
        "duration_seconds": duration,
        "domains_scanned": len(targets),
        "total_raw_findings": raw_count,
        "verified_findings": len(verified_findings),
        "false_positives_filtered": false_positives_filtered,
        "chains_found": len(chains),
        "threads_used": args.threads,
        "timeout_seconds": args.timeout,
        "domains_by_type": {dtype: len(doms) for dtype, doms in summary.items()},
    }

    # Ensure output directory exists
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    # Generate report
    print(f"{c.PROGRESS}[*] Generating reports...{c.RESET}")
    reporter = Reporter()
    report_result = reporter.generate_report(
        verified_findings, chains, scan_stats, output_dir
    )

    # Final summary
    print(f"\n{c.SUCCESS}[+] Scan complete in {_format_duration(duration)}{c.RESET}")
    if report_result.get("json_report"):
        print(f"    JSON: {report_result['json_report']}")
    if report_result.get("markdown_report"):
        print(f"    Markdown: {report_result['markdown_report']}")
    print()

    return 0


def _handle_dry_run(classified, classifier, targets, c) -> int:
    """Handle --dry-run mode: show classification and planned tests without scanning."""
    print(f"{c.WARNING}[*] Mode: DRY RUN (no network requests){c.RESET}")
    print()

    print(f"{c.HEADER}[*] Planned Tests:{c.RESET}")
    total_tests = 0

    for domain, dtype in classified.items():
        tests = classifier.get_tests_for_type(dtype)
        total_tests += len(tests)
        color = c.domain_color(dtype)
        print(f"  {color}{domain}{c.RESET} ({dtype}):")
        for test_name in tests:
            desc = TEST_DESCRIPTIONS.get(test_name, test_name)
            print(f"    - {test_name}: {desc}")
        print()

    # Estimate scan time
    domain_count = len(targets)
    if domain_count <= 5:
        estimate = "~1 minute"
    elif domain_count <= 20:
        estimate = "~5-10 minutes"
    elif domain_count <= 50:
        estimate = "~30-60 minutes"
    else:
        estimate = "~1-2 hours"

    print(
        f"{c.DIM}[*] Total tests planned: {total_tests} "
        f"across {domain_count} domain(s){c.RESET}"
    )
    print(
        f"{c.DIM}[*] Estimated scan time: {estimate} "
        f"for {domain_count} domain(s){c.RESET}"
    )
    print(f"{c.DIM}[*] Dry run complete. Use without --dry-run to execute scan.{c.RESET}")
    print()

    return 0


# =============================================================================
# ANALYZE SUBCOMMAND
# =============================================================================


def cmd_analyze(args) -> int:
    """Execute the analyze subcommand: re-analyze existing Monster output."""
    c = Colors

    # Print banner
    print(BANNER)

    input_path = args.input
    output_dir = args.output

    print(f"{c.HEADER}[*] Analyze mode: Re-processing Monster output{c.RESET}")
    print(f"    Input: {input_path}")
    print(f"    Output: {output_dir}")
    print()

    # Load Monster findings
    findings = _load_monster_findings(input_path)
    if not findings:
        print(f"{c.ERROR}[!] No findings loaded from {input_path}{c.RESET}")
        return 1

    print(f"{c.SUBHEADER}[*] Loaded {len(findings)} finding(s) from Monster output{c.RESET}")
    print()

    start_time = time.time()

    # Verify through v2 pipeline
    print(f"{c.PROGRESS}[*] Running v2 verification pipeline...{c.RESET}")
    verifier = Verifier()
    verified_findings = verifier.verify_all(findings)

    false_positives_filtered = len(findings) - len(verified_findings)
    print(
        f"{c.SUBHEADER}[*] Verified: {len(verified_findings)} | "
        f"False positives filtered: {false_positives_filtered}{c.RESET}"
    )
    print()

    # Correlate
    print(f"{c.PROGRESS}[*] Correlating findings...{c.RESET}")
    correlator = SmartCorrelator()
    chains = correlator.correlate(verified_findings)
    print(f"{c.SUBHEADER}[*] Attack chains found: {len(chains)}{c.RESET}")
    print()

    # Build stats
    duration = time.time() - start_time
    scan_stats = {
        "duration_seconds": duration,
        "domains_scanned": len(set(f.domain for f in findings)),
        "total_raw_findings": len(findings),
        "verified_findings": len(verified_findings),
        "false_positives_filtered": false_positives_filtered,
        "chains_found": len(chains),
        "mode": "analyze",
        "input_path": input_path,
    }

    # Ensure output directory
    os.makedirs(output_dir, exist_ok=True)

    # Generate report
    print(f"{c.PROGRESS}[*] Generating reports...{c.RESET}")
    reporter = Reporter()
    report_result = reporter.generate_report(
        verified_findings, chains, scan_stats, output_dir
    )

    # Final summary
    print(f"\n{c.SUCCESS}[+] Analysis complete in {_format_duration(duration)}{c.RESET}")
    if report_result.get("json_report"):
        print(f"    JSON: {report_result['json_report']}")
    if report_result.get("markdown_report"):
        print(f"    Markdown: {report_result['markdown_report']}")
    print()

    return 0


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _load_targets(args) -> list:
    """
    Load target domains from --target (single) or --scope (file).

    Args:
        args: Parsed argparse namespace with target/scope attributes.

    Returns:
        List of domain strings to scan.
    """
    targets = []

    if args.target:
        # Single target
        domain = args.target.strip()
        # Strip protocol if provided
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        # Strip trailing path
        domain = domain.split("/")[0]
        targets.append(domain)

    elif args.scope:
        # File with multiple targets
        scope_path = Path(args.scope)
        if not scope_path.exists():
            print(f"{Colors.ERROR}[!] Scope file not found: {args.scope}{Colors.RESET}")
            return []

        with open(scope_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip protocol if provided
                if "://" in line:
                    line = line.split("://", 1)[1]
                # Strip trailing path
                line = line.split("/")[0]
                if line:
                    targets.append(line)

    return targets


def _load_monster_findings(input_path: str) -> list:
    """
    Load findings from Monster JSON report file(s).

    Supports:
    - Single JSON file path
    - Directory containing JSON files

    Args:
        input_path: Path to a JSON file or directory of JSON files.

    Returns:
        List of Finding objects converted from Monster format.
    """
    findings = []
    path = Path(input_path)

    if path.is_file() and path.suffix == ".json":
        findings.extend(_parse_monster_json(path))
    elif path.is_dir():
        for json_file in sorted(path.glob("*.json")):
            findings.extend(_parse_monster_json(json_file))
    else:
        print(f"{Colors.WARNING}[!] Input path is not a JSON file or directory: {input_path}{Colors.RESET}")

    return findings


def _parse_monster_json(filepath: Path) -> list:
    """
    Parse a single Monster JSON report into Finding objects.

    Handles both Monster v1 and v2 report formats.

    Args:
        filepath: Path to the JSON report file.

    Returns:
        List of Finding objects.
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"{Colors.DIM}[!] Could not parse {filepath}: {e}{Colors.RESET}")
        return findings

    # Handle different Monster JSON formats
    # Format 1: {"findings": [...]}
    if isinstance(data, dict) and "findings" in data:
        raw_findings = data["findings"]
    # Format 2: {"vulnerabilities": [...]}
    elif isinstance(data, dict) and "vulnerabilities" in data:
        raw_findings = data["vulnerabilities"]
    # Format 3: {"report_these": [...], "investigate_further": [...], ...}
    elif isinstance(data, dict) and "report_these" in data:
        raw_findings = []
        for key in ("report_these", "investigate_further", "informational"):
            raw_findings.extend(data.get(key, []))
    # Format 4: list of findings directly
    elif isinstance(data, list):
        raw_findings = data
    else:
        # Try to extract any list of dicts that looks like findings
        raw_findings = []
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                if any(k in value[0] for k in ("severity", "finding_type", "title", "vulnerability")):
                    raw_findings.extend(value)

    # Convert raw dicts to Finding objects
    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        finding = Finding(
            finding_type=item.get("finding_type", item.get("type", item.get("vulnerability_type", ""))),
            domain=item.get("domain", item.get("target", item.get("host", ""))),
            url=item.get("url", item.get("endpoint", "")),
            severity=item.get("severity", "medium"),
            title=item.get("title", item.get("name", "")),
            description=item.get("description", item.get("details", "")),
            evidence=item.get("evidence", item.get("proof", "")),
            impact=item.get("impact", ""),
            reproduction_steps=item.get("reproduction_steps", item.get("steps", [])),
            verified=item.get("verified", False),
            confidence=item.get("confidence", 0.5),
            raw_response_code=item.get("raw_response_code", item.get("status_code", 0)),
            raw_response_headers=item.get("raw_response_headers", {}),
            timestamp=item.get("timestamp", ""),
        )

        # Skip empty findings
        if finding.domain or finding.url:
            findings.append(finding)

    return findings


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================


def main():
    """Main entry point for super_monster CLI."""
    parser = argparse.ArgumentParser(
        prog="super_monster",
        description="Super Monster v2.0 - Elite Adaptive Bug Bounty Scanner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Super Monster v{VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan targets adaptively")
    scan_parser.add_argument("--target", help="Single domain to scan")
    scan_parser.add_argument("--scope", help="File with domains (one per line)")
    scan_parser.add_argument(
        "-o", "--output", default=OUTPUT_DIR, help="Output directory"
    )
    scan_parser.add_argument(
        "--dry-run", action="store_true", help="Show plan without scanning"
    )
    scan_parser.add_argument(
        "--threads", type=int, default=MAX_THREADS, help="Concurrent threads"
    )
    scan_parser.add_argument(
        "--timeout", type=int, default=REQUEST_TIMEOUT, help="Request timeout (seconds)"
    )
    scan_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    # analyze subcommand
    analyze_parser = subparsers.add_parser(
        "analyze", help="Re-analyze existing Monster output"
    )
    analyze_parser.add_argument(
        "--input", required=True, help="Path to Monster JSON report(s)"
    )
    analyze_parser.add_argument(
        "-o", "--output", default=OUTPUT_DIR, help="Output directory"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "analyze":
        return cmd_analyze(args)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
