"""
Super Monster v1.0.0 - Master CLI Controller

Full command-line interface with argparse subcommands for:
- correlate: Run cross-finding correlation engine
- retest: Check findings for retest scheduling
- prioritize: Score and rank findings by priority
- plan: Generate attack plans from findings
- diff: Compare two reports for changes
- full: Run complete pipeline (correlate -> prioritize -> plan -> report)

Features:
- Professional colored banner display
- Pipeline orchestration with progress indicators
- Timing and performance metrics
- Comprehensive error handling
- Multiple output formats (json, markdown, html, csv)
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _FakeColor:
        def __getattr__(self, name):
            return ""
    Fore = _FakeColor()
    Back = _FakeColor()
    Style = _FakeColor()

from super_monster import VERSION
from super_monster.config import (
    Colors, TOOL_NAME, TOOL_BANNER, DEFAULT_DB_PATH, DEFAULT_OUTPUT_DIR,
    DEFAULT_REPORTS_DIR, SCORING_WEIGHTS, DOMAIN_TIERS, SEVERITY_LEVELS,
    CORRELATION_RULES, RETEST_INTERVALS, NOTIFICATION_THRESHOLDS,
    BOUNTY_ESTIMATES, calculate_priority_score, get_severity_from_cvss,
    get_domain_tier, get_bounty_estimate, get_notification_level,
)
from super_monster.finding_db import FindingDB, Finding


# =============================================================================
# BANNER AND UI HELPERS
# =============================================================================

BANNER_ART = f"""
{Fore.MAGENTA}{Style.BRIGHT}
  ____                         __  __                 _
 / ___| _   _ _ __   ___ _ __|  \/  | ___  _ __  ___| |_ ___ _ __
 \___ \| | | | '_ \ / _ \ '__| |\/| |/ _ \| '_ \/ __| __/ _ \ '__|
  ___) | |_| | |_) |  __/ |  | |  | | (_) | | | \__ \ ||  __/ |
 |____/ \__,_| .__/ \___|_|  |_|  |_|\___/|_| |_|___/\__\___|_|
             |_|
{Style.RESET_ALL}
{Fore.CYAN}  Bug Bounty Intelligence Engine v{VERSION}{Style.RESET_ALL}
{Fore.WHITE}{Style.DIM}  Multi-target correlation | Auto-retest | AI prioritization{Style.RESET_ALL}
{Fore.WHITE}{Style.DIM}  Attack planning | Diff analysis | Elite reporting{Style.RESET_ALL}
"""


def print_banner():
    """Display the Super Monster banner."""
    print(BANNER_ART)


def print_header(text: str):
    """Print a section header."""
    print(f"\n{Colors.HEADER}{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}{Colors.RESET}")


def print_subheader(text: str):
    """Print a subsection header."""
    print(f"\n{Colors.SUBHEADER}--- {text} ---{Colors.RESET}")


def print_success(text: str):
    """Print a success message."""
    print(f"{Colors.SUCCESS}[+]{Colors.RESET} {text}")


def print_warning(text: str):
    """Print a warning message."""
    print(f"{Colors.WARNING}[!]{Colors.RESET} {text}")


def print_error(text: str):
    """Print an error message."""
    print(f"{Colors.ERROR}[X]{Colors.RESET} {text}")


def print_info(text: str):
    """Print an info message."""
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {text}")


def print_progress(current: int, total: int, prefix: str = ""):
    """Display a progress bar."""
    if total == 0:
        return
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = "=" * filled + "-" * (bar_length - filled)
    percent = round(100 * current / total, 1)
    prefix_str = f"{prefix}: " if prefix else ""
    sys.stdout.write(f"\r{Colors.PROGRESS_TEXT}{prefix_str}[{Colors.PROGRESS_BAR}{bar}{Colors.RESET}] {percent}%")
    sys.stdout.flush()
    if current >= total:
        print()


def print_timing(start_time: float, label: str = ""):
    """Print elapsed time since start."""
    elapsed = time.time() - start_time
    label_str = f" ({label})" if label else ""
    if elapsed < 60:
        print(f"{Colors.TIMER}  Time{label_str}: {elapsed:.2f}s{Colors.RESET}")
    else:
        minutes = int(elapsed // 60)
        seconds = elapsed % 60
        print(f"{Colors.TIMER}  Time{label_str}: {minutes}m {seconds:.1f}s{Colors.RESET}")


def format_severity(severity: str) -> str:
    """Format severity with color."""
    color = Colors.severity_color(severity)
    return f"{color}{severity}{Colors.RESET}"


def format_count(count: int, label: str) -> str:
    """Format a count with label."""
    return f"{Colors.COUNT}{count}{Colors.RESET} {label}"



# =============================================================================
# SUBCOMMAND IMPLEMENTATIONS
# =============================================================================

def cmd_correlate(args) -> int:
    """Execute the correlate subcommand."""
    start_time = time.time()
    print_header("CORRELATION ENGINE")

    # Load or create database
    db = _load_database(args)
    if db is None:
        return 1

    # Import findings if input specified
    if args.input:
        import_stats = _import_findings(db, args.input)
        if import_stats.get("error"):
            print_error(import_stats["error"])
            return 1

    if db.count() == 0:
        print_warning("No findings in database. Import some reports first.")
        return 0

    print_info(f"Analyzing {db.count()} findings for correlations...")

    # Run correlation analysis
    chains_found = 0
    total_rules = len(CORRELATION_RULES)

    for idx, (rule_name, rule_config) in enumerate(CORRELATION_RULES.items()):
        print_progress(idx + 1, total_rules, "Correlating")

        required_types = rule_config["required_types"]
        optional_types = rule_config.get("optional_types", [])
        min_findings = rule_config.get("min_findings", 2)
        confidence_threshold = rule_config.get("confidence_threshold", 0.7)

        # Find findings matching required types
        matching_required = []
        for req_type in required_types:
            matching_required.extend(db.by_type(req_type))

        if len(matching_required) < min_findings:
            continue

        # Find findings matching optional types
        matching_optional = []
        for opt_type in optional_types:
            matching_optional.extend(db.by_type(opt_type))

        # Group by domain for same-domain correlation
        domain_groups: Dict[str, List[Finding]] = {}
        for f in matching_required + matching_optional:
            domain = f.domain or "unknown"
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(f)

        # Create chains for domains with multiple related findings
        for domain, domain_findings in domain_groups.items():
            required_in_domain = [f for f in domain_findings if f.finding_type in required_types]
            if len(required_in_domain) < 1:
                continue

            optional_in_domain = [f for f in domain_findings if f.finding_type in optional_types]

            # Calculate confidence
            confidence = _calculate_correlation_confidence(
                required_in_domain, optional_in_domain, rule_config
            )

            if confidence >= confidence_threshold:
                chain_findings = required_in_domain + optional_in_domain[:3]
                child_ids = [f.id for f in chain_findings]

                if len(child_ids) >= 2:
                    composite_id = db.create_composite_finding(
                        child_ids=child_ids,
                        title=f"[CHAIN] {rule_config['description']} on {domain}",
                        description=rule_config.get("chain_description", ""),
                        severity=rule_config.get("severity_boost", "HIGH"),
                        chain_description=rule_config.get("chain_description", ""),
                    )
                    if composite_id:
                        chains_found += 1

    print()
    print_subheader("Correlation Results")
    print_success(f"Found {chains_found} correlation chains")
    print_info(f"Total findings in database: {db.count()}")

    # Display chains
    chains = db.get_correlation_chains()
    if chains:
        print_subheader("Detected Chains")
        for chain in chains[:10]:
            sev_color = Colors.severity_color(chain["max_severity"])
            print(f"  {sev_color}{chain['max_severity']}{Colors.RESET} | "
                  f"{chain['finding_count']} findings | "
                  f"Domains: {', '.join(chain['domains'][:3])}")
            for finding_info in chain["findings"][:3]:
                print(f"    -> {finding_info['title'][:60]}")

    # Save database
    if db.db_path:
        db.save()
        print_success(f"Database saved to: {db.db_path}")

    print_timing(start_time, "correlation")
    return 0


def cmd_retest(args) -> int:
    """Execute the retest subcommand."""
    start_time = time.time()
    print_header("RETEST SCHEDULER")

    db = _load_database(args)
    if db is None:
        return 1

    # Import findings if input specified
    if hasattr(args, 'input') and args.input:
        import_stats = _import_findings(db, args.input)
        if import_stats.get("error"):
            print_error(import_stats["error"])
            return 1

    if db.count() == 0:
        print_warning("No findings in database.")
        return 0

    print_info(f"Checking {db.count()} findings for retest scheduling...")

    # Get findings needing retest
    needs_retest = db.needs_retest()

    if not needs_retest:
        print_success("All findings are up to date. No retests needed.")
        print_timing(start_time, "retest check")
        return 0

    print_subheader(f"Findings Due for Retest ({len(needs_retest)})")

    # Group by severity
    by_severity: Dict[str, List[Finding]] = {}
    for finding in needs_retest:
        sev = finding.severity or "INFO"
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(finding)

    for severity in SEVERITY_LEVELS:
        findings_in_sev = by_severity.get(severity, [])
        if not findings_in_sev:
            continue

        sev_color = Colors.severity_color(severity)
        print(f"\n  {sev_color}{severity}{Colors.RESET} ({len(findings_in_sev)} findings):")

        for finding in findings_in_sev[:5]:
            age_str = f"{finding.age_hours():.0f}h ago"
            retest_str = f"retested {finding.retest_count}x" if finding.retest_count > 0 else "never retested"
            print(f"    [{finding.id}] {finding.title[:50]} ({age_str}, {retest_str})")
            print(f"      URL: {finding.url[:70]}")

        if len(findings_in_sev) > 5:
            print(f"    ... and {len(findings_in_sev) - 5} more")

    # Generate retest schedule
    print_subheader("Retest Schedule")
    for severity in SEVERITY_LEVELS:
        count = len(by_severity.get(severity, []))
        if count > 0:
            interval = RETEST_INTERVALS[severity]
            print(f"  {Colors.severity_color(severity)}{severity}{Colors.RESET}: "
                  f"{count} findings, interval: {interval['initial_hours']}h initial, "
                  f"{interval['followup_hours']}h follow-up")

    # Export retest list if output specified
    if hasattr(args, 'output') and args.output:
        retest_data = {
            "retest_schedule": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_due": len(needs_retest),
                "findings": [f.to_dict() for f in needs_retest],
            }
        }
        os.makedirs(args.output, exist_ok=True)
        output_file = os.path.join(args.output, "retest_schedule.json")
        with open(output_file, "w") as f:
            json.dump(retest_data, f, indent=2, default=str)
        print_success(f"Retest schedule saved to: {output_file}")

    if db.db_path:
        db.save()

    print_timing(start_time, "retest")
    return 0


def cmd_prioritize(args) -> int:
    """Execute the prioritize subcommand."""
    start_time = time.time()
    print_header("PRIORITY SCORING ENGINE")

    db = _load_database(args)
    if db is None:
        return 1

    if db.count() == 0:
        print_warning("No findings in database.")
        return 0

    print_info(f"Scoring {db.count()} findings...")
    print_info(f"Weights: CVSS={SCORING_WEIGHTS['cvss_base']}, "
               f"Exploit={SCORING_WEIGHTS['exploitability']}, "
               f"Impact={SCORING_WEIGHTS['business_impact']}, "
               f"Bounty={SCORING_WEIGHTS['bug_bounty_value']}, "
               f"Correlation={SCORING_WEIGHTS['correlation_bonus']}")

    # Score all findings
    all_findings = db.get_all()
    for idx, finding in enumerate(all_findings):
        print_progress(idx + 1, len(all_findings), "Scoring")

        # Calculate priority score
        finding_dict = finding.to_dict()
        priority = calculate_priority_score(finding_dict)
        finding.priority_score = priority

        # Calculate bounty estimate
        bounty = get_bounty_estimate(finding.severity)
        finding.bounty_estimate = bounty["median"]

        # Calculate domain tier impact
        if finding.domain:
            tier, multiplier = get_domain_tier(finding.domain)
            finding.priority_score = round(min(finding.priority_score * (1 + (multiplier - 1) * 0.3), 10.0), 2)

    print()

    # Display top prioritized findings
    top_findings = sorted(all_findings, key=lambda f: f.priority_score, reverse=True)

    limit = getattr(args, 'limit', 20) or 20
    print_subheader(f"Top {min(limit, len(top_findings))} Priority Findings")

    for i, finding in enumerate(top_findings[:limit]):
        sev_color = Colors.severity_color(finding.severity)
        score_color = Colors.score_color(finding.priority_score)
        bounty_str = f"${finding.bounty_estimate:,.0f}" if finding.bounty_estimate else "$?"

        print(f"  {Colors.COUNT}#{i+1}{Colors.RESET} "
              f"{score_color}[{finding.priority_score:.1f}]{Colors.RESET} "
              f"{sev_color}{finding.severity:<8}{Colors.RESET} "
              f"{finding.title[:45]}")
        print(f"       CVSS: {finding.cvss_score} | Type: {finding.finding_type} | "
              f"Est. Bounty: {bounty_str} | {finding.domain}")

    # Summary statistics
    print_subheader("Priority Distribution")
    high_priority = [f for f in all_findings if f.priority_score >= 7.0]
    med_priority = [f for f in all_findings if 4.0 <= f.priority_score < 7.0]
    low_priority = [f for f in all_findings if f.priority_score < 4.0]

    print(f"  {Colors.SCORE_HIGH}High Priority (7+):{Colors.RESET}   {len(high_priority)} findings")
    print(f"  {Colors.SCORE_MEDIUM}Medium Priority (4-7):{Colors.RESET} {len(med_priority)} findings")
    print(f"  {Colors.SCORE_LOW}Low Priority (<4):{Colors.RESET}    {len(low_priority)} findings")

    total_bounty = sum(f.bounty_estimate for f in all_findings)
    print(f"\n  {Colors.HIGHLIGHT}Total Estimated Bounty: ${total_bounty:,.0f}{Colors.RESET}")

    # Save results
    if hasattr(args, 'output') and args.output:
        os.makedirs(args.output, exist_ok=True)
        output_file = os.path.join(args.output, "prioritized_findings.json")
        priority_data = {
            "priority_report": {
                "generated_at": datetime.utcnow().isoformat(),
                "scoring_weights": SCORING_WEIGHTS,
                "total_findings": len(all_findings),
                "total_estimated_bounty": total_bounty,
            },
            "findings": [f.to_dict() for f in top_findings],
        }
        with open(output_file, "w") as f:
            json.dump(priority_data, f, indent=2, default=str)
        print_success(f"Priority report saved to: {output_file}")

    if db.db_path:
        db.save()
        print_success(f"Database updated: {db.db_path}")

    print_timing(start_time, "prioritization")
    return 0



def cmd_plan(args) -> int:
    """Execute the plan (attack planning) subcommand."""
    start_time = time.time()
    print_header("ATTACK PLAN GENERATOR")

    db = _load_database(args)
    if db is None:
        return 1

    # Import findings if input specified
    if hasattr(args, 'input') and args.input:
        import_stats = _import_findings(db, args.input)
        if import_stats.get("error"):
            print_error(import_stats["error"])
            return 1

    if db.count() == 0:
        print_warning("No findings in database. Import reports first.")
        return 0

    print_info(f"Generating attack plans from {db.count()} findings...")

    # Get high-priority findings for planning
    all_findings = sorted(db.get_all(), key=lambda f: f.priority_score, reverse=True)
    plan_candidates = [f for f in all_findings if f.priority_score >= 3.0 or f.severity in ("CRITICAL", "HIGH")]

    if not plan_candidates:
        print_warning("No findings with sufficient priority for attack planning.")
        return 0

    # Generate attack plans grouped by domain
    domain_plans: Dict[str, Dict[str, Any]] = {}
    for finding in plan_candidates:
        domain = finding.domain or "unknown"
        if domain not in domain_plans:
            domain_plans[domain] = {
                "domain": domain,
                "tier": get_domain_tier(domain),
                "findings": [],
                "attack_vectors": [],
                "exploitation_steps": [],
                "estimated_impact": "",
                "total_bounty_estimate": 0.0,
            }
        domain_plans[domain]["findings"].append(finding)
        domain_plans[domain]["total_bounty_estimate"] += finding.bounty_estimate

    # Build exploitation plans per domain
    plans_generated = 0
    attack_plans = []

    for domain, plan_data in domain_plans.items():
        findings = plan_data["findings"]
        tier_name, tier_multiplier = plan_data["tier"]

        # Generate attack vectors based on finding types
        attack_vectors = _generate_attack_vectors(findings)
        exploitation_steps = _generate_exploitation_steps(findings)
        impact_assessment = _assess_impact(findings, tier_name)

        plan = {
            "plan_id": f"PLAN-{plans_generated + 1:03d}",
            "domain": domain,
            "domain_tier": tier_name,
            "tier_multiplier": tier_multiplier,
            "finding_count": len(findings),
            "max_severity": max(findings, key=lambda f: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(f.severity, 0)).severity,
            "attack_vectors": attack_vectors,
            "exploitation_steps": exploitation_steps,
            "impact_assessment": impact_assessment,
            "estimated_bounty": plan_data["total_bounty_estimate"],
            "findings_summary": [
                {"id": f.id, "type": f.finding_type, "severity": f.severity, "title": f.title[:60]}
                for f in findings[:10]
            ],
            "recommended_tools": _recommend_tools(findings),
            "time_estimate_hours": _estimate_exploitation_time(findings),
        }
        attack_plans.append(plan)
        plans_generated += 1

    # Display plans
    print_subheader(f"Generated {plans_generated} Attack Plans")

    for plan in sorted(attack_plans, key=lambda p: p["estimated_bounty"], reverse=True)[:10]:
        sev_color = Colors.severity_color(plan["max_severity"])
        print(f"\n  {Colors.HIGHLIGHT}{plan['plan_id']}{Colors.RESET} | "
              f"{plan['domain']} ({plan['domain_tier']})")
        print(f"    Severity: {sev_color}{plan['max_severity']}{Colors.RESET} | "
              f"Findings: {plan['finding_count']} | "
              f"Est. Bounty: ${plan['estimated_bounty']:,.0f}")
        print(f"    Time Est: ~{plan['time_estimate_hours']}h | "
              f"Vectors: {len(plan['attack_vectors'])}")

        for vector in plan["attack_vectors"][:3]:
            print(f"      -> {vector}")

        if plan["exploitation_steps"]:
            print(f"    Steps:")
            for i, step in enumerate(plan["exploitation_steps"][:4], 1):
                print(f"      {i}. {step}")

    # Save plans
    output_dir = getattr(args, 'output', None) or DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "attack_plans.json")

    plan_output = {
        "attack_plan_report": {
            "generated_at": datetime.utcnow().isoformat(),
            "generator": TOOL_BANNER,
            "total_plans": plans_generated,
            "total_estimated_bounty": sum(p["estimated_bounty"] for p in attack_plans),
        },
        "plans": attack_plans,
    }

    with open(output_file, "w") as f:
        json.dump(plan_output, f, indent=2, default=str)
    print_success(f"Attack plans saved to: {output_file}")

    if db.db_path:
        db.save()

    print_timing(start_time, "planning")
    return 0


def cmd_diff(args) -> int:
    """Execute the diff subcommand to compare two reports."""
    start_time = time.time()
    print_header("DIFF ENGINE")

    old_path = args.old
    new_path = args.new

    if not os.path.exists(old_path):
        print_error(f"Old report not found: {old_path}")
        return 1
    if not os.path.exists(new_path):
        print_error(f"New report not found: {new_path}")
        return 1

    print_info(f"Comparing reports:")
    print_info(f"  Old: {old_path}")
    print_info(f"  New: {new_path}")

    # Load both reports
    try:
        with open(old_path, "r") as f:
            old_data = json.load(f)
        with open(new_path, "r") as f:
            new_data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print_error(f"Failed to load reports: {e}")
        return 1

    # Extract findings
    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])

    # Create fingerprints for comparison
    def make_fingerprint(f):
        components = [
            f.get("finding_type", "").lower().strip(),
            f.get("url", "").lower().strip().rstrip("/"),
            f.get("evidence", "").strip()[:500],
        ]
        raw = "|".join(components)
        import hashlib
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    old_fps = {make_fingerprint(f): f for f in old_findings}
    new_fps = {make_fingerprint(f): f for f in new_findings}

    old_fp_set = set(old_fps.keys())
    new_fp_set = set(new_fps.keys())

    # Calculate diff
    added_fps = new_fp_set - old_fp_set
    removed_fps = old_fp_set - new_fp_set
    unchanged_fps = old_fp_set & new_fp_set

    added = [new_fps[fp] for fp in added_fps]
    removed = [old_fps[fp] for fp in removed_fps]
    unchanged = [new_fps[fp] for fp in unchanged_fps]

    # Display results
    print_subheader("Diff Summary")
    print(f"  Old report: {len(old_findings)} findings")
    print(f"  New report: {len(new_findings)} findings")
    print(f"  {Colors.SUCCESS}NEW findings:     +{len(added)}{Colors.RESET}")
    print(f"  {Colors.ERROR}REMOVED findings: -{len(removed)}{Colors.RESET}")
    print(f"  {Colors.DIMMED}UNCHANGED:         {len(unchanged)}{Colors.RESET}")

    if added:
        print_subheader(f"New Findings (+{len(added)})")
        for f in sorted(added, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5)):
            sev = f.get("severity", "INFO")
            sev_color = Colors.severity_color(sev)
            print(f"  {Colors.SUCCESS}+{Colors.RESET} {sev_color}{sev:<8}{Colors.RESET} "
                  f"{f.get('title', 'Unknown')[:55]}")
            print(f"    URL: {f.get('url', 'N/A')[:70]}")

    if removed:
        print_subheader(f"Removed/Fixed Findings (-{len(removed)})")
        for f in sorted(removed, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5)):
            sev = f.get("severity", "INFO")
            sev_color = Colors.severity_color(sev)
            print(f"  {Colors.ERROR}-{Colors.RESET} {sev_color}{sev:<8}{Colors.RESET} "
                  f"{f.get('title', 'Unknown')[:55]}")

    # Metadata comparison
    old_meta = old_data.get("report_metadata", {})
    new_meta = new_data.get("report_metadata", {})

    if old_meta or new_meta:
        print_subheader("Metadata Changes")
        print(f"  Target: {old_meta.get('target', '?')} -> {new_meta.get('target', '?')}")
        print(f"  Old scan: {old_meta.get('generated_at', '?')}")
        print(f"  New scan: {new_meta.get('generated_at', '?')}")
        print(f"  Modules old: {old_meta.get('modules_run', [])}")
        print(f"  Modules new: {new_meta.get('modules_run', [])}")

    # Save diff report
    output_dir = getattr(args, 'output', None) or DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    diff_output = {
        "diff_report": {
            "generated_at": datetime.utcnow().isoformat(),
            "old_report": old_path,
            "new_report": new_path,
            "summary": {
                "old_count": len(old_findings),
                "new_count": len(new_findings),
                "added": len(added),
                "removed": len(removed),
                "unchanged": len(unchanged),
            },
        },
        "added_findings": added,
        "removed_findings": removed,
    }

    output_file = os.path.join(output_dir, "diff_report.json")
    with open(output_file, "w") as f:
        json.dump(diff_output, f, indent=2, default=str)
    print_success(f"Diff report saved to: {output_file}")

    print_timing(start_time, "diff")
    return 0



def cmd_full(args) -> int:
    """Execute the full pipeline: import -> correlate -> prioritize -> plan -> report."""
    start_time = time.time()
    print_banner()
    print_header("FULL PIPELINE EXECUTION")

    # Step 1: Import
    print_subheader("Step 1/4: Import Findings")
    step_start = time.time()

    db = _load_database(args)
    if db is None:
        return 1

    input_dir = getattr(args, 'input', None) or DEFAULT_REPORTS_DIR
    if os.path.exists(input_dir):
        import_stats = _import_findings(db, input_dir)
        print_success(f"Imported {import_stats.get('imported_new', 0)} new findings "
                      f"({import_stats.get('duplicates_skipped', 0)} duplicates skipped)")
    else:
        print_warning(f"Input directory not found: {input_dir}")
        if db.count() == 0:
            print_error("No findings available. Provide --input with report files.")
            return 1

    print_timing(step_start, "import")

    if db.count() == 0:
        print_warning("No findings to process.")
        return 0

    # Step 2: Correlate
    print_subheader("Step 2/4: Correlation Analysis")
    step_start = time.time()

    chains_found = 0
    for rule_name, rule_config in CORRELATION_RULES.items():
        required_types = rule_config["required_types"]
        confidence_threshold = rule_config.get("confidence_threshold", 0.7)

        matching_required = []
        for req_type in required_types:
            matching_required.extend(db.by_type(req_type))

        if len(matching_required) < rule_config.get("min_findings", 2):
            continue

        matching_optional = []
        for opt_type in rule_config.get("optional_types", []):
            matching_optional.extend(db.by_type(opt_type))

        # Group by domain
        domain_groups: Dict[str, List[Finding]] = {}
        for f in matching_required + matching_optional:
            domain = f.domain or "unknown"
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(f)

        for domain, domain_findings in domain_groups.items():
            required_in_domain = [f for f in domain_findings if f.finding_type in required_types]
            optional_in_domain = [f for f in domain_findings if f.finding_type in rule_config.get("optional_types", [])]

            if not required_in_domain:
                continue

            confidence = _calculate_correlation_confidence(required_in_domain, optional_in_domain, rule_config)
            if confidence >= confidence_threshold:
                chain_findings = required_in_domain + optional_in_domain[:3]
                child_ids = [f.id for f in chain_findings]
                if len(child_ids) >= 2:
                    composite_id = db.create_composite_finding(
                        child_ids=child_ids,
                        title=f"[CHAIN] {rule_config['description']} on {domain}",
                        description=rule_config.get("chain_description", ""),
                        severity=rule_config.get("severity_boost", "HIGH"),
                        chain_description=rule_config.get("chain_description", ""),
                    )
                    if composite_id:
                        chains_found += 1

    print_success(f"Found {chains_found} correlation chains")
    print_timing(step_start, "correlation")

    # Step 3: Prioritize
    print_subheader("Step 3/4: Priority Scoring")
    step_start = time.time()

    all_findings = db.get_all()
    for finding in all_findings:
        finding_dict = finding.to_dict()
        finding.priority_score = calculate_priority_score(finding_dict)
        bounty = get_bounty_estimate(finding.severity)
        finding.bounty_estimate = bounty["median"]
        if finding.domain:
            _, multiplier = get_domain_tier(finding.domain)
            finding.priority_score = round(min(finding.priority_score * (1 + (multiplier - 1) * 0.3), 10.0), 2)

    top_findings = sorted(all_findings, key=lambda f: f.priority_score, reverse=True)
    print_success(f"Scored {len(all_findings)} findings")
    print_timing(step_start, "prioritization")

    # Step 4: Generate Report
    print_subheader("Step 4/4: Report Generation")
    step_start = time.time()

    output_dir = getattr(args, 'output', None) or DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    # Generate JSON report
    summary = db.export_summary()
    stats = db.statistics()

    report = {
        "super_monster_report": {
            "generated_at": datetime.utcnow().isoformat(),
            "generator": TOOL_BANNER,
            "pipeline": "full",
            "total_findings": db.count(),
            "correlation_chains": chains_found,
            "total_estimated_bounty": sum(f.bounty_estimate for f in all_findings),
        },
        "executive_summary": summary,
        "statistics": stats,
        "top_priority_findings": [f.to_dict() for f in top_findings[:20]],
        "correlation_chains": db.get_correlation_chains(),
    }

    report_file = os.path.join(output_dir, f"super_monster_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print_success(f"Report saved to: {report_file}")
    print_timing(step_start, "reporting")

    # Save database
    if db.db_path:
        db.save()
        print_success(f"Database saved to: {db.db_path}")

    # Final summary
    print_header("PIPELINE COMPLETE")
    print(f"  Total findings:       {Colors.COUNT}{db.count()}{Colors.RESET}")
    print(f"  Correlation chains:   {Colors.COUNT}{chains_found}{Colors.RESET}")
    print(f"  Estimated bounty:     {Colors.HIGHLIGHT}${sum(f.bounty_estimate for f in all_findings):,.0f}{Colors.RESET}")
    print(f"  Report:               {report_file}")
    print_timing(start_time, "total pipeline")

    return 0



# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _load_database(args) -> Optional[FindingDB]:
    """Load or create the finding database from args."""
    db_path = getattr(args, 'db', None) or DEFAULT_DB_PATH
    try:
        db = FindingDB(db_path)
        if os.path.exists(db_path):
            print_info(f"Loaded database: {db_path} ({db.count()} findings)")
        else:
            print_info(f"Created new database: {db_path}")
        return db
    except Exception as e:
        print_error(f"Failed to load database: {e}")
        return None


def _import_findings(db: FindingDB, input_path: str) -> Dict[str, Any]:
    """Import findings from a file or directory."""
    if os.path.isdir(input_path):
        stats = db.import_directory(input_path)
        if stats.get("files_processed", 0) > 0:
            print_info(f"Processed {stats['files_processed']} report files")
            print_info(f"Targets: {', '.join(stats.get('targets', []))}")
        return stats
    elif os.path.isfile(input_path):
        stats = db.import_monster_report(input_path)
        return stats
    else:
        return {"error": f"Input path not found: {input_path}"}


def _calculate_correlation_confidence(
    required: List[Finding], optional: List[Finding], rule_config: Dict
) -> float:
    """Calculate confidence score for a potential correlation."""
    confidence = 0.5  # Base confidence

    # More required findings = higher confidence
    min_required = rule_config.get("min_findings", 2)
    if len(required) >= min_required:
        confidence += 0.2
    if len(required) >= min_required * 2:
        confidence += 0.1

    # Optional findings boost confidence
    if optional:
        confidence += min(len(optional) * 0.05, 0.15)

    # Same domain findings are more likely correlated
    domains = set(f.domain for f in required + optional if f.domain)
    if len(domains) == 1:
        confidence += 0.1

    # Higher CVSS findings are more likely to be exploitable chains
    max_cvss = max((f.cvss_score for f in required), default=0)
    if max_cvss >= 7.0:
        confidence += 0.05

    return min(confidence, 1.0)


def _generate_attack_vectors(findings: List[Finding]) -> List[str]:
    """Generate attack vector descriptions from findings."""
    vectors = []
    finding_types = set(f.finding_type for f in findings)

    vector_map = {
        "sqli": "SQL Injection: Extract database contents via injectable parameters",
        "xss_stored": "Stored XSS: Inject persistent malicious scripts for session theft",
        "xss_reflected": "Reflected XSS: Craft phishing URLs with injected scripts",
        "ssrf": "SSRF: Access internal services and cloud metadata endpoints",
        "auth_bypass": "Auth Bypass: Circumvent authentication to access protected resources",
        "idor": "IDOR: Enumerate and access other users' data via predictable references",
        "cors": "CORS: Exploit misconfigured origins for cross-site data theft",
        "open_redirect": "Open Redirect: Redirect users to phishing pages via trusted domain",
        "file_upload": "File Upload: Upload web shells for remote code execution",
        "rce": "RCE: Execute arbitrary commands on the target server",
        "subdomain_takeover": "Subdomain Takeover: Claim unclaimed subdomain for phishing/cookie theft",
        "csrf": "CSRF: Force authenticated users to perform unintended actions",
        "path_traversal": "Path Traversal: Read sensitive files outside web root",
        "xxe": "XXE: Extract files and SSRF via XML entity injection",
        "ssti": "SSTI: Achieve code execution through template injection",
        "deserialization": "Deserialization: Execute code through unsafe object deserialization",
        "info_disclosure": "Info Disclosure: Gather credentials and internal details for further attacks",
        "credential_exposure": "Credential Exposure: Use leaked credentials for unauthorized access",
        "api_key_leak": "API Key Leak: Abuse exposed keys for service access and data theft",
        "race_condition": "Race Condition: Exploit timing gaps for duplicate transactions or privilege escalation",
    }

    for ftype in finding_types:
        if ftype in vector_map:
            vectors.append(vector_map[ftype])

    if not vectors:
        vectors.append("Manual testing: Further investigate identified weaknesses")

    return vectors[:8]


def _generate_exploitation_steps(findings: List[Finding]) -> List[str]:
    """Generate ordered exploitation steps."""
    steps = []
    finding_types = [f.finding_type for f in sorted(findings, key=lambda x: x.priority_score, reverse=True)]

    # Reconnaissance phase
    steps.append("Enumerate all identified endpoints and parameters")

    # Initial access
    if any(t in finding_types for t in ["auth_bypass", "credential_exposure", "default_credentials"]):
        steps.append("Attempt authentication bypass or use exposed credentials")
    elif any(t in finding_types for t in ["sqli", "sqli_blind", "sqli_error"]):
        steps.append("Exploit SQL injection to extract credentials or bypass auth")
    elif any(t in finding_types for t in ["xss_stored", "xss_reflected"]):
        steps.append("Craft XSS payload to steal admin session tokens")

    # Escalation
    if any(t in finding_types for t in ["ssrf", "cloud_metadata"]):
        steps.append("Pivot through SSRF to access internal services and cloud metadata")
    if any(t in finding_types for t in ["idor", "broken_access_control"]):
        steps.append("Escalate access via IDOR to enumerate all user data")
    if any(t in finding_types for t in ["file_upload", "rce", "ssti", "deserialization"]):
        steps.append("Achieve remote code execution through upload/injection vector")
    if any(t in finding_types for t in ["path_traversal", "lfi"]):
        steps.append("Read sensitive configuration files via path traversal")

    # Data extraction
    if any(t in finding_types for t in ["sqli", "idor", "pii_leak", "data_exposure"]):
        steps.append("Extract and document sensitive data for impact demonstration")

    # Reporting
    steps.append("Document full attack chain with screenshots and evidence")
    steps.append("Write detailed report with reproduction steps and remediation")

    return steps[:10]


def _assess_impact(findings: List[Finding], tier_name: str) -> str:
    """Generate impact assessment based on findings and domain tier."""
    max_severity = "INFO"
    for f in findings:
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        if sev_order.get(f.severity, 0) > sev_order.get(max_severity, 0):
            max_severity = f.severity

    impact_descriptions = {
        "CRITICAL": "Complete system compromise possible. Immediate action required.",
        "HIGH": "Significant data exposure or unauthorized access achievable.",
        "MEDIUM": "Limited data exposure or functionality abuse possible.",
        "LOW": "Minor information leakage or low-impact issues.",
        "INFO": "Informational findings with minimal direct impact.",
    }

    tier_context = {
        "tier_1_critical": " Target is a critical payment/auth system - impact is amplified.",
        "tier_2_high": " Target handles user data - breach would affect multiple users.",
        "tier_3_medium": " Target is public-facing - exploitation visible to all users.",
        "tier_4_low": " Target is development/staging - limited production impact.",
        "tier_5_info": " Target is low-value - minimal business impact.",
    }

    base_impact = impact_descriptions.get(max_severity, "Unknown impact.")
    tier_addition = tier_context.get(tier_name, "")

    return base_impact + tier_addition


def _recommend_tools(findings: List[Finding]) -> List[str]:
    """Recommend exploitation tools based on finding types."""
    tools = set()
    finding_types = set(f.finding_type for f in findings)

    tool_map = {
        "sqli": ["sqlmap", "Burp Suite Intruder"],
        "xss_stored": ["Burp Suite", "XSS Hunter", "dalfox"],
        "xss_reflected": ["Burp Suite Repeater", "dalfox", "kxss"],
        "ssrf": ["Burp Suite Collaborator", "interact.sh"],
        "cors": ["Burp Suite", "CORScanner"],
        "idor": ["Burp Suite Autorize", "Postman"],
        "file_upload": ["Burp Suite", "fuxploider"],
        "subdomain_takeover": ["subjack", "nuclei"],
        "rce": ["Burp Suite", "reverse shell generator"],
        "auth_bypass": ["Burp Suite", "ffuf"],
        "path_traversal": ["dotdotpwn", "Burp Suite"],
        "xxe": ["Burp Suite", "XXEinjector"],
        "ssti": ["tplmap", "Burp Suite"],
        "open_redirect": ["Burp Suite", "OpenRedireX"],
        "race_condition": ["Burp Suite Turbo Intruder", "racepwn"],
        "csrf": ["Burp Suite CSRF PoC Generator"],
    }

    for ftype in finding_types:
        if ftype in tool_map:
            tools.update(tool_map[ftype])

    tools.add("Burp Suite Professional")  # Always recommend
    return sorted(list(tools))[:10]


def _estimate_exploitation_time(findings: List[Finding]) -> int:
    """Estimate hours needed to exploit findings."""
    base_hours = 1
    type_hours = {
        "rce": 2, "sqli": 3, "auth_bypass": 2, "ssrf": 3,
        "xss_stored": 2, "xss_reflected": 1, "idor": 2,
        "file_upload": 3, "cors": 1, "open_redirect": 1,
        "subdomain_takeover": 2, "csrf": 1, "xxe": 3,
        "ssti": 3, "deserialization": 4, "race_condition": 3,
    }

    total = base_hours
    seen_types = set()
    for f in findings:
        if f.finding_type not in seen_types:
            total += type_hours.get(f.finding_type, 1)
            seen_types.add(f.finding_type)

    return min(total, 40)



# =============================================================================
# ARGUMENT PARSER AND MAIN ENTRY POINT
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="super_monster",
        description="Super Monster - Bug Bounty Intelligence & Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m super_monster full --input ./monster_output/reports --output ./super_output
  python -m super_monster correlate --input ./monster_output/reports --db findings.json
  python -m super_monster prioritize --db findings.json --limit 20
  python -m super_monster plan --db findings.json --output ./attack_plans
  python -m super_monster retest --db findings.json
  python -m super_monster diff --old report_old.json --new report_new.json
        """,
    )

    parser.add_argument(
        "--version", action="version",
        version=f"Super Monster v{VERSION}",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Minimal output (errors only)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output with debug information",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- correlate subcommand ---
    p_correlate = subparsers.add_parser(
        "correlate",
        help="Run cross-finding correlation engine to detect attack chains",
        description="Analyze findings for correlation patterns and chain detection. "
                    "Identifies multi-step attack paths across findings.",
    )
    p_correlate.add_argument("--input", "-i", help="Input directory or file with Monster JSON reports")
    p_correlate.add_argument("--db", help=f"Path to findings database (default: {DEFAULT_DB_PATH})")
    p_correlate.add_argument("--output", "-o", help="Output directory for results")
    p_correlate.add_argument("--min-confidence", type=float, default=0.6,
                             help="Minimum confidence threshold for correlations (default: 0.6)")
    p_correlate.add_argument("--format", choices=["json", "markdown", "csv"], default="json",
                             help="Output format (default: json)")
    p_correlate.set_defaults(func=cmd_correlate)

    # --- retest subcommand ---
    p_retest = subparsers.add_parser(
        "retest",
        help="Check and schedule finding retests based on severity intervals",
        description="Analyze findings for retest scheduling. Shows which findings "
                    "are due for verification based on configured intervals.",
    )
    p_retest.add_argument("--input", "-i", help="Input directory or file with Monster JSON reports")
    p_retest.add_argument("--db", help=f"Path to findings database (default: {DEFAULT_DB_PATH})")
    p_retest.add_argument("--output", "-o", help="Output directory for retest schedule")
    p_retest.add_argument("--strategy", choices=["full", "critical_only", "oldest_first", "random_sample"],
                          default="full", help="Retest strategy (default: full)")
    p_retest.add_argument("--severity", choices=SEVERITY_LEVELS,
                          help="Filter by severity level")
    p_retest.add_argument("--force", action="store_true",
                          help="Force retest check regardless of intervals")
    p_retest.add_argument("--webhook", help="Webhook URL for retest notifications")
    p_retest.set_defaults(func=cmd_retest)

    # --- prioritize subcommand ---
    p_prioritize = subparsers.add_parser(
        "prioritize",
        help="Score and rank findings by composite priority score",
        description="Calculate priority scores using CVSS, exploitability, business impact, "
                    "bounty value, and correlation bonuses. Rank findings for maximum ROI.",
    )
    p_prioritize.add_argument("--input", "-i", help="Input directory or file with Monster JSON reports")
    p_prioritize.add_argument("--db", help=f"Path to findings database (default: {DEFAULT_DB_PATH})")
    p_prioritize.add_argument("--output", "-o", help="Output directory for priority report")
    p_prioritize.add_argument("--limit", type=int, default=20,
                              help="Number of top findings to display (default: 20)")
    p_prioritize.add_argument("--min-score", type=float, default=0.0,
                              help="Minimum priority score to include (default: 0.0)")
    p_prioritize.add_argument("--format", choices=["json", "markdown", "csv"], default="json",
                              help="Output format (default: json)")
    p_prioritize.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti", "synack"],
                              default="hackerone", help="Bug bounty platform for estimates (default: hackerone)")
    p_prioritize.set_defaults(func=cmd_prioritize)

    # --- plan subcommand ---
    p_plan = subparsers.add_parser(
        "plan",
        help="Generate attack plans with exploitation steps and tool recommendations",
        description="Create actionable attack plans based on findings. Generates "
                    "exploitation steps, tool recommendations, and time estimates.",
    )
    p_plan.add_argument("--input", "-i", help="Input directory or file with Monster JSON reports")
    p_plan.add_argument("--db", help=f"Path to findings database (default: {DEFAULT_DB_PATH})")
    p_plan.add_argument("--output", "-o", help="Output directory for attack plans")
    p_plan.add_argument("--domain", help="Generate plan for specific domain only")
    p_plan.add_argument("--severity", choices=SEVERITY_LEVELS,
                        help="Minimum severity for plan inclusion")
    p_plan.add_argument("--format", choices=["json", "markdown"], default="json",
                        help="Output format (default: json)")
    p_plan.set_defaults(func=cmd_plan)

    # --- diff subcommand ---
    p_diff = subparsers.add_parser(
        "diff",
        help="Compare two Monster reports to identify new, fixed, and changed findings",
        description="Temporal diff analysis between two scan reports. Shows what was "
                    "added, removed (possibly fixed), and unchanged between scans.",
    )
    p_diff.add_argument("--old", required=True, help="Path to the older report (baseline)")
    p_diff.add_argument("--new", required=True, help="Path to the newer report (comparison)")
    p_diff.add_argument("--output", "-o", help="Output directory for diff report")
    p_diff.add_argument("--format", choices=["json", "markdown"], default="json",
                        help="Output format (default: json)")
    p_diff.add_argument("--show-unchanged", action="store_true",
                        help="Also display unchanged findings")
    p_diff.set_defaults(func=cmd_diff)

    # --- full subcommand ---
    p_full = subparsers.add_parser(
        "full",
        help="Run complete pipeline: import -> correlate -> prioritize -> plan -> report",
        description="Execute the full Super Monster pipeline. Imports findings from Monster "
                    "reports, runs correlation, scores priorities, generates attack plans, "
                    "and produces a comprehensive intelligence report.",
    )
    p_full.add_argument("--input", "-i", default=DEFAULT_REPORTS_DIR,
                        help=f"Input directory with Monster JSON reports (default: {DEFAULT_REPORTS_DIR})")
    p_full.add_argument("--db", help=f"Path to findings database (default: {DEFAULT_DB_PATH})")
    p_full.add_argument("--output", "-o", default=DEFAULT_OUTPUT_DIR,
                        help=f"Output directory for all results (default: {DEFAULT_OUTPUT_DIR})")
    p_full.add_argument("--format", choices=["json", "markdown", "html"], default="json",
                        help="Report output format (default: json)")
    p_full.add_argument("--webhook", help="Webhook URL for notifications")
    p_full.add_argument("--no-correlate", action="store_true",
                        help="Skip correlation step")
    p_full.add_argument("--no-plan", action="store_true",
                        help="Skip attack plan generation")
    p_full.set_defaults(func=cmd_full)

    return parser


def main() -> int:
    """Main entry point for Super Monster CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Handle no command
    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    # Disable colors if requested
    if getattr(args, 'no_color', False):
        os.environ["NO_COLOR"] = "1"

    # Execute the appropriate subcommand
    try:
        if hasattr(args, 'func'):
            return args.func(args)
        else:
            parser.print_help()
            return 0
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.RESET}")
        return 130
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
