"""
Super Monster v2 - Reporter

Generates clean, honest output. NO bounty estimates. Categorizes findings
into three tiers:
1. REPORT THESE - Verified, real impact, HIGH+ on sensitive domains
2. INVESTIGATE FURTHER - Verified but needs manual confirmation
3. INFORMATIONAL - Low severity, useful for context only

Output formats: Console (colored), JSON file, Markdown (HackerOne-ready).
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import List

from .config import Colors, SEVERITY_ORDER, OUTPUT_DIR
from .smart_scanner import Finding
from .correlator import Chain


class Reporter:
    """
    Generates structured, honest reports from verified findings and chains.

    Three output categories, three output formats, zero bounty estimates.
    Focus is on severity, evidence, and actionable reproduction steps.
    """

    # Domain types considered sensitive (findings here are more reportable)
    SENSITIVE_DOMAIN_TYPES = ("payment", "auth", "api", "admin")

    # Domain type keywords for classification
    _TYPE_PREFIXES = {
        "payment": ["payment.", "pay.", "checkout.", "billing."],
        "auth": ["auth.", "login.", "sso.", "id.", "member.", "mauth."],
        "api": ["api.", "rs-open-api.", "cmapi.", "cart-front-api."],
        "admin": ["admin.", "manage.", "dashboard.", "partners."],
        "cdn": ["cdn.", "static.", "assets.", "media.", "img."],
        "web": ["www.", "m.", "shop.", "pages.", "review."],
    }

    def __init__(self):
        """Initialize reporter."""
        pass

    def generate_report(
        self,
        verified_findings: list,
        chains: list,
        scan_stats: dict,
        output_dir: str = None,
    ) -> dict:
        """
        Generate complete report from verified findings and chains.

        Args:
            verified_findings: List of verified Finding objects.
            chains: List of Chain objects from correlator.
            scan_stats: Dict with scan statistics.
            output_dir: Output directory for files. Defaults to OUTPUT_DIR.

        Returns:
            Dict with report data including file paths.
        """
        if output_dir is None:
            output_dir = OUTPUT_DIR

        # Categorize findings into three tiers
        categorized = self._categorize_findings(verified_findings)

        # Print console report
        self._print_console_report(categorized, chains, scan_stats)

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Generate file reports
        json_path = self._generate_json_report(
            categorized, chains, scan_stats, output_dir
        )
        md_path = self._generate_markdown_report(
            categorized, chains, scan_stats, output_dir
        )

        return {
            "categorized": categorized,
            "chains": chains,
            "scan_stats": scan_stats,
            "json_report": json_path,
            "markdown_report": md_path,
            "report_these_count": len(categorized.get("report_these", [])),
            "investigate_count": len(categorized.get("investigate_further", [])),
            "informational_count": len(categorized.get("informational", [])),
        }

    def _get_domain_type(self, domain: str) -> str:
        """Determine domain type from domain name."""
        domain_lower = domain.lower()

        for dtype, prefixes in self._TYPE_PREFIXES.items():
            for prefix in prefixes:
                if domain_lower.startswith(prefix):
                    return dtype

        # Keyword fallback
        first_part = domain_lower.split(".")[0]
        type_keywords = {
            "payment": ["payment", "pay", "checkout", "billing"],
            "auth": ["auth", "login", "sso", "oauth", "session"],
            "api": ["api", "rest", "graphql", "gateway"],
            "admin": ["admin", "manage", "dashboard"],
            "cdn": ["cdn", "static", "assets", "media"],
            "web": ["www", "web", "shop", "store"],
        }
        for dtype, keywords in type_keywords.items():
            for keyword in keywords:
                if keyword in first_part:
                    return dtype

        return "web"

    def _categorize_findings(self, findings: list) -> dict:
        """
        Sort findings into three categories.

        REPORT THESE:
          - HIGH or CRITICAL severity
          - On sensitive domain types (payment, auth, api, admin)
          - Verified with high confidence

        INVESTIGATE FURTHER:
          - MEDIUM severity findings
          - OR HIGH findings on less sensitive domains (web, cdn)
          - Need manual exploitation proof

        INFORMATIONAL:
          - LOW or INFO severity
          - Findings on CDN/static domains
          - Useful context but unlikely to get bounty

        Args:
            findings: List of Finding objects.

        Returns:
            Dict with keys: report_these, investigate_further, informational.
        """
        report_these = []
        investigate_further = []
        informational = []

        for finding in findings:
            severity = finding.severity.lower()
            domain_type = self._get_domain_type(finding.domain)
            severity_rank = SEVERITY_ORDER.get(severity, 4)

            if severity_rank <= 1 and domain_type in self.SENSITIVE_DOMAIN_TYPES:
                # HIGH or CRITICAL on sensitive domain -> report
                report_these.append(finding)
            elif severity_rank <= 1 and domain_type not in self.SENSITIVE_DOMAIN_TYPES:
                # HIGH on non-sensitive domain -> investigate
                investigate_further.append(finding)
            elif severity_rank == 2:
                # MEDIUM -> investigate
                investigate_further.append(finding)
            else:
                # LOW, INFO, or CDN/static -> informational
                informational.append(finding)

        # Sort each category by severity (most severe first)
        report_these.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 4))
        investigate_further.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 4))
        informational.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 4))

        return {
            "report_these": report_these,
            "investigate_further": investigate_further,
            "informational": informational,
        }

    def _print_console_report(
        self, categorized: dict, chains: list, scan_stats: dict
    ):
        """
        Print colored console output with findings summary.

        Shows banner, categorized findings, attack chains, and stats.
        """
        c = Colors

        # Header
        print(f"\n{c.BANNER}SUPER MONSTER v2.0 - Scan Complete{c.RESET}")
        print(f"{c.BANNER}==================================={c.RESET}\n")

        # REPORT THESE section
        report_these = categorized.get("report_these", [])
        if report_these:
            print(
                f"{c.CRITICAL}REPORT THESE "
                f"(verified, real impact):{c.RESET}"
            )
            for i, finding in enumerate(report_these, 1):
                sev_color = c.severity_color(finding.severity)
                print(
                    f"  {i}. {sev_color}[{finding.severity.upper()}]{c.RESET} "
                    f"{finding.title} on {finding.domain}"
                )
                if finding.evidence:
                    evidence_short = finding.evidence[:100]
                    print(f"     {c.DIM}Evidence: {evidence_short}{c.RESET}")
            print()
        else:
            print(
                f"{c.DIM}REPORT THESE: None "
                f"(no high-impact verified findings){c.RESET}\n"
            )

        # ATTACK CHAINS section
        if chains:
            print(f"{c.WARNING}ATTACK CHAINS:{c.RESET}")
            for i, chain in enumerate(chains, 1):
                sev_color = c.severity_color(chain.severity)
                print(
                    f"  {sev_color}Chain #{i}: {chain.title}{c.RESET}"
                )
                print(f"  -> Impact: {chain.impact[:100]}")
                print(f"  -> Confidence: {chain.confidence:.2f}")
                print()
        else:
            print(f"{c.DIM}ATTACK CHAINS: None detected{c.RESET}\n")

        # INVESTIGATE FURTHER section
        investigate = categorized.get("investigate_further", [])
        if investigate:
            print(
                f"{c.MEDIUM}INVESTIGATE FURTHER "
                f"(needs manual verification):{c.RESET}"
            )
            count_start = len(report_these) + 1
            for i, finding in enumerate(investigate, count_start):
                sev_color = c.severity_color(finding.severity)
                print(
                    f"  {i}. {sev_color}[{finding.severity.upper()}]{c.RESET} "
                    f"{finding.title} on {finding.domain}"
                )
            print()
        else:
            print(
                f"{c.DIM}INVESTIGATE FURTHER: None{c.RESET}\n"
            )

        # INFORMATIONAL section
        informational = categorized.get("informational", [])
        if informational:
            print(f"{c.DIM}INFORMATIONAL:{c.RESET}")
            count_start = len(report_these) + len(investigate) + 1

            # Group informational by type to reduce noise
            by_type = {}
            for finding in informational:
                key = finding.finding_type
                if key not in by_type:
                    by_type[key] = []
                by_type[key].append(finding)

            idx = count_start
            for finding_type, findings_group in by_type.items():
                if len(findings_group) == 1:
                    f = findings_group[0]
                    print(
                        f"  {idx}. {c.DIM}[{f.severity.upper()}] "
                        f"{f.title} on {f.domain}{c.RESET}"
                    )
                else:
                    # Summarize multiple similar findings
                    sample = findings_group[0]
                    print(
                        f"  {idx}. {c.DIM}[{sample.severity.upper()}] "
                        f"{sample.title} on {len(findings_group)} domains{c.RESET}"
                    )
                idx += 1
            print()
        else:
            print(f"{c.DIM}INFORMATIONAL: None{c.RESET}\n")

        # Stats footer
        print(f"{c.DIM}---{c.RESET}")
        duration = scan_stats.get("duration_seconds", 0)
        duration_str = self._format_duration(duration)
        domains_scanned = scan_stats.get("domains_scanned", 0)
        verified_count = scan_stats.get("verified_findings", 0)
        fp_filtered = scan_stats.get("false_positives_filtered", 0)

        print(
            f"{c.DIM}Duration: {duration_str} | "
            f"Domains: {domains_scanned} | "
            f"Verified: {verified_count} | "
            f"False positives filtered: {fp_filtered}{c.RESET}"
        )

        # Report file paths (shown after generation)
        print(f"{c.DIM}Reports saved to: ./{OUTPUT_DIR}/{c.RESET}\n")

    def _generate_json_report(
        self, categorized: dict, chains: list, scan_stats: dict, output_dir: str
    ) -> str:
        """
        Generate JSON report file with all findings and metadata.

        Args:
            categorized: Dict with categorized findings.
            chains: List of Chain objects.
            scan_stats: Dict with scan statistics.
            output_dir: Output directory path.

        Returns:
            Path to the generated JSON file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"super_monster_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        report_data = {
            "meta": {
                "tool": "Super Monster v2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_stats": scan_stats,
            },
            "summary": {
                "report_these": len(categorized.get("report_these", [])),
                "investigate_further": len(categorized.get("investigate_further", [])),
                "informational": len(categorized.get("informational", [])),
                "chains": len(chains),
            },
            "report_these": [
                self._finding_to_dict(f)
                for f in categorized.get("report_these", [])
            ],
            "investigate_further": [
                self._finding_to_dict(f)
                for f in categorized.get("investigate_further", [])
            ],
            "informational": [
                self._finding_to_dict(f)
                for f in categorized.get("informational", [])
            ],
            "chains": [
                self._chain_to_dict(c) for c in chains
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return filepath

    def _generate_markdown_report(
        self, categorized: dict, chains: list, scan_stats: dict, output_dir: str
    ) -> str:
        """
        Generate Markdown report formatted for HackerOne submission.

        Only includes REPORT THESE items in full detail. Other categories
        get a brief summary.

        Args:
            categorized: Dict with categorized findings.
            chains: List of Chain objects.
            scan_stats: Dict with scan statistics.
            output_dir: Output directory path.

        Returns:
            Path to the generated Markdown file.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"super_monster_report_{timestamp}.md"
        filepath = os.path.join(output_dir, filename)

        lines = []

        # Header
        lines.append("# Super Monster v2.0 - Security Assessment Report")
        lines.append("")
        lines.append(
            f"**Generated:** "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        lines.append(
            f"**Scan Duration:** "
            f"{self._format_duration(scan_stats.get('duration_seconds', 0))}"
        )
        lines.append(
            f"**Domains Scanned:** {scan_stats.get('domains_scanned', 0)}"
        )
        lines.append(
            f"**Verified Findings:** {scan_stats.get('verified_findings', 0)}"
        )
        lines.append(
            f"**False Positives Filtered:** "
            f"{scan_stats.get('false_positives_filtered', 0)}"
        )
        lines.append("")
        lines.append("---")
        lines.append("")

        # REPORT THESE - Full detail for HackerOne
        report_these = categorized.get("report_these", [])
        lines.append("## Findings Ready to Report")
        lines.append("")

        if report_these:
            lines.append(
                f"The following {len(report_these)} finding(s) are verified, "
                f"have real security impact, and are ready for submission."
            )
            lines.append("")

            for i, finding in enumerate(report_these, 1):
                lines.append(f"### {i}. {finding.title}")
                lines.append("")
                lines.append(self._format_finding_for_h1(finding))
                lines.append("")
        else:
            lines.append("No high-impact findings ready for immediate reporting.")
            lines.append("")

        # Attack Chains
        if chains:
            lines.append("## Attack Chains")
            lines.append("")
            lines.append(
                "The following attack chains combine multiple findings "
                "into exploitable attack paths."
            )
            lines.append("")

            for i, chain in enumerate(chains, 1):
                lines.append(f"### Chain #{i}: {chain.title}")
                lines.append("")
                lines.append(self._format_chain_summary(chain))
                lines.append("")

        # INVESTIGATE FURTHER - Brief summary
        investigate = categorized.get("investigate_further", [])
        if investigate:
            lines.append("## Investigate Further")
            lines.append("")
            lines.append(
                "These findings are verified but need manual exploitation "
                "proof before reporting."
            )
            lines.append("")

            for finding in investigate:
                lines.append(
                    f"- **[{finding.severity.upper()}]** "
                    f"{finding.title} on `{finding.domain}`"
                )
            lines.append("")

        # INFORMATIONAL - Brief list
        informational = categorized.get("informational", [])
        if informational:
            lines.append("## Informational")
            lines.append("")
            lines.append(
                "Low severity findings for context. "
                "Unlikely to receive bounty individually."
            )
            lines.append("")

            # Group by type
            by_type = {}
            for finding in informational:
                key = finding.finding_type
                if key not in by_type:
                    by_type[key] = []
                by_type[key].append(finding)

            for ftype, findings_list in by_type.items():
                if len(findings_list) == 1:
                    f = findings_list[0]
                    lines.append(
                        f"- [{f.severity.upper()}] {f.title} on `{f.domain}`"
                    )
                else:
                    sample = findings_list[0]
                    lines.append(
                        f"- [{sample.severity.upper()}] {sample.title} "
                        f"on {len(findings_list)} domains"
                    )
            lines.append("")

        # Stats footer
        lines.append("---")
        lines.append("")
        lines.append("## Scan Statistics")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(
            f"| Duration | "
            f"{self._format_duration(scan_stats.get('duration_seconds', 0))} |"
        )
        lines.append(
            f"| Domains Scanned | {scan_stats.get('domains_scanned', 0)} |"
        )
        lines.append(
            f"| Total Raw Findings | "
            f"{scan_stats.get('total_raw_findings', 0)} |"
        )
        lines.append(
            f"| False Positives Filtered | "
            f"{scan_stats.get('false_positives_filtered', 0)} |"
        )
        lines.append(
            f"| Verified Findings | {scan_stats.get('verified_findings', 0)} |"
        )
        lines.append(
            f"| Attack Chains | {scan_stats.get('chains_found', 0)} |"
        )
        lines.append("")

        # Domain breakdown if available
        domains_by_type = scan_stats.get("domains_by_type", {})
        if domains_by_type:
            lines.append("### Domains by Type")
            lines.append("")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for dtype, count in sorted(
                domains_by_type.items(), key=lambda x: x[1], reverse=True
            ):
                lines.append(f"| {dtype} | {count} |")
            lines.append("")

        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return filepath

    def _format_finding_for_h1(self, finding) -> str:
        """
        Format a single finding as HackerOne-ready markdown.

        Includes: Title, Severity, Domain, Description, Steps to Reproduce,
        Impact, Evidence.

        Args:
            finding: A Finding object.

        Returns:
            Formatted markdown string.
        """
        lines = []

        lines.append(f"**Severity:** {finding.severity.upper()}")
        lines.append(f"**Domain:** `{finding.domain}`")
        lines.append(f"**URL:** `{finding.url}`")
        lines.append(f"**Type:** {finding.finding_type}")
        lines.append("")

        # Description
        lines.append("**Description:**")
        lines.append("")
        lines.append(finding.description)
        lines.append("")

        # Steps to Reproduce
        if finding.reproduction_steps:
            lines.append("**Steps to Reproduce:**")
            lines.append("")
            for i, step in enumerate(finding.reproduction_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Impact
        if finding.impact:
            lines.append("**Impact:**")
            lines.append("")
            lines.append(finding.impact)
            lines.append("")

        # Evidence
        if finding.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            lines.append(f"```")
            lines.append(finding.evidence)
            lines.append(f"```")
            lines.append("")

        # Confidence
        lines.append(f"**Verification Confidence:** {finding.confidence:.0%}")
        lines.append("")

        return "\n".join(lines)

    def _format_chain_summary(self, chain) -> str:
        """
        Format an attack chain for display in reports.

        Args:
            chain: A Chain object.

        Returns:
            Formatted markdown string.
        """
        lines = []

        lines.append(f"**Severity:** {chain.severity.upper()}")
        lines.append(f"**Confidence:** {chain.confidence:.2f}")
        lines.append(f"**Exploitability:** {chain.exploitability}")
        lines.append(f"**Domains:** {', '.join(f'`{d}`' for d in chain.domains)}")
        lines.append("")

        lines.append(f"**Description:**")
        lines.append("")
        lines.append(chain.description)
        lines.append("")

        lines.append(f"**Impact:**")
        lines.append("")
        lines.append(chain.impact)
        lines.append("")

        # Constituent findings
        if chain.findings:
            lines.append("**Constituent Findings:**")
            lines.append("")
            for finding in chain.findings:
                lines.append(
                    f"- [{finding.severity.upper()}] "
                    f"{finding.title} on `{finding.domain}`"
                )
            lines.append("")

        # Reproduction steps
        if chain.reproduction_steps:
            lines.append("**Reproduction Steps:**")
            lines.append("")
            for step in chain.reproduction_steps:
                lines.append(f"- {step}")
            lines.append("")

        return "\n".join(lines)

    def _finding_to_dict(self, finding) -> dict:
        """Convert a Finding dataclass to a serializable dict."""
        return {
            "finding_type": finding.finding_type,
            "domain": finding.domain,
            "url": finding.url,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "impact": finding.impact,
            "reproduction_steps": finding.reproduction_steps,
            "verified": finding.verified,
            "confidence": finding.confidence,
            "raw_response_code": finding.raw_response_code,
            "timestamp": finding.timestamp,
        }

    def _chain_to_dict(self, chain) -> dict:
        """Convert a Chain dataclass to a serializable dict."""
        return {
            "title": chain.title,
            "description": chain.description,
            "severity": chain.severity,
            "confidence": chain.confidence,
            "exploitability": chain.exploitability,
            "impact": chain.impact,
            "domains": chain.domains,
            "reproduction_steps": chain.reproduction_steps,
            "findings": [
                self._finding_to_dict(f) for f in chain.findings
            ],
        }

    def _format_duration(self, seconds: float) -> str:
        """Format seconds into human-readable duration."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            secs = int(seconds % 60)
            return f"{hours}h {minutes}m {secs}s"
