"""
Super Monster v1.0.0 - Multi-Format Report Generation System

Comprehensive reporting engine for bug bounty findings. Generates reports in
multiple formats (JSON, Markdown, HTML) with advanced visualization features:
- Correlation maps showing connections between findings as ASCII art graphs
- Attack path visualization with tree diagrams showing exploitation steps
- Priority-ranked finding lists with full scoring metadata
- Retest history timelines showing finding lifecycle progression
- Business impact assessments aggregated by domain and tier
- Bug bounty optimization recommendations for submission ordering
- HackerOne and Bugcrowd report templates with correlation context
- Dark-themed HTML reports with collapsible sections and severity badges
- Statistics dashboards with colored metrics and bar charts
- Domain risk scoring with tier-based multipliers
"""

import json
import os
import sys
import time
import hashlib
import html as html_module
import textwrap
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

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

from super_monster.config import (
    Colors,
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_BANNER,
    SEVERITY_LEVELS,
    SCORING_WEIGHTS,
    DOMAIN_TIERS,
    BOUNTY_ESTIMATES,
    REPORT_FORMAT_VERSION,
    REPORT_LIMITS,
    PLATFORM_CONFIG,
    get_domain_tier,
    get_bounty_estimate,
    calculate_priority_score,
)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ReportSection:
    """Represents a single section within a generated report."""

    title: str = ""
    content: str = ""
    section_type: str = "text"
    order: int = 0


# =============================================================================
# ASCII GRAPH BUILDER
# =============================================================================

class AsciiGraphBuilder:
    """Builds ASCII art graphs showing relationships between findings."""

    def __init__(self):
        self.nodes: Dict[str, Dict[str, str]] = {}
        self.edges: List[Dict[str, str]] = []

    def add_node(self, node_id: str, label: str, node_type: str = "default") -> None:
        """Add a node to the graph with a label and type."""
        self.nodes[node_id] = {"label": label, "type": node_type}

    def add_edge(self, from_node: str, to_node: str, label: str = "") -> None:
        """Add a directed edge between two nodes."""
        self.edges.append({
            "from": from_node,
            "to": to_node,
            "label": label,
        })

    def render(self) -> str:
        """Render the graph as ASCII art with boxes and connectors."""
        if not self.nodes:
            return "  (no nodes to display)"

        lines = []
        rendered_nodes = {}
        node_list = list(self.nodes.items())

        # Determine layout: group nodes by type
        type_groups: Dict[str, List[str]] = {}
        for nid, ndata in node_list:
            ntype = ndata["type"]
            if ntype not in type_groups:
                type_groups[ntype] = []
            type_groups[ntype].append(nid)

        # Render each group
        y_offset = 0
        for group_type, group_nodes in type_groups.items():
            if group_type != "default":
                lines.append(f"  [{group_type.upper()}]")
                lines.append("")

            for idx, nid in enumerate(group_nodes):
                label = self.nodes[nid]["label"]
                box_lines = self._draw_box(label, max(len(label) + 4, 30))
                for bl in box_lines:
                    lines.append(f"    {bl}")
                rendered_nodes[nid] = y_offset + len(box_lines) // 2
                y_offset += len(box_lines)

                # Draw connections from this node
                outgoing = [e for e in self.edges if e["from"] == nid]
                for edge in outgoing:
                    connector = self._draw_connector("down")
                    edge_label = edge["label"]
                    if edge_label:
                        lines.append(f"    {connector} --[{edge_label}]-->")
                    else:
                        lines.append(f"    {connector}")
                    y_offset += 1

            lines.append("")
            y_offset += 1

        return "\n".join(lines)

    def _draw_box(self, label: str, width: int) -> List[str]:
        """Draw an ASCII box around a label."""
        width = max(width, len(label) + 4)
        top = "+" + "-" * (width - 2) + "+"
        padding = width - 4 - len(label)
        left_pad = padding // 2
        right_pad = padding - left_pad
        middle = "| " + " " * left_pad + label + " " * right_pad + " |"
        bottom = "+" + "-" * (width - 2) + "+"
        return [top, middle, bottom]

    def _draw_connector(self, direction: str) -> str:
        """Draw a connector line in the given direction."""
        connectors = {
            "down": "|",
            "right": "-->",
            "left": "<--",
            "both": "<-->",
            "down_right": "+-->",
            "down_left": "<--+",
        }
        return connectors.get(direction, "|")



# =============================================================================
# BOUNTY REPORT TEMPLATE GENERATOR
# =============================================================================

class BountyReportTemplate:
    """Generates platform-specific bug bounty report templates."""

    def generate_hackerone(self, finding: Any, context: Dict[str, Any] = None) -> str:
        """Generate a HackerOne-formatted vulnerability report."""
        context = context or {}
        chain_desc = context.get("chain_description", "")
        related = context.get("related_findings", [])

        title = getattr(finding, "title", str(finding)) if hasattr(finding, "title") else str(finding)
        severity = getattr(finding, "severity", "MEDIUM")
        description = getattr(finding, "description", "")
        url = getattr(finding, "url", "")
        evidence = getattr(finding, "evidence", "")
        cvss = getattr(finding, "cvss_score", 0.0)
        cwe = getattr(finding, "cwe_id", "")
        remediation = getattr(finding, "remediation", "")
        finding_type = getattr(finding, "finding_type", "")

        report_lines = [
            f"## Summary",
            f"",
            f"**Title:** {title}",
            f"**Severity:** {severity}",
            f"**CVSS Score:** {cvss}",
            f"**CWE:** {cwe}" if cwe else "",
            f"**Vulnerability Type:** {finding_type}",
            f"",
            f"## Description",
            f"",
            description,
            f"",
        ]

        # Steps to reproduce
        report_lines.append("## Steps to Reproduce")
        report_lines.append("")
        steps = self._format_steps_to_reproduce(finding)
        report_lines.append(steps)
        report_lines.append("")

        # Supporting material / PoC
        report_lines.append("## Supporting Material / Proof of Concept")
        report_lines.append("")
        poc = self._format_poc_section(finding)
        report_lines.append(poc)
        report_lines.append("")

        # Impact
        report_lines.append("## Impact")
        report_lines.append("")
        impact = self._format_impact_statement(finding)
        report_lines.append(impact)
        report_lines.append("")

        # Attack chain context if available
        if chain_desc:
            report_lines.append("## Attack Chain Context")
            report_lines.append("")
            report_lines.append(f"This vulnerability is part of a broader attack chain:")
            report_lines.append(f"")
            report_lines.append(f"> {chain_desc}")
            report_lines.append("")
            if related:
                report_lines.append("**Related findings in this chain:**")
                for rf in related[:5]:
                    rf_title = getattr(rf, "title", str(rf))
                    rf_sev = getattr(rf, "severity", "")
                    report_lines.append(f"- [{rf_sev}] {rf_title}")
                report_lines.append("")

        # Remediation
        if remediation:
            report_lines.append("## Suggested Remediation")
            report_lines.append("")
            report_lines.append(remediation)
            report_lines.append("")

        return "\n".join(line for line in report_lines if line is not None)

    def generate_bugcrowd(self, finding: Any, context: Dict[str, Any] = None) -> str:
        """Generate a Bugcrowd-formatted vulnerability report."""
        context = context or {}
        chain_desc = context.get("chain_description", "")
        related = context.get("related_findings", [])

        title = getattr(finding, "title", str(finding))
        severity = getattr(finding, "severity", "MEDIUM")
        description = getattr(finding, "description", "")
        url = getattr(finding, "url", "")
        evidence = getattr(finding, "evidence", "")
        cvss = getattr(finding, "cvss_score", 0.0)
        cwe = getattr(finding, "cwe_id", "")
        remediation = getattr(finding, "remediation", "")
        finding_type = getattr(finding, "finding_type", "")

        # Map severity to Bugcrowd priority
        priority_map = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P5"}
        priority = priority_map.get(severity, "P3")

        report_lines = [
            f"# {title}",
            f"",
            f"**Priority:** {priority} ({severity})",
            f"**CVSS:** {cvss}",
            f"**CWE:** {cwe}" if cwe else "",
            f"**Type:** {finding_type}",
            f"**URL:** {url}" if url else "",
            f"",
            f"---",
            f"",
            f"## Vulnerability Details",
            f"",
            description,
            f"",
            f"## Reproduction Steps",
            f"",
        ]

        steps = self._format_steps_to_reproduce(finding)
        report_lines.append(steps)
        report_lines.append("")

        report_lines.append("## Proof of Concept")
        report_lines.append("")
        poc = self._format_poc_section(finding)
        report_lines.append(poc)
        report_lines.append("")

        report_lines.append("## Business Impact")
        report_lines.append("")
        impact = self._format_impact_statement(finding)
        report_lines.append(impact)
        report_lines.append("")

        if chain_desc:
            report_lines.append("## Attack Chain")
            report_lines.append("")
            report_lines.append(chain_desc)
            report_lines.append("")
            if related:
                report_lines.append("### Chained Vulnerabilities")
                for rf in related[:5]:
                    rf_title = getattr(rf, "title", str(rf))
                    rf_sev = getattr(rf, "severity", "")
                    report_lines.append(f"- **{rf_sev}**: {rf_title}")
                report_lines.append("")

        if remediation:
            report_lines.append("## Fix Recommendation")
            report_lines.append("")
            report_lines.append(remediation)
            report_lines.append("")

        return "\n".join(line for line in report_lines if line is not None)

    def generate_generic(self, finding: Any, context: Dict[str, Any] = None) -> str:
        """Generate a generic vulnerability report suitable for any platform."""
        context = context or {}
        chain_desc = context.get("chain_description", "")

        title = getattr(finding, "title", str(finding))
        severity = getattr(finding, "severity", "MEDIUM")
        description = getattr(finding, "description", "")
        url = getattr(finding, "url", "")
        evidence = getattr(finding, "evidence", "")
        cvss = getattr(finding, "cvss_score", 0.0)
        cwe = getattr(finding, "cwe_id", "")
        remediation = getattr(finding, "remediation", "")
        finding_type = getattr(finding, "finding_type", "")

        report_lines = [
            f"VULNERABILITY REPORT",
            f"=" * 60,
            f"",
            f"Title:      {title}",
            f"Severity:   {severity}",
            f"CVSS:       {cvss}",
            f"CWE:        {cwe}",
            f"Type:       {finding_type}",
            f"URL:        {url}",
            f"",
            f"-" * 60,
            f"DESCRIPTION",
            f"-" * 60,
            f"",
            description,
            f"",
            f"-" * 60,
            f"STEPS TO REPRODUCE",
            f"-" * 60,
            f"",
            self._format_steps_to_reproduce(finding),
            f"",
            f"-" * 60,
            f"PROOF OF CONCEPT",
            f"-" * 60,
            f"",
            self._format_poc_section(finding),
            f"",
            f"-" * 60,
            f"IMPACT",
            f"-" * 60,
            f"",
            self._format_impact_statement(finding),
            f"",
        ]

        if chain_desc:
            report_lines.extend([
                f"-" * 60,
                f"ATTACK CHAIN CONTEXT",
                f"-" * 60,
                f"",
                chain_desc,
                f"",
            ])

        if remediation:
            report_lines.extend([
                f"-" * 60,
                f"REMEDIATION",
                f"-" * 60,
                f"",
                remediation,
                f"",
            ])

        report_lines.append("=" * 60)
        return "\n".join(report_lines)

    def _format_steps_to_reproduce(self, finding: Any) -> str:
        """Format steps to reproduce from finding evidence."""
        url = getattr(finding, "url", "")
        evidence = getattr(finding, "evidence", "")
        finding_type = getattr(finding, "finding_type", "")

        steps = []
        step_num = 1

        if url:
            steps.append(f"{step_num}. Navigate to: {url}")
            step_num += 1

        if finding_type in ("cors", "missing_headers", "cookie_flags"):
            steps.append(f"{step_num}. Inspect the HTTP response headers")
            step_num += 1
            steps.append(f"{step_num}. Observe the misconfiguration in the response")
            step_num += 1
        elif finding_type in ("xss_reflected", "xss_stored", "xss_dom"):
            steps.append(f"{step_num}. Inject the XSS payload into the vulnerable parameter")
            step_num += 1
            steps.append(f"{step_num}. Observe JavaScript execution in the browser context")
            step_num += 1
        elif finding_type in ("sqli", "sqli_blind", "sqli_error"):
            steps.append(f"{step_num}. Inject SQL payload into the vulnerable parameter")
            step_num += 1
            steps.append(f"{step_num}. Observe database error or altered behavior")
            step_num += 1
        elif finding_type == "ssrf":
            steps.append(f"{step_num}. Provide a controlled URL as the parameter value")
            step_num += 1
            steps.append(f"{step_num}. Monitor the controlled server for incoming requests")
            step_num += 1
        elif finding_type in ("idor", "broken_access_control"):
            steps.append(f"{step_num}. Authenticate as a low-privilege user")
            step_num += 1
            steps.append(f"{step_num}. Modify resource identifiers to access other users' data")
            step_num += 1
        elif finding_type == "open_redirect":
            steps.append(f"{step_num}. Modify the redirect parameter to point to an external domain")
            step_num += 1
            steps.append(f"{step_num}. Observe the redirect to the attacker-controlled domain")
            step_num += 1
        else:
            steps.append(f"{step_num}. Observe the vulnerability behavior as described above")
            step_num += 1

        if evidence:
            steps.append(f"{step_num}. Evidence: {evidence[:500]}")

        return "\n".join(steps) if steps else "1. See description above for reproduction steps."

    def _format_impact_statement(self, finding: Any) -> str:
        """Format an impact statement based on finding type and severity."""
        severity = getattr(finding, "severity", "MEDIUM")
        finding_type = getattr(finding, "finding_type", "")
        domain = getattr(finding, "domain", "")

        impact_templates = {
            "CRITICAL": (
                "This vulnerability has a CRITICAL impact on the application's security posture. "
                "An attacker could exploit this to gain unauthorized access to sensitive systems, "
                "exfiltrate confidential data, or execute arbitrary code on the server."
            ),
            "HIGH": (
                "This vulnerability presents a HIGH risk to the application. "
                "Successful exploitation could lead to significant data exposure, "
                "unauthorized access to restricted functionality, or compromise of user accounts."
            ),
            "MEDIUM": (
                "This vulnerability presents a MEDIUM risk. While exploitation may require "
                "specific conditions, it could still lead to data exposure or limited "
                "unauthorized access if successfully exploited."
            ),
            "LOW": (
                "This vulnerability presents a LOW risk. While the direct impact is limited, "
                "it could provide information useful for further attacks or contribute to "
                "a broader attack chain."
            ),
            "INFO": (
                "This is an informational finding that indicates a potential area of concern. "
                "While not directly exploitable, it may indicate deeper issues or provide "
                "reconnaissance value to an attacker."
            ),
        }

        base_impact = impact_templates.get(severity, impact_templates["MEDIUM"])

        if domain:
            base_impact += f"\n\nAffected asset: {domain}"

        type_impacts = {
            "rce": "\n\nRemote code execution allows complete server compromise.",
            "sqli": "\n\nSQL injection enables extraction of entire database contents.",
            "auth_bypass": "\n\nAuthentication bypass grants unauthorized access to protected resources.",
            "ssrf": "\n\nSSRF can be used to access internal services and cloud metadata.",
            "xss_stored": "\n\nStored XSS affects all users viewing the affected page.",
            "idor": "\n\nIDOR enables access to other users' private data.",
        }

        if finding_type in type_impacts:
            base_impact += type_impacts[finding_type]

        return base_impact

    def _format_poc_section(self, finding: Any) -> str:
        """Format proof of concept section from finding evidence."""
        url = getattr(finding, "url", "")
        evidence = getattr(finding, "evidence", "")
        finding_type = getattr(finding, "finding_type", "")

        poc_lines = []

        if url:
            poc_lines.append(f"**Target URL:** `{url}`")
            poc_lines.append("")

        if evidence:
            poc_lines.append("**Evidence:**")
            poc_lines.append("```")
            poc_lines.append(evidence[:2000])
            poc_lines.append("```")
            poc_lines.append("")

        # Generate curl command
        if url:
            poc_lines.append("**Reproduction command:**")
            poc_lines.append("```bash")
            if finding_type == "cors":
                poc_lines.append(f'curl -s -I -H "Origin: https://evil.com" "{url}"')
            elif finding_type in ("missing_headers", "cookie_flags"):
                poc_lines.append(f'curl -s -I "{url}"')
            elif finding_type == "open_redirect":
                poc_lines.append(f'curl -s -I -L "{url}"')
            else:
                poc_lines.append(f'curl -s -v "{url}"')
            poc_lines.append("```")

        if not poc_lines:
            poc_lines.append("See evidence in the description section above.")

        return "\n".join(poc_lines)



# =============================================================================
# SUPER REPORTER - Main Report Generation Engine
# =============================================================================

class SuperReporter:
    """
    Multi-format report generator for Super Monster findings.

    Produces JSON, Markdown, and HTML reports with advanced visualizations
    including correlation maps, attack path trees, and bounty optimization
    recommendations.
    """

    def __init__(self, db=None, output_dir: str = "super_output"):
        """Initialize the reporter with optional database and output directory."""
        self.db = db
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.template_engine = BountyReportTemplate()
        self.graph_builder = AsciiGraphBuilder()

    def generate_all_reports(self, findings: List[Any], chains: List[Dict],
                            stats: Dict[str, Any]) -> Dict[str, str]:
        """Generate all three report formats and return paths to generated files."""
        reports_dir = self.output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results = {}

        # JSON Report
        json_content = self.generate_json_report(findings, chains, stats)
        json_path = reports_dir / f"super_report_{timestamp}.json"
        json_path.write_text(json_content, encoding="utf-8")
        results["json"] = str(json_path)

        # Markdown Report
        md_content = self.generate_markdown_report(findings, chains, stats)
        md_path = reports_dir / f"super_report_{timestamp}.md"
        md_path.write_text(md_content, encoding="utf-8")
        results["markdown"] = str(md_path)

        # HTML Report
        html_content = self.generate_html_report(findings, chains, stats)
        html_path = reports_dir / f"super_report_{timestamp}.html"
        html_path.write_text(html_content, encoding="utf-8")
        results["html"] = str(html_path)

        return results

    def generate_json_report(self, findings: List[Any], chains: List[Dict],
                            stats: Dict[str, Any]) -> str:
        """Generate a full JSON report with all sections."""
        report_data = self._build_report_data(findings, chains, stats)

        # Build full JSON structure
        json_report = {
            "report_metadata": {
                "generator": TOOL_NAME,
                "version": TOOL_VERSION,
                "report_format_version": REPORT_FORMAT_VERSION,
                "timestamp": self.generated_at,
                "total_findings": len(findings),
                "total_chains": len(chains),
                "generation_time_ms": int(time.time() * 1000),
            },
            "executive_summary": report_data["executive_summary"],
            "statistics": report_data["statistics"],
            "findings": [
                f.to_dict() if hasattr(f, "to_dict") else (
                    f if isinstance(f, dict) else {"raw": str(f)}
                )
                for f in findings
            ],
            "correlations": report_data["correlations"],
            "attack_chains": report_data["attack_paths"],
            "priority_rankings": report_data["priority_rankings"],
            "retest_timeline": report_data["retest_timeline"],
            "business_impact": report_data["business_impact"],
            "bounty_optimization": report_data["bounty_optimization"],
        }

        return json.dumps(json_report, indent=2, default=str)

    def generate_markdown_report(self, findings: List[Any], chains: List[Dict],
                                 stats: Dict[str, Any]) -> str:
        """Generate a detailed Markdown report with tables and ASCII art."""
        report_data = self._build_report_data(findings, chains, stats)
        sections = []

        # Header
        sections.append(f"# {TOOL_BANNER} - Security Assessment Report")
        sections.append("")
        sections.append(f"**Generated:** {self.generated_at}")
        sections.append(f"**Total Findings:** {len(findings)}")
        sections.append(f"**Attack Chains:** {len(chains)}")
        sections.append("")

        # Table of Contents
        sections.append("## Table of Contents")
        sections.append("")
        sections.append("1. [Executive Summary](#executive-summary)")
        sections.append("2. [Statistics Dashboard](#statistics-dashboard)")
        sections.append("3. [Correlation Map](#correlation-map)")
        sections.append("4. [Attack Paths](#attack-paths)")
        sections.append("5. [Priority Rankings](#priority-rankings)")
        sections.append("6. [Retest Timeline](#retest-timeline)")
        sections.append("7. [Business Impact](#business-impact)")
        sections.append("8. [Bounty Optimization](#bounty-optimization)")
        sections.append("9. [Detailed Findings](#detailed-findings)")
        sections.append("")

        # Executive Summary
        sections.append("## Executive Summary")
        sections.append("")
        exec_summary = report_data["executive_summary"]
        sections.append(f"**Risk Level:** {exec_summary.get('overall_risk_level', 'N/A')}")
        sections.append(f"**Risk Score:** {exec_summary.get('risk_score', 0):.1f}/10.0")
        sections.append(f"**Total Estimated Bounty:** ${exec_summary.get('total_bounty_estimate', 0):,.0f}")
        sections.append("")
        sections.append("### Severity Distribution")
        sections.append("")
        sev_dist = exec_summary.get("severity_distribution", {})
        for sev in SEVERITY_LEVELS:
            count = sev_dist.get(sev, 0)
            badge = self._format_severity_badge_md(sev)
            bar = "#" * min(count * 2, 40)
            sections.append(f"- {badge} `{bar}` ({count})")
        sections.append("")

        # Statistics Dashboard
        sections.append("## Statistics Dashboard")
        sections.append("")
        stats_data = report_data["statistics"]
        sections.append("### Finding Metrics")
        sections.append("")
        sections.append(f"| Metric | Value |")
        sections.append(f"|--------|-------|")
        sections.append(f"| Total Findings | {stats_data.get('total_findings', 0)} |")
        sections.append(f"| Unique Domains | {stats_data.get('unique_domains', 0)} |")
        sections.append(f"| Finding Types | {stats_data.get('unique_types', 0)} |")
        sections.append(f"| Avg CVSS | {stats_data.get('avg_cvss', 0):.1f} |")
        sections.append(f"| Max CVSS | {stats_data.get('max_cvss', 0):.1f} |")
        sections.append(f"| Fix Rate | {stats_data.get('fix_rate', 0):.1f}% |")
        sections.append("")

        # ASCII bar chart for severity
        sections.append("### Severity Distribution (Bar Chart)")
        sections.append("")
        sections.append("```")
        max_count = max(sev_dist.values()) if sev_dist else 1
        for sev in SEVERITY_LEVELS:
            count = sev_dist.get(sev, 0)
            bar_len = int((count / max(max_count, 1)) * 30)
            bar = "█" * bar_len
            sections.append(f"  {sev:10s} | {bar} ({count})")
        sections.append("```")
        sections.append("")

        # Type distribution
        sections.append("### Finding Type Distribution")
        sections.append("")
        type_dist = stats_data.get("type_distribution", {})
        if type_dist:
            headers = ["Type", "Count", "Avg CVSS"]
            rows = []
            for ftype, tdata in sorted(type_dist.items(), key=lambda x: x[1].get("count", 0), reverse=True)[:15]:
                if isinstance(tdata, dict):
                    rows.append([ftype, str(tdata.get("count", 0)), f"{tdata.get('avg_cvss', 0):.1f}"])
                else:
                    rows.append([ftype, str(tdata), "N/A"])
            sections.append(self._format_markdown_table(headers, rows))
        sections.append("")

        # Correlation Map
        sections.append("## Correlation Map")
        sections.append("")
        sections.append("```")
        correlation_map = self._generate_ascii_correlation_map(findings, chains)
        sections.append(correlation_map)
        sections.append("```")
        sections.append("")

        # Attack Paths
        sections.append("## Attack Paths")
        sections.append("")
        sections.append("```")
        attack_tree = self._generate_attack_tree_ascii(chains)
        sections.append(attack_tree)
        sections.append("```")
        sections.append("")

        # Priority Rankings
        sections.append("## Priority Rankings")
        sections.append("")
        priority_list = report_data["priority_rankings"]
        if priority_list:
            headers = ["#", "Title", "Severity", "CVSS", "Priority", "Bounty Est.", "Domain"]
            rows = []
            for idx, item in enumerate(priority_list[:30], 1):
                rows.append([
                    str(idx),
                    item.get("title", "N/A")[:40],
                    item.get("severity", "N/A"),
                    f"{item.get('cvss_score', 0):.1f}",
                    f"{item.get('priority_score', 0):.2f}",
                    f"${item.get('bounty_estimate', 0):,.0f}",
                    item.get("domain", "N/A")[:20],
                ])
            sections.append(self._format_markdown_table(headers, rows))
        else:
            sections.append("No findings to rank.")
        sections.append("")

        # Retest Timeline
        sections.append("## Retest Timeline")
        sections.append("")
        retest_timeline = report_data["retest_timeline"]
        if retest_timeline:
            for entry in retest_timeline[:20]:
                finding_title = entry.get("title", "Unknown")
                status = entry.get("latest_status", "unknown")
                retest_count = entry.get("retest_count", 0)
                last_tested = entry.get("last_retest", "never")
                sections.append(f"- **{finding_title}** [{status}] - Tested {retest_count}x (last: {last_tested})")
        else:
            sections.append("No retest history available.")
        sections.append("")

        # Business Impact
        sections.append("## Business Impact")
        sections.append("")
        biz_impact = report_data["business_impact"]
        domain_risks = biz_impact.get("domain_risks", {})
        if domain_risks:
            headers = ["Domain", "Tier", "Risk Score", "Findings", "Est. Bounty"]
            rows = []
            for domain, ddata in sorted(domain_risks.items(), key=lambda x: x[1].get("risk_score", 0), reverse=True):
                rows.append([
                    domain[:30],
                    ddata.get("tier", "N/A"),
                    f"{ddata.get('risk_score', 0):.1f}",
                    str(ddata.get("finding_count", 0)),
                    f"${ddata.get('bounty_total', 0):,.0f}",
                ])
            sections.append(self._format_markdown_table(headers, rows))
        else:
            sections.append("No domain impact data available.")
        sections.append("")

        # Bounty Optimization
        sections.append("## Bounty Optimization")
        sections.append("")
        bounty_opt = report_data["bounty_optimization"]
        sections.append(f"**Total Estimated Bounty:** ${bounty_opt.get('total_estimate', 0):,.0f}")
        sections.append(f"**Recommended Submission Order:**")
        sections.append("")
        submission_order = bounty_opt.get("submission_order", [])
        for idx, item in enumerate(submission_order[:15], 1):
            sections.append(
                f"{idx}. [{item.get('severity', 'N/A')}] {item.get('title', 'N/A')} "
                f"- Est. ${item.get('bounty_estimate', 0):,.0f} "
                f"(Dupe prob: {item.get('dupe_probability', 0):.0%})"
            )
        sections.append("")
        sections.append("### Optimization Tips")
        sections.append("")
        tips = bounty_opt.get("tips", [])
        for tip in tips:
            sections.append(f"- {tip}")
        sections.append("")

        # Detailed Findings
        sections.append("## Detailed Findings")
        sections.append("")
        for idx, finding in enumerate(findings[:REPORT_LIMITS.get("max_findings_per_page", 50)], 1):
            title = getattr(finding, "title", "Unknown") if hasattr(finding, "title") else finding.get("title", "Unknown") if isinstance(finding, dict) else str(finding)
            severity = getattr(finding, "severity", "INFO") if hasattr(finding, "severity") else finding.get("severity", "INFO") if isinstance(finding, dict) else "INFO"
            badge = self._format_severity_badge_md(severity)
            sections.append(f"### {idx}. {badge} {title}")
            sections.append("")

            desc = getattr(finding, "description", "") if hasattr(finding, "description") else finding.get("description", "") if isinstance(finding, dict) else ""
            url = getattr(finding, "url", "") if hasattr(finding, "url") else finding.get("url", "") if isinstance(finding, dict) else ""
            evidence = getattr(finding, "evidence", "") if hasattr(finding, "evidence") else finding.get("evidence", "") if isinstance(finding, dict) else ""

            if url:
                sections.append(f"**URL:** `{url}`")
            if desc:
                sections.append(f"**Description:** {desc[:500]}")
            if evidence:
                sections.append(f"**Evidence:** `{evidence[:300]}`")
            sections.append("")

        return "\n".join(sections)

    def generate_html_report(self, findings: List[Any], chains: List[Dict],
                            stats: Dict[str, Any]) -> str:
        """Generate a dark-themed HTML report with collapsible sections."""
        report_data = self._build_report_data(findings, chains, stats)
        html_template = self._get_html_template()

        # Build body content
        body_sections = []

        # Header section
        body_sections.append(f'<div class="report-header">')
        body_sections.append(f'  <h1>{html_module.escape(TOOL_BANNER)}</h1>')
        body_sections.append(f'  <p class="subtitle">Security Assessment Report</p>')
        body_sections.append(f'  <p class="meta">Generated: {html_module.escape(self.generated_at)} | '
                           f'Findings: {len(findings)} | Chains: {len(chains)}</p>')
        body_sections.append(f'</div>')

        # Stats cards
        stats_html = self._render_html_stats_cards(report_data["statistics"])
        body_sections.append(stats_html)

        # Executive Summary
        exec_summary = report_data["executive_summary"]
        exec_content = f'<p><strong>Risk Level:</strong> {html_module.escape(str(exec_summary.get("overall_risk_level", "N/A")))}</p>'
        exec_content += f'<p><strong>Risk Score:</strong> {exec_summary.get("risk_score", 0):.1f}/10.0</p>'
        exec_content += f'<p><strong>Total Estimated Bounty:</strong> ${exec_summary.get("total_bounty_estimate", 0):,.0f}</p>'
        sev_dist = exec_summary.get("severity_distribution", {})
        exec_content += '<div class="severity-bars">'
        for sev in SEVERITY_LEVELS:
            count = sev_dist.get(sev, 0)
            badge = self._format_severity_badge_html(sev)
            exec_content += f'<div class="sev-row">{badge} <span class="bar-count">{count}</span></div>'
        exec_content += '</div>'
        body_sections.append(self._render_html_section("Executive Summary", exec_content))

        # Findings section
        findings_html = ""
        for idx, finding in enumerate(findings[:REPORT_LIMITS.get("max_findings_per_page", 50)], 1):
            findings_html += self._render_html_finding_card(finding)
        body_sections.append(self._render_html_section("Findings", findings_html))

        # Correlation section
        corr_data = report_data["correlations"]
        corr_html = '<div class="correlation-section">'
        if corr_data.get("chains"):
            for chain in corr_data["chains"][:10]:
                corr_html += self._render_html_chain_card(chain)
        else:
            corr_html += '<p class="no-data">No correlation chains detected.</p>'
        corr_html += '</div>'
        body_sections.append(self._render_html_section("Correlation Chains", corr_html))

        # Attack Paths section
        attack_paths = report_data["attack_paths"]
        attack_html = '<div class="attack-paths">'
        if attack_paths.get("paths"):
            for path in attack_paths["paths"][:10]:
                attack_html += '<div class="attack-path-card">'
                attack_html += f'<h4>{html_module.escape(str(path.get("description", "Attack Path")))}</h4>'
                steps = path.get("steps", [])
                if steps:
                    attack_html += '<ol class="attack-steps">'
                    for step in steps:
                        attack_html += f'<li>{html_module.escape(str(step))}</li>'
                    attack_html += '</ol>'
                attack_html += '</div>'
        else:
            attack_html += '<p class="no-data">No attack paths identified.</p>'
        attack_html += '</div>'
        body_sections.append(self._render_html_section("Attack Paths", attack_html))

        # Priority Rankings
        priority_list = report_data["priority_rankings"]
        priority_html = ""
        if priority_list:
            headers = ["#", "Title", "Severity", "CVSS", "Priority", "Bounty"]
            rows = []
            for idx, item in enumerate(priority_list[:20], 1):
                rows.append([
                    str(idx),
                    html_module.escape(str(item.get("title", "N/A"))[:40]),
                    item.get("severity", "N/A"),
                    f"{item.get('cvss_score', 0):.1f}",
                    f"{item.get('priority_score', 0):.2f}",
                    f"${item.get('bounty_estimate', 0):,.0f}",
                ])
            priority_html = self._render_html_table(headers, rows)
        else:
            priority_html = '<p class="no-data">No priority rankings available.</p>'
        body_sections.append(self._render_html_section("Priority Rankings", priority_html))

        # Business Impact
        biz_impact = report_data["business_impact"]
        biz_html = '<div class="business-impact">'
        domain_risks = biz_impact.get("domain_risks", {})
        if domain_risks:
            headers = ["Domain", "Tier", "Risk Score", "Findings", "Bounty"]
            rows = []
            for domain, ddata in sorted(domain_risks.items(), key=lambda x: x[1].get("risk_score", 0), reverse=True):
                rows.append([
                    html_module.escape(domain[:30]),
                    ddata.get("tier", "N/A"),
                    f"{ddata.get('risk_score', 0):.1f}",
                    str(ddata.get("finding_count", 0)),
                    f"${ddata.get('bounty_total', 0):,.0f}",
                ])
            biz_html += self._render_html_table(headers, rows)
        else:
            biz_html += '<p class="no-data">No domain risk data available.</p>'
        biz_html += '</div>'
        body_sections.append(self._render_html_section("Business Impact", biz_html))

        # Bounty Optimization
        bounty_opt = report_data["bounty_optimization"]
        bounty_html = f'<p><strong>Total Estimated Bounty:</strong> ${bounty_opt.get("total_estimate", 0):,.0f}</p>'
        bounty_html += '<h4>Recommended Submission Order:</h4><ol>'
        for item in bounty_opt.get("submission_order", [])[:10]:
            sev = item.get("severity", "N/A")
            title = html_module.escape(str(item.get("title", "N/A")))
            est = item.get("bounty_estimate", 0)
            dupe = item.get("dupe_probability", 0)
            badge = self._format_severity_badge_html(sev)
            bounty_html += f'<li>{badge} {title} - ${est:,.0f} (Dupe: {dupe:.0%})</li>'
        bounty_html += '</ol>'
        tips = bounty_opt.get("tips", [])
        if tips:
            bounty_html += '<h4>Optimization Tips:</h4><ul>'
            for tip in tips:
                bounty_html += f'<li>{html_module.escape(tip)}</li>'
            bounty_html += '</ul>'
        body_sections.append(self._render_html_section("Bounty Optimization", bounty_html))

        # Assemble full HTML
        body_content = "\n".join(body_sections)
        full_html = html_template.replace("{{BODY_CONTENT}}", body_content)
        full_html = full_html.replace("{{TITLE}}", f"{TOOL_BANNER} Report")
        full_html = full_html.replace("{{GENERATED_AT}}", self.generated_at)

        return full_html

    def _build_report_data(self, findings: List[Any], chains: List[Dict],
                          stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build the complete report data structure from raw inputs."""
        return {
            "executive_summary": self._build_executive_summary(findings, chains, stats),
            "statistics": self._build_statistics_dashboard(findings, stats),
            "correlations": self._build_correlation_section(findings, chains),
            "attack_paths": self._build_attack_path_section(chains),
            "priority_rankings": self._build_priority_section(findings),
            "retest_timeline": self._build_retest_timeline(findings),
            "business_impact": self._build_business_impact(findings),
            "bounty_optimization": self._build_bounty_optimization(findings),
        }

    def _build_executive_summary(self, findings: List[Any], chains: List[Dict],
                                 stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build the executive summary section with overall risk assessment."""
        severity_dist = {}
        for sev in SEVERITY_LEVELS:
            severity_dist[sev] = 0

        total_bounty = 0.0
        for f in findings:
            sev = getattr(f, "severity", "INFO") if hasattr(f, "severity") else f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
            bounty = getattr(f, "bounty_estimate", 0) if hasattr(f, "bounty_estimate") else f.get("bounty_estimate", 0) if isinstance(f, dict) else 0
            total_bounty += float(bounty or 0)

        risk_score = self._calculate_risk_score(findings)

        if risk_score >= 8.0:
            risk_level = "CRITICAL"
        elif risk_score >= 6.0:
            risk_level = "HIGH"
        elif risk_score >= 4.0:
            risk_level = "MEDIUM"
        elif risk_score >= 2.0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        return {
            "overall_risk_level": risk_level,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "total_chains": len(chains),
            "severity_distribution": severity_dist,
            "total_bounty_estimate": total_bounty,
            "critical_count": severity_dist.get("CRITICAL", 0),
            "high_count": severity_dist.get("HIGH", 0),
            "domains_affected": len(set(
                getattr(f, "domain", "") if hasattr(f, "domain") else f.get("domain", "") if isinstance(f, dict) else ""
                for f in findings
            ) - {""}),
        }

    def _build_statistics_dashboard(self, findings: List[Any],
                                    stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build statistics dashboard with aggregated metrics."""
        if not findings:
            return {
                "total_findings": 0,
                "unique_domains": 0,
                "unique_types": 0,
                "avg_cvss": 0.0,
                "max_cvss": 0.0,
                "fix_rate": 0.0,
                "severity_distribution": {s: 0 for s in SEVERITY_LEVELS},
                "type_distribution": {},
            }

        domains = set()
        types = set()
        cvss_scores = []
        fixed_count = 0
        type_data = {}
        severity_dist = {s: 0 for s in SEVERITY_LEVELS}

        for f in findings:
            domain = getattr(f, "domain", "") if hasattr(f, "domain") else f.get("domain", "") if isinstance(f, dict) else ""
            ftype = getattr(f, "finding_type", "") if hasattr(f, "finding_type") else f.get("finding_type", "") if isinstance(f, dict) else ""
            cvss = getattr(f, "cvss_score", 0) if hasattr(f, "cvss_score") else f.get("cvss_score", 0) if isinstance(f, dict) else 0
            severity = getattr(f, "severity", "INFO") if hasattr(f, "severity") else f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
            status = getattr(f, "status", "new") if hasattr(f, "status") else f.get("status", "new") if isinstance(f, dict) else "new"

            if domain:
                domains.add(domain)
            if ftype:
                types.add(ftype)
                if ftype not in type_data:
                    type_data[ftype] = {"count": 0, "cvss_total": 0.0}
                type_data[ftype]["count"] += 1
                type_data[ftype]["cvss_total"] += float(cvss or 0)

            cvss_scores.append(float(cvss or 0))
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            if status == "fixed":
                fixed_count += 1

        # Compute averages for types
        type_distribution = {}
        for ftype, tdata in type_data.items():
            count = tdata["count"]
            type_distribution[ftype] = {
                "count": count,
                "avg_cvss": round(tdata["cvss_total"] / max(count, 1), 1),
            }

        total = len(findings)
        avg_cvss = sum(cvss_scores) / max(len(cvss_scores), 1)
        max_cvss = max(cvss_scores) if cvss_scores else 0.0
        fix_rate = (fixed_count / max(total, 1)) * 100

        return {
            "total_findings": total,
            "unique_domains": len(domains),
            "unique_types": len(types),
            "avg_cvss": round(avg_cvss, 1),
            "max_cvss": round(max_cvss, 1),
            "fix_rate": round(fix_rate, 1),
            "severity_distribution": severity_dist,
            "type_distribution": type_distribution,
            "fixed_count": fixed_count,
            "open_count": total - fixed_count,
        }


    def _build_correlation_section(self, findings: List[Any],
                                   chains: List[Dict]) -> Dict[str, Any]:
        """Build the correlation section with chain details."""
        processed_chains = []
        for chain in chains:
            chain_entry = {
                "chain_id": chain.get("chain_id", chain.get("id", "")),
                "description": chain.get("description", chain.get("chain_description", "")),
                "severity_boost": chain.get("severity_boost", ""),
                "confidence": chain.get("confidence", 0.0),
                "finding_ids": chain.get("finding_ids", chain.get("findings", [])),
                "finding_count": len(chain.get("finding_ids", chain.get("findings", []))),
                "chain_type": chain.get("chain_type", chain.get("rule_name", "")),
            }
            processed_chains.append(chain_entry)

        # Build correlation matrix showing finding relationships
        finding_ids = []
        for f in findings:
            fid = getattr(f, "id", "") if hasattr(f, "id") else f.get("id", "") if isinstance(f, dict) else ""
            if fid:
                finding_ids.append(fid)

        correlation_matrix = {}
        for chain in chains:
            chain_findings = chain.get("finding_ids", chain.get("findings", []))
            for fid in chain_findings:
                if fid not in correlation_matrix:
                    correlation_matrix[fid] = []
                for other_fid in chain_findings:
                    if other_fid != fid and other_fid not in correlation_matrix[fid]:
                        correlation_matrix[fid].append(other_fid)

        return {
            "chains": processed_chains,
            "total_chains": len(processed_chains),
            "correlation_matrix": correlation_matrix,
            "correlated_finding_count": len(correlation_matrix),
        }

    def _build_attack_path_section(self, chains: List[Dict]) -> Dict[str, Any]:
        """Build attack path section with exploitation scenarios."""
        paths = []
        for chain in chains:
            description = chain.get("description", chain.get("chain_description", "Unknown attack path"))
            findings_in_chain = chain.get("finding_ids", chain.get("findings", []))
            severity = chain.get("severity_boost", "HIGH")
            confidence = chain.get("confidence", 0.0)

            # Generate steps based on chain type
            chain_type = chain.get("chain_type", chain.get("rule_name", ""))
            steps = self._generate_attack_steps(chain_type, findings_in_chain)

            path_entry = {
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "steps": steps,
                "finding_count": len(findings_in_chain),
                "complexity": self._estimate_attack_complexity(chain_type),
                "prerequisites": self._get_attack_prerequisites(chain_type),
            }
            paths.append(path_entry)

        return {
            "paths": paths,
            "total_paths": len(paths),
            "highest_severity": max(
                (p.get("severity", "LOW") for p in paths),
                key=lambda s: SEVERITY_LEVELS.index(s) if s in SEVERITY_LEVELS else 99,
                default="N/A"
            ) if paths else "N/A",
        }

    def _generate_attack_steps(self, chain_type: str, finding_ids: List[str]) -> List[str]:
        """Generate exploitation steps based on chain type."""
        step_templates = {
            "auth_bypass_chain": [
                "Identify authentication weakness in target endpoint",
                "Craft bypass payload to circumvent authentication",
                "Access protected resources without valid credentials",
                "Enumerate additional endpoints accessible via bypass",
                "Extract sensitive data from unauthorized access",
            ],
            "ssrf_to_cloud": [
                "Identify SSRF injection point in target parameter",
                "Test internal network access via SSRF",
                "Access cloud metadata endpoint (169.254.169.254)",
                "Extract IAM credentials from metadata response",
                "Use extracted credentials for cloud infrastructure access",
            ],
            "xss_to_account_takeover": [
                "Inject XSS payload into vulnerable parameter",
                "Craft payload to exfiltrate session cookies",
                "Host cookie receiver on attacker-controlled server",
                "Capture victim session token via XSS execution",
                "Use stolen session to impersonate victim",
            ],
            "sqli_data_exfil": [
                "Identify SQL injection point in application",
                "Determine database type and version",
                "Enumerate database tables and columns",
                "Extract sensitive data (credentials, PII)",
                "Verify data integrity and completeness",
            ],
            "cors_data_theft": [
                "Identify permissive CORS configuration",
                "Create attacker-hosted page with cross-origin request",
                "Trick victim into visiting attacker page",
                "Read cross-origin response containing sensitive data",
                "Exfiltrate data to attacker server",
            ],
            "file_upload_rce": [
                "Identify file upload functionality",
                "Bypass file type restrictions (extension, MIME, magic bytes)",
                "Upload web shell or executable payload",
                "Access uploaded file via direct URL",
                "Execute arbitrary commands on the server",
            ],
        }

        steps = step_templates.get(chain_type, [
            "Identify initial vulnerability entry point",
            "Exploit the vulnerability to establish access",
            "Chain with related findings for escalated impact",
            "Achieve final objective (data access, code execution, etc.)",
        ])

        return steps

    def _estimate_attack_complexity(self, chain_type: str) -> str:
        """Estimate attack complexity for a chain type."""
        complexity_map = {
            "auth_bypass_chain": "MEDIUM",
            "ssrf_to_cloud": "MEDIUM",
            "xss_to_account_takeover": "LOW",
            "sqli_data_exfil": "LOW",
            "cors_data_theft": "LOW",
            "file_upload_rce": "HIGH",
            "open_redirect_phishing": "LOW",
            "subdomain_takeover_chain": "MEDIUM",
            "info_leak_to_access": "HIGH",
            "race_condition_abuse": "HIGH",
            "header_injection_chain": "MEDIUM",
            "idor_mass_data": "LOW",
        }
        return complexity_map.get(chain_type, "MEDIUM")

    def _get_attack_prerequisites(self, chain_type: str) -> List[str]:
        """Get prerequisites for an attack chain type."""
        prereq_map = {
            "auth_bypass_chain": ["Network access to target", "Valid test account (optional)"],
            "ssrf_to_cloud": ["Network access to target", "Cloud-hosted infrastructure"],
            "xss_to_account_takeover": ["Victim must visit attacker page or trigger XSS"],
            "sqli_data_exfil": ["Network access to target", "Vulnerable parameter identified"],
            "cors_data_theft": ["Victim must visit attacker page while authenticated"],
            "file_upload_rce": ["Network access to target", "File upload feature accessible"],
            "open_redirect_phishing": ["Victim must click crafted link"],
            "subdomain_takeover_chain": ["Dangling DNS record identified"],
            "info_leak_to_access": ["Information disclosure endpoint accessible"],
            "race_condition_abuse": ["Ability to send concurrent requests"],
        }
        return prereq_map.get(chain_type, ["Network access to target"])

    def _build_priority_section(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Build priority-ranked list of findings."""
        priority_list = []
        for f in findings:
            if hasattr(f, "title"):
                entry = {
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "priority_score": f.priority_score,
                    "bounty_estimate": f.bounty_estimate,
                    "domain": f.domain,
                    "finding_type": f.finding_type,
                    "dupe_probability": f.dupe_probability,
                    "status": f.status,
                }
            elif isinstance(f, dict):
                entry = {
                    "title": f.get("title", "Unknown"),
                    "severity": f.get("severity", "INFO"),
                    "cvss_score": f.get("cvss_score", 0.0),
                    "priority_score": f.get("priority_score", 0.0),
                    "bounty_estimate": f.get("bounty_estimate", 0.0),
                    "domain": f.get("domain", ""),
                    "finding_type": f.get("finding_type", ""),
                    "dupe_probability": f.get("dupe_probability", 0.0),
                    "status": f.get("status", "new"),
                }
            else:
                continue
            priority_list.append(entry)

        # Sort by priority score descending
        priority_list.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
        return priority_list

    def _build_retest_timeline(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Build retest timeline showing finding lifecycle."""
        timeline = []
        for f in findings:
            if hasattr(f, "retest_history"):
                retest_history = f.retest_history
                retest_count = f.retest_count
                last_retest = f.last_retest
                title = f.title
                status = f.status
                severity = f.severity
            elif isinstance(f, dict):
                retest_history = f.get("retest_history", [])
                retest_count = f.get("retest_count", 0)
                last_retest = f.get("last_retest", "")
                title = f.get("title", "Unknown")
                status = f.get("status", "new")
                severity = f.get("severity", "INFO")
            else:
                continue

            if retest_count > 0 or retest_history:
                latest_status = "unknown"
                if retest_history:
                    latest_entry = retest_history[-1] if isinstance(retest_history[-1], dict) else {"status": str(retest_history[-1])}
                    latest_status = latest_entry.get("status", latest_entry.get("result", "unknown"))
                else:
                    latest_status = status

                timeline.append({
                    "title": title,
                    "severity": severity,
                    "retest_count": retest_count,
                    "last_retest": last_retest or "N/A",
                    "latest_status": latest_status,
                    "history": retest_history[:10],
                })

        # Sort by retest count descending
        timeline.sort(key=lambda x: x.get("retest_count", 0), reverse=True)
        return timeline

    def _build_business_impact(self, findings: List[Any]) -> Dict[str, Any]:
        """Build business impact assessment grouped by domain."""
        domain_risks = self._calculate_domain_risk(findings)

        total_risk = sum(d.get("risk_score", 0) for d in domain_risks.values())
        affected_domains = len(domain_risks)
        highest_risk_domain = ""
        highest_risk_score = 0.0

        for domain, ddata in domain_risks.items():
            if ddata.get("risk_score", 0) > highest_risk_score:
                highest_risk_score = ddata["risk_score"]
                highest_risk_domain = domain

        return {
            "domain_risks": domain_risks,
            "total_risk_score": round(total_risk, 1),
            "affected_domains": affected_domains,
            "highest_risk_domain": highest_risk_domain,
            "highest_risk_score": round(highest_risk_score, 1),
        }

    def _build_bounty_optimization(self, findings: List[Any]) -> Dict[str, Any]:
        """Build bounty optimization recommendations."""
        submission_order = []
        total_estimate = 0.0

        for f in findings:
            if hasattr(f, "title"):
                entry = {
                    "title": f.title,
                    "severity": f.severity,
                    "bounty_estimate": float(f.bounty_estimate or 0),
                    "dupe_probability": float(f.dupe_probability or 0),
                    "priority_score": float(f.priority_score or 0),
                    "finding_type": f.finding_type,
                }
            elif isinstance(f, dict):
                entry = {
                    "title": f.get("title", "Unknown"),
                    "severity": f.get("severity", "INFO"),
                    "bounty_estimate": float(f.get("bounty_estimate", 0) or 0),
                    "dupe_probability": float(f.get("dupe_probability", 0) or 0),
                    "priority_score": float(f.get("priority_score", 0) or 0),
                    "finding_type": f.get("finding_type", ""),
                }
            else:
                continue

            total_estimate += entry["bounty_estimate"]
            submission_order.append(entry)

        # Sort by expected value (bounty * (1 - dupe_probability))
        submission_order.sort(
            key=lambda x: x["bounty_estimate"] * (1.0 - x["dupe_probability"]),
            reverse=True
        )

        # Generate optimization tips
        tips = self._generate_bounty_tips(submission_order)

        return {
            "total_estimate": round(total_estimate, 0),
            "submission_order": submission_order,
            "tips": tips,
            "optimal_count": len([s for s in submission_order if s["dupe_probability"] < 0.5]),
            "high_dupe_count": len([s for s in submission_order if s["dupe_probability"] >= 0.5]),
        }

    def _generate_bounty_tips(self, submission_order: List[Dict]) -> List[str]:
        """Generate actionable bounty optimization tips."""
        tips = []

        if not submission_order:
            tips.append("No findings available for bounty optimization.")
            return tips

        # Tip: Submit critical/high first
        critical_high = [s for s in submission_order if s["severity"] in ("CRITICAL", "HIGH")]
        if critical_high:
            tips.append(
                f"Submit {len(critical_high)} critical/high findings first for maximum payout potential."
            )

        # Tip: Avoid high dupe probability
        high_dupe = [s for s in submission_order if s["dupe_probability"] >= 0.5]
        if high_dupe:
            tips.append(
                f"{len(high_dupe)} findings have >50% dupe probability. Consider adding unique PoC details."
            )

        # Tip: Chain findings for higher impact
        chainable = [s for s in submission_order if s["finding_type"] in (
            "cors", "open_redirect", "info_disclosure", "ssrf"
        )]
        if chainable:
            tips.append(
                "Chain lower-severity findings together in a single report to demonstrate higher impact."
            )

        # Tip: Focus on unique finding types
        types_seen = set()
        unique_types = []
        for s in submission_order:
            if s["finding_type"] not in types_seen:
                types_seen.add(s["finding_type"])
                unique_types.append(s)
        if len(unique_types) < len(submission_order):
            tips.append(
                "Multiple findings of the same type detected. Group them or submit the highest-impact one first."
            )

        # Tip: Time-sensitive submissions
        tips.append(
            "Submit within program business hours for faster triage response times."
        )

        # Tip: Platform selection
        top_severity = submission_order[0]["severity"] if submission_order else "MEDIUM"
        if top_severity == "CRITICAL":
            tips.append(
                "For critical findings, HackerOne typically offers higher payouts than other platforms."
            )

        return tips


    def _generate_ascii_correlation_map(self, findings: List[Any],
                                        chains: List[Dict]) -> str:
        """Generate an ASCII art graph showing connections between findings."""
        if not chains:
            return "  No correlations detected - findings appear isolated.\n"

        builder = AsciiGraphBuilder()

        # Add finding nodes
        finding_map = {}
        for f in findings:
            fid = getattr(f, "id", "") if hasattr(f, "id") else f.get("id", "") if isinstance(f, dict) else ""
            title = getattr(f, "title", "") if hasattr(f, "title") else f.get("title", "") if isinstance(f, dict) else ""
            severity = getattr(f, "severity", "INFO") if hasattr(f, "severity") else f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
            if fid:
                finding_map[fid] = {"title": title[:25], "severity": severity}
                builder.add_node(fid, f"[{severity}] {title[:25]}", severity.lower())

        # Add edges from chains
        for chain in chains:
            chain_findings = chain.get("finding_ids", chain.get("findings", []))
            description = chain.get("description", chain.get("chain_description", ""))[:30]
            for i in range(len(chain_findings) - 1):
                from_id = chain_findings[i]
                to_id = chain_findings[i + 1]
                if from_id in finding_map and to_id in finding_map:
                    builder.add_edge(from_id, to_id, description)

        rendered = builder.render()

        # Add legend
        legend = [
            "",
            "  LEGEND:",
            "  +------+    Boxes represent individual findings",
            "  | Node | -> Arrows show exploitation flow direction",
            "  +------+    Labels show chain description",
            "",
            f"  Total Nodes: {len(finding_map)}",
            f"  Total Chains: {len(chains)}",
        ]

        return rendered + "\n" + "\n".join(legend)

    def _generate_attack_tree_ascii(self, chains: List[Dict]) -> str:
        """Generate an ASCII art tree showing exploitation paths."""
        if not chains:
            return "  No attack paths identified.\n"

        lines = []
        lines.append("  ATTACK PATH TREE")
        lines.append("  " + "=" * 50)
        lines.append("")
        lines.append("  [ATTACKER] (Unauthenticated)")
        lines.append("       |")

        for idx, chain in enumerate(chains[:8]):
            description = chain.get("description", chain.get("chain_description", "Unknown"))[:45]
            severity = chain.get("severity_boost", "HIGH")
            confidence = chain.get("confidence", 0.0)
            chain_type = chain.get("chain_type", chain.get("rule_name", "unknown"))

            is_last = idx == min(len(chains), 8) - 1
            branch = "└" if is_last else "├"
            continuation = " " if is_last else "│"

            lines.append(f"       {branch}── [{severity}] {description}")

            # Show steps for this path
            steps = self._generate_attack_steps(chain_type, [])
            for step_idx, step in enumerate(steps[:4]):
                step_branch = "└" if step_idx == min(len(steps), 4) - 1 else "├"
                lines.append(f"       {continuation}       {step_branch}── {step[:50]}")

            # Show confidence and complexity
            complexity = self._estimate_attack_complexity(chain_type)
            lines.append(f"       {continuation}       ")
            lines.append(f"       {continuation}       [Confidence: {confidence:.0%} | Complexity: {complexity}]")
            lines.append(f"       {continuation}")

        lines.append("")
        lines.append("  " + "-" * 50)
        lines.append(f"  Total Attack Paths: {len(chains)}")
        lines.append(f"  Highest Severity Path: {chains[0].get('severity_boost', 'N/A') if chains else 'N/A'}")
        lines.append("")

        return "\n".join(lines)

    def _generate_hackerone_template(self, finding: Any) -> str:
        """Generate a HackerOne report template for a single finding."""
        return self.template_engine.generate_hackerone(finding, {})

    def _generate_bugcrowd_template(self, finding: Any) -> str:
        """Generate a Bugcrowd report template for a single finding."""
        return self.template_engine.generate_bugcrowd(finding, {})

    def _format_markdown_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Format a markdown table with proper alignment."""
        if not headers:
            return ""

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        # Build header
        header_line = "| " + " | ".join(
            h.ljust(widths[i]) for i, h in enumerate(headers)
        ) + " |"
        separator = "|" + "|".join(
            "-" * (widths[i] + 2) for i in range(len(headers))
        ) + "|"

        # Build rows
        table_lines = [header_line, separator]
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                width = widths[i] if i < len(widths) else 10
                cells.append(str(cell).ljust(width))
            table_lines.append("| " + " | ".join(cells) + " |")

        return "\n".join(table_lines)

    def _format_severity_badge_md(self, severity: str) -> str:
        """Format a severity badge for Markdown output."""
        badge_map = {
            "CRITICAL": "🔴 **CRITICAL**",
            "HIGH": "🟠 **HIGH**",
            "MEDIUM": "🟡 **MEDIUM**",
            "LOW": "🔵 **LOW**",
            "INFO": "⚪ **INFO**",
        }
        return badge_map.get(severity.upper(), f"**{severity}**")

    def _format_severity_badge_html(self, severity: str) -> str:
        """Format a severity badge for HTML output."""
        color_map = {
            "CRITICAL": "#ff4444",
            "HIGH": "#ff8c00",
            "MEDIUM": "#ffd700",
            "LOW": "#4488ff",
            "INFO": "#999999",
        }
        color = color_map.get(severity.upper(), "#999999")
        sev_text = html_module.escape(severity.upper())
        return (
            f'<span class="severity-badge" style="background-color: {color}; '
            f'color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; '
            f'font-weight: bold;">{sev_text}</span>'
        )

    def _get_html_template(self) -> str:
        """Get the dark-theme HTML template with embedded CSS."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #1a1a2e;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }
        .report-header {
            background: linear-gradient(135deg, #0f3460, #16213e);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
            border: 1px solid #0f3460;
        }
        .report-header h1 {
            color: #e94560;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .report-header .subtitle {
            color: #a0a0b0;
            font-size: 1.2em;
        }
        .report-header .meta {
            color: #808090;
            font-size: 0.9em;
            margin-top: 10px;
        }
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background-color: #16213e;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #0f3460;
        }
        .stat-card .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .stat-label {
            color: #808090;
            font-size: 0.9em;
        }
        .stat-critical { color: #ff4444; }
        .stat-high { color: #ff8c00; }
        .stat-medium { color: #ffd700; }
        .stat-low { color: #4488ff; }
        .stat-info { color: #999999; }
        .stat-success { color: #44ff44; }
        details {
            background-color: #16213e;
            border: 1px solid #0f3460;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }
        summary {
            background-color: #0f3460;
            padding: 15px 20px;
            cursor: pointer;
            font-size: 1.2em;
            font-weight: bold;
            color: #e0e0e0;
        }
        summary:hover {
            background-color: #1a4080;
        }
        .section-content {
            padding: 20px;
        }
        .finding-card {
            background-color: #1a1a2e;
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
        }
        .finding-card h4 {
            color: #e0e0e0;
            margin-bottom: 8px;
        }
        .finding-card .finding-meta {
            color: #808090;
            font-size: 0.85em;
            margin-bottom: 8px;
        }
        .finding-card .finding-desc {
            color: #c0c0c0;
            font-size: 0.9em;
        }
        .chain-card {
            background-color: #1a1a2e;
            border: 1px solid #e94560;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
        }
        .chain-card h4 { color: #e94560; }
        .attack-path-card {
            background-color: #1a1a2e;
            border-left: 3px solid #ff8c00;
            padding: 12px 15px;
            margin-bottom: 10px;
        }
        .attack-path-card h4 { color: #ff8c00; margin-bottom: 8px; }
        .attack-steps { margin-left: 20px; color: #c0c0c0; }
        .attack-steps li { margin-bottom: 4px; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th {
            background-color: #0f3460;
            color: #e0e0e0;
            padding: 10px;
            text-align: left;
            font-size: 0.9em;
        }
        td {
            padding: 8px 10px;
            border-bottom: 1px solid #16213e;
            color: #c0c0c0;
            font-size: 0.85em;
        }
        tr:hover td { background-color: #1a2a4e; }
        .severity-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: #fff;
        }
        .severity-bars { margin: 10px 0; }
        .sev-row { margin: 5px 0; }
        .bar-count { margin-left: 10px; color: #808090; }
        .no-data { color: #606070; font-style: italic; padding: 20px; }
        .business-impact { margin: 10px 0; }
        a { color: #4488ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code {
            background-color: #0f3460;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        .correlation-section { margin: 10px 0; }
    </style>
</head>
<body>
{{BODY_CONTENT}}
<footer style="text-align: center; margin-top: 40px; padding: 20px; color: #606070; border-top: 1px solid #0f3460;">
    <p>Generated by {{TITLE}} on {{GENERATED_AT}}</p>
</footer>
</body>
</html>'''

    def _render_html_section(self, title: str, content: str) -> str:
        """Render a collapsible HTML section using details/summary."""
        safe_title = html_module.escape(title)
        return f'''<details open>
    <summary>{safe_title}</summary>
    <div class="section-content">
        {content}
    </div>
</details>'''

    def _render_html_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Render an HTML table with headers and rows."""
        html_parts = ['<table>']
        html_parts.append('<thead><tr>')
        for h in headers:
            html_parts.append(f'<th>{html_module.escape(str(h))}</th>')
        html_parts.append('</tr></thead>')
        html_parts.append('<tbody>')
        for row in rows:
            html_parts.append('<tr>')
            for cell in row:
                html_parts.append(f'<td>{str(cell)}</td>')
            html_parts.append('</tr>')
        html_parts.append('</tbody>')
        html_parts.append('</table>')
        return "\n".join(html_parts)

    def _render_html_stats_cards(self, stats: Dict[str, Any]) -> str:
        """Render statistics as colored card widgets."""
        sev_dist = stats.get("severity_distribution", {})
        cards = [
            ("Total Findings", stats.get("total_findings", 0), "stat-info"),
            ("Critical", sev_dist.get("CRITICAL", 0), "stat-critical"),
            ("High", sev_dist.get("HIGH", 0), "stat-high"),
            ("Medium", sev_dist.get("MEDIUM", 0), "stat-medium"),
            ("Low", sev_dist.get("LOW", 0), "stat-low"),
            ("Domains", stats.get("unique_domains", 0), "stat-info"),
            ("Avg CVSS", f"{stats.get('avg_cvss', 0):.1f}", "stat-medium"),
            ("Fix Rate", f"{stats.get('fix_rate', 0):.0f}%", "stat-success"),
        ]

        html_parts = ['<div class="stats-container">']
        for label, value, css_class in cards:
            html_parts.append(f'''<div class="stat-card">
    <div class="stat-value {css_class}">{value}</div>
    <div class="stat-label">{html_module.escape(label)}</div>
</div>''')
        html_parts.append('</div>')
        return "\n".join(html_parts)


    def _render_html_finding_card(self, finding: Any) -> str:
        """Render a single finding as an HTML card with all metadata."""
        if hasattr(finding, "title"):
            title = finding.title
            severity = finding.severity
            cvss = finding.cvss_score
            url = finding.url
            description = finding.description
            finding_type = finding.finding_type
            domain = finding.domain
            cwe = finding.cwe_id
            status = finding.status
            priority = finding.priority_score
            bounty = finding.bounty_estimate
        elif isinstance(finding, dict):
            title = finding.get("title", "Unknown")
            severity = finding.get("severity", "INFO")
            cvss = finding.get("cvss_score", 0.0)
            url = finding.get("url", "")
            description = finding.get("description", "")
            finding_type = finding.get("finding_type", "")
            domain = finding.get("domain", "")
            cwe = finding.get("cwe_id", "")
            status = finding.get("status", "new")
            priority = finding.get("priority_score", 0.0)
            bounty = finding.get("bounty_estimate", 0.0)
        else:
            return f'<div class="finding-card"><p>{html_module.escape(str(finding))}</p></div>'

        badge = self._format_severity_badge_html(severity)
        safe_title = html_module.escape(str(title))
        safe_desc = html_module.escape(str(description)[:500])
        safe_url = html_module.escape(str(url))
        safe_type = html_module.escape(str(finding_type))
        safe_domain = html_module.escape(str(domain))
        safe_cwe = html_module.escape(str(cwe))

        return f'''<div class="finding-card">
    <h4>{badge} {safe_title}</h4>
    <div class="finding-meta">
        Type: {safe_type} | Domain: {safe_domain} | CVSS: {cvss} | CWE: {safe_cwe} |
        Status: {html_module.escape(str(status))} | Priority: {priority:.2f} | Est. Bounty: ${float(bounty or 0):,.0f}
    </div>
    <div class="finding-desc">{safe_desc}</div>
    {f'<div class="finding-meta" style="margin-top: 8px;">URL: <code>{safe_url}</code></div>' if url else ''}
</div>'''

    def _render_html_chain_card(self, chain: Dict[str, Any]) -> str:
        """Render a correlation chain as an HTML card."""
        chain_id = chain.get("chain_id", chain.get("id", "N/A"))
        description = chain.get("description", "Unknown chain")
        severity = chain.get("severity_boost", "HIGH")
        confidence = chain.get("confidence", 0.0)
        finding_count = chain.get("finding_count", 0)
        chain_type = chain.get("chain_type", "")

        badge = self._format_severity_badge_html(severity)
        safe_desc = html_module.escape(str(description))
        safe_type = html_module.escape(str(chain_type))

        return f'''<div class="chain-card">
    <h4>{badge} {safe_desc}</h4>
    <div class="finding-meta">
        Chain ID: {html_module.escape(str(chain_id))} |
        Type: {safe_type} |
        Confidence: {confidence:.0%} |
        Findings: {finding_count}
    </div>
</div>'''

    def _calculate_risk_score(self, findings: List[Any]) -> float:
        """Calculate overall risk score from 0-10 based on findings."""
        if not findings:
            return 0.0

        severity_weights = {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 2.0,
            "INFO": 0.5,
        }

        total_weight = 0.0
        for f in findings:
            severity = getattr(f, "severity", "INFO") if hasattr(f, "severity") else f.get("severity", "INFO") if isinstance(f, dict) else "INFO"
            cvss = getattr(f, "cvss_score", 0) if hasattr(f, "cvss_score") else f.get("cvss_score", 0) if isinstance(f, dict) else 0
            weight = severity_weights.get(severity, 1.0)
            # Combine severity weight with CVSS
            combined = (weight + float(cvss or 0)) / 2.0
            total_weight += combined

        # Normalize: more findings = higher risk, but with diminishing returns
        count = len(findings)
        if count == 0:
            return 0.0

        avg_score = total_weight / count
        # Apply count bonus with logarithmic scaling
        import math
        count_bonus = min(math.log2(count + 1) * 0.5, 2.0)
        risk = min(avg_score + count_bonus, 10.0)

        return round(risk, 1)

    def _calculate_domain_risk(self, findings: List[Any]) -> Dict[str, Any]:
        """Calculate risk scores grouped by domain."""
        domain_data: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            if hasattr(f, "domain"):
                domain = f.domain
                severity = f.severity
                cvss = f.cvss_score
                bounty = f.bounty_estimate
            elif isinstance(f, dict):
                domain = f.get("domain", "")
                severity = f.get("severity", "INFO")
                cvss = f.get("cvss_score", 0)
                bounty = f.get("bounty_estimate", 0)
            else:
                continue

            if not domain:
                domain = "unknown"

            if domain not in domain_data:
                tier_name, tier_mult = get_domain_tier(domain)
                domain_data[domain] = {
                    "tier": tier_name,
                    "tier_multiplier": tier_mult,
                    "finding_count": 0,
                    "findings_by_severity": {s: 0 for s in SEVERITY_LEVELS},
                    "cvss_total": 0.0,
                    "bounty_total": 0.0,
                    "risk_score": 0.0,
                }

            domain_data[domain]["finding_count"] += 1
            domain_data[domain]["findings_by_severity"][severity] = \
                domain_data[domain]["findings_by_severity"].get(severity, 0) + 1
            domain_data[domain]["cvss_total"] += float(cvss or 0)
            domain_data[domain]["bounty_total"] += float(bounty or 0)

        # Calculate risk scores per domain
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0.5}
        for domain, ddata in domain_data.items():
            weighted_sum = 0.0
            for sev, count in ddata["findings_by_severity"].items():
                weighted_sum += severity_weights.get(sev, 1) * count

            count = ddata["finding_count"]
            if count > 0:
                avg_weighted = weighted_sum / count
                multiplier = ddata["tier_multiplier"]
                # Risk = avg severity weight * tier multiplier, capped at 10
                risk = min(avg_weighted * multiplier * 0.5, 10.0)
                ddata["risk_score"] = round(risk, 1)

        return domain_data

