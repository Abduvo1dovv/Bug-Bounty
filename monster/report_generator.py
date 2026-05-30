"""
Monster - Professional Bug Bounty Report Generator.

Generates reports in multiple formats (JSON, Markdown, HTML) with CVSS 3.1
scoring, HackerOne-format findings, and executive summaries.
"""

import json
import math
import os
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

from monster.utils import ColorOutput, FileManager


# ---------------------------------------------------------------------------
# CVSS 3.1 Calculator
# ---------------------------------------------------------------------------

class CVSSCalculator:
    """CVSS 3.1 Base Score calculator."""

    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_VALUES_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_VALUES = {"N": 0.85, "R": 0.62}
    CIA_VALUES = {"H": 0.56, "L": 0.22, "N": 0.0}

    def calculate(self, vector_string):
        """
        Calculate CVSS 3.1 base score from a vector string.

        Args:
            vector_string: e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        Returns:
            Float score between 0.0 and 10.0
        """
        metrics = {}
        for part in vector_string.replace("CVSS:3.1/", "").split("/"):
            if ":" in part:
                key, val = part.split(":", 1)
                metrics[key.upper()] = val.upper()

        av = self.AV_VALUES.get(metrics.get("AV", "N"), 0.85)
        ac = self.AC_VALUES.get(metrics.get("AC", "L"), 0.77)
        ui = self.UI_VALUES.get(metrics.get("UI", "N"), 0.85)

        scope_changed = metrics.get("S", "U") == "C"

        if scope_changed:
            pr = self.PR_VALUES_C.get(metrics.get("PR", "N"), 0.85)
        else:
            pr = self.PR_VALUES_U.get(metrics.get("PR", "N"), 0.85)

        c = self.CIA_VALUES.get(metrics.get("C", "N"), 0.0)
        i = self.CIA_VALUES.get(metrics.get("I", "N"), 0.0)
        a = self.CIA_VALUES.get(metrics.get("A", "N"), 0.0)

        # Impact Sub-Score
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if iss <= 0:
            return 0.0

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return 0.0

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round up to 1 decimal
        return math.ceil(base_score * 10) / 10.0

    @staticmethod
    def severity_from_score(score):
        """Map CVSS score to severity string."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "INFO"


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Professional bug bounty report generator with multiple output formats."""

    def __init__(self, output_dir="./output"):
        self.output_dir = output_dir
        self.file_mgr = FileManager(output_dir)
        self.cvss = CVSSCalculator()

    def generate_full_report(self, scan_results, metadata=None):
        """
        Generate all report formats from scan results.

        Args:
            scan_results: Dict with keys like 'recon', 'js_analysis', 'vulnerabilities'
            metadata: Dict with scan metadata (target, duration, modules)
        """
        metadata = metadata or {}
        findings = scan_results.get("vulnerabilities", {}).get("findings", [])

        ColorOutput.info("Generating reports...")

        self.generate_json_report(scan_results, metadata)
        self.generate_markdown_report(findings, metadata)
        self.generate_html_report(findings, scan_results, metadata)
        self.generate_executive_summary(findings, metadata)

        # Individual finding reports
        findings_dir = os.path.join(self.output_dir, "findings")
        os.makedirs(findings_dir, exist_ok=True)
        for idx, finding in enumerate(findings, 1):
            report = self.generate_hackerone_report(finding)
            ftype = finding.get("finding_type", "finding").lower().replace(" ", "_")
            filepath = os.path.join(findings_dir, f"{ftype}_{idx:03d}.md")
            with open(filepath, "w") as f:
                f.write(report)

        ColorOutput.success(f"Reports saved to {self.output_dir}")

    def generate_json_report(self, scan_results, metadata=None):
        """Generate machine-readable JSON report."""
        metadata = metadata or {}
        report = {
            "metadata": {
                "tool": "Monster v1.0",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "target": metadata.get("target", "unknown"),
                "duration": metadata.get("duration", 0),
                "modules": metadata.get("modules", []),
            },
            "statistics": self._calculate_statistics(scan_results),
            "results": scan_results,
        }
        self.file_mgr.save_json(report, "report.json")
        ColorOutput.success(f"JSON report: {os.path.join(self.output_dir, 'report.json')}")

    def generate_markdown_report(self, findings, metadata=None):
        """Generate formatted Markdown report."""
        metadata = metadata or {}
        target = metadata.get("target", "Unknown Target")
        lines = []

        lines.append(f"# Monster Security Report - {target}")
        lines.append("")
        lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}")
        lines.append("**Tool:** Monster v1.0")
        lines.append("")

        lines.append("## Table of Contents")
        lines.append("")
        lines.append("1. [Executive Summary](#executive-summary)")
        lines.append("2. [Findings Overview](#findings-overview)")
        lines.append("3. [Detailed Findings](#detailed-findings)")
        lines.append("4. [Remediation Priorities](#remediation-priorities)")
        lines.append("")

        lines.append("## Executive Summary")
        lines.append("")
        counts = self._count_severities(findings)
        lines.append(f"Total findings: **{len(findings)}**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")
        lines.append("")

        lines.append("## Findings Overview")
        lines.append("")
        lines.append("| # | Severity | Title | URL |")
        lines.append("|---|----------|-------|-----|")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            url = f.get("url", "N/A")
            lines.append(f"| {idx} | {sev} | {title} | {url} |")
        lines.append("")

        lines.append("## Detailed Findings")
        lines.append("")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            lines.append(f"### {idx}. [{sev}] {f.get('title', 'Unknown')}")
            lines.append("")
            lines.append(f"**Type:** {f.get('finding_type', 'N/A')}")
            lines.append(f"**URL:** {f.get('url', 'N/A')}")
            lines.append(f"**CVSS:** {f.get('cvss_score', 0.0)}")
            lines.append(f"**CWE:** {f.get('cwe_id', 'N/A')}")
            lines.append("")
            lines.append(f"**Description:** {f.get('description', '')}")
            lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f.get("evidence", ""))
                lines.append("```")
                lines.append("")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f.get('remediation', '')}")
                lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("## Remediation Priorities")
        lines.append("")
        lines.append("1. Address all CRITICAL and HIGH severity findings immediately")
        lines.append("2. Plan remediation for MEDIUM findings within 30 days")
        lines.append("3. Address LOW findings during regular maintenance cycles")
        lines.append("")

        content = "\n".join(lines)
        self.file_mgr.save_text(content, "report.md")
        ColorOutput.success(f"Markdown report: {os.path.join(self.output_dir, 'report.md')}")

    def generate_html_report(self, findings, scan_results=None, metadata=None):
        """Generate dark-themed HTML dashboard report."""
        metadata = metadata or {}
        scan_results = scan_results or {}
        target = metadata.get("target", "Unknown Target")
        counts = self._count_severities(findings)
        total = len(findings)
        timestamp = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())

        html_parts = []
        html_parts.append('<!DOCTYPE html>\n<html lang="en">\n<head>')
        html_parts.append('<meta charset="UTF-8">')
        html_parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_parts.append(f'<title>Monster Report - {target}</title>')
        html_parts.append('<style>')
        html_parts.append(self._get_css())
        html_parts.append('</style>')
        html_parts.append('</head>\n<body>\n<div class="container">')
        html_parts.append(f'<h1>Monster Security Report</h1>')
        html_parts.append(f'<p class="meta">Target: {target} | Generated: {timestamp}</p>')
        html_parts.append('<h2>Statistics</h2>')
        html_parts.append('<div class="stats">')
        for sev_name, sev_class in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low"), ("INFO", "info")]:
            html_parts.append(f'<div class="stat-card {sev_class}"><div class="number">{counts.get(sev_name, 0)}</div><div class="label">{sev_name}</div></div>')
        html_parts.append(f'<div class="stat-card"><div class="number">{total}</div><div class="label">Total</div></div>')
        html_parts.append('</div>')
        html_parts.append('<h2>Findings</h2>')

        for f in findings:
            sev = f.get("severity", "INFO").lower()
            title = f.get("title", "Unknown")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            url = f.get("url", "")
            remediation = f.get("remediation", "")
            cvss_val = f.get("cvss_score", 0.0)
            cwe = f.get("cwe_id", "")

            html_parts.append(f'<div class="finding {sev}">')
            html_parts.append(f'<div class="finding-title"><span class="badge {sev}">{sev.upper()}</span> {title}</div>')
            html_parts.append(f'<div class="detail"><strong>URL:</strong> {url}</div>')
            html_parts.append(f'<div class="detail"><strong>CVSS:</strong> {cvss_val} | <strong>CWE:</strong> {cwe}</div>')
            html_parts.append(f'<div class="detail">{desc}</div>')
            if evidence:
                html_parts.append(f'<div class="evidence">{evidence}</div>')
            if remediation:
                html_parts.append(f'<div class="detail"><strong>Fix:</strong> {remediation}</div>')
            html_parts.append('</div>')

        html_parts.append('<footer><p>Generated by Monster v1.0 - Bug Bounty Intelligence Platform</p></footer>')
        html_parts.append('</div>\n</body>\n</html>')

        html = "\n".join(html_parts)
        self.file_mgr.save_html(html, "report.html")
        ColorOutput.success(f"HTML report: {os.path.join(self.output_dir, 'report.html')}")

    def generate_executive_summary(self, findings, metadata=None):
        """Generate a quick text executive summary."""
        metadata = metadata or {}
        target = metadata.get("target", "Unknown")
        counts = self._count_severities(findings)
        total = len(findings)

        lines = []
        lines.append("=" * 60)
        lines.append("MONSTER - EXECUTIVE SECURITY SUMMARY")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Target: {target}")
        lines.append(f"Date: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}")
        lines.append(f"Total Findings: {total}")
        lines.append("")
        lines.append("SEVERITY BREAKDOWN:")
        lines.append(f"  Critical: {counts.get('CRITICAL', 0)}")
        lines.append(f"  High:     {counts.get('HIGH', 0)}")
        lines.append(f"  Medium:   {counts.get('MEDIUM', 0)}")
        lines.append(f"  Low:      {counts.get('LOW', 0)}")
        lines.append(f"  Info:     {counts.get('INFO', 0)}")
        lines.append("")

        critical_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if critical_high:
            lines.append("TOP PRIORITY ISSUES:")
            for idx, f in enumerate(critical_high[:5], 1):
                lines.append(f"  {idx}. [{f.get('severity')}] {f.get('title')} - {f.get('url')}")
            lines.append("")

        if counts.get("CRITICAL", 0) > 0:
            posture = "POOR - Critical vulnerabilities require immediate attention"
        elif counts.get("HIGH", 0) > 0:
            posture = "BELOW AVERAGE - High severity issues need prompt remediation"
        elif counts.get("MEDIUM", 0) > 0:
            posture = "AVERAGE - Medium issues should be addressed within 30 days"
        elif total > 0:
            posture = "GOOD - Only low/informational findings detected"
        else:
            posture = "EXCELLENT - No significant security issues found"

        lines.append(f"OVERALL SECURITY POSTURE: {posture}")
        lines.append("")
        lines.append("=" * 60)

        content = "\n".join(lines)
        self.file_mgr.save_text(content, "summary.txt")
        ColorOutput.success(f"Summary: {os.path.join(self.output_dir, 'summary.txt')}")

    def generate_hackerone_report(self, finding):
        """Generate a single finding in HackerOne report format."""
        sev = finding.get("severity", "INFO")
        title = finding.get("title", "Unknown Vulnerability")
        desc = finding.get("description", "")
        url = finding.get("url", "")
        evidence = finding.get("evidence", "")
        remediation = finding.get("remediation", "")
        cvss_val = finding.get("cvss_score", 0.0)
        cwe = finding.get("cwe_id", "")
        ftype = finding.get("finding_type", "")

        lines = []
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Severity:** {sev}")
        lines.append(f"**CVSS Score:** {cvss_val}")
        lines.append(f"**CWE:** {cwe}")
        lines.append(f"**Type:** {ftype}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(desc)
        lines.append("")
        lines.append("## Affected URL")
        lines.append("")
        lines.append(f"`{url}`")
        lines.append("")
        lines.append("## Steps to Reproduce")
        lines.append("")
        lines.append(f"1. Navigate to `{url}`")
        lines.append("2. Observe the vulnerability as described above")
        lines.append("")
        if evidence:
            lines.append("## Evidence / Proof of Concept")
            lines.append("")
            lines.append("```")
            lines.append(evidence)
            lines.append("```")
            lines.append("")
        lines.append("## Impact")
        lines.append("")
        lines.append(self._describe_impact(sev, ftype))
        lines.append("")
        lines.append("## Remediation")
        lines.append("")
        lines.append(remediation if remediation else "Apply appropriate security controls.")
        lines.append("")
        if cwe:
            cwe_num = cwe.replace("CWE-", "")
            lines.append("## References")
            lines.append("")
            lines.append(f"- https://cwe.mitre.org/data/definitions/{cwe_num}.html")
            lines.append("- https://owasp.org/www-community/vulnerabilities/")
            lines.append("")

        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Private Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _get_css():
        """Return CSS for HTML report."""
        return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #1a1a2e; color: #eee; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #0ff; margin-bottom: 10px; }
h2 { color: #0ff; margin: 20px 0 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }
.meta { color: #888; margin-bottom: 20px; }
.stats { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
.stat-card { background: #16213e; border-radius: 8px; padding: 15px 25px; text-align: center; min-width: 100px; }
.stat-card .number { font-size: 2em; font-weight: bold; }
.stat-card.critical .number { color: #ff0040; }
.stat-card.high .number { color: #ff4500; }
.stat-card.medium .number { color: #ffa500; }
.stat-card.low .number { color: #00bfff; }
.stat-card.info .number { color: #888; }
.stat-card .label { color: #aaa; font-size: 0.85em; text-transform: uppercase; }
.finding { background: #16213e; border-radius: 8px; padding: 15px; margin: 10px 0; border-left: 4px solid #333; }
.finding.critical { border-left-color: #ff0040; }
.finding.high { border-left-color: #ff4500; }
.finding.medium { border-left-color: #ffa500; }
.finding.low { border-left-color: #00bfff; }
.finding.info { border-left-color: #888; }
.finding-title { font-size: 1.1em; font-weight: bold; margin-bottom: 8px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; }
.badge.critical { background: #ff0040; color: #fff; }
.badge.high { background: #ff4500; color: #fff; }
.badge.medium { background: #ffa500; color: #000; }
.badge.low { background: #00bfff; color: #000; }
.badge.info { background: #555; color: #fff; }
.detail { color: #bbb; margin: 5px 0; font-size: 0.9em; }
.evidence { background: #0d1117; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 0.85em; margin: 8px 0; white-space: pre-wrap; color: #7ee787; }
footer { margin-top: 40px; text-align: center; color: #555; font-size: 0.85em; }
@media print { body { background: #fff; color: #000; } .finding { border: 1px solid #ddd; } }
"""

    @staticmethod
    def _count_severities(findings):
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _describe_impact(severity, finding_type):
        """Generate an impact description based on severity and type."""
        impacts = {
            "CORS Misconfiguration": "An attacker could steal sensitive data from authenticated users by hosting a malicious page that makes cross-origin requests.",
            "Missing Security Header": "The absence of security headers increases the attack surface and may allow various client-side attacks.",
            "Cookie Security": "Insecure cookie configuration may allow session hijacking through network interception or XSS attacks.",
            "Subdomain Takeover": "An attacker could claim the abandoned subdomain and serve malicious content, potentially stealing cookies or phishing users.",
            "SSL/TLS": "SSL/TLS issues may allow man-in-the-middle attacks or cause trust warnings for users.",
            "Email Security": "Missing email authentication records allow attackers to send spoofed emails appearing to come from this domain.",
            "CSP Weakness": "A weak Content Security Policy may not prevent cross-site scripting (XSS) attacks.",
            "Open Redirect": "Open redirect vulnerabilities can be used in phishing attacks to redirect users to malicious sites.",
            "Information Disclosure": "Exposed version information helps attackers identify known vulnerabilities in specific software versions.",
            "Clickjacking": "Without framing protection, an attacker could trick users into clicking hidden UI elements on the target site.",
            "Host Header Injection": "Host header injection can lead to cache poisoning, password reset poisoning, or SSRF attacks.",
            "HTTP Methods": "Unnecessary HTTP methods may allow unauthorized data modification or information leakage.",
        }
        return impacts.get(finding_type, "This vulnerability could be exploited by an attacker to compromise the security of the application or its users.")

    def _calculate_statistics(self, scan_results):
        """Calculate scan statistics from results."""
        stats = {
            "total_subdomains": 0,
            "total_urls": 0,
            "total_js_files": 0,
            "total_endpoints": 0,
            "total_findings": 0,
            "findings_by_severity": {},
        }

        recon = scan_results.get("recon", {})
        if isinstance(recon, dict):
            stats["total_subdomains"] = len(recon.get("subdomains", []))
            stats["total_urls"] = len(recon.get("wayback_urls", []))

        js = scan_results.get("js_analysis", {})
        if isinstance(js, dict):
            stats["total_js_files"] = len(js.get("js_files", []))
            stats["total_endpoints"] = len(js.get("endpoints", []))

        vulns = scan_results.get("vulnerabilities", {})
        findings = vulns.get("findings", []) if isinstance(vulns, dict) else []
        stats["total_findings"] = len(findings)
        stats["findings_by_severity"] = self._count_severities(findings)

        return stats
