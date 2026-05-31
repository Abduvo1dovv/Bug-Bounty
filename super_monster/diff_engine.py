"""
Super Monster v1.0.0 - Diff Engine Module

Compare two Monster scan reports or directories of reports to detect:
- New findings (not in old scan)
- Removed findings (in old but not new = possibly fixed)
- Changed findings (severity or evidence changed)
- New subdomains appeared
- Technology changes
- Certificate changes

Features:
- Unified diff output with clear sections
- Color-coded additions (green) and removals (red)
- Summary statistics
- JSON and Markdown output
- Fingerprint-based comparison for accuracy
- Fuzzy matching for similar findings
- Severity change tracking
- Timeline analysis
"""

import hashlib
import json
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

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
    Colors, SEVERITY_LEVELS, SEVERITY_ORDER, TOOL_BANNER,
    DEFAULT_OUTPUT_DIR, DIFF_CONFIG,
)


# =============================================================================
# CONSTANTS
# =============================================================================

DIFF_STATUS_NEW = "NEW"
DIFF_STATUS_REMOVED = "REMOVED"
DIFF_STATUS_CHANGED = "CHANGED"
DIFF_STATUS_UNCHANGED = "UNCHANGED"

SIMILARITY_THRESHOLD = 0.85


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DiffFinding:
    """A finding in the diff context."""
    finding_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    fingerprint: str = ""
    domain: str = ""

    def compute_fingerprint(self) -> str:
        """Generate fingerprint for comparison."""
        components = [
            self.finding_type.lower().strip(),
            self.url.lower().strip().rstrip("/"),
            self.evidence.strip()[:500],
        ]
        raw = "|".join(components)
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return self.fingerprint

    def compute_loose_fingerprint(self) -> str:
        """Generate a looser fingerprint for fuzzy matching."""
        components = [
            self.finding_type.lower().strip(),
            urlparse(self.url).netloc.lower() if self.url else "",
            urlparse(self.url).path.lower().rstrip("/") if self.url else "",
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_report_finding(cls, data: Dict[str, Any]) -> "DiffFinding":
        """Create from a Monster report finding dict."""
        url = data.get("url", "")
        f = cls(
            finding_type=data.get("finding_type", "unknown"),
            severity=data.get("severity", "INFO").upper(),
            title=data.get("title", ""),
            description=data.get("description", ""),
            url=url,
            evidence=data.get("evidence", ""),
            remediation=data.get("remediation", ""),
            cvss_score=float(data.get("cvss_score", 0.0)),
            cwe_id=data.get("cwe_id", ""),
            domain=urlparse(url).netloc if url else "",
        )
        f.compute_fingerprint()
        return f

    def similarity_to(self, other: "DiffFinding") -> float:
        """Calculate similarity score to another finding (0.0-1.0)."""
        scores = []
        # Type match
        if self.finding_type == other.finding_type:
            scores.append(1.0)
        else:
            scores.append(0.0)
        # URL similarity
        url_sim = SequenceMatcher(None, self.url.lower(), other.url.lower()).ratio()
        scores.append(url_sim)
        # Title similarity
        title_sim = SequenceMatcher(None, self.title.lower(), other.title.lower()).ratio()
        scores.append(title_sim)
        # Evidence similarity
        ev_a = self.evidence[:200].lower()
        ev_b = other.evidence[:200].lower()
        if ev_a and ev_b:
            ev_sim = SequenceMatcher(None, ev_a, ev_b).ratio()
            scores.append(ev_sim)
        # Weighted average
        weights = [0.35, 0.30, 0.20, 0.15] if len(scores) == 4 else [0.4, 0.35, 0.25]
        total = sum(s * w for s, w in zip(scores, weights))
        return round(total, 4)


@dataclass
class DiffChange:
    """Represents a single change between two findings."""
    field_name: str = ""
    old_value: str = ""
    new_value: str = ""
    change_type: str = ""  # added, removed, modified

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiffEntry:
    """A single entry in the diff report."""
    status: str = ""  # NEW, REMOVED, CHANGED, UNCHANGED
    finding: dict = field(default_factory=dict)
    matched_finding: dict = field(default_factory=dict)
    changes: list = field(default_factory=list)
    similarity_score: float = 0.0
    severity: str = ""
    domain: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiffReport:
    """Complete diff report between two scans."""
    report_id: str = ""
    generated_at: str = ""
    old_report_path: str = ""
    new_report_path: str = ""
    old_metadata: dict = field(default_factory=dict)
    new_metadata: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    new_findings: list = field(default_factory=list)
    removed_findings: list = field(default_factory=list)
    changed_findings: list = field(default_factory=list)
    unchanged_findings: list = field(default_factory=list)
    subdomain_changes: dict = field(default_factory=dict)
    technology_changes: dict = field(default_factory=dict)
    severity_changes: list = field(default_factory=list)
    timeline: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        total_old = len(self.removed_findings) + len(self.changed_findings) + len(self.unchanged_findings)
        total_new = len(self.new_findings) + len(self.changed_findings) + len(self.unchanged_findings)

        self.summary = {
            "old_total": total_old,
            "new_total": total_new,
            "new_findings_count": len(self.new_findings),
            "removed_findings_count": len(self.removed_findings),
            "changed_findings_count": len(self.changed_findings),
            "unchanged_count": len(self.unchanged_findings),
            "net_change": total_new - total_old,
            "new_by_severity": self._count_by_severity(self.new_findings),
            "removed_by_severity": self._count_by_severity(self.removed_findings),
            "fix_rate": round(
                len(self.removed_findings) / total_old * 100 if total_old > 0 else 0, 1
            ),
            "new_finding_rate": round(
                len(self.new_findings) / total_new * 100 if total_new > 0 else 0, 1
            ),
        }
        return self.summary

    def _count_by_severity(self, findings_list: list) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = defaultdict(int)
        for entry in findings_list:
            if isinstance(entry, dict):
                sev = entry.get("severity", entry.get("finding", {}).get("severity", "INFO"))
            else:
                sev = "INFO"
            counts[sev] += 1
        return dict(counts)


# =============================================================================
# DIFF ENGINE CLASS
# =============================================================================

class DiffEngine:
    """
    Engine for comparing two Monster scan reports.
    
    Detects new findings, removed findings (fixed), changed findings,
    new subdomains, technology changes, and generates comprehensive
    diff reports with color-coded output.
    """

    def __init__(self, similarity_threshold: float = SIMILARITY_THRESHOLD,
                 show_unchanged: bool = False, output_format: str = "json"):
        """
        Initialize the DiffEngine.

        Args:
            similarity_threshold: Minimum similarity for fuzzy matching.
            show_unchanged: Whether to include unchanged findings in output.
            output_format: Default output format (json, markdown).
        """
        self.similarity_threshold = similarity_threshold
        self.show_unchanged = show_unchanged
        self.output_format = output_format
        self._stats = {"comparisons": 0, "fuzzy_matches": 0, "exact_matches": 0}

    def load_report(self, path: str) -> Dict[str, Any]:
        """
        Load a Monster JSON report from file.

        Args:
            path: Path to the JSON report file.

        Returns:
            Parsed report dictionary.

        Raises:
            FileNotFoundError: If the file does not exist.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Report not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_reports_from_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """
        Load all JSON reports from a directory.

        Args:
            dir_path: Path to directory containing JSON reports.

        Returns:
            List of parsed report dictionaries.
        """
        reports = []
        if not os.path.isdir(dir_path):
            return reports

        for filename in sorted(os.listdir(dir_path)):
            if filename.endswith(".json") and "monster_report" in filename:
                filepath = os.path.join(dir_path, filename)
                try:
                    report = self.load_report(filepath)
                    report["_source_file"] = filepath
                    reports.append(report)
                except (json.JSONDecodeError, IOError):
                    continue

        return reports

    def extract_findings(self, report: Dict[str, Any]) -> List[DiffFinding]:
        """
        Extract findings from a report as DiffFinding objects.

        Args:
            report: Parsed report dictionary.

        Returns:
            List of DiffFinding objects with fingerprints.
        """
        findings_data = report.get("findings", [])
        findings = []

        for f_data in findings_data:
            finding = DiffFinding.from_report_finding(f_data)
            findings.append(finding)

        return findings

    def extract_subdomains(self, report: Dict[str, Any]) -> Set[str]:
        """
        Extract all subdomains mentioned in a report.

        Args:
            report: Parsed report dictionary.

        Returns:
            Set of subdomain strings.
        """
        subdomains = set()

        # From findings
        for f in report.get("findings", []):
            url = f.get("url", "")
            if url:
                parsed = urlparse(url)
                if parsed.netloc:
                    subdomains.add(parsed.netloc.lower())

        # From recon_summary if available
        recon = report.get("recon_summary", {})
        if isinstance(recon, dict):
            for sub in recon.get("subdomains_found", []):
                if isinstance(sub, str):
                    subdomains.add(sub.lower())
                elif isinstance(sub, dict):
                    subdomains.add(sub.get("subdomain", "").lower())

        return subdomains

    def extract_technologies(self, report: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract detected technologies from a report.

        Args:
            report: Parsed report dictionary.

        Returns:
            Dictionary mapping technology categories to detected values.
        """
        techs = defaultdict(list)

        # From findings evidence and headers
        for f in report.get("findings", []):
            evidence = f.get("evidence", "").lower()

            # Detect server technologies
            if "server:" in evidence:
                server_match = re.search(r"server:\s*(.+?)(?:\n|$)", evidence)
                if server_match:
                    techs["server"].append(server_match.group(1).strip())

            if "x-powered-by:" in evidence:
                powered_match = re.search(r"x-powered-by:\s*(.+?)(?:\n|$)", evidence)
                if powered_match:
                    techs["framework"].append(powered_match.group(1).strip())

        # From recon_summary
        recon = report.get("recon_summary", {})
        if isinstance(recon, dict):
            for tech in recon.get("technologies_detected", []):
                if isinstance(tech, str):
                    techs["detected"].append(tech)
                elif isinstance(tech, dict):
                    category = tech.get("category", "other")
                    techs[category].append(tech.get("name", ""))

        # Deduplicate
        return {k: sorted(set(v)) for k, v in techs.items()}

    def compare(self, old_report: Dict[str, Any],
                new_report: Dict[str, Any]) -> DiffReport:
        """
        Compare two reports and generate a comprehensive diff.

        Args:
            old_report: The older (baseline) report.
            new_report: The newer (comparison) report.

        Returns:
            DiffReport with all detected changes.
        """
        import uuid
        report = DiffReport(
            report_id=f"DIFF-{uuid.uuid4().hex[:8].upper()}",
            generated_at=datetime.utcnow().isoformat(),
            old_metadata=old_report.get("report_metadata", {}),
            new_metadata=new_report.get("report_metadata", {}),
        )

        # Extract findings
        old_findings = self.extract_findings(old_report)
        new_findings = self.extract_findings(new_report)

        # Build fingerprint maps
        old_fp_map = {}
        for f in old_findings:
            old_fp_map[f.fingerprint] = f

        new_fp_map = {}
        for f in new_findings:
            new_fp_map[f.fingerprint] = f

        old_fp_set = set(old_fp_map.keys())
        new_fp_set = set(new_fp_map.keys())

        # Exact matches
        exact_match_fps = old_fp_set & new_fp_set
        only_in_old_fps = old_fp_set - new_fp_set
        only_in_new_fps = new_fp_set - old_fp_set

        self._stats["exact_matches"] = len(exact_match_fps)

        # Unchanged findings
        for fp in exact_match_fps:
            old_f = old_fp_map[fp]
            new_f = new_fp_map[fp]
            # Check for severity changes
            if old_f.severity != new_f.severity:
                entry = {
                    "finding": new_f.to_dict(),
                    "old_finding": old_f.to_dict(),
                    "severity": new_f.severity,
                    "domain": new_f.domain,
                    "changes": [{"field": "severity", "old": old_f.severity, "new": new_f.severity}],
                }
                report.changed_findings.append(entry)
                report.severity_changes.append({
                    "title": new_f.title,
                    "old_severity": old_f.severity,
                    "new_severity": new_f.severity,
                    "url": new_f.url,
                })
            else:
                if self.show_unchanged:
                    report.unchanged_findings.append({"finding": new_f.to_dict(), "severity": new_f.severity, "domain": new_f.domain})

        # Fuzzy matching for remaining findings
        unmatched_old = [old_fp_map[fp] for fp in only_in_old_fps]
        unmatched_new = [new_fp_map[fp] for fp in only_in_new_fps]

        fuzzy_matched_old = set()
        fuzzy_matched_new = set()

        for new_f in unmatched_new:
            best_match = None
            best_score = 0.0

            for old_f in unmatched_old:
                if old_f.fingerprint in fuzzy_matched_old:
                    continue
                score = new_f.similarity_to(old_f)
                self._stats["comparisons"] += 1

                if score > best_score and score >= self.similarity_threshold:
                    best_score = score
                    best_match = old_f

            if best_match:
                # This is a changed finding
                fuzzy_matched_old.add(best_match.fingerprint)
                fuzzy_matched_new.add(new_f.fingerprint)
                self._stats["fuzzy_matches"] += 1

                changes = self._detect_changes(best_match, new_f)
                entry = {
                    "finding": new_f.to_dict(),
                    "old_finding": best_match.to_dict(),
                    "severity": new_f.severity,
                    "domain": new_f.domain,
                    "changes": [c.to_dict() for c in changes],
                    "similarity_score": best_score,
                }
                report.changed_findings.append(entry)

        # Remaining unmatched = new and removed
        for new_f in unmatched_new:
            if new_f.fingerprint not in fuzzy_matched_new:
                report.new_findings.append({
                    "finding": new_f.to_dict(),
                    "severity": new_f.severity,
                    "domain": new_f.domain,
                })

        for old_f in unmatched_old:
            if old_f.fingerprint not in fuzzy_matched_old:
                report.removed_findings.append({
                    "finding": old_f.to_dict(),
                    "severity": old_f.severity,
                    "domain": old_f.domain,
                })

        # Subdomain changes
        old_subs = self.extract_subdomains(old_report)
        new_subs = self.extract_subdomains(new_report)
        report.subdomain_changes = {
            "new_subdomains": sorted(list(new_subs - old_subs)),
            "removed_subdomains": sorted(list(old_subs - new_subs)),
            "unchanged_subdomains": sorted(list(old_subs & new_subs)),
            "old_count": len(old_subs),
            "new_count": len(new_subs),
        }

        # Technology changes
        old_techs = self.extract_technologies(old_report)
        new_techs = self.extract_technologies(new_report)
        all_categories = set(list(old_techs.keys()) + list(new_techs.keys()))
        tech_changes = {}
        for cat in all_categories:
            old_set = set(old_techs.get(cat, []))
            new_set = set(new_techs.get(cat, []))
            if old_set != new_set:
                tech_changes[cat] = {
                    "added": sorted(list(new_set - old_set)),
                    "removed": sorted(list(old_set - new_set)),
                }
        report.technology_changes = tech_changes

        # Timeline
        old_time = report.old_metadata.get("generated_at", "")
        new_time = report.new_metadata.get("generated_at", "")
        report.timeline = {
            "old_scan_time": old_time,
            "new_scan_time": new_time,
            "old_target": report.old_metadata.get("target", ""),
            "new_target": report.new_metadata.get("target", ""),
        }

        # Calculate summary
        report.calculate_summary()

        return report

    def compare_files(self, old_path: str, new_path: str) -> DiffReport:
        """
        Compare two report files.

        Args:
            old_path: Path to the older report file.
            new_path: Path to the newer report file.

        Returns:
            DiffReport with comparison results.
        """
        old_report = self.load_report(old_path)
        new_report = self.load_report(new_path)

        report = self.compare(old_report, new_report)
        report.old_report_path = old_path
        report.new_report_path = new_path

        return report

    def compare_directories(self, old_dir: str, new_dir: str) -> DiffReport:
        """
        Compare reports from two directories.

        Merges all findings from each directory into composite reports
        and then performs the diff.

        Args:
            old_dir: Directory with older reports.
            new_dir: Directory with newer reports.

        Returns:
            DiffReport with comparison results.
        """
        old_reports = self.load_reports_from_directory(old_dir)
        new_reports = self.load_reports_from_directory(new_dir)

        # Merge into composite reports
        old_composite = self._merge_reports(old_reports)
        new_composite = self._merge_reports(new_reports)

        report = self.compare(old_composite, new_composite)
        report.old_report_path = old_dir
        report.new_report_path = new_dir

        return report

    def _merge_reports(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple reports into a single composite report."""
        composite = {
            "report_metadata": {
                "target": "merged",
                "generated_at": datetime.utcnow().isoformat(),
                "reports_merged": len(reports),
            },
            "findings": [],
            "recon_summary": {"subdomains_found": [], "technologies_detected": []},
        }

        seen_fps = set()
        for report in reports:
            meta = report.get("report_metadata", {})
            if meta.get("target"):
                composite["report_metadata"]["target"] = meta["target"]

            for f in report.get("findings", []):
                fp = self._finding_fingerprint(f)
                if fp not in seen_fps:
                    composite["findings"].append(f)
                    seen_fps.add(fp)

            recon = report.get("recon_summary", {})
            if isinstance(recon, dict):
                composite["recon_summary"]["subdomains_found"].extend(
                    recon.get("subdomains_found", [])
                )
                composite["recon_summary"]["technologies_detected"].extend(
                    recon.get("technologies_detected", [])
                )

        return composite

    def _finding_fingerprint(self, f: Dict[str, Any]) -> str:
        """Generate fingerprint for a raw finding dict."""
        components = [
            f.get("finding_type", "").lower().strip(),
            f.get("url", "").lower().strip().rstrip("/"),
            f.get("evidence", "").strip()[:500],
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def _detect_changes(self, old_f: DiffFinding, new_f: DiffFinding) -> List[DiffChange]:
        """Detect specific changes between two similar findings."""
        changes = []

        if old_f.severity != new_f.severity:
            changes.append(DiffChange(
                field_name="severity",
                old_value=old_f.severity,
                new_value=new_f.severity,
                change_type="modified",
            ))

        if old_f.cvss_score != new_f.cvss_score:
            changes.append(DiffChange(
                field_name="cvss_score",
                old_value=str(old_f.cvss_score),
                new_value=str(new_f.cvss_score),
                change_type="modified",
            ))

        if old_f.evidence != new_f.evidence:
            changes.append(DiffChange(
                field_name="evidence",
                old_value=old_f.evidence[:100],
                new_value=new_f.evidence[:100],
                change_type="modified",
            ))

        if old_f.url != new_f.url:
            changes.append(DiffChange(
                field_name="url",
                old_value=old_f.url,
                new_value=new_f.url,
                change_type="modified",
            ))

        if old_f.title != new_f.title:
            changes.append(DiffChange(
                field_name="title",
                old_value=old_f.title,
                new_value=new_f.title,
                change_type="modified",
            ))

        return changes


    def print_diff(self, report: DiffReport) -> None:
        """
        Print color-coded diff report to terminal.

        Args:
            report: The DiffReport to display.
        """
        summary = report.summary or report.calculate_summary()

        print(f"\n{Colors.HEADER}{'=' * 70}")
        print(f"  DIFF REPORT - Scan Comparison")
        print(f"{'=' * 70}{Colors.RESET}")
        print(f"  Old: {report.old_report_path or report.old_metadata.get('target', '?')}")
        print(f"  New: {report.new_report_path or report.new_metadata.get('target', '?')}")
        print(f"  Generated: {report.generated_at}")
        print()

        # Summary stats
        print(f"{Colors.SUBHEADER}--- Summary ---{Colors.RESET}")
        print(f"  Old findings:  {summary.get('old_total', 0)}")
        print(f"  New findings:  {summary.get('new_total', 0)}")
        print(f"  Net change:    {summary.get('net_change', 0):+d}")
        print()
        print(f"  {Fore.GREEN}+ New findings:     {summary.get('new_findings_count', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.RED}- Removed (fixed):  {summary.get('removed_findings_count', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}~ Changed:          {summary.get('changed_findings_count', 0)}{Style.RESET_ALL}")
        print(f"  {Style.DIM}= Unchanged:        {summary.get('unchanged_count', 0)}{Style.RESET_ALL}")
        print()
        print(f"  Fix rate: {Fore.GREEN}{summary.get('fix_rate', 0):.1f}%{Style.RESET_ALL}")
        print()

        # New findings
        if report.new_findings:
            print(f"{Colors.SUBHEADER}--- New Findings (+{len(report.new_findings)}) ---{Colors.RESET}")
            sorted_new = sorted(
                report.new_findings,
                key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 0),
                reverse=True
            )
            for entry in sorted_new[:20]:
                finding = entry.get("finding", {})
                sev = finding.get("severity", entry.get("severity", "INFO"))
                title = finding.get("title", "Unknown")[:55]
                sev_color = Colors.severity_color(sev)
                print(f"  {Fore.GREEN}+{Style.RESET_ALL} {sev_color}{sev:<8}{Style.RESET_ALL} {title}")
                if finding.get("url"):
                    print(f"    URL: {finding['url'][:70]}")

            if len(report.new_findings) > 20:
                print(f"  ... and {len(report.new_findings) - 20} more")
            print()

        # Removed findings
        if report.removed_findings:
            print(f"{Colors.SUBHEADER}--- Removed/Fixed Findings (-{len(report.removed_findings)}) ---{Colors.RESET}")
            sorted_removed = sorted(
                report.removed_findings,
                key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 0),
                reverse=True
            )
            for entry in sorted_removed[:20]:
                finding = entry.get("finding", {})
                sev = finding.get("severity", entry.get("severity", "INFO"))
                title = finding.get("title", "Unknown")[:55]
                sev_color = Colors.severity_color(sev)
                print(f"  {Fore.RED}-{Style.RESET_ALL} {sev_color}{sev:<8}{Style.RESET_ALL} {title}")

            if len(report.removed_findings) > 20:
                print(f"  ... and {len(report.removed_findings) - 20} more")
            print()

        # Changed findings
        if report.changed_findings:
            print(f"{Colors.SUBHEADER}--- Changed Findings (~{len(report.changed_findings)}) ---{Colors.RESET}")
            for entry in report.changed_findings[:10]:
                finding = entry.get("finding", {})
                title = finding.get("title", "Unknown")[:45]
                changes = entry.get("changes", [])
                print(f"  {Fore.YELLOW}~{Style.RESET_ALL} {title}")
                for change in changes[:3]:
                    field = change.get("field_name", "?")
                    old_val = str(change.get("old_value", ""))[:30]
                    new_val = str(change.get("new_value", ""))[:30]
                    print(f"    {field}: {Fore.RED}{old_val}{Style.RESET_ALL} -> {Fore.GREEN}{new_val}{Style.RESET_ALL}")
            print()

        # Subdomain changes
        sub_changes = report.subdomain_changes
        if sub_changes.get("new_subdomains") or sub_changes.get("removed_subdomains"):
            print(f"{Colors.SUBHEADER}--- Subdomain Changes ---{Colors.RESET}")
            for sub in sub_changes.get("new_subdomains", [])[:10]:
                print(f"  {Fore.GREEN}+ {sub}{Style.RESET_ALL}")
            for sub in sub_changes.get("removed_subdomains", [])[:10]:
                print(f"  {Fore.RED}- {sub}{Style.RESET_ALL}")
            print()

        # Technology changes
        if report.technology_changes:
            print(f"{Colors.SUBHEADER}--- Technology Changes ---{Colors.RESET}")
            for category, changes in report.technology_changes.items():
                for tech in changes.get("added", []):
                    print(f"  {Fore.GREEN}+ [{category}] {tech}{Style.RESET_ALL}")
                for tech in changes.get("removed", []):
                    print(f"  {Fore.RED}- [{category}] {tech}{Style.RESET_ALL}")
            print()

        print(f"{Colors.HEADER}{'=' * 70}{Colors.RESET}")

    def generate_json_report(self, report: DiffReport) -> str:
        """Generate JSON formatted diff report."""
        return json.dumps(report.to_dict(), indent=2, default=str)

    def generate_markdown_report(self, report: DiffReport) -> str:
        """Generate Markdown formatted diff report."""
        summary = report.summary or report.calculate_summary()
        lines = []

        lines.append("# Scan Diff Report")
        lines.append("")
        lines.append(f"**Generated:** {report.generated_at}")
        lines.append(f"**Old Report:** {report.old_report_path}")
        lines.append(f"**New Report:** {report.new_report_path}")
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Old findings | {summary.get('old_total', 0)} |")
        lines.append(f"| New findings | {summary.get('new_total', 0)} |")
        lines.append(f"| Added | +{summary.get('new_findings_count', 0)} |")
        lines.append(f"| Removed (fixed) | -{summary.get('removed_findings_count', 0)} |")
        lines.append(f"| Changed | {summary.get('changed_findings_count', 0)} |")
        lines.append(f"| Fix rate | {summary.get('fix_rate', 0):.1f}% |")
        lines.append("")

        if report.new_findings:
            lines.append("## New Findings")
            lines.append("")
            lines.append("| Severity | Title | URL |")
            lines.append("|----------|-------|-----|")
            for entry in report.new_findings[:50]:
                f = entry.get("finding", {})
                sev = f.get("severity", "INFO")
                title = f.get("title", "?")[:50]
                url = f.get("url", "")[:60]
                lines.append(f"| {sev} | {title} | {url} |")
            lines.append("")

        if report.removed_findings:
            lines.append("## Removed/Fixed Findings")
            lines.append("")
            lines.append("| Severity | Title |")
            lines.append("|----------|-------|")
            for entry in report.removed_findings[:50]:
                f = entry.get("finding", {})
                sev = f.get("severity", "INFO")
                title = f.get("title", "?")[:50]
                lines.append(f"| {sev} | {title} |")
            lines.append("")

        if report.subdomain_changes.get("new_subdomains"):
            lines.append("## New Subdomains")
            lines.append("")
            for sub in report.subdomain_changes["new_subdomains"]:
                lines.append(f"- {sub}")
            lines.append("")

        return "\n".join(lines)

    def save_report(self, report: DiffReport, output_dir: str,
                    formats: List[str] = None) -> Dict[str, str]:
        """
        Save diff report to files.

        Args:
            report: The DiffReport to save.
            output_dir: Output directory.
            formats: List of formats to save (json, markdown).

        Returns:
            Dictionary mapping format to file path.
        """
        formats = formats or ["json", "markdown"]
        os.makedirs(output_dir, exist_ok=True)
        saved = {}

        if "json" in formats:
            json_path = os.path.join(output_dir, f"diff_{report.report_id}.json")
            with open(json_path, "w") as f:
                f.write(self.generate_json_report(report))
            saved["json"] = json_path

        if "markdown" in formats:
            md_path = os.path.join(output_dir, f"diff_{report.report_id}.md")
            with open(md_path, "w") as f:
                f.write(self.generate_markdown_report(report))
            saved["markdown"] = md_path

        return saved


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def compare_reports(old_path: str, new_path: str,
                    output_dir: str = None,
                    show_unchanged: bool = False) -> DiffReport:
    """
    Convenience function to compare two report files.

    Args:
        old_path: Path to older report.
        new_path: Path to newer report.
        output_dir: Optional output directory for saving results.
        show_unchanged: Whether to include unchanged findings.

    Returns:
        DiffReport with comparison results.
    """
    engine = DiffEngine(show_unchanged=show_unchanged)

    if os.path.isdir(old_path) and os.path.isdir(new_path):
        report = engine.compare_directories(old_path, new_path)
    else:
        report = engine.compare_files(old_path, new_path)

    if output_dir:
        engine.save_report(report, output_dir)

    return report


def print_diff_summary(old_path: str, new_path: str) -> None:
    """
    Print a colored diff summary to terminal.

    Args:
        old_path: Path to older report.
        new_path: Path to newer report.
    """
    engine = DiffEngine()
    report = engine.compare_files(old_path, new_path)
    engine.print_diff(report)
