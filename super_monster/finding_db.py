"""
Super Monster v1.0.0 - Finding Database Module

Central data store for all vulnerability findings. Provides:
- JSON-based persistent storage with atomic writes
- Import from Monster v2.0.0 JSON report format
- Fingerprint-based deduplication engine
- Query methods: by_severity, by_domain, by_type, by_status, by_date_range
- Finding lifecycle tracking (new -> reported -> fixed/not_fixed)
- Correlation ID management for chain detection
- Export for reporting in multiple formats
- Composite/escalated finding support
- Retest history tracking per finding
- Statistics and aggregation methods
"""

import json
import hashlib
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Finding:
    """Represents a single security finding with full metadata."""

    id: str = ""
    finding_type: str = ""
    severity: str = "INFO"
    title: str = ""
    description: str = ""
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""

    # Metadata
    domain: str = ""
    target: str = ""
    source_report: str = ""
    discovered_at: str = ""
    updated_at: str = ""
    fingerprint: str = ""

    # Lifecycle
    status: str = "new"
    reported_at: str = ""
    fixed_at: str = ""
    retest_history: list = field(default_factory=list)
    retest_count: int = 0
    last_retest: str = ""

    # Correlation
    correlation_ids: list = field(default_factory=list)
    is_composite: bool = False
    composite_children: list = field(default_factory=list)
    chain_description: str = ""

    # Prioritization
    priority_score: float = 0.0
    bounty_estimate: float = 0.0
    dupe_probability: float = 0.0

    # Tags and notes
    tags: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    platform: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create a Finding from a dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def compute_fingerprint(self) -> str:
        """Generate a unique fingerprint for deduplication."""
        components = [
            self.finding_type.lower().strip(),
            self.url.lower().strip().rstrip("/"),
            self.evidence.strip()[:500],
        ]
        raw = "|".join(components)
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return self.fingerprint

    def add_retest(self, status: str, notes: str = "") -> None:
        """Record a retest result."""
        retest_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,
            "notes": notes,
            "retest_number": self.retest_count + 1,
        }
        self.retest_history.append(retest_entry)
        self.retest_count += 1
        self.last_retest = retest_entry["timestamp"]
        self.updated_at = retest_entry["timestamp"]
        if status in ("fixed", "not_fixed", "partially_fixed", "regressed"):
            self.status = status

    def add_note(self, note: str, author: str = "system") -> None:
        """Add a note to the finding."""
        note_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "author": author,
            "content": note,
        }
        self.notes.append(note_entry)
        self.updated_at = note_entry["timestamp"]

    def add_correlation(self, correlation_id: str) -> None:
        """Associate this finding with a correlation chain."""
        if correlation_id not in self.correlation_ids:
            self.correlation_ids.append(correlation_id)
            self.updated_at = datetime.utcnow().isoformat()

    def matches_fingerprint(self, other_fingerprint: str) -> bool:
        """Check if this finding matches another fingerprint."""
        if not self.fingerprint:
            self.compute_fingerprint()
        return self.fingerprint == other_fingerprint

    def age_hours(self) -> float:
        """Calculate the age of this finding in hours."""
        if not self.discovered_at:
            return 0.0
        try:
            discovered = datetime.fromisoformat(self.discovered_at)
            now = datetime.utcnow()
            delta = now - discovered
            return delta.total_seconds() / 3600.0
        except (ValueError, TypeError):
            return 0.0

    def needs_retest(self, interval_hours: int) -> bool:
        """Check if this finding is due for a retest."""
        if self.status in ("fixed", "invalid", "duplicate", "wontfix"):
            return False
        if not self.last_retest:
            return self.age_hours() >= interval_hours
        try:
            last = datetime.fromisoformat(self.last_retest)
            now = datetime.utcnow()
            hours_since = (now - last).total_seconds() / 3600.0
            return hours_since >= interval_hours
        except (ValueError, TypeError):
            return True



# =============================================================================
# FINDING DATABASE CLASS
# =============================================================================

class FindingDB:
    """
    JSON-based findings database with full lifecycle management.

    Stores all findings with metadata, supports querying, deduplication,
    import/export, and correlation tracking. Data is persisted to a JSON
    file with atomic writes to prevent corruption.
    """

    def __init__(self, db_path: str = None):
        """
        Initialize the finding database.

        Args:
            db_path: Path to the JSON database file. If None, uses in-memory only.
        """
        self.db_path = db_path
        self.findings: Dict[str, Finding] = {}
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "total_imports": 0,
            "total_findings_ever": 0,
        }
        self._fingerprint_index: Dict[str, str] = {}  # fingerprint -> finding_id
        self._domain_index: Dict[str, List[str]] = {}  # domain -> [finding_ids]
        self._type_index: Dict[str, List[str]] = {}  # finding_type -> [finding_ids]
        self._severity_index: Dict[str, List[str]] = {}  # severity -> [finding_ids]
        self._status_index: Dict[str, List[str]] = {}  # status -> [finding_ids]
        self._correlation_index: Dict[str, List[str]] = {}  # corr_id -> [finding_ids]

        if self.db_path and os.path.exists(self.db_path):
            self.load()

    def _generate_id(self) -> str:
        """Generate a unique finding ID."""
        return f"SM-{uuid.uuid4().hex[:12].upper()}"

    def _rebuild_indexes(self) -> None:
        """Rebuild all indexes from current findings."""
        self._fingerprint_index.clear()
        self._domain_index.clear()
        self._type_index.clear()
        self._severity_index.clear()
        self._status_index.clear()
        self._correlation_index.clear()

        for finding_id, finding in self.findings.items():
            # Fingerprint index
            if finding.fingerprint:
                self._fingerprint_index[finding.fingerprint] = finding_id

            # Domain index
            domain = finding.domain or "unknown"
            if domain not in self._domain_index:
                self._domain_index[domain] = []
            self._domain_index[domain].append(finding_id)

            # Type index
            ftype = finding.finding_type or "unknown"
            if ftype not in self._type_index:
                self._type_index[ftype] = []
            self._type_index[ftype].append(finding_id)

            # Severity index
            severity = finding.severity or "INFO"
            if severity not in self._severity_index:
                self._severity_index[severity] = []
            self._severity_index[severity].append(finding_id)

            # Status index
            status = finding.status or "new"
            if status not in self._status_index:
                self._status_index[status] = []
            self._status_index[status].append(finding_id)

            # Correlation index
            for corr_id in finding.correlation_ids:
                if corr_id not in self._correlation_index:
                    self._correlation_index[corr_id] = []
                self._correlation_index[corr_id].append(finding_id)

    def _add_to_indexes(self, finding: Finding) -> None:
        """Add a single finding to all indexes."""
        finding_id = finding.id

        if finding.fingerprint:
            self._fingerprint_index[finding.fingerprint] = finding_id

        domain = finding.domain or "unknown"
        if domain not in self._domain_index:
            self._domain_index[domain] = []
        if finding_id not in self._domain_index[domain]:
            self._domain_index[domain].append(finding_id)

        ftype = finding.finding_type or "unknown"
        if ftype not in self._type_index:
            self._type_index[ftype] = []
        if finding_id not in self._type_index[ftype]:
            self._type_index[ftype].append(finding_id)

        severity = finding.severity or "INFO"
        if severity not in self._severity_index:
            self._severity_index[severity] = []
        if finding_id not in self._severity_index[severity]:
            self._severity_index[severity].append(finding_id)

        status = finding.status or "new"
        if status not in self._status_index:
            self._status_index[status] = []
        if finding_id not in self._status_index[status]:
            self._status_index[status].append(finding_id)

        for corr_id in finding.correlation_ids:
            if corr_id not in self._correlation_index:
                self._correlation_index[corr_id] = []
            if finding_id not in self._correlation_index[corr_id]:
                self._correlation_index[corr_id].append(finding_id)

    def _remove_from_indexes(self, finding: Finding) -> None:
        """Remove a single finding from all indexes."""
        finding_id = finding.id

        if finding.fingerprint and finding.fingerprint in self._fingerprint_index:
            del self._fingerprint_index[finding.fingerprint]

        domain = finding.domain or "unknown"
        if domain in self._domain_index and finding_id in self._domain_index[domain]:
            self._domain_index[domain].remove(finding_id)

        ftype = finding.finding_type or "unknown"
        if ftype in self._type_index and finding_id in self._type_index[ftype]:
            self._type_index[ftype].remove(finding_id)

        severity = finding.severity or "INFO"
        if severity in self._severity_index and finding_id in self._severity_index[severity]:
            self._severity_index[severity].remove(finding_id)

        status = finding.status or "new"
        if status in self._status_index and finding_id in self._status_index[status]:
            self._status_index[status].remove(finding_id)

        for corr_id in finding.correlation_ids:
            if corr_id in self._correlation_index and finding_id in self._correlation_index[corr_id]:
                self._correlation_index[corr_id].remove(finding_id)

    # =========================================================================
    # PERSISTENCE METHODS
    # =========================================================================

    def load(self) -> bool:
        """
        Load the database from disk.

        Returns:
            True if loaded successfully, False otherwise.
        """
        if not self.db_path or not os.path.exists(self.db_path):
            return False

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.metadata = data.get("metadata", self.metadata)
            findings_data = data.get("findings", {})

            self.findings.clear()
            for finding_id, finding_dict in findings_data.items():
                finding = Finding.from_dict(finding_dict)
                finding.id = finding_id
                self.findings[finding_id] = finding

            self._rebuild_indexes()
            return True

        except (json.JSONDecodeError, IOError, OSError) as e:
            return False

    def save(self) -> bool:
        """
        Save the database to disk with atomic write.

        Returns:
            True if saved successfully, False otherwise.
        """
        if not self.db_path:
            return False

        self.metadata["updated_at"] = datetime.utcnow().isoformat()
        self.metadata["total_findings"] = len(self.findings)

        data = {
            "metadata": self.metadata,
            "findings": {fid: f.to_dict() for fid, f in self.findings.items()},
        }

        # Atomic write: write to temp file then rename
        temp_path = self.db_path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            # Atomic rename
            shutil.move(temp_path, self.db_path)
            return True

        except (IOError, OSError) as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            return False

    # =========================================================================
    # CRUD OPERATIONS
    # =========================================================================

    def add_finding(self, finding: Finding, deduplicate: bool = True) -> Tuple[str, bool]:
        """
        Add a finding to the database.

        Args:
            finding: The Finding object to add.
            deduplicate: Whether to check for duplicates first.

        Returns:
            Tuple of (finding_id, is_new). is_new is False if it was a duplicate.
        """
        # Ensure fingerprint is computed
        if not finding.fingerprint:
            finding.compute_fingerprint()

        # Check for duplicates
        if deduplicate:
            existing_id = self._fingerprint_index.get(finding.fingerprint)
            if existing_id and existing_id in self.findings:
                # Update existing finding with any new information
                existing = self.findings[existing_id]
                existing.updated_at = datetime.utcnow().isoformat()
                if finding.source_report and finding.source_report not in (existing.notes or []):
                    existing.add_note(f"Also seen in report: {finding.source_report}")
                return existing_id, False

        # Assign ID if not present
        if not finding.id:
            finding.id = self._generate_id()

        # Set timestamps
        if not finding.discovered_at:
            finding.discovered_at = datetime.utcnow().isoformat()
        if not finding.updated_at:
            finding.updated_at = datetime.utcnow().isoformat()

        # Store
        self.findings[finding.id] = finding
        self._add_to_indexes(finding)
        self.metadata["total_findings_ever"] = self.metadata.get("total_findings_ever", 0) + 1

        return finding.id, True

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by its ID."""
        return self.findings.get(finding_id)

    def update_finding(self, finding_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update specific fields of a finding.

        Args:
            finding_id: The ID of the finding to update.
            updates: Dictionary of field names to new values.

        Returns:
            True if updated successfully, False if finding not found.
        """
        finding = self.findings.get(finding_id)
        if not finding:
            return False

        # Remove from indexes before update
        self._remove_from_indexes(finding)

        # Apply updates
        for key, value in updates.items():
            if hasattr(finding, key):
                setattr(finding, key, value)

        finding.updated_at = datetime.utcnow().isoformat()

        # Recompute fingerprint if relevant fields changed
        if any(k in updates for k in ("finding_type", "url", "evidence")):
            finding.compute_fingerprint()

        # Re-add to indexes
        self._add_to_indexes(finding)

        return True

    def delete_finding(self, finding_id: str) -> bool:
        """
        Remove a finding from the database.

        Args:
            finding_id: The ID of the finding to remove.

        Returns:
            True if deleted, False if not found.
        """
        finding = self.findings.get(finding_id)
        if not finding:
            return False

        self._remove_from_indexes(finding)
        del self.findings[finding_id]
        return True

    def update_status(self, finding_id: str, new_status: str, notes: str = "") -> bool:
        """
        Update the lifecycle status of a finding with validation.

        Args:
            finding_id: The ID of the finding.
            new_status: The new status to set.
            notes: Optional notes about the status change.

        Returns:
            True if status was updated, False if invalid transition.
        """
        finding = self.findings.get(finding_id)
        if not finding:
            return False

        from super_monster.config import validate_state_transition, FINDING_STATES

        if finding.status and not validate_state_transition(finding.status, new_status):
            # Allow force-setting if the state is not in the machine
            if finding.status in FINDING_STATES:
                return False

        # Remove from old status index
        old_status = finding.status or "new"
        if old_status in self._status_index and finding_id in self._status_index[old_status]:
            self._status_index[old_status].remove(finding_id)

        # Update status
        finding.status = new_status
        finding.updated_at = datetime.utcnow().isoformat()

        if new_status == "reported" and not finding.reported_at:
            finding.reported_at = datetime.utcnow().isoformat()
        elif new_status == "fixed" and not finding.fixed_at:
            finding.fixed_at = datetime.utcnow().isoformat()

        if notes:
            finding.add_note(f"Status changed to {new_status}: {notes}")

        # Add to new status index
        if new_status not in self._status_index:
            self._status_index[new_status] = []
        self._status_index[new_status].append(finding_id)

        return True


    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def by_severity(self, severity: str) -> List[Finding]:
        """
        Query findings by severity level.

        Args:
            severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO

        Returns:
            List of findings matching the severity.
        """
        severity = severity.upper()
        finding_ids = self._severity_index.get(severity, [])
        return [self.findings[fid] for fid in finding_ids if fid in self.findings]

    def by_domain(self, domain: str) -> List[Finding]:
        """
        Query findings by domain name.

        Args:
            domain: The domain to filter by.

        Returns:
            List of findings for the specified domain.
        """
        domain_lower = domain.lower()
        finding_ids = self._domain_index.get(domain_lower, [])
        # Also do partial match
        results = []
        for d, ids in self._domain_index.items():
            if domain_lower in d or d in domain_lower:
                for fid in ids:
                    if fid in self.findings and fid not in [r.id for r in results]:
                        results.append(self.findings[fid])
        return results

    def by_type(self, finding_type: str) -> List[Finding]:
        """
        Query findings by finding type.

        Args:
            finding_type: The type to filter by (e.g., 'cors', 'xss_stored').

        Returns:
            List of findings matching the type.
        """
        finding_type = finding_type.lower()
        finding_ids = self._type_index.get(finding_type, [])
        return [self.findings[fid] for fid in finding_ids if fid in self.findings]

    def by_status(self, status: str) -> List[Finding]:
        """
        Query findings by lifecycle status.

        Args:
            status: The status to filter by (e.g., 'new', 'reported', 'fixed').

        Returns:
            List of findings in the specified status.
        """
        status = status.lower()
        finding_ids = self._status_index.get(status, [])
        return [self.findings[fid] for fid in finding_ids if fid in self.findings]

    def by_date_range(self, start_date: str, end_date: str = None) -> List[Finding]:
        """
        Query findings discovered within a date range.

        Args:
            start_date: ISO format start date string.
            end_date: ISO format end date string. Defaults to now.

        Returns:
            List of findings discovered within the range.
        """
        try:
            start = datetime.fromisoformat(start_date)
        except (ValueError, TypeError):
            return []

        if end_date:
            try:
                end = datetime.fromisoformat(end_date)
            except (ValueError, TypeError):
                end = datetime.utcnow()
        else:
            end = datetime.utcnow()

        results = []
        for finding in self.findings.values():
            if not finding.discovered_at:
                continue
            try:
                discovered = datetime.fromisoformat(finding.discovered_at)
                if start <= discovered <= end:
                    results.append(finding)
            except (ValueError, TypeError):
                continue

        return sorted(results, key=lambda f: f.discovered_at, reverse=True)

    def by_correlation(self, correlation_id: str) -> List[Finding]:
        """
        Query findings by correlation chain ID.

        Args:
            correlation_id: The correlation chain identifier.

        Returns:
            List of findings in the specified correlation chain.
        """
        finding_ids = self._correlation_index.get(correlation_id, [])
        return [self.findings[fid] for fid in finding_ids if fid in self.findings]

    def by_target(self, target: str) -> List[Finding]:
        """
        Query findings by target (original scan target).

        Args:
            target: The target domain that was scanned.

        Returns:
            List of findings from scans of that target.
        """
        target_lower = target.lower()
        return [f for f in self.findings.values() if f.target.lower() == target_lower]

    def by_cvss_range(self, min_cvss: float, max_cvss: float = 10.0) -> List[Finding]:
        """
        Query findings within a CVSS score range.

        Args:
            min_cvss: Minimum CVSS score (inclusive).
            max_cvss: Maximum CVSS score (inclusive).

        Returns:
            List of findings within the score range.
        """
        return [
            f for f in self.findings.values()
            if min_cvss <= f.cvss_score <= max_cvss
        ]

    def by_priority(self, min_priority: float = 0.0, limit: int = 50) -> List[Finding]:
        """
        Get findings sorted by priority score.

        Args:
            min_priority: Minimum priority score to include.
            limit: Maximum number of results.

        Returns:
            List of findings sorted by priority (highest first).
        """
        filtered = [f for f in self.findings.values() if f.priority_score >= min_priority]
        sorted_findings = sorted(filtered, key=lambda f: f.priority_score, reverse=True)
        return sorted_findings[:limit]

    def needs_retest(self) -> List[Finding]:
        """
        Get all findings that are due for retesting.

        Returns:
            List of findings needing retest based on configured intervals.
        """
        from super_monster.config import RETEST_INTERVALS

        results = []
        for finding in self.findings.values():
            if finding.status in ("fixed", "invalid", "duplicate", "wontfix"):
                continue
            interval_config = RETEST_INTERVALS.get(finding.severity, RETEST_INTERVALS["MEDIUM"])
            max_retests = interval_config["max_retests"]
            if finding.retest_count >= max_retests:
                continue
            interval = interval_config["initial_hours"] if finding.retest_count == 0 else interval_config["followup_hours"]
            if finding.needs_retest(interval):
                results.append(finding)

        return sorted(results, key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5),
            f.discovered_at or ""
        ))

    def search(self, query: str) -> List[Finding]:
        """
        Full-text search across finding fields.

        Args:
            query: Search string to match against titles, descriptions, URLs, evidence.

        Returns:
            List of matching findings.
        """
        query_lower = query.lower()
        results = []
        for finding in self.findings.values():
            searchable = " ".join([
                finding.title,
                finding.description,
                finding.url,
                finding.evidence,
                finding.finding_type,
                finding.domain,
                finding.cwe_id,
            ]).lower()
            if query_lower in searchable:
                results.append(finding)
        return results

    def get_all(self) -> List[Finding]:
        """Get all findings as a list."""
        return list(self.findings.values())

    def count(self) -> int:
        """Get total number of findings."""
        return len(self.findings)


    # =========================================================================
    # IMPORT METHODS
    # =========================================================================

    def import_monster_report(self, report_path: str) -> Dict[str, Any]:
        """
        Import findings from a Monster v2.0.0 JSON report file.

        Parses the report_metadata and findings[] array, creating Finding objects
        with proper metadata and fingerprints.

        Args:
            report_path: Path to the Monster JSON report file.

        Returns:
            Dictionary with import statistics:
            {
                "total_in_report": int,
                "imported_new": int,
                "duplicates_skipped": int,
                "errors": int,
                "target": str,
                "report_file": str,
            }
        """
        stats = {
            "total_in_report": 0,
            "imported_new": 0,
            "duplicates_skipped": 0,
            "errors": 0,
            "target": "",
            "report_file": os.path.basename(report_path),
        }

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, IOError, OSError) as e:
            stats["errors"] = 1
            return stats

        # Extract metadata
        metadata = report_data.get("report_metadata", {})
        target = metadata.get("target", "")
        generated_at = metadata.get("generated_at", "")
        generator = metadata.get("generator", "")
        modules_run = metadata.get("modules_run", [])
        stats["target"] = target

        # Process findings
        findings_list = report_data.get("findings", [])
        stats["total_in_report"] = len(findings_list)

        for finding_data in findings_list:
            try:
                finding = Finding(
                    finding_type=finding_data.get("finding_type", "unknown"),
                    severity=finding_data.get("severity", "INFO").upper(),
                    title=finding_data.get("title", ""),
                    description=finding_data.get("description", ""),
                    url=finding_data.get("url", ""),
                    evidence=finding_data.get("evidence", ""),
                    remediation=finding_data.get("remediation", ""),
                    cvss_score=float(finding_data.get("cvss_score", 0.0)),
                    cwe_id=finding_data.get("cwe_id", ""),
                    domain=self._extract_domain(finding_data.get("url", "")),
                    target=target,
                    source_report=os.path.basename(report_path),
                    discovered_at=generated_at or datetime.utcnow().isoformat(),
                )

                finding_id, is_new = self.add_finding(finding, deduplicate=True)

                if is_new:
                    stats["imported_new"] += 1
                else:
                    stats["duplicates_skipped"] += 1

            except Exception as e:
                stats["errors"] += 1
                continue

        self.metadata["total_imports"] = self.metadata.get("total_imports", 0) + 1
        return stats

    def import_directory(self, directory: str, pattern: str = "*.json") -> Dict[str, Any]:
        """
        Import all Monster JSON reports from a directory.

        Args:
            directory: Path to directory containing report files.
            pattern: Glob pattern for matching report files.

        Returns:
            Aggregated import statistics across all files.
        """
        from pathlib import Path

        dir_path = Path(directory)
        if not dir_path.exists():
            return {"error": f"Directory not found: {directory}", "files_processed": 0}

        report_files = sorted(dir_path.glob(pattern))
        # Filter to only Monster report JSON files
        monster_reports = [
            f for f in report_files
            if f.name.startswith("monster_report_") and f.suffix == ".json"
        ]

        if not monster_reports:
            # Fallback: try all JSON files
            monster_reports = report_files

        aggregate_stats = {
            "files_processed": 0,
            "total_in_reports": 0,
            "imported_new": 0,
            "duplicates_skipped": 0,
            "errors": 0,
            "targets": [],
            "per_file": [],
        }

        for report_file in monster_reports:
            file_stats = self.import_monster_report(str(report_file))
            aggregate_stats["files_processed"] += 1
            aggregate_stats["total_in_reports"] += file_stats["total_in_report"]
            aggregate_stats["imported_new"] += file_stats["imported_new"]
            aggregate_stats["duplicates_skipped"] += file_stats["duplicates_skipped"]
            aggregate_stats["errors"] += file_stats["errors"]
            if file_stats["target"] and file_stats["target"] not in aggregate_stats["targets"]:
                aggregate_stats["targets"].append(file_stats["target"])
            aggregate_stats["per_file"].append(file_stats)

        return aggregate_stats

    def import_findings_list(self, findings_list: List[Dict[str, Any]], source: str = "manual") -> Dict[str, Any]:
        """
        Import findings from a list of dictionaries.

        Args:
            findings_list: List of finding dictionaries.
            source: Source identifier for tracking.

        Returns:
            Import statistics.
        """
        stats = {"total": len(findings_list), "imported": 0, "duplicates": 0, "errors": 0}

        for finding_data in findings_list:
            try:
                finding = Finding.from_dict(finding_data)
                finding.source_report = source
                if not finding.discovered_at:
                    finding.discovered_at = datetime.utcnow().isoformat()

                finding_id, is_new = self.add_finding(finding, deduplicate=True)
                if is_new:
                    stats["imported"] += 1
                else:
                    stats["duplicates"] += 1
            except Exception:
                stats["errors"] += 1

        return stats

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from a URL."""
        if not url:
            return ""
        # Simple extraction without urllib to avoid import overhead
        url = url.lower()
        if "://" in url:
            url = url.split("://", 1)[1]
        if "/" in url:
            url = url.split("/", 1)[0]
        if ":" in url:
            url = url.split(":", 1)[0]
        return url

    # =========================================================================
    # EXPORT METHODS
    # =========================================================================

    def export_json(self, output_path: str = None, filtered: List[Finding] = None) -> str:
        """
        Export findings to JSON format.

        Args:
            output_path: Optional file path to write to.
            filtered: Optional subset of findings to export. Exports all if None.

        Returns:
            JSON string of the exported data.
        """
        findings_to_export = filtered if filtered is not None else list(self.findings.values())

        export_data = {
            "export_metadata": {
                "exported_at": datetime.utcnow().isoformat(),
                "exporter": "Super Monster v1.0.0",
                "total_findings": len(findings_to_export),
                "severity_breakdown": self._severity_breakdown(findings_to_export),
            },
            "findings": [f.to_dict() for f in findings_to_export],
        }

        json_str = json.dumps(export_data, indent=2, default=str)

        if output_path:
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    def export_csv(self, output_path: str, filtered: List[Finding] = None) -> int:
        """
        Export findings to CSV format.

        Args:
            output_path: File path to write CSV to.
            filtered: Optional subset of findings to export.

        Returns:
            Number of rows exported.
        """
        import csv

        findings_to_export = filtered if filtered is not None else list(self.findings.values())

        headers = [
            "id", "finding_type", "severity", "title", "url", "domain",
            "cvss_score", "cwe_id", "status", "priority_score",
            "discovered_at", "target", "dupe_probability",
        ]

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for finding in findings_to_export:
                row = finding.to_dict()
                writer.writerow({k: row.get(k, "") for k in headers})

        return len(findings_to_export)

    def export_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the database contents.

        Returns:
            Dictionary with database statistics and breakdowns.
        """
        all_findings = list(self.findings.values())

        severity_breakdown = self._severity_breakdown(all_findings)
        status_breakdown = {}
        type_breakdown = {}
        domain_breakdown = {}

        for f in all_findings:
            status_breakdown[f.status] = status_breakdown.get(f.status, 0) + 1
            type_breakdown[f.finding_type] = type_breakdown.get(f.finding_type, 0) + 1
            domain_breakdown[f.domain] = domain_breakdown.get(f.domain, 0) + 1

        # Top findings by priority
        top_priority = sorted(all_findings, key=lambda x: x.priority_score, reverse=True)[:10]

        return {
            "total_findings": len(all_findings),
            "severity_breakdown": severity_breakdown,
            "status_breakdown": status_breakdown,
            "type_breakdown": type_breakdown,
            "domain_breakdown": domain_breakdown,
            "unique_domains": len(domain_breakdown),
            "unique_types": len(type_breakdown),
            "correlation_chains": len(self._correlation_index),
            "avg_cvss": round(sum(f.cvss_score for f in all_findings) / max(len(all_findings), 1), 2),
            "top_priority_findings": [
                {"id": f.id, "title": f.title, "severity": f.severity, "score": f.priority_score}
                for f in top_priority
            ],
            "metadata": self.metadata,
        }

    def _severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.upper() if f.severity else "INFO"
            if sev in breakdown:
                breakdown[sev] += 1
            else:
                breakdown["INFO"] += 1
        return breakdown


    # =========================================================================
    # DEDUPLICATION ENGINE
    # =========================================================================

    def deduplicate(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Run the deduplication engine across all findings.

        Uses fingerprint-based matching (finding_type + url + evidence hash).
        In aggressive mode, also uses fuzzy URL matching and title similarity.

        Args:
            aggressive: If True, use fuzzy matching in addition to exact fingerprints.

        Returns:
            Dictionary with deduplication results:
            {
                "total_before": int,
                "duplicates_found": int,
                "duplicates_removed": int,
                "duplicate_groups": list,
            }
        """
        stats = {
            "total_before": len(self.findings),
            "duplicates_found": 0,
            "duplicates_removed": 0,
            "duplicate_groups": [],
        }

        # Phase 1: Exact fingerprint matching
        fingerprint_groups: Dict[str, List[str]] = {}
        for finding_id, finding in self.findings.items():
            if not finding.fingerprint:
                finding.compute_fingerprint()
            fp = finding.fingerprint
            if fp not in fingerprint_groups:
                fingerprint_groups[fp] = []
            fingerprint_groups[fp].append(finding_id)

        # Process groups with more than one finding
        for fp, group_ids in fingerprint_groups.items():
            if len(group_ids) <= 1:
                continue

            stats["duplicates_found"] += len(group_ids) - 1

            # Keep the finding with the earliest discovery date
            group_findings = [(fid, self.findings[fid]) for fid in group_ids]
            group_findings.sort(key=lambda x: x[1].discovered_at or "9999")
            primary_id, primary_finding = group_findings[0]

            duplicate_ids = [fid for fid, _ in group_findings[1:]]
            stats["duplicate_groups"].append({
                "primary": primary_id,
                "duplicates": duplicate_ids,
                "fingerprint": fp,
            })

            for dup_id in duplicate_ids:
                dup_finding = self.findings[dup_id]
                # Merge useful info into primary
                if dup_finding.source_report:
                    primary_finding.add_note(
                        f"Merged duplicate from: {dup_finding.source_report}"
                    )
                # Mark as duplicate or remove
                self.delete_finding(dup_id)
                stats["duplicates_removed"] += 1

        # Phase 2: Fuzzy matching (aggressive mode)
        if aggressive:
            self._fuzzy_deduplicate(stats)

        return stats

    def _fuzzy_deduplicate(self, stats: Dict[str, Any]) -> None:
        """
        Perform fuzzy deduplication based on URL similarity and title matching.

        Modifies stats dict in place.
        """
        processed_pairs = set()
        findings_list = list(self.findings.items())

        for i in range(len(findings_list)):
            fid_a, finding_a = findings_list[i]
            if fid_a not in self.findings:
                continue

            for j in range(i + 1, len(findings_list)):
                fid_b, finding_b = findings_list[j]
                if fid_b not in self.findings:
                    continue

                pair_key = tuple(sorted([fid_a, fid_b]))
                if pair_key in processed_pairs:
                    continue
                processed_pairs.add(pair_key)

                # Check if same type
                if finding_a.finding_type != finding_b.finding_type:
                    continue

                # Check URL similarity
                similarity = self._url_similarity(finding_a.url, finding_b.url)
                if similarity < 0.85:
                    continue

                # Check title similarity
                title_sim = self._text_similarity(finding_a.title, finding_b.title)
                if title_sim < 0.80:
                    continue

                # These are likely duplicates
                stats["duplicates_found"] += 1

                # Keep the one with higher CVSS or earlier discovery
                if finding_a.cvss_score >= finding_b.cvss_score:
                    primary, duplicate_id = finding_a, fid_b
                else:
                    primary, duplicate_id = finding_b, fid_a

                dup_finding = self.findings.get(duplicate_id)
                if dup_finding:
                    primary.add_note(f"Fuzzy-merged duplicate: {dup_finding.title[:50]}")
                    self.delete_finding(duplicate_id)
                    stats["duplicates_removed"] += 1

    @staticmethod
    def _url_similarity(url_a: str, url_b: str) -> float:
        """Calculate similarity between two URLs (0.0 to 1.0)."""
        if not url_a or not url_b:
            return 0.0
        if url_a == url_b:
            return 1.0

        # Normalize URLs
        a = url_a.lower().rstrip("/")
        b = url_b.lower().rstrip("/")
        if a == b:
            return 1.0

        # Remove protocol
        if "://" in a:
            a = a.split("://", 1)[1]
        if "://" in b:
            b = b.split("://", 1)[1]
        if a == b:
            return 0.98

        # Character-level similarity (simple ratio)
        common = sum(1 for ca, cb in zip(a, b) if ca == cb)
        max_len = max(len(a), len(b))
        if max_len == 0:
            return 1.0
        return common / max_len

    @staticmethod
    def _text_similarity(text_a: str, text_b: str) -> float:
        """Calculate similarity between two text strings (0.0 to 1.0)."""
        if not text_a or not text_b:
            return 0.0
        if text_a == text_b:
            return 1.0

        a_lower = text_a.lower()
        b_lower = text_b.lower()
        if a_lower == b_lower:
            return 1.0

        # Word-level Jaccard similarity
        words_a = set(a_lower.split())
        words_b = set(b_lower.split())

        if not words_a or not words_b:
            return 0.0

        intersection = words_a & words_b
        union = words_a | words_b

        return len(intersection) / len(union) if union else 0.0

    def find_potential_duplicates(self, finding: Finding, threshold: float = 0.7) -> List[Tuple[str, float]]:
        """
        Find potential duplicates of a given finding in the database.

        Args:
            finding: The finding to check against the database.
            threshold: Minimum similarity score to be considered a potential dupe.

        Returns:
            List of tuples (finding_id, similarity_score).
        """
        if not finding.fingerprint:
            finding.compute_fingerprint()

        # Check exact fingerprint match first
        exact_match = self._fingerprint_index.get(finding.fingerprint)
        if exact_match:
            return [(exact_match, 1.0)]

        # Fuzzy matching
        candidates = []
        for fid, existing in self.findings.items():
            if existing.finding_type != finding.finding_type:
                continue

            url_sim = self._url_similarity(finding.url, existing.url)
            title_sim = self._text_similarity(finding.title, existing.title)

            # Weighted similarity
            overall_sim = (url_sim * 0.6) + (title_sim * 0.4)
            if overall_sim >= threshold:
                candidates.append((fid, round(overall_sim, 3)))

        return sorted(candidates, key=lambda x: x[1], reverse=True)

    # =========================================================================
    # STATISTICS AND AGGREGATION
    # =========================================================================

    def statistics(self) -> Dict[str, Any]:
        """
        Compute comprehensive statistics about the findings database.

        Returns:
            Dictionary of statistics.
        """
        all_findings = list(self.findings.values())
        if not all_findings:
            return {
                "total": 0,
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "status_breakdown": {},
                "avg_cvss": 0.0,
                "max_cvss": 0.0,
                "unique_domains": 0,
                "unique_types": 0,
                "correlation_chains": 0,
                "needs_retest": 0,
                "total_bounty_estimate": 0.0,
            }

        cvss_scores = [f.cvss_score for f in all_findings if f.cvss_score > 0]
        retest_needed = len(self.needs_retest())
        total_bounty = sum(f.bounty_estimate for f in all_findings)

        return {
            "total": len(all_findings),
            "severity_breakdown": self._severity_breakdown(all_findings),
            "status_breakdown": {
                status: len(ids) for status, ids in self._status_index.items()
            },
            "type_breakdown": {
                ftype: len(ids) for ftype, ids in self._type_index.items()
            },
            "domain_breakdown": {
                domain: len(ids) for domain, ids in self._domain_index.items()
            },
            "avg_cvss": round(sum(cvss_scores) / max(len(cvss_scores), 1), 2),
            "max_cvss": max(cvss_scores) if cvss_scores else 0.0,
            "min_cvss": min(cvss_scores) if cvss_scores else 0.0,
            "unique_domains": len(self._domain_index),
            "unique_types": len(self._type_index),
            "correlation_chains": len(self._correlation_index),
            "needs_retest": retest_needed,
            "total_bounty_estimate": round(total_bounty, 2),
            "avg_priority_score": round(
                sum(f.priority_score for f in all_findings) / len(all_findings), 2
            ),
            "findings_with_correlation": sum(
                1 for f in all_findings if f.correlation_ids
            ),
            "composite_findings": sum(1 for f in all_findings if f.is_composite),
        }

    def severity_trend(self, days: int = 30) -> Dict[str, List[int]]:
        """
        Calculate finding trends over time by severity.

        Args:
            days: Number of days to look back.

        Returns:
            Dictionary mapping severity to list of daily counts.
        """
        now = datetime.utcnow()
        trends: Dict[str, List[int]] = {sev: [0] * days for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}

        for finding in self.findings.values():
            if not finding.discovered_at:
                continue
            try:
                discovered = datetime.fromisoformat(finding.discovered_at)
                days_ago = (now - discovered).days
                if 0 <= days_ago < days:
                    day_index = days - 1 - days_ago
                    severity = finding.severity.upper() if finding.severity else "INFO"
                    if severity in trends:
                        trends[severity][day_index] += 1
            except (ValueError, TypeError):
                continue

        return trends

    def domain_risk_scores(self) -> Dict[str, float]:
        """
        Calculate risk scores for each domain based on findings.

        Returns:
            Dictionary mapping domain to risk score.
        """
        from super_monster.config import SEVERITY_ORDER

        domain_scores: Dict[str, float] = {}

        for domain, finding_ids in self._domain_index.items():
            score = 0.0
            for fid in finding_ids:
                finding = self.findings.get(fid)
                if not finding:
                    continue
                severity_weight = SEVERITY_ORDER.get(finding.severity, 1) * 2
                score += severity_weight + finding.cvss_score
            domain_scores[domain] = round(score, 2)

        return dict(sorted(domain_scores.items(), key=lambda x: x[1], reverse=True))

    # =========================================================================
    # LIFECYCLE AND CORRELATION HELPERS
    # =========================================================================

    def create_composite_finding(
        self, child_ids: List[str], title: str, description: str,
        severity: str = "HIGH", chain_description: str = ""
    ) -> Optional[str]:
        """
        Create a composite/escalated finding from multiple child findings.

        Args:
            child_ids: List of finding IDs that form the chain.
            title: Title for the composite finding.
            description: Description of the composite/chain.
            severity: Severity of the composite finding.
            chain_description: Description of how the chain works.

        Returns:
            ID of the new composite finding, or None if creation failed.
        """
        # Validate child findings exist
        children = []
        for cid in child_ids:
            child = self.findings.get(cid)
            if child:
                children.append(child)

        if len(children) < 2:
            return None

        # Generate correlation ID
        correlation_id = f"CHAIN-{uuid.uuid4().hex[:8].upper()}"

        # Create composite finding
        max_cvss = max(c.cvss_score for c in children)
        urls = list(set(c.url for c in children if c.url))

        composite = Finding(
            finding_type="composite_chain",
            severity=severity,
            title=title,
            description=description,
            url=urls[0] if urls else "",
            evidence=f"Chain of {len(children)} findings: " + ", ".join(c.title[:30] for c in children),
            remediation="Address each finding in the chain. See composite_children for details.",
            cvss_score=min(max_cvss + 1.0, 10.0),
            cwe_id=children[0].cwe_id if children else "",
            domain=children[0].domain if children else "",
            target=children[0].target if children else "",
            is_composite=True,
            composite_children=child_ids,
            correlation_ids=[correlation_id],
            chain_description=chain_description,
        )

        composite_id, _ = self.add_finding(composite, deduplicate=False)

        # Link children to correlation
        for child in children:
            child.add_correlation(correlation_id)
            # Update index
            if correlation_id not in self._correlation_index:
                self._correlation_index[correlation_id] = []
            if child.id not in self._correlation_index[correlation_id]:
                self._correlation_index[correlation_id].append(child.id)

        return composite_id

    def get_correlation_chains(self) -> List[Dict[str, Any]]:
        """
        Get all correlation chains with their findings.

        Returns:
            List of chain dictionaries with findings and metadata.
        """
        chains = []
        for corr_id, finding_ids in self._correlation_index.items():
            chain_findings = [self.findings[fid] for fid in finding_ids if fid in self.findings]
            if not chain_findings:
                continue

            max_severity = max(
                chain_findings,
                key=lambda f: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(f.severity, 0)
            ).severity

            chains.append({
                "correlation_id": corr_id,
                "finding_count": len(chain_findings),
                "max_severity": max_severity,
                "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in chain_findings],
                "domains": list(set(f.domain for f in chain_findings if f.domain)),
            })

        return sorted(chains, key=lambda x: x["finding_count"], reverse=True)

    def merge_databases(self, other_db_path: str) -> Dict[str, Any]:
        """
        Merge another FindingDB into this one with deduplication.

        Args:
            other_db_path: Path to the other database JSON file.

        Returns:
            Merge statistics.
        """
        stats = {"total_from_other": 0, "merged_new": 0, "duplicates": 0, "errors": 0}

        try:
            other_db = FindingDB(other_db_path)
        except Exception:
            stats["errors"] = 1
            return stats

        stats["total_from_other"] = other_db.count()

        for finding in other_db.get_all():
            try:
                finding_id, is_new = self.add_finding(finding, deduplicate=True)
                if is_new:
                    stats["merged_new"] += 1
                else:
                    stats["duplicates"] += 1
            except Exception:
                stats["errors"] += 1

        return stats

    def cleanup(self, max_age_days: int = 365, remove_invalid: bool = True) -> Dict[str, int]:
        """
        Clean up old or invalid findings from the database.

        Args:
            max_age_days: Remove findings older than this many days.
            remove_invalid: Whether to remove findings marked as invalid.

        Returns:
            Dictionary with cleanup counts.
        """
        removed = {"old": 0, "invalid": 0, "total": 0}
        now = datetime.utcnow()
        to_remove = []

        for finding_id, finding in self.findings.items():
            # Remove very old findings
            if finding.discovered_at:
                try:
                    discovered = datetime.fromisoformat(finding.discovered_at)
                    age_days = (now - discovered).days
                    if age_days > max_age_days and finding.status in ("fixed", "invalid", "duplicate"):
                        to_remove.append(finding_id)
                        removed["old"] += 1
                        continue
                except (ValueError, TypeError):
                    pass

            # Remove invalid findings
            if remove_invalid and finding.status == "invalid":
                to_remove.append(finding_id)
                removed["invalid"] += 1

        for fid in to_remove:
            self.delete_finding(fid)
            removed["total"] += 1

        return removed
