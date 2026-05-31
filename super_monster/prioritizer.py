"""
Super Monster v1.0.0 - Priority Scoring Engine Module

Full AI-based (rule-based) scoring engine for bug bounty finding prioritization.
Ranks findings by exploitability, business impact, and bug bounty value using
weighted multi-factor scoring.

Scoring Factors (weights from config):
- CVSS Base Score (0.25): Standardized vulnerability severity
- Exploitability (0.20): Ease of exploitation considering attack vector
- Business Impact (0.25): Domain criticality and data sensitivity
- Bug Bounty Value (0.15): Expected payout and novelty factor
- Correlation Bonus (0.15): Chain participation and systemic presence

Features:
- PriorityEngine class with comprehensive scoring pipeline
- Domain auto-classification by business tier from domain name
- Dupe probability estimation per finding type
- Priority-ranked output with submission recommendations
- Estimated bounty ranges per platform
- Colored terminal output with professional formatting
- Report generation in JSON and Markdown formats
- Batch scoring with progress indicators
- Configurable weights and thresholds
"""

import json
import os
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
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
    Colors, SCORING_WEIGHTS, DOMAIN_TIERS, SEVERITY_LEVELS, SEVERITY_ORDER,
    TOOL_BANNER, BOUNTY_ESTIMATES, DUPE_PROBABILITY, FINDING_TYPE_SEVERITY_MAP,
    EXPLOITABILITY_WEIGHTS, BUSINESS_IMPACT_MULTIPLIERS,
    CORRELATION_BONUS_MULTIPLIERS, CONFIDENCE_THRESHOLDS,
    DEFAULT_OUTPUT_DIR, DEFAULT_DB_PATH,
    get_domain_tier, get_bounty_estimate, get_dupe_probability,
    get_severity_from_cvss, calculate_priority_score,
)
from super_monster.finding_db import FindingDB, Finding


# =============================================================================
# CONSTANTS
# =============================================================================

# Submission recommendation thresholds
SUBMISSION_THRESHOLDS = {
    "SUBMIT_IMMEDIATELY": {
        "min_score": 8.0,
        "description": "High-value finding with strong exploitability - submit now",
        "color": Colors.CRITICAL,
        "emoji": "!!",
        "action": "Submit within 24 hours for maximum bounty",
    },
    "SUBMIT": {
        "min_score": 6.0,
        "description": "Solid finding worth reporting",
        "color": Colors.HIGH,
        "emoji": "! ",
        "action": "Submit with detailed PoC and impact analysis",
    },
    "CONSIDER": {
        "min_score": 4.0,
        "description": "May be worth reporting depending on program scope",
        "color": Colors.MEDIUM,
        "emoji": "* ",
        "action": "Consider submitting after reducing dupe probability",
    },
    "SKIP": {
        "min_score": 0.0,
        "description": "Low value or high dupe probability - skip",
        "color": Colors.LOW,
        "emoji": ". ",
        "action": "Skip unless you have unique evidence or chain",
    },
}

# Exploitability factors for different finding characteristics
EXPLOITABILITY_FACTORS = {
    "auth_not_required": 3.0,
    "auth_required": -2.0,
    "user_interaction_required": -2.0,
    "no_user_interaction": 2.0,
    "network_accessible": 3.0,
    "local_only": -3.0,
    "public_exploit_available": 5.0,
    "custom_exploit_needed": -1.0,
    "automated_exploitable": 4.0,
    "manual_exploitation": -1.0,
    "stable_exploit": 2.0,
    "unreliable_exploit": -2.0,
    "no_waf_protection": 2.0,
    "waf_bypass_needed": -2.0,
    "default_config_vuln": 3.0,
    "complex_config_needed": -2.0,
}

# Business impact factors
BUSINESS_IMPACT_FACTORS = {
    "payment_data_at_risk": 5.0,
    "pii_exposure": 4.0,
    "authentication_compromise": 4.5,
    "admin_access_possible": 5.0,
    "mass_user_impact": 4.0,
    "single_user_impact": 2.0,
    "service_disruption": 3.0,
    "data_modification": 3.5,
    "reputation_damage": 3.0,
    "regulatory_violation": 4.0,
    "supply_chain_risk": 4.5,
    "internal_only_impact": 1.0,
}

# Bug bounty value modifiers
BOUNTY_VALUE_MODIFIERS = {
    "novel_technique": 5.0,
    "common_finding": -3.0,
    "chainable": 3.0,
    "clear_poc": 2.0,
    "no_poc": -3.0,
    "unique_endpoint": 2.0,
    "common_endpoint": -2.0,
    "first_report_likely": 3.0,
    "likely_duplicate": -4.0,
    "high_program_payout": 2.0,
    "low_program_payout": -1.0,
    "in_scope": 2.0,
    "edge_of_scope": -2.0,
}

# Finding type exploitability scores (0.0-1.0)
TYPE_EXPLOITABILITY = {
    "rce": 0.95,
    "sqli": 0.90,
    "sqli_blind": 0.75,
    "sqli_error": 0.85,
    "auth_bypass": 0.90,
    "ssrf": 0.80,
    "ssrf_blind": 0.60,
    "xss_stored": 0.80,
    "xss_reflected": 0.70,
    "xss_dom": 0.65,
    "idor": 0.85,
    "broken_access_control": 0.80,
    "privilege_escalation": 0.85,
    "file_upload": 0.75,
    "unrestricted_upload": 0.85,
    "path_traversal": 0.75,
    "lfi": 0.80,
    "rfi": 0.90,
    "xxe": 0.70,
    "ssti": 0.80,
    "deserialization": 0.85,
    "cors": 0.55,
    "csrf": 0.60,
    "open_redirect": 0.50,
    "subdomain_takeover": 0.75,
    "header_injection": 0.55,
    "crlf_injection": 0.60,
    "cache_poisoning": 0.65,
    "clickjacking": 0.40,
    "session_fixation": 0.60,
    "session_hijack": 0.70,
    "cookie_theft": 0.65,
    "info_disclosure": 0.40,
    "credential_exposure": 0.90,
    "api_key_leak": 0.85,
    "pii_leak": 0.70,
    "data_exposure": 0.60,
    "missing_headers": 0.20,
    "cookie_flags": 0.25,
    "version_disclosure": 0.15,
    "directory_listing": 0.30,
    "backup_file": 0.55,
    "debug_endpoint": 0.65,
    "default_credentials": 0.95,
    "weak_password": 0.50,
    "race_condition": 0.70,
    "business_logic": 0.75,
    "payment_bypass": 0.90,
    "rate_limiting": 0.35,
    "dos": 0.45,
    "jwt_vulnerability": 0.75,
    "graphql_introspection": 0.30,
    "websocket_hijack": 0.55,
    "prototype_pollution": 0.60,
}

# Domain keywords for tier classification
DOMAIN_CRITICAL_KEYWORDS = [
    "pay", "payment", "billing", "checkout", "stripe", "paypal",
    "auth", "login", "sso", "oauth", "identity", "iam",
    "api", "gateway", "graphql", "core", "admin", "console",
]

DOMAIN_HIGH_KEYWORDS = [
    "user", "account", "profile", "member", "customer",
    "data", "db", "database", "storage", "backup",
    "internal", "intranet", "corp", "mail", "upload",
]

DOMAIN_MEDIUM_KEYWORDS = [
    "www", "web", "app", "mobile", "shop", "store",
    "blog", "news", "content", "support", "docs",
]

DOMAIN_LOW_KEYWORDS = [
    "dev", "staging", "test", "qa", "sandbox",
    "demo", "preview", "beta", "ci", "build",
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PriorityScore:
    """Detailed priority score breakdown for a finding."""
    finding_id: str = ""
    total_score: float = 0.0
    cvss_component: float = 0.0
    exploitability_component: float = 0.0
    business_impact_component: float = 0.0
    bounty_value_component: float = 0.0
    correlation_bonus_component: float = 0.0
    domain_multiplier: float = 1.0
    domain_tier: str = ""
    dupe_probability: float = 0.0
    submission_recommendation: str = ""
    estimated_bounty_min: float = 0.0
    estimated_bounty_max: float = 0.0
    estimated_bounty_median: float = 0.0
    factors: dict = field(default_factory=dict)
    penalties: dict = field(default_factory=dict)
    bonuses: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PriorityScore":
        """Create from dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class PrioritizedFinding:
    """A finding with its priority score and recommendation."""
    finding: Finding = field(default_factory=Finding)
    score: PriorityScore = field(default_factory=PriorityScore)
    rank: int = 0
    recommendation: str = ""
    action_items: list = field(default_factory=list)
    report_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding": self.finding.to_dict(),
            "score": self.score.to_dict(),
            "rank": self.rank,
            "recommendation": self.recommendation,
            "action_items": self.action_items,
            "report_notes": self.report_notes,
        }


@dataclass
class PriorityReport:
    """Complete priority analysis report."""
    report_id: str = ""
    generated_at: str = ""
    generator: str = TOOL_BANNER
    scoring_weights: dict = field(default_factory=dict)
    total_findings: int = 0
    total_scored: int = 0
    total_estimated_bounty: float = 0.0
    submission_summary: dict = field(default_factory=dict)
    top_findings: list = field(default_factory=list)
    domain_analysis: dict = field(default_factory=dict)
    dupe_analysis: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# =============================================================================
# PRIORITY ENGINE CLASS
# =============================================================================

class PriorityEngine:
    """
    Main priority scoring engine for bug bounty findings.
    
    Applies a weighted multi-factor scoring formula to rank findings
    by their value for submission. Considers exploitability, business
    impact, bounty potential, and correlation with other findings.
    
    Usage:
        engine = PriorityEngine()
        engine.load_findings(db)
        results = engine.score_all()
        engine.print_ranked_results()
        engine.generate_report(output_dir)
    """

    def __init__(self, db: FindingDB = None, platform: str = "hackerone",
                 min_score: float = 0.0, weights: Dict[str, float] = None,
                 output_dir: str = None):
        """
        Initialize the priority engine.

        Args:
            db: FindingDB instance to load findings from.
            platform: Bug bounty platform for bounty estimates.
            min_score: Minimum score threshold for inclusion in reports.
            weights: Custom scoring weights (overrides config defaults).
            output_dir: Directory for output files.
        """
        self.db = db
        self.platform = platform
        self.min_score = min_score
        self.weights = weights or dict(SCORING_WEIGHTS)
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.findings: List[Finding] = []
        self.scored_findings: List[PrioritizedFinding] = []
        self.priority_scores: Dict[str, PriorityScore] = {}
        self._domain_tiers: Dict[str, Tuple[str, float]] = {}
        self._dupe_cache: Dict[str, float] = {}
        self._correlation_scores: Dict[str, float] = {}
        self.stats: Dict[str, Any] = {
            "total_scored": 0,
            "submit_immediately_count": 0,
            "submit_count": 0,
            "consider_count": 0,
            "skip_count": 0,
            "total_estimated_bounty": 0.0,
            "avg_score": 0.0,
            "max_score": 0.0,
            "processing_time": 0.0,
        }

    def load_findings(self, db: FindingDB = None) -> int:
        """
        Load findings from the database for scoring.

        Args:
            db: Optional FindingDB override.

        Returns:
            Number of findings loaded.
        """
        if db:
            self.db = db
        if not self.db:
            return 0

        self.findings = self.db.get_all()
        self._precompute_domain_tiers()
        self._precompute_dupe_probabilities()
        self._precompute_correlation_scores()
        return len(self.findings)

    def load_findings_from_reports(self, input_path: str) -> int:
        """
        Load findings from Monster JSON reports.

        Args:
            input_path: Path to report file or directory.

        Returns:
            Number of findings loaded.
        """
        if not self.db:
            self.db = FindingDB()

        if os.path.isdir(input_path):
            self.db.import_directory(input_path)
        elif os.path.isfile(input_path):
            self.db.import_monster_report(input_path)

        return self.load_findings()

    def _precompute_domain_tiers(self):
        """Pre-compute domain tier classifications for all domains."""
        self._domain_tiers.clear()
        domains = set(f.domain for f in self.findings if f.domain)
        for domain in domains:
            tier_name, multiplier = self._classify_domain(domain)
            self._domain_tiers[domain] = (tier_name, multiplier)

    def _precompute_dupe_probabilities(self):
        """Pre-compute duplicate probabilities for all findings."""
        self._dupe_cache.clear()

        # Count findings by type and domain
        type_domain_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        type_counts: Dict[str, int] = defaultdict(int)

        for f in self.findings:
            type_counts[f.finding_type] += 1
            type_domain_counts[f.finding_type][f.domain] += 1

        for f in self.findings:
            dupe_prob = self._calculate_dupe_probability(
                f, type_counts, type_domain_counts
            )
            self._dupe_cache[f.id] = dupe_prob

    def _precompute_correlation_scores(self):
        """Pre-compute correlation bonus scores for findings with chains."""
        self._correlation_scores.clear()
        for f in self.findings:
            corr_count = len(f.correlation_ids)
            if corr_count >= 4:
                self._correlation_scores[f.id] = 1.0
            elif corr_count >= 3:
                self._correlation_scores[f.id] = 0.8
            elif corr_count >= 2:
                self._correlation_scores[f.id] = 0.6
            elif corr_count >= 1:
                self._correlation_scores[f.id] = 0.3
            else:
                self._correlation_scores[f.id] = 0.0

            # Bonus for composite/chain findings
            if f.is_composite:
                self._correlation_scores[f.id] = min(
                    self._correlation_scores[f.id] + 0.3, 1.0
                )

    # =========================================================================
    # SCORING METHODS
    # =========================================================================

    def score_finding(self, finding: Finding) -> PriorityScore:
        """
        Calculate the full priority score for a single finding.

        Applies all scoring factors with configured weights to produce
        a composite score from 0.0 to 10.0.

        Args:
            finding: The Finding to score.

        Returns:
            PriorityScore with detailed breakdown.
        """
        # Component 1: CVSS Base Score
        cvss_component = self._score_cvss(finding)

        # Component 2: Exploitability
        exploit_component = self._score_exploitability(finding)

        # Component 3: Business Impact
        impact_component = self._score_business_impact(finding)

        # Component 4: Bug Bounty Value
        bounty_component = self._score_bounty_value(finding)

        # Component 5: Correlation Bonus
        correlation_component = self._score_correlation_bonus(finding)

        # Apply weights
        weighted_score = (
            cvss_component * self.weights.get("cvss_base", 0.25) +
            exploit_component * self.weights.get("exploitability", 0.20) +
            impact_component * self.weights.get("business_impact", 0.25) +
            bounty_component * self.weights.get("bug_bounty_value", 0.15) +
            correlation_component * self.weights.get("correlation_bonus", 0.15)
        )

        # Scale to 0-10
        total_score = min(weighted_score * 10.0, 10.0)

        # Apply domain multiplier
        domain_tier, domain_mult = self._domain_tiers.get(
            finding.domain, ("tier_3_medium", 1.5)
        )
        # Domain multiplier adjusts score by up to 30%
        total_score = min(total_score * (1 + (domain_mult - 1) * 0.3), 10.0)

        # Get dupe probability
        dupe_prob = self._dupe_cache.get(finding.id, 0.25)

        # Get bounty estimates
        bounty_est = get_bounty_estimate(finding.severity, self.platform)

        # Determine submission recommendation
        recommendation = self._get_recommendation(total_score, dupe_prob)

        # Build score object
        score = PriorityScore(
            finding_id=finding.id,
            total_score=round(total_score, 2),
            cvss_component=round(cvss_component, 4),
            exploitability_component=round(exploit_component, 4),
            business_impact_component=round(impact_component, 4),
            bounty_value_component=round(bounty_component, 4),
            correlation_bonus_component=round(correlation_component, 4),
            domain_multiplier=domain_mult,
            domain_tier=domain_tier,
            dupe_probability=round(dupe_prob, 3),
            submission_recommendation=recommendation,
            estimated_bounty_min=bounty_est.get("min", 0),
            estimated_bounty_max=bounty_est.get("max", 0),
            estimated_bounty_median=bounty_est.get("median", 0),
            factors=self._get_scoring_factors(finding),
            penalties=self._get_scoring_penalties(finding, dupe_prob),
            bonuses=self._get_scoring_bonuses(finding),
        )

        return score

    def _score_cvss(self, finding: Finding) -> float:
        """
        Score the CVSS base component (0.0-1.0).
        
        Direct mapping of CVSS score to a 0-1 scale.
        """
        if finding.cvss_score > 0:
            return min(finding.cvss_score / 10.0, 1.0)

        # Estimate from severity if no CVSS
        severity_cvss = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25,
            "INFO": 0.05,
        }
        return severity_cvss.get(finding.severity, 0.3)

    def _score_exploitability(self, finding: Finding) -> float:
        """
        Score the exploitability component (0.0-1.0).
        
        Based on finding type exploitability rating, evidence quality,
        and attack complexity indicators.
        """
        # Base exploitability from finding type
        base_score = TYPE_EXPLOITABILITY.get(finding.finding_type, 0.5)

        # Adjust based on evidence quality
        if finding.evidence:
            evidence_len = len(finding.evidence)
            if evidence_len > 500:
                base_score = min(base_score + 0.10, 1.0)
            elif evidence_len > 200:
                base_score = min(base_score + 0.05, 1.0)
            elif evidence_len < 50:
                base_score = max(base_score - 0.05, 0.0)

        # Check for exploitation indicators in evidence
        evidence_lower = (finding.evidence or "").lower()
        if any(kw in evidence_lower for kw in ["poc", "proof of concept", "exploit"]):
            base_score = min(base_score + 0.10, 1.0)
        if any(kw in evidence_lower for kw in ["authenticated", "login required"]):
            base_score = max(base_score - 0.10, 0.0)
        if any(kw in evidence_lower for kw in ["unauthenticated", "no auth"]):
            base_score = min(base_score + 0.05, 1.0)

        # Network accessibility check from URL
        if finding.url:
            parsed = urlparse(finding.url)
            if parsed.scheme == "https":
                base_score = min(base_score + 0.02, 1.0)
            # Public-facing endpoints are more exploitable
            if parsed.port and int(parsed.port) in (80, 443, 8080, 8443):
                base_score = min(base_score + 0.03, 1.0)

        return max(min(base_score, 1.0), 0.0)

    def _score_business_impact(self, finding: Finding) -> float:
        """
        Score the business impact component (0.0-1.0).
        
        Based on domain tier, finding type impact, and data sensitivity.
        """
        # Base from severity
        severity_impact = {
            "CRITICAL": 1.0,
            "HIGH": 0.80,
            "MEDIUM": 0.50,
            "LOW": 0.25,
            "INFO": 0.10,
        }
        base_score = severity_impact.get(finding.severity, 0.3)

        # Domain tier boost
        tier_name, multiplier = self._domain_tiers.get(
            finding.domain, ("tier_3_medium", 1.5)
        )
        tier_boost = {
            "tier_1_critical": 0.30,
            "tier_2_high": 0.20,
            "tier_3_medium": 0.10,
            "tier_4_low": 0.00,
            "tier_5_info": -0.10,
        }
        base_score += tier_boost.get(tier_name, 0.0)

        # Finding type impact boost
        high_impact_types = {
            "rce": 0.20,
            "sqli": 0.15,
            "auth_bypass": 0.20,
            "credential_exposure": 0.15,
            "payment_bypass": 0.20,
            "privilege_escalation": 0.15,
            "pii_leak": 0.10,
            "session_hijack": 0.10,
            "idor": 0.10,
            "ssrf": 0.10,
        }
        base_score += high_impact_types.get(finding.finding_type, 0.0)

        # Check description for business-critical keywords
        desc_lower = (finding.description or "").lower()
        if any(kw in desc_lower for kw in ["payment", "credit card", "financial"]):
            base_score = min(base_score + 0.15, 1.0)
        if any(kw in desc_lower for kw in ["admin", "administrator", "root"]):
            base_score = min(base_score + 0.10, 1.0)
        if any(kw in desc_lower for kw in ["personal data", "pii", "gdpr"]):
            base_score = min(base_score + 0.10, 1.0)
        if any(kw in desc_lower for kw in ["all users", "every user", "mass"]):
            base_score = min(base_score + 0.10, 1.0)

        return max(min(base_score, 1.0), 0.0)

    def _score_bounty_value(self, finding: Finding) -> float:
        """
        Score the bug bounty value component (0.0-1.0).
        
        Considers expected payout, novelty, chainability, and
        likelihood of being a duplicate.
        """
        # Base from severity/bounty estimates
        bounty_est = get_bounty_estimate(finding.severity, self.platform)
        median_bounty = bounty_est.get("median", 0)
        # Normalize: $20k+ = 1.0, $0 = 0.0
        base_score = min(median_bounty / 20000.0, 1.0)

        # Dupe probability penalty
        dupe_prob = self._dupe_cache.get(finding.id, 0.25)
        dupe_penalty = dupe_prob * 0.4  # Max 40% penalty
        base_score = max(base_score - dupe_penalty, 0.0)

        # Novelty bonus for uncommon finding types
        common_types = {"missing_headers", "cookie_flags", "version_disclosure",
                       "cors", "open_redirect", "info_disclosure"}
        rare_types = {"race_condition", "deserialization", "ssti", "prototype_pollution",
                     "subdomain_takeover", "cache_poisoning", "business_logic"}

        if finding.finding_type in common_types:
            base_score = max(base_score - 0.15, 0.0)
        elif finding.finding_type in rare_types:
            base_score = min(base_score + 0.15, 1.0)

        # Chainability bonus
        if finding.correlation_ids:
            base_score = min(base_score + 0.10, 1.0)
        if finding.is_composite:
            base_score = min(base_score + 0.15, 1.0)

        # Clear evidence/PoC bonus
        if finding.evidence and len(finding.evidence) > 200:
            base_score = min(base_score + 0.05, 1.0)

        return max(min(base_score, 1.0), 0.0)

    def _score_correlation_bonus(self, finding: Finding) -> float:
        """
        Score the correlation bonus component (0.0-1.0).
        
        Higher scores for findings that are part of attack chains,
        appear on multiple targets, or have systemic characteristics.
        """
        return self._correlation_scores.get(finding.id, 0.0)

    # =========================================================================
    # DOMAIN CLASSIFICATION
    # =========================================================================

    def _classify_domain(self, domain: str) -> Tuple[str, float]:
        """
        Classify a domain into a business tier based on name patterns.

        Uses keyword matching and regex patterns from config to determine
        the business criticality of a domain/subdomain.

        Args:
            domain: The domain/subdomain to classify.

        Returns:
            Tuple of (tier_name, multiplier).
        """
        if not domain:
            return "tier_3_medium", 1.5

        domain_lower = domain.lower().strip()

        # Use config-based classification first
        tier_name, multiplier = get_domain_tier(domain_lower)
        return tier_name, multiplier

    def _calculate_dupe_probability(self, finding: Finding,
                                     type_counts: Dict[str, int],
                                     type_domain_counts: Dict[str, Dict[str, int]]) -> float:
        """
        Calculate the probability that a finding is a duplicate.

        Considers:
        - Base dupe rate for the finding type
        - Number of similar findings in same domain
        - Whether the endpoint is commonly tested
        - Age of the finding (older programs have more reports)

        Args:
            finding: The finding to assess.
            type_counts: Global counts per finding type.
            type_domain_counts: Counts per type per domain.

        Returns:
            Dupe probability from 0.0 to 0.99.
        """
        # Get base probability from config
        base_prob = get_dupe_probability(finding.finding_type)

        # Adjust based on how many of this type exist in our data
        type_count = type_counts.get(finding.finding_type, 0)
        if type_count > 10:
            base_prob = min(base_prob + 0.15, 0.95)
        elif type_count > 5:
            base_prob = min(base_prob + 0.10, 0.90)

        # Same domain same type is higher dupe
        same_domain_count = type_domain_counts.get(
            finding.finding_type, {}
        ).get(finding.domain, 0)
        if same_domain_count > 3:
            base_prob = min(base_prob + 0.20, 0.95)
        elif same_domain_count > 1:
            base_prob = min(base_prob + 0.10, 0.90)

        # Common endpoints are more likely dupes
        if finding.url:
            common_paths = ["/login", "/api", "/admin", "/wp-admin",
                          "/graphql", "/.env", "/robots.txt", "/sitemap.xml"]
            parsed = urlparse(finding.url)
            if any(cp in parsed.path.lower() for cp in common_paths):
                base_prob = min(base_prob + 0.10, 0.95)

        # Novel finding types are less likely dupes
        novel_types = {"race_condition", "business_logic", "deserialization",
                      "ssti", "prototype_pollution", "cache_poisoning"}
        if finding.finding_type in novel_types:
            base_prob = max(base_prob - 0.15, 0.05)

        # Composite findings are very unlikely to be dupes
        if finding.is_composite:
            base_prob = max(base_prob - 0.30, 0.02)

        return max(min(base_prob, 0.99), 0.01)

    def _get_recommendation(self, score: float, dupe_prob: float) -> str:
        """
        Determine submission recommendation based on score and dupe probability.

        Args:
            score: The total priority score (0-10).
            dupe_prob: The duplicate probability (0-1).

        Returns:
            Recommendation string.
        """
        # High dupe probability reduces recommendation level
        effective_score = score * (1 - dupe_prob * 0.5)

        if effective_score >= SUBMISSION_THRESHOLDS["SUBMIT_IMMEDIATELY"]["min_score"]:
            return "SUBMIT_IMMEDIATELY"
        elif effective_score >= SUBMISSION_THRESHOLDS["SUBMIT"]["min_score"]:
            return "SUBMIT"
        elif effective_score >= SUBMISSION_THRESHOLDS["CONSIDER"]["min_score"]:
            return "CONSIDER"
        else:
            return "SKIP"

    def _get_scoring_factors(self, finding: Finding) -> Dict[str, float]:
        """Get positive scoring factors for a finding."""
        factors = {}

        if finding.cvss_score >= 9.0:
            factors["critical_cvss"] = finding.cvss_score
        elif finding.cvss_score >= 7.0:
            factors["high_cvss"] = finding.cvss_score

        exploit_score = TYPE_EXPLOITABILITY.get(finding.finding_type, 0.5)
        if exploit_score >= 0.8:
            factors["high_exploitability"] = exploit_score

        tier_name, mult = self._domain_tiers.get(finding.domain, ("tier_3_medium", 1.5))
        if mult >= 2.0:
            factors["critical_domain"] = mult

        if finding.correlation_ids:
            factors["in_correlation_chain"] = len(finding.correlation_ids)

        if finding.is_composite:
            factors["composite_finding"] = 1.0

        return factors

    def _get_scoring_penalties(self, finding: Finding, dupe_prob: float) -> Dict[str, float]:
        """Get negative scoring penalties for a finding."""
        penalties = {}

        if dupe_prob >= 0.7:
            penalties["high_dupe_probability"] = dupe_prob
        elif dupe_prob >= 0.5:
            penalties["medium_dupe_probability"] = dupe_prob

        common_types = {"missing_headers", "cookie_flags", "version_disclosure"}
        if finding.finding_type in common_types:
            penalties["common_finding_type"] = 0.3

        tier_name, mult = self._domain_tiers.get(finding.domain, ("tier_3_medium", 1.5))
        if mult <= 1.0:
            penalties["low_value_domain"] = mult

        if not finding.evidence or len(finding.evidence) < 50:
            penalties["weak_evidence"] = 0.2

        return penalties

    def _get_scoring_bonuses(self, finding: Finding) -> Dict[str, float]:
        """Get bonus scoring factors for a finding."""
        bonuses = {}

        novel_types = {"race_condition", "business_logic", "deserialization",
                      "ssti", "prototype_pollution", "cache_poisoning",
                      "subdomain_takeover"}
        if finding.finding_type in novel_types:
            bonuses["novel_finding_type"] = 0.15

        if finding.evidence and len(finding.evidence) > 500:
            bonuses["detailed_evidence"] = 0.1

        if finding.is_composite and finding.composite_children:
            chain_len = len(finding.composite_children)
            if chain_len >= 4:
                bonuses["long_chain"] = 0.2
            elif chain_len >= 2:
                bonuses["medium_chain"] = 0.1

        return bonuses

    # =========================================================================
    # BATCH SCORING
    # =========================================================================

    def score_all(self) -> List[PrioritizedFinding]:
        """
        Score all loaded findings and rank them.

        Returns:
            List of PrioritizedFinding objects sorted by score (highest first).
        """
        start_time = time.time()
        self.scored_findings = []
        self.priority_scores.clear()

        for finding in self.findings:
            score = self.score_finding(finding)
            self.priority_scores[finding.id] = score

            # Update finding in DB
            finding.priority_score = score.total_score
            finding.bounty_estimate = score.estimated_bounty_median
            finding.dupe_probability = score.dupe_probability

            # Create PrioritizedFinding
            prioritized = PrioritizedFinding(
                finding=finding,
                score=score,
                recommendation=score.submission_recommendation,
                action_items=self._generate_action_items(finding, score),
                report_notes=self._generate_report_notes(finding, score),
            )
            self.scored_findings.append(prioritized)

        # Sort by score descending
        self.scored_findings.sort(key=lambda pf: pf.score.total_score, reverse=True)

        # Assign ranks
        for i, pf in enumerate(self.scored_findings):
            pf.rank = i + 1

        # Compute stats
        self._compute_stats(start_time)

        return self.scored_findings

    def _generate_action_items(self, finding: Finding, score: PriorityScore) -> List[str]:
        """Generate actionable items based on score and finding type."""
        items = []

        if score.submission_recommendation == "SUBMIT_IMMEDIATELY":
            items.append("Write detailed report with clear reproduction steps")
            items.append("Include impact analysis and affected user count")
            items.append("Attach PoC screenshots/video")
            items.append(f"Estimated bounty: ${score.estimated_bounty_min}-${score.estimated_bounty_max}")
        elif score.submission_recommendation == "SUBMIT":
            items.append("Prepare report with reproduction steps")
            items.append("Demonstrate business impact")
            if score.dupe_probability > 0.4:
                items.append("Add unique angle to differentiate from potential dupes")
        elif score.submission_recommendation == "CONSIDER":
            items.append("Check if program explicitly accepts this finding type")
            if score.dupe_probability > 0.5:
                items.append("High dupe risk - find novel exploitation path")
            items.append("Consider chaining with other findings for higher impact")
        else:
            items.append("Low priority - focus on higher value targets")
            if finding.correlation_ids:
                items.append("May be useful as part of a larger chain")

        # Type-specific actions
        if finding.finding_type in ("xss_stored", "xss_reflected"):
            items.append("Demonstrate impact beyond alert() - steal session/CSRF")
        elif finding.finding_type == "ssrf":
            items.append("Attempt internal service discovery and cloud metadata access")
        elif finding.finding_type in ("sqli", "sqli_blind"):
            items.append("Extract sample data to demonstrate data access")
        elif finding.finding_type == "idor":
            items.append("Show access to other users data with minimal IDs")

        return items[:6]

    def _generate_report_notes(self, finding: Finding, score: PriorityScore) -> str:
        """Generate brief report notes for a scored finding."""
        notes_parts = []

        if score.total_score >= 8.0:
            notes_parts.append("High-value target")
        if score.dupe_probability >= 0.6:
            notes_parts.append(f"Dupe risk: {score.dupe_probability:.0%}")
        if score.domain_tier in ("tier_1_critical", "tier_2_high"):
            notes_parts.append(f"Critical domain ({score.domain_tier})")
        if finding.is_composite:
            notes_parts.append("Part of attack chain")
        if score.correlation_bonus_component > 0.5:
            notes_parts.append("Strong correlation bonus")

        return " | ".join(notes_parts) if notes_parts else ""

    def _compute_stats(self, start_time: float):
        """Compute summary statistics after scoring."""
        self.stats["total_scored"] = len(self.scored_findings)
        self.stats["processing_time"] = time.time() - start_time

        scores = [pf.score.total_score for pf in self.scored_findings]
        if scores:
            self.stats["avg_score"] = round(sum(scores) / len(scores), 2)
            self.stats["max_score"] = round(max(scores), 2)

        self.stats["submit_immediately_count"] = sum(
            1 for pf in self.scored_findings
            if pf.score.submission_recommendation == "SUBMIT_IMMEDIATELY"
        )
        self.stats["submit_count"] = sum(
            1 for pf in self.scored_findings
            if pf.score.submission_recommendation == "SUBMIT"
        )
        self.stats["consider_count"] = sum(
            1 for pf in self.scored_findings
            if pf.score.submission_recommendation == "CONSIDER"
        )
        self.stats["skip_count"] = sum(
            1 for pf in self.scored_findings
            if pf.score.submission_recommendation == "SKIP"
        )
        self.stats["total_estimated_bounty"] = sum(
            pf.score.estimated_bounty_median for pf in self.scored_findings
        )

    # =========================================================================
    # TERMINAL OUTPUT
    # =========================================================================

    def print_ranked_results(self, limit: int = 20):
        """
        Print the ranked findings list with colored terminal output.

        Displays a professional formatted table with scores, severities,
        recommendations, and bounty estimates.

        Args:
            limit: Maximum number of findings to display.
        """
        if not self.scored_findings:
            print(f"  {Colors.WARNING}No scored findings to display.{Colors.RESET}")
            return

        print(f"\n{Colors.HEADER}{'=' * 70}")
        print(f"  PRIORITY RANKED FINDINGS")
        print(f"{'=' * 70}{Colors.RESET}")
        print(f"  {Colors.LABEL}Platform:{Colors.RESET} {self.platform.title()} | "
              f"{Colors.LABEL}Scored:{Colors.RESET} {len(self.scored_findings)} findings")
        print(f"  {Colors.LABEL}Weights:{Colors.RESET} CVSS={self.weights['cvss_base']}, "
              f"Exploit={self.weights['exploitability']}, "
              f"Impact={self.weights['business_impact']}, "
              f"Bounty={self.weights['bug_bounty_value']}, "
              f"Corr={self.weights['correlation_bonus']}")
        print()

        # Print column headers
        header = (f"  {'#':<4} {'Score':<7} {'Sev':<9} {'Rec':<20} "
                  f"{'Type':<20} {'Domain':<20} {'Bounty':<10}")
        print(f"{Colors.SUBHEADER}{header}{Colors.RESET}")
        print(f"  {'-' * 90}")

        displayed = 0
        for pf in self.scored_findings[:limit]:
            if pf.score.total_score < self.min_score:
                continue

            sev_color = Colors.severity_color(pf.finding.severity)
            score_color = Colors.score_color(pf.score.total_score)
            rec = pf.score.submission_recommendation
            rec_config = SUBMISSION_THRESHOLDS.get(rec, SUBMISSION_THRESHOLDS["SKIP"])
            rec_color = rec_config["color"]
            rec_emoji = rec_config["emoji"]

            bounty_str = f"${pf.score.estimated_bounty_median:,.0f}"
            dupe_str = f"{pf.score.dupe_probability:.0%}"

            line = (
                f"  {pf.rank:<4} "
                f"{score_color}[{pf.score.total_score:>4.1f}]{Colors.RESET} "
                f"{sev_color}{pf.finding.severity:<9}{Colors.RESET}"
                f"{rec_color}{rec_emoji} {rec:<17}{Colors.RESET} "
                f"{pf.finding.finding_type:<20} "
                f"{(pf.finding.domain or 'unknown')[:20]:<20} "
                f"{bounty_str:<10}"
            )
            print(line)

            # Print title on second line for high-priority findings
            if pf.score.total_score >= 6.0:
                print(f"       {Colors.DIMMED}{pf.finding.title[:65]}{Colors.RESET}")
                if pf.report_notes:
                    print(f"       {Colors.ACCENT}{pf.report_notes}{Colors.RESET}")

            displayed += 1

        print(f"  {'-' * 90}")
        print(f"  Showing {displayed} of {len(self.scored_findings)} findings")
        print()

    def print_submission_summary(self):
        """Print a summary of submission recommendations."""
        print(f"\n{Colors.SUBHEADER}--- Submission Recommendations ---{Colors.RESET}")
        print()

        categories = [
            ("SUBMIT_IMMEDIATELY", Colors.CRITICAL, "!!"),
            ("SUBMIT", Colors.HIGH, "! "),
            ("CONSIDER", Colors.MEDIUM, "* "),
            ("SKIP", Colors.LOW, ". "),
        ]

        for cat_name, color, emoji in categories:
            count = sum(
                1 for pf in self.scored_findings
                if pf.score.submission_recommendation == cat_name
            )
            threshold = SUBMISSION_THRESHOLDS[cat_name]
            bar_len = min(count * 2, 40)
            bar = "#" * bar_len

            print(f"  {color}[{emoji}] {cat_name:<20}{Colors.RESET} "
                  f"{Colors.PROGRESS_BAR}{bar}{Colors.RESET} {count} findings")
            print(f"       {Colors.DIMMED}{threshold['action']}{Colors.RESET}")
            print()

        # Total bounty estimate
        total_bounty = sum(
            pf.score.estimated_bounty_median for pf in self.scored_findings
            if pf.score.submission_recommendation in ("SUBMIT_IMMEDIATELY", "SUBMIT")
        )
        print(f"  {Colors.HIGHLIGHT}Estimated Total Bounty (Submit + Immediate): "
              f"${total_bounty:,.0f}{Colors.RESET}")
        print()

    def print_domain_analysis(self):
        """Print domain tier analysis with colored output."""
        print(f"\n{Colors.SUBHEADER}--- Domain Analysis ---{Colors.RESET}")
        print()

        # Group by domain tier
        tier_groups: Dict[str, List[PrioritizedFinding]] = defaultdict(list)
        for pf in self.scored_findings:
            tier = pf.score.domain_tier
            tier_groups[tier].append(pf)

        tier_order = ["tier_1_critical", "tier_2_high", "tier_3_medium",
                     "tier_4_low", "tier_5_info"]
        tier_colors = {
            "tier_1_critical": Colors.CRITICAL,
            "tier_2_high": Colors.HIGH,
            "tier_3_medium": Colors.MEDIUM,
            "tier_4_low": Colors.LOW,
            "tier_5_info": Colors.INFO,
        }
        tier_labels = {
            "tier_1_critical": "CRITICAL (Payment/Auth/API)",
            "tier_2_high": "HIGH (User Data/Internal)",
            "tier_3_medium": "MEDIUM (Public Web/Apps)",
            "tier_4_low": "LOW (Dev/Staging/Test)",
            "tier_5_info": "INFO (Static/Marketing)",
        }

        for tier in tier_order:
            findings_in_tier = tier_groups.get(tier, [])
            if not findings_in_tier:
                continue

            color = tier_colors.get(tier, Colors.INFO)
            label = tier_labels.get(tier, tier)
            count = len(findings_in_tier)
            avg_score = sum(pf.score.total_score for pf in findings_in_tier) / count
            total_bounty = sum(pf.score.estimated_bounty_median for pf in findings_in_tier)

            print(f"  {color}{label}{Colors.RESET}")
            print(f"    Findings: {count} | Avg Score: {avg_score:.1f} | "
                  f"Est. Bounty: ${total_bounty:,.0f}")

            # Show unique domains in this tier
            domains = set(pf.finding.domain for pf in findings_in_tier if pf.finding.domain)
            if domains:
                print(f"    Domains: {', '.join(sorted(domains)[:5])}")
            print()

    def print_dupe_analysis(self):
        """Print duplicate probability analysis."""
        print(f"\n{Colors.SUBHEADER}--- Duplicate Probability Analysis ---{Colors.RESET}")
        print()

        # Group by dupe probability range
        high_dupe = [pf for pf in self.scored_findings if pf.score.dupe_probability >= 0.7]
        medium_dupe = [pf for pf in self.scored_findings if 0.4 <= pf.score.dupe_probability < 0.7]
        low_dupe = [pf for pf in self.scored_findings if pf.score.dupe_probability < 0.4]

        print(f"  {Colors.ERROR}High Dupe Risk (70%+):{Colors.RESET}    {len(high_dupe)} findings")
        for pf in high_dupe[:5]:
            print(f"    [{pf.score.dupe_probability:.0%}] {pf.finding.finding_type} - "
                  f"{pf.finding.title[:40]}")

        print(f"\n  {Colors.WARNING}Medium Dupe Risk (40-70%):{Colors.RESET} {len(medium_dupe)} findings")
        for pf in medium_dupe[:5]:
            print(f"    [{pf.score.dupe_probability:.0%}] {pf.finding.finding_type} - "
                  f"{pf.finding.title[:40]}")

        print(f"\n  {Colors.SUCCESS}Low Dupe Risk (<40%):{Colors.RESET}     {len(low_dupe)} findings")
        for pf in low_dupe[:5]:
            print(f"    [{pf.score.dupe_probability:.0%}] {pf.finding.finding_type} - "
                  f"{pf.finding.title[:40]}")

        print()
        if high_dupe:
            common_types = defaultdict(int)
            for pf in high_dupe:
                common_types[pf.finding.finding_type] += 1
            print(f"  {Colors.DIMMED}Most common high-dupe types:{Colors.RESET}")
            for ftype, count in sorted(common_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {ftype}: {count} findings")
        print()

    def print_full_report(self, limit: int = 20):
        """Print the complete priority analysis report to terminal."""
        self.print_ranked_results(limit)
        self.print_submission_summary()
        self.print_domain_analysis()
        self.print_dupe_analysis()

    # =========================================================================
    # REPORT GENERATION
    # =========================================================================

    def generate_report(self, output_dir: str = None,
                        format: str = "json") -> Dict[str, str]:
        """
        Generate priority report files.

        Args:
            output_dir: Output directory. Uses self.output_dir if None.
            format: Output format ("json", "markdown", or "both").

        Returns:
            Dictionary mapping format to file path.
        """
        output_dir = output_dir or self.output_dir
        os.makedirs(output_dir, exist_ok=True)
        output_files = {}

        if format in ("json", "both"):
            json_path = os.path.join(output_dir, "prioritized_findings.json")
            self._write_json_report(json_path)
            output_files["json"] = json_path

        if format in ("markdown", "both"):
            md_path = os.path.join(output_dir, "priority_report.md")
            self._write_markdown_report(md_path)
            output_files["markdown"] = md_path

        return output_files

    def _write_json_report(self, path: str):
        """Write the JSON priority report."""
        report_data = {
            "priority_report": {
                "report_id": f"PRI-RPT-{uuid.uuid4().hex[:8].upper()}",
                "generated_at": datetime.utcnow().isoformat(),
                "generator": TOOL_BANNER,
                "platform": self.platform,
                "scoring_weights": self.weights,
                "total_findings": len(self.findings),
                "total_scored": len(self.scored_findings),
                "total_estimated_bounty": self.stats["total_estimated_bounty"],
                "statistics": self.stats,
                "submission_summary": {
                    "submit_immediately": self.stats["submit_immediately_count"],
                    "submit": self.stats["submit_count"],
                    "consider": self.stats["consider_count"],
                    "skip": self.stats["skip_count"],
                },
            },
            "findings": [pf.to_dict() for pf in self.scored_findings],
            "domain_analysis": self._build_domain_analysis(),
            "type_analysis": self._build_type_analysis(),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

    def _write_markdown_report(self, path: str):
        """Write the Markdown priority report."""
        lines = []
        lines.append("# Priority Analysis Report")
        lines.append("")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append(f"Generator: {TOOL_BANNER}")
        lines.append(f"Platform: {self.platform.title()}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Findings:** {len(self.findings)}")
        lines.append(f"- **Total Scored:** {len(self.scored_findings)}")
        lines.append(f"- **Estimated Total Bounty:** ${self.stats['total_estimated_bounty']:,.0f}")
        lines.append(f"- **Average Score:** {self.stats['avg_score']:.1f}/10")
        lines.append(f"- **Max Score:** {self.stats['max_score']:.1f}/10")
        lines.append("")

        # Submission breakdown
        lines.append("## Submission Recommendations")
        lines.append("")
        lines.append("| Recommendation | Count | Description |")
        lines.append("|----------------|-------|-------------|")
        lines.append(f"| SUBMIT IMMEDIATELY | {self.stats['submit_immediately_count']} | High-value, submit now |")
        lines.append(f"| SUBMIT | {self.stats['submit_count']} | Solid finding, worth reporting |")
        lines.append(f"| CONSIDER | {self.stats['consider_count']} | Evaluate scope and dupe risk |")
        lines.append(f"| SKIP | {self.stats['skip_count']} | Low value or high dupe risk |")
        lines.append("")

        # Top findings table
        lines.append("## Top Findings")
        lines.append("")
        lines.append("| # | Score | Severity | Type | Domain | Recommendation | Est. Bounty |")
        lines.append("|---|-------|----------|------|--------|---------------|-------------|")

        for pf in self.scored_findings[:30]:
            lines.append(
                f"| {pf.rank} | {pf.score.total_score:.1f} | {pf.finding.severity} | "
                f"{pf.finding.finding_type} | {pf.finding.domain or '?'} | "
                f"{pf.score.submission_recommendation} | "
                f"${pf.score.estimated_bounty_median:,.0f} |"
            )
        lines.append("")

        # Detailed findings
        lines.append("## Detailed Analysis")
        lines.append("")

        for pf in self.scored_findings[:15]:
            lines.append(f"### #{pf.rank}: {pf.finding.title}")
            lines.append("")
            lines.append(f"- **Score:** {pf.score.total_score:.1f}/10")
            lines.append(f"- **Severity:** {pf.finding.severity}")
            lines.append(f"- **Type:** {pf.finding.finding_type}")
            lines.append(f"- **Domain:** {pf.finding.domain}")
            lines.append(f"- **CVSS:** {pf.finding.cvss_score}")
            lines.append(f"- **Recommendation:** {pf.score.submission_recommendation}")
            lines.append(f"- **Dupe Probability:** {pf.score.dupe_probability:.0%}")
            lines.append(f"- **Estimated Bounty:** ${pf.score.estimated_bounty_min}-${pf.score.estimated_bounty_max}")
            lines.append("")

            if pf.action_items:
                lines.append("**Action Items:**")
                for item in pf.action_items:
                    lines.append(f"- {item}")
                lines.append("")

            lines.append("**Score Breakdown:**")
            lines.append(f"- CVSS Component: {pf.score.cvss_component:.3f}")
            lines.append(f"- Exploitability: {pf.score.exploitability_component:.3f}")
            lines.append(f"- Business Impact: {pf.score.business_impact_component:.3f}")
            lines.append(f"- Bounty Value: {pf.score.bounty_value_component:.3f}")
            lines.append(f"- Correlation Bonus: {pf.score.correlation_bonus_component:.3f}")
            lines.append(f"- Domain Multiplier: {pf.score.domain_multiplier:.1f}x ({pf.score.domain_tier})")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _build_domain_analysis(self) -> Dict[str, Any]:
        """Build domain analysis section for JSON report."""
        analysis = {}
        for domain, (tier, mult) in self._domain_tiers.items():
            domain_findings = [pf for pf in self.scored_findings if pf.finding.domain == domain]
            if not domain_findings:
                continue
            analysis[domain] = {
                "tier": tier,
                "multiplier": mult,
                "finding_count": len(domain_findings),
                "avg_score": round(sum(pf.score.total_score for pf in domain_findings) / len(domain_findings), 2),
                "max_score": round(max(pf.score.total_score for pf in domain_findings), 2),
                "total_bounty": sum(pf.score.estimated_bounty_median for pf in domain_findings),
            }
        return analysis

    def _build_type_analysis(self) -> Dict[str, Any]:
        """Build finding type analysis section for JSON report."""
        analysis: Dict[str, Any] = {}
        type_groups: Dict[str, List[PrioritizedFinding]] = defaultdict(list)
        for pf in self.scored_findings:
            type_groups[pf.finding.finding_type].append(pf)

        for ftype, findings_of_type in type_groups.items():
            scores = [pf.score.total_score for pf in findings_of_type]
            dupes = [pf.score.dupe_probability for pf in findings_of_type]
            analysis[ftype] = {
                "count": len(findings_of_type),
                "avg_score": round(sum(scores) / len(scores), 2),
                "max_score": round(max(scores), 2),
                "avg_dupe_probability": round(sum(dupes) / len(dupes), 3),
                "total_bounty": sum(pf.score.estimated_bounty_median for pf in findings_of_type),
                "exploitability": TYPE_EXPLOITABILITY.get(ftype, 0.5),
            }
        return analysis

    # =========================================================================
    # ADVANCED ANALYSIS
    # =========================================================================

    def get_roi_rankings(self) -> List[Dict[str, Any]]:
        """
        Calculate ROI (Return on Investment) rankings.
        
        Considers estimated bounty vs. estimated time to exploit
        to rank findings by dollar-per-hour value.

        Returns:
            List of findings ranked by ROI.
        """
        roi_list = []

        for pf in self.scored_findings:
            # Estimate exploitation time in hours
            type_hours = {
                "rce": 2, "sqli": 3, "auth_bypass": 2, "ssrf": 3,
                "xss_stored": 2, "xss_reflected": 1, "idor": 2,
                "file_upload": 3, "cors": 1, "open_redirect": 1,
                "subdomain_takeover": 2, "csrf": 1, "xxe": 3,
                "ssti": 3, "deserialization": 4, "race_condition": 3,
                "session_hijack": 2, "cookie_theft": 1, "info_disclosure": 0.5,
                "credential_exposure": 1, "api_key_leak": 1,
            }
            hours = type_hours.get(pf.finding.finding_type, 2)

            # Factor in report writing time
            hours += 1.5  # Base report time
            if pf.score.submission_recommendation == "SUBMIT_IMMEDIATELY":
                hours += 0.5  # Extra for detailed PoC
            elif pf.score.submission_recommendation == "CONSIDER":
                hours += 1.0  # Extra for differentiation

            # Factor in dupe risk (wasted time if dupe)
            effective_bounty = pf.score.estimated_bounty_median * (1 - pf.score.dupe_probability)

            # ROI = effective bounty / hours
            roi = effective_bounty / max(hours, 0.5)

            roi_list.append({
                "finding_id": pf.finding.id,
                "rank": pf.rank,
                "type": pf.finding.finding_type,
                "domain": pf.finding.domain,
                "severity": pf.finding.severity,
                "estimated_bounty": pf.score.estimated_bounty_median,
                "effective_bounty": round(effective_bounty, 0),
                "estimated_hours": round(hours, 1),
                "roi_per_hour": round(roi, 0),
                "dupe_probability": pf.score.dupe_probability,
                "recommendation": pf.score.submission_recommendation,
            })

        roi_list.sort(key=lambda x: x["roi_per_hour"], reverse=True)
        return roi_list

    def get_quick_wins(self, max_hours: float = 2.0) -> List[PrioritizedFinding]:
        """
        Get findings that can be reported quickly (quick wins).

        Args:
            max_hours: Maximum estimated exploitation time.

        Returns:
            List of findings achievable within the time limit.
        """
        quick_type_hours = {
            "cors": 0.5, "open_redirect": 0.5, "cookie_flags": 0.5,
            "missing_headers": 0.5, "version_disclosure": 0.5,
            "xss_reflected": 1.0, "info_disclosure": 0.5,
            "directory_listing": 0.5, "subdomain_takeover": 1.5,
            "credential_exposure": 1.0, "api_key_leak": 1.0,
        }

        quick_wins = []
        for pf in self.scored_findings:
            hours = quick_type_hours.get(pf.finding.finding_type, 3.0)
            if hours <= max_hours and pf.score.submission_recommendation != "SKIP":
                quick_wins.append(pf)

        return quick_wins

    def get_high_impact_targets(self) -> List[Dict[str, Any]]:
        """
        Identify highest-impact targets (domains) based on aggregate scores.

        Returns:
            List of domains ranked by total potential bounty.
        """
        domain_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "findings": 0, "total_score": 0.0, "max_score": 0.0,
            "total_bounty": 0.0, "tier": "", "severities": defaultdict(int),
        })

        for pf in self.scored_findings:
            domain = pf.finding.domain or "unknown"
            stats = domain_stats[domain]
            stats["findings"] += 1
            stats["total_score"] += pf.score.total_score
            stats["max_score"] = max(stats["max_score"], pf.score.total_score)
            stats["total_bounty"] += pf.score.estimated_bounty_median
            stats["tier"] = pf.score.domain_tier
            stats["severities"][pf.finding.severity] += 1

        # Convert to list and sort
        targets = []
        for domain, stats in domain_stats.items():
            targets.append({
                "domain": domain,
                "tier": stats["tier"],
                "finding_count": stats["findings"],
                "avg_score": round(stats["total_score"] / stats["findings"], 2),
                "max_score": round(stats["max_score"], 2),
                "total_bounty": stats["total_bounty"],
                "severity_breakdown": dict(stats["severities"]),
            })

        targets.sort(key=lambda t: t["total_bounty"], reverse=True)
        return targets

    def get_submission_queue(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate a submission queue organized by priority.

        Returns:
            Dictionary with findings grouped by recommendation level.
        """
        queue = {
            "SUBMIT_IMMEDIATELY": [],
            "SUBMIT": [],
            "CONSIDER": [],
            "SKIP": [],
        }

        for pf in self.scored_findings:
            entry = {
                "rank": pf.rank,
                "finding_id": pf.finding.id,
                "title": pf.finding.title,
                "type": pf.finding.finding_type,
                "severity": pf.finding.severity,
                "domain": pf.finding.domain,
                "score": pf.score.total_score,
                "estimated_bounty": pf.score.estimated_bounty_median,
                "dupe_probability": pf.score.dupe_probability,
                "action_items": pf.action_items[:3],
            }
            rec = pf.score.submission_recommendation
            if rec in queue:
                queue[rec].append(entry)

        return queue

    def compare_findings(self, finding_id_1: str, finding_id_2: str) -> Dict[str, Any]:
        """
        Compare two findings side by side for prioritization.

        Args:
            finding_id_1: First finding ID.
            finding_id_2: Second finding ID.

        Returns:
            Comparison dictionary with scores and recommendation.
        """
        score1 = self.priority_scores.get(finding_id_1)
        score2 = self.priority_scores.get(finding_id_2)

        if not score1 or not score2:
            return {"error": "One or both findings not found"}

        return {
            "finding_1": {
                "id": finding_id_1,
                "score": score1.total_score,
                "recommendation": score1.submission_recommendation,
                "bounty": score1.estimated_bounty_median,
                "dupe_prob": score1.dupe_probability,
            },
            "finding_2": {
                "id": finding_id_2,
                "score": score2.total_score,
                "recommendation": score2.submission_recommendation,
                "bounty": score2.estimated_bounty_median,
                "dupe_prob": score2.dupe_probability,
            },
            "winner": finding_id_1 if score1.total_score >= score2.total_score else finding_id_2,
            "score_difference": abs(score1.total_score - score2.total_score),
            "recommendation": (
                "Both are worth submitting" if score1.total_score >= 6 and score2.total_score >= 6
                else f"Prioritize the one with score {max(score1.total_score, score2.total_score):.1f}"
            ),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive priority analysis statistics."""
        return {
            "scoring": self.stats,
            "domain_tiers": {
                tier: sum(1 for d, (t, _) in self._domain_tiers.items() if t == tier)
                for tier in ["tier_1_critical", "tier_2_high", "tier_3_medium",
                            "tier_4_low", "tier_5_info"]
            },
            "score_distribution": {
                "9_10": sum(1 for pf in self.scored_findings if pf.score.total_score >= 9.0),
                "7_9": sum(1 for pf in self.scored_findings if 7.0 <= pf.score.total_score < 9.0),
                "5_7": sum(1 for pf in self.scored_findings if 5.0 <= pf.score.total_score < 7.0),
                "3_5": sum(1 for pf in self.scored_findings if 3.0 <= pf.score.total_score < 5.0),
                "0_3": sum(1 for pf in self.scored_findings if pf.score.total_score < 3.0),
            },
            "top_types": self._get_top_types(),
            "top_domains": self._get_top_domains(),
        }

    def _get_top_types(self) -> List[Dict[str, Any]]:
        """Get top finding types by average score."""
        type_scores: Dict[str, List[float]] = defaultdict(list)
        for pf in self.scored_findings:
            type_scores[pf.finding.finding_type].append(pf.score.total_score)

        top = []
        for ftype, scores in type_scores.items():
            top.append({
                "type": ftype,
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
                "max_score": round(max(scores), 2),
            })
        top.sort(key=lambda x: x["avg_score"], reverse=True)
        return top[:10]

    def _get_top_domains(self) -> List[Dict[str, Any]]:
        """Get top domains by total bounty potential."""
        domain_bounty: Dict[str, float] = defaultdict(float)
        domain_count: Dict[str, int] = defaultdict(int)
        for pf in self.scored_findings:
            domain_bounty[pf.finding.domain or "unknown"] += pf.score.estimated_bounty_median
            domain_count[pf.finding.domain or "unknown"] += 1

        top = []
        for domain in domain_bounty:
            top.append({
                "domain": domain,
                "total_bounty": domain_bounty[domain],
                "finding_count": domain_count[domain],
            })
        top.sort(key=lambda x: x["total_bounty"], reverse=True)
        return top[:10]


# =============================================================================
# BOUNTY ESTIMATOR CLASS
# =============================================================================

class BountyEstimator:
    """
    Estimates bug bounty payouts based on finding characteristics,
    platform, program size, and historical data patterns.
    """

    def __init__(self, platform: str = "hackerone"):
        """
        Initialize the bounty estimator.

        Args:
            platform: Target bug bounty platform.
        """
        self.platform = platform

    def estimate(self, finding: Finding, domain_tier: str = "tier_3_medium",
                 is_chain: bool = False) -> Dict[str, Any]:
        """
        Estimate bounty range for a specific finding.

        Args:
            finding: The finding to estimate bounty for.
            domain_tier: The domain tier classification.
            is_chain: Whether this finding is part of a chain.

        Returns:
            Dictionary with min, max, median, and adjusted estimates.
        """
        # Get base estimate from config
        base = get_bounty_estimate(finding.severity, self.platform)

        # Tier multiplier
        tier_multipliers = {
            "tier_1_critical": 2.0,
            "tier_2_high": 1.5,
            "tier_3_medium": 1.0,
            "tier_4_low": 0.5,
            "tier_5_info": 0.3,
        }
        tier_mult = tier_multipliers.get(domain_tier, 1.0)

        # Chain bonus
        chain_mult = 1.5 if is_chain else 1.0

        # Finding type rarity bonus
        rare_types = {"race_condition", "business_logic", "deserialization",
                     "prototype_pollution", "cache_poisoning"}
        rarity_mult = 1.3 if finding.finding_type in rare_types else 1.0

        # Apply multipliers
        adjusted_min = base["min"] * tier_mult * chain_mult * rarity_mult
        adjusted_max = base["max"] * tier_mult * chain_mult * rarity_mult
        adjusted_median = base["median"] * tier_mult * chain_mult * rarity_mult

        return {
            "min": round(adjusted_min, 0),
            "max": round(adjusted_max, 0),
            "median": round(adjusted_median, 0),
            "base": base,
            "multipliers": {
                "tier": tier_mult,
                "chain": chain_mult,
                "rarity": rarity_mult,
                "total": round(tier_mult * chain_mult * rarity_mult, 2),
            },
            "platform": self.platform,
            "confidence": self._estimate_confidence(finding),
        }

    def _estimate_confidence(self, finding: Finding) -> str:
        """Estimate confidence level of the bounty prediction."""
        if finding.cvss_score >= 9.0:
            return "high"
        elif finding.cvss_score >= 7.0:
            return "medium"
        elif finding.cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def estimate_total(self, findings: List[Finding],
                       domain_tiers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Estimate total bounty potential for a set of findings.

        Args:
            findings: List of findings.
            domain_tiers: Optional domain tier overrides.

        Returns:
            Total bounty estimation with breakdown.
        """
        total_min = 0.0
        total_max = 0.0
        total_median = 0.0
        breakdowns = []

        for finding in findings:
            tier = "tier_3_medium"
            if domain_tiers and finding.domain in domain_tiers:
                tier = domain_tiers[finding.domain]
            elif finding.domain:
                tier_name, _ = get_domain_tier(finding.domain)
                tier = tier_name

            estimate = self.estimate(
                finding, domain_tier=tier, is_chain=bool(finding.correlation_ids)
            )
            total_min += estimate["min"]
            total_max += estimate["max"]
            total_median += estimate["median"]

            breakdowns.append({
                "finding_id": finding.id,
                "type": finding.finding_type,
                "severity": finding.severity,
                "estimate": estimate,
            })

        return {
            "total_min": round(total_min, 0),
            "total_max": round(total_max, 0),
            "total_median": round(total_median, 0),
            "finding_count": len(findings),
            "platform": self.platform,
            "breakdowns": breakdowns[:20],
        }


# =============================================================================
# DUPE PROBABILITY ANALYZER
# =============================================================================

class DupeProbabilityAnalyzer:
    """
    Analyzes duplicate probability for findings based on type,
    endpoint commonality, domain coverage, and program history.
    """

    def __init__(self, findings: List[Finding] = None):
        """
        Initialize the dupe analyzer.

        Args:
            findings: List of findings to analyze.
        """
        self.findings = findings or []
        self._type_counts: Dict[str, int] = defaultdict(int)
        self._domain_type_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._endpoint_counts: Dict[str, int] = defaultdict(int)

        if self.findings:
            self._build_counts()

    def _build_counts(self):
        """Build counting indexes for probability calculation."""
        for f in self.findings:
            self._type_counts[f.finding_type] += 1
            self._domain_type_counts[f.domain][f.finding_type] += 1
            if f.url:
                parsed = urlparse(f.url)
                endpoint = f"{parsed.netloc}{parsed.path}"
                self._endpoint_counts[endpoint] += 1

    def analyze(self, finding: Finding) -> Dict[str, Any]:
        """
        Perform detailed dupe probability analysis for a finding.

        Args:
            finding: The finding to analyze.

        Returns:
            Detailed dupe analysis dictionary.
        """
        # Base probability from finding type
        base_prob = get_dupe_probability(finding.finding_type)

        # Factors that increase dupe probability
        factors = []

        # Same type on same domain
        same_domain_count = self._domain_type_counts.get(
            finding.domain, {}
        ).get(finding.finding_type, 0)
        if same_domain_count > 3:
            factors.append(("many_same_type_same_domain", 0.20))
        elif same_domain_count > 1:
            factors.append(("some_same_type_same_domain", 0.10))

        # Common endpoint
        if finding.url:
            parsed = urlparse(finding.url)
            endpoint = f"{parsed.netloc}{parsed.path}"
            if self._endpoint_counts.get(endpoint, 0) > 2:
                factors.append(("common_endpoint", 0.15))

        # Global type prevalence
        total_of_type = self._type_counts.get(finding.finding_type, 0)
        if total_of_type > 10:
            factors.append(("high_type_prevalence", 0.10))

        # Common vulnerability type
        common_types = {"missing_headers", "cookie_flags", "cors",
                       "version_disclosure", "info_disclosure"}
        if finding.finding_type in common_types:
            factors.append(("common_vuln_type", 0.15))

        # Factors that decrease dupe probability
        if finding.is_composite:
            factors.append(("composite_finding", -0.30))
        if finding.correlation_ids:
            factors.append(("part_of_chain", -0.15))
        if finding.finding_type in ("race_condition", "business_logic", "deserialization"):
            factors.append(("novel_type", -0.15))

        # Calculate final probability
        adjustment = sum(f[1] for f in factors)
        final_prob = max(min(base_prob + adjustment, 0.99), 0.01)

        return {
            "finding_id": finding.id,
            "finding_type": finding.finding_type,
            "base_probability": base_prob,
            "final_probability": round(final_prob, 3),
            "factors": factors,
            "adjustment": round(adjustment, 3),
            "risk_level": (
                "HIGH" if final_prob >= 0.7
                else "MEDIUM" if final_prob >= 0.4
                else "LOW"
            ),
            "recommendation": self._dupe_recommendation(final_prob, finding),
        }

    def _dupe_recommendation(self, dupe_prob: float, finding: Finding) -> str:
        """Generate recommendation based on dupe probability."""
        if dupe_prob >= 0.8:
            return "Very high dupe risk. Only submit with unique exploitation path or novel impact."
        elif dupe_prob >= 0.6:
            return "Moderate dupe risk. Differentiate with detailed PoC and unique context."
        elif dupe_prob >= 0.4:
            return "Some dupe risk. Standard submission with clear impact should be fine."
        else:
            return "Low dupe risk. Submit with confidence."


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def prioritize_findings(input_path: str, output_dir: str = None,
                        db_path: str = None, platform: str = "hackerone",
                        limit: int = 20, min_score: float = 0.0) -> Dict[str, Any]:
    """
    High-level utility function to prioritize findings.
    
    This is the main entry point called by the CLI subcommand.

    Args:
        input_path: Path to Monster JSON reports (file or directory).
        output_dir: Output directory for results.
        db_path: Path to findings database file.
        platform: Bug bounty platform name.
        limit: Number of top findings to display.
        min_score: Minimum score threshold.

    Returns:
        Dictionary with prioritization results.
    """
    # Initialize database
    db = FindingDB(db_path) if db_path else FindingDB()

    # Import findings
    if input_path:
        if os.path.isdir(input_path):
            db.import_directory(input_path)
        elif os.path.isfile(input_path):
            db.import_monster_report(input_path)

    if db.count() == 0:
        return {"error": "No findings to prioritize", "total_scored": 0}

    # Create and run engine
    engine = PriorityEngine(
        db=db,
        platform=platform,
        min_score=min_score,
        output_dir=output_dir or DEFAULT_OUTPUT_DIR,
    )
    engine.load_findings()
    engine.score_all()

    # Print results
    engine.print_full_report(limit)

    # Generate output files
    output_files = engine.generate_report(output_dir, format="json")

    # Save database
    if db_path and db.db_path:
        db.save()

    return {
        "total_findings": len(engine.findings),
        "total_scored": len(engine.scored_findings),
        "total_estimated_bounty": engine.stats["total_estimated_bounty"],
        "statistics": engine.stats,
        "output_files": output_files,
        "submission_queue": engine.get_submission_queue(),
    }


def quick_prioritize(findings: List[Dict[str, Any]],
                     platform: str = "hackerone") -> List[Dict[str, Any]]:
    """
    Quick prioritization from a list of finding dictionaries.

    Args:
        findings: List of finding dictionaries.
        platform: Bug bounty platform.

    Returns:
        List of scored findings sorted by priority.
    """
    db = FindingDB()
    for f_dict in findings:
        finding = Finding.from_dict(f_dict)
        if not finding.id:
            finding.id = f"QP-{uuid.uuid4().hex[:8].upper()}"
        finding.compute_fingerprint()
        db.add_finding(finding, deduplicate=True)

    engine = PriorityEngine(db=db, platform=platform)
    engine.load_findings()
    engine.score_all()

    return [pf.to_dict() for pf in engine.scored_findings]


def get_priority_summary(db: FindingDB, platform: str = "hackerone") -> str:
    """
    Get a brief text summary of priority analysis for a FindingDB.

    Args:
        db: The FindingDB to analyze.
        platform: Bug bounty platform.

    Returns:
        Multi-line text summary string.
    """
    engine = PriorityEngine(db=db, platform=platform)
    engine.load_findings()
    engine.score_all()

    lines = []
    lines.append(f"Priority Summary ({db.count()} findings)")
    lines.append(f"  Submit Immediately: {engine.stats['submit_immediately_count']}")
    lines.append(f"  Submit: {engine.stats['submit_count']}")
    lines.append(f"  Consider: {engine.stats['consider_count']}")
    lines.append(f"  Skip: {engine.stats['skip_count']}")
    lines.append(f"  Total Est. Bounty: ${engine.stats['total_estimated_bounty']:,.0f}")

    if engine.scored_findings:
        top = engine.scored_findings[0]
        lines.append(f"  Top Finding: {top.finding.title[:40]} (score: {top.score.total_score:.1f})")

    return "\n".join(lines)


# =============================================================================
# FINDING SCORER (SIMPLIFIED INTERFACE)
# =============================================================================

class FindingScorer:
    """
    Simplified scoring interface for individual findings.
    
    Provides a quick way to get a priority score without setting up
    the full PriorityEngine. Useful for real-time scoring during import.
    """

    def __init__(self, platform: str = "hackerone"):
        """
        Initialize the scorer.

        Args:
            platform: Bug bounty platform for estimates.
        """
        self.platform = platform
        self._weights = dict(SCORING_WEIGHTS)

    def score(self, finding: Finding) -> float:
        """
        Quick-score a single finding.

        Args:
            finding: Finding to score.

        Returns:
            Priority score from 0.0 to 10.0.
        """
        # CVSS component
        cvss = min(finding.cvss_score / 10.0, 1.0) if finding.cvss_score > 0 else (
            {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25, "INFO": 0.05}.get(
                finding.severity, 0.3
            )
        )

        # Exploitability component
        exploit = TYPE_EXPLOITABILITY.get(finding.finding_type, 0.5)

        # Business impact
        impact = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}.get(
            finding.severity, 0.3
        )

        # Domain tier boost
        if finding.domain:
            _, mult = get_domain_tier(finding.domain)
            impact = min(impact * (1 + (mult - 1) * 0.2), 1.0)

        # Bounty value
        bounty_est = get_bounty_estimate(finding.severity, self.platform)
        bounty = min(bounty_est.get("median", 0) / 20000.0, 1.0)

        # Correlation bonus
        corr = 0.0
        if finding.correlation_ids:
            corr = min(len(finding.correlation_ids) * 0.2, 1.0)
        if finding.is_composite:
            corr = min(corr + 0.3, 1.0)

        # Weighted total
        total = (
            cvss * self._weights["cvss_base"] +
            exploit * self._weights["exploitability"] +
            impact * self._weights["business_impact"] +
            bounty * self._weights["bug_bounty_value"] +
            corr * self._weights["correlation_bonus"]
        )

        return round(min(total * 10.0, 10.0), 2)

    def score_batch(self, findings: List[Finding]) -> List[Tuple[Finding, float]]:
        """
        Score a batch of findings.

        Args:
            findings: List of findings to score.

        Returns:
            List of (finding, score) tuples sorted by score descending.
        """
        scored = [(f, self.score(f)) for f in findings]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def get_recommendation(self, score: float) -> str:
        """Get submission recommendation from a score."""
        if score >= 8.0:
            return "SUBMIT_IMMEDIATELY"
        elif score >= 6.0:
            return "SUBMIT"
        elif score >= 4.0:
            return "CONSIDER"
        return "SKIP"

    def get_bounty_range(self, finding: Finding) -> Dict[str, float]:
        """Get estimated bounty range for a finding."""
        return get_bounty_estimate(finding.severity, self.platform)


# =============================================================================
# SUBMISSION PLANNER
# =============================================================================

class SubmissionPlanner:
    """
    Plans the optimal order for submitting findings to maximize
    total bounty earnings considering time constraints and dupe risk.
    """

    def __init__(self, scored_findings: List[PrioritizedFinding] = None):
        """
        Initialize the submission planner.

        Args:
            scored_findings: Pre-scored findings from PriorityEngine.
        """
        self.findings = scored_findings or []

    def plan_submissions(self, available_hours: float = 40.0,
                         max_submissions: int = 20) -> Dict[str, Any]:
        """
        Create an optimized submission plan.

        Args:
            available_hours: Total hours available for report writing.
            max_submissions: Maximum number of submissions to plan.

        Returns:
            Submission plan with ordered findings and time estimates.
        """
        # Estimate time per finding type
        type_hours = {
            "rce": 3.0, "sqli": 3.5, "auth_bypass": 3.0, "ssrf": 3.0,
            "xss_stored": 2.5, "xss_reflected": 2.0, "idor": 2.5,
            "file_upload": 3.0, "cors": 1.5, "open_redirect": 1.5,
            "subdomain_takeover": 2.0, "csrf": 2.0, "xxe": 3.0,
            "ssti": 3.0, "deserialization": 3.5, "race_condition": 3.0,
            "info_disclosure": 1.5, "credential_exposure": 2.0,
            "missing_headers": 1.0, "cookie_flags": 1.0,
        }

        plan = []
        total_hours_used = 0.0
        total_expected_bounty = 0.0

        # Sort by expected value (bounty * (1 - dupe_prob) / time)
        candidates = []
        for pf in self.findings:
            if pf.score.submission_recommendation == "SKIP":
                continue
            hours = type_hours.get(pf.finding.finding_type, 2.5)
            effective_bounty = pf.score.estimated_bounty_median * (1 - pf.score.dupe_probability)
            value_per_hour = effective_bounty / max(hours, 0.5)
            candidates.append((pf, hours, effective_bounty, value_per_hour))

        candidates.sort(key=lambda x: x[3], reverse=True)

        for pf, hours, effective_bounty, value_per_hour in candidates:
            if total_hours_used + hours > available_hours:
                continue
            if len(plan) >= max_submissions:
                break

            total_hours_used += hours
            total_expected_bounty += effective_bounty

            plan.append({
                "order": len(plan) + 1,
                "finding_id": pf.finding.id,
                "title": pf.finding.title,
                "type": pf.finding.finding_type,
                "severity": pf.finding.severity,
                "domain": pf.finding.domain,
                "score": pf.score.total_score,
                "estimated_hours": hours,
                "expected_bounty": round(effective_bounty, 0),
                "value_per_hour": round(value_per_hour, 0),
                "dupe_probability": pf.score.dupe_probability,
                "recommendation": pf.score.submission_recommendation,
            })

        return {
            "plan": plan,
            "total_submissions": len(plan),
            "total_hours": round(total_hours_used, 1),
            "available_hours": available_hours,
            "total_expected_bounty": round(total_expected_bounty, 0),
            "avg_value_per_hour": round(total_expected_bounty / max(total_hours_used, 1), 0),
            "findings_skipped": len(self.findings) - len(plan),
        }

    def get_daily_schedule(self, hours_per_day: float = 8.0,
                           days: int = 5) -> List[Dict[str, Any]]:
        """
        Create a daily submission schedule.

        Args:
            hours_per_day: Hours available per day.
            days: Number of days to plan for.

        Returns:
            List of daily plans with assigned findings.
        """
        total_hours = hours_per_day * days
        full_plan = self.plan_submissions(available_hours=total_hours)

        schedule = []
        day_findings = []
        day_hours = 0.0
        current_day = 1

        for entry in full_plan["plan"]:
            if day_hours + entry["estimated_hours"] > hours_per_day:
                if day_findings:
                    schedule.append({
                        "day": current_day,
                        "findings": day_findings,
                        "total_hours": round(day_hours, 1),
                        "expected_bounty": sum(f["expected_bounty"] for f in day_findings),
                    })
                current_day += 1
                day_findings = []
                day_hours = 0.0
                if current_day > days:
                    break

            day_findings.append(entry)
            day_hours += entry["estimated_hours"]

        # Add last day
        if day_findings:
            schedule.append({
                "day": current_day,
                "findings": day_findings,
                "total_hours": round(day_hours, 1),
                "expected_bounty": sum(f["expected_bounty"] for f in day_findings),
            })

        return schedule


# =============================================================================
# SCORING CALIBRATOR
# =============================================================================

class ScoringCalibrator:
    """
    Calibrates scoring weights based on historical submission results.
    
    If the user provides feedback on past submissions (accepted, rejected,
    dupe), the calibrator adjusts weights to improve future predictions.
    """

    def __init__(self, current_weights: Dict[str, float] = None):
        """
        Initialize the calibrator.

        Args:
            current_weights: Current scoring weights.
        """
        self.weights = current_weights or dict(SCORING_WEIGHTS)
        self.feedback_history: List[Dict[str, Any]] = []

    def add_feedback(self, finding_type: str, severity: str,
                     score: float, outcome: str, actual_bounty: float = 0.0):
        """
        Add historical feedback for calibration.

        Args:
            finding_type: Type of the submitted finding.
            severity: Severity level.
            score: Priority score that was given.
            outcome: "accepted", "duplicate", "rejected", "informative".
            actual_bounty: Actual bounty received.
        """
        self.feedback_history.append({
            "finding_type": finding_type,
            "severity": severity,
            "score": score,
            "outcome": outcome,
            "actual_bounty": actual_bounty,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def calibrate(self) -> Dict[str, float]:
        """
        Calibrate weights based on feedback history.

        Returns:
            Adjusted weights dictionary.
        """
        if len(self.feedback_history) < 5:
            return self.weights

        # Analyze outcomes
        accepted = [f for f in self.feedback_history if f["outcome"] == "accepted"]
        duplicates = [f for f in self.feedback_history if f["outcome"] == "duplicate"]
        rejected = [f for f in self.feedback_history if f["outcome"] == "rejected"]

        # If high-score findings are often dupes, increase bounty_value weight
        # (which includes dupe penalty)
        if duplicates:
            avg_dupe_score = sum(f["score"] for f in duplicates) / len(duplicates)
            if avg_dupe_score > 6.0:
                # High-scoring findings being dupes means we need more dupe penalty
                self.weights["bug_bounty_value"] = min(
                    self.weights["bug_bounty_value"] + 0.02, 0.25
                )
                self.weights["exploitability"] = max(
                    self.weights["exploitability"] - 0.01, 0.10
                )

        # If accepted findings have high correlation bonus, keep or increase it
        if accepted:
            corr_findings = [f for f in accepted if f["score"] >= 7.0]
            if len(corr_findings) > len(accepted) * 0.3:
                self.weights["correlation_bonus"] = min(
                    self.weights["correlation_bonus"] + 0.01, 0.20
                )

        # Normalize weights to sum to 1.0
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: round(v / total, 3) for k, v in self.weights.items()}

        return self.weights

    def get_accuracy_metrics(self) -> Dict[str, Any]:
        """Calculate accuracy metrics from feedback history."""
        if not self.feedback_history:
            return {"error": "No feedback data available"}

        total = len(self.feedback_history)
        accepted = sum(1 for f in self.feedback_history if f["outcome"] == "accepted")
        duplicates = sum(1 for f in self.feedback_history if f["outcome"] == "duplicate")
        rejected = sum(1 for f in self.feedback_history if f["outcome"] == "rejected")

        return {
            "total_submissions": total,
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "acceptance_rate": round(accepted / total, 3) if total > 0 else 0,
            "dupe_rate": round(duplicates / total, 3) if total > 0 else 0,
            "total_bounty_earned": sum(
                f["actual_bounty"] for f in self.feedback_history
            ),
        }
