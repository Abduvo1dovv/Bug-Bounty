"""
Monster v2.0.0 Report Generator Module

Comprehensive report generation for bug bounty reconnaissance and
vulnerability assessment results. Supports multiple output formats
including JSON, Markdown, HTML (interactive), CSV, and platform-specific
templates (HackerOne, Bugcrowd, Intigriti).

Features:
    - CVSS v3.1 score calculation
    - OWASP Top 10 2021 mapping
    - Risk scoring and prioritization
    - Multiple report formats (JSON, MD, HTML, CSV)
    - Interactive HTML with dark theme
    - Bug bounty platform templates
    - Remediation planning
    - Comparison reports (diff between scans)
    - Executive summaries
    - Risk matrix visualization

Usage:
    from monster.report_generator import ReportGenerator, CVSSCalculator
    generator = ReportGenerator(output_dir="./reports")
    generator.generate_full_report(scan_results, metadata)
"""

import os
import re
import csv
import json
import math
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple, Set
from dataclasses import dataclass, field

from monster.utils import ColorOutput, FileManager


# =============================================================================
# CVSS v3.1 CALCULATOR
# =============================================================================


class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.

    Calculates Common Vulnerability Scoring System version 3.1 base scores
    from vector strings. Implements the official NIST/FIRST specification
    for base metric calculations.

    Reference: https://www.first.org/cvss/v3.1/specification-document

    Attributes:
        METRIC_VALUES: Dictionary mapping CVSS metrics to their numeric values.
        SEVERITY_LEVELS: Mapping of score ranges to severity labels.
    """

    # CVSS v3.1 metric value mappings
    METRIC_VALUES = {
        # Attack Vector (AV)
        "AV": {
            "N": 0.85,   # Network
            "A": 0.62,   # Adjacent
            "L": 0.55,   # Local
            "P": 0.20,   # Physical
        },
        # Attack Complexity (AC)
        "AC": {
            "L": 0.77,   # Low
            "H": 0.44,   # High
        },
        # Privileges Required (PR) - Scope Unchanged
        "PR_U": {
            "N": 0.85,   # None
            "L": 0.62,   # Low
            "H": 0.27,   # High
        },
        # Privileges Required (PR) - Scope Changed
        "PR_C": {
            "N": 0.85,   # None
            "L": 0.68,   # Low
            "H": 0.50,   # High
        },
        # User Interaction (UI)
        "UI": {
            "N": 0.85,   # None
            "R": 0.62,   # Required
        },
        # Scope (S)
        "S": {
            "U": False,  # Unchanged
            "C": True,   # Changed
        },
        # Confidentiality Impact (C)
        "C": {
            "N": 0.00,   # None
            "L": 0.22,   # Low
            "H": 0.56,   # High
        },
        # Integrity Impact (I)
        "I": {
            "N": 0.00,   # None
            "L": 0.22,   # Low
            "H": 0.56,   # High
        },
        # Availability Impact (A)
        "A": {
            "N": 0.00,   # None
            "L": 0.22,   # Low
            "H": 0.56,   # High
        },
    }

    # Severity level thresholds per CVSS v3.1 specification
    SEVERITY_LEVELS = {
        "NONE": (0.0, 0.0),
        "LOW": (0.1, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 8.9),
        "CRITICAL": (9.0, 10.0),
    }

    # Common vulnerability type to CVSS vector mappings
    COMMON_VECTORS = {
        "xss_reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "xss_stored": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cors_misconfig": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "missing_headers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "clickjacking": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "crlf_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "subdomain_takeover": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rate_limit_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "host_header_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cache_poisoning": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "request_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "broken_access_control": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "insecure_deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }

    def __init__(self):
        """Initialize the CVSS calculator."""
        self._cache = {}

    def calculate_base_score(self, vector_string: str) -> float:
        """
        Calculate CVSS v3.1 base score from a vector string.

        Args:
            vector_string: CVSS v3.1 vector string.
                Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        Returns:
            Base score as a float between 0.0 and 10.0.

        Raises:
            ValueError: If the vector string is invalid or malformed.
        """
        if not vector_string:
            return 0.0

        # Check cache first
        if vector_string in self._cache:
            return self._cache[vector_string]

        # Parse the vector string
        metrics = self._parse_vector(vector_string)
        if not metrics:
            return 0.0

        # Determine scope
        scope_changed = self.METRIC_VALUES["S"].get(metrics.get("S", "U"), False)

        # Get privilege required values based on scope
        pr_key = "PR_C" if scope_changed else "PR_U"
        pr_value = self.METRIC_VALUES[pr_key].get(metrics.get("PR", "N"), 0.85)

        # Calculate Impact Sub Score (ISS)
        conf_impact = self.METRIC_VALUES["C"].get(metrics.get("C", "N"), 0.0)
        integ_impact = self.METRIC_VALUES["I"].get(metrics.get("I", "N"), 0.0)
        avail_impact = self.METRIC_VALUES["A"].get(metrics.get("A", "N"), 0.0)

        iss = 1.0 - ((1.0 - conf_impact) * (1.0 - integ_impact) * (1.0 - avail_impact))

        # Calculate Impact Score
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # If impact is zero or negative, base score is 0
        if impact <= 0:
            self._cache[vector_string] = 0.0
            return 0.0

        # Calculate Exploitability Sub Score
        av_value = self.METRIC_VALUES["AV"].get(metrics.get("AV", "N"), 0.85)
        ac_value = self.METRIC_VALUES["AC"].get(metrics.get("AC", "L"), 0.77)
        ui_value = self.METRIC_VALUES["UI"].get(metrics.get("UI", "N"), 0.85)

        exploitability = 8.22 * av_value * ac_value * pr_value * ui_value

        # Calculate Base Score
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round up to nearest tenth (CVSS spec roundup)
        base_score = self._roundup(base_score)

        # Cache the result
        self._cache[vector_string] = base_score
        return base_score

    def _parse_vector(self, vector_string: str) -> Dict[str, str]:
        """
        Parse a CVSS v3.1 vector string into metric components.

        Args:
            vector_string: Full CVSS vector string with prefix.

        Returns:
            Dictionary mapping metric abbreviations to their values.
        """
        metrics = {}

        # Remove prefix if present
        vector = vector_string
        if vector.startswith("CVSS:3.1/"):
            vector = vector[9:]
        elif vector.startswith("CVSS:3.0/"):
            vector = vector[9:]

        # Parse each metric
        parts = vector.split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value

        return metrics

    @staticmethod
    def _roundup(value: float) -> float:
        """
        Round up to one decimal place as specified by CVSS v3.1.

        The CVSS specification requires a specific rounding method:
        round up to the nearest 0.1.

        Args:
            value: The value to round up.

        Returns:
            Value rounded up to one decimal place.
        """
        return math.ceil(value * 10) / 10.0

    @staticmethod
    def severity_from_score(score: float) -> str:
        """
        Determine severity label from a CVSS score.

        Args:
            score: CVSS base score (0.0 to 10.0).

        Returns:
            Severity string: NONE, LOW, MEDIUM, HIGH, or CRITICAL.
        """
        if score == 0.0:
            return "NONE"
        elif score <= 3.9:
            return "LOW"
        elif score <= 6.9:
            return "MEDIUM"
        elif score <= 8.9:
            return "HIGH"
        else:
            return "CRITICAL"

    def get_vector_for_type(self, finding_type: str) -> str:
        """
        Get a default CVSS vector for a common vulnerability type.

        Args:
            finding_type: The type/category of vulnerability.

        Returns:
            CVSS vector string or empty string if type not recognized.
        """
        # Normalize the finding type
        normalized = finding_type.lower().replace(" ", "_").replace("-", "_")
        return self.COMMON_VECTORS.get(normalized, "")

    def score_finding(self, finding_type: str) -> Tuple[float, str]:
        """
        Calculate score and severity for a finding type.

        Args:
            finding_type: The vulnerability type/category.

        Returns:
            Tuple of (score, severity_label).
        """
        vector = self.get_vector_for_type(finding_type)
        if vector:
            score = self.calculate_base_score(vector)
            severity = self.severity_from_score(score)
            return (score, severity)
        return (0.0, "NONE")

    def explain_vector(self, vector_string: str) -> Dict[str, str]:
        """
        Provide human-readable explanation of a CVSS vector.

        Args:
            vector_string: CVSS v3.1 vector string.

        Returns:
            Dictionary with metric names and their descriptions.
        """
        explanations = {
            "AV": {
                "N": "Network - Exploitable from any network",
                "A": "Adjacent - Exploitable from adjacent network",
                "L": "Local - Requires local access",
                "P": "Physical - Requires physical access",
            },
            "AC": {
                "L": "Low - No special conditions needed",
                "H": "High - Special conditions required",
            },
            "PR": {
                "N": "None - No privileges needed",
                "L": "Low - Basic user privileges needed",
                "H": "High - Admin/elevated privileges needed",
            },
            "UI": {
                "N": "None - No user interaction needed",
                "R": "Required - Victim must perform action",
            },
            "S": {
                "U": "Unchanged - Impact limited to vulnerable component",
                "C": "Changed - Impact extends beyond vulnerable component",
            },
            "C": {
                "N": "None - No confidentiality impact",
                "L": "Low - Limited information disclosure",
                "H": "High - Total information disclosure",
            },
            "I": {
                "N": "None - No integrity impact",
                "L": "Low - Limited data modification",
                "H": "High - Total data modification",
            },
            "A": {
                "N": "None - No availability impact",
                "L": "Low - Reduced performance/availability",
                "H": "High - Total denial of service",
            },
        }

        metrics = self._parse_vector(vector_string)
        result = {}
        for key, value in metrics.items():
            if key in explanations and value in explanations[key]:
                result[key] = explanations[key][value]
            else:
                result[key] = f"{key}:{value}"
        return result

    def compare_vectors(self, vector1: str, vector2: str) -> Dict[str, Any]:
        """
        Compare two CVSS vectors and show differences.

        Args:
            vector1: First CVSS vector string.
            vector2: Second CVSS vector string.

        Returns:
            Dictionary with comparison data including score difference.
        """
        metrics1 = self._parse_vector(vector1)
        metrics2 = self._parse_vector(vector2)
        score1 = self.calculate_base_score(vector1)
        score2 = self.calculate_base_score(vector2)

        differences = {}
        all_keys = set(list(metrics1.keys()) + list(metrics2.keys()))
        for key in all_keys:
            val1 = metrics1.get(key, "?")
            val2 = metrics2.get(key, "?")
            if val1 != val2:
                differences[key] = {"from": val1, "to": val2}

        return {
            "vector1": vector1,
            "vector2": vector2,
            "score1": score1,
            "score2": score2,
            "score_difference": round(score2 - score1, 1),
            "severity1": self.severity_from_score(score1),
            "severity2": self.severity_from_score(score2),
            "metric_differences": differences,
        }


# =============================================================================
# OWASP TOP 10 MAPPER
# =============================================================================


class OWASPMapper:
    """
    Maps vulnerability findings to OWASP Top 10 2021 categories.

    Provides classification of discovered vulnerabilities against the
    OWASP Top 10 2021 framework for standardized risk communication.

    Reference: https://owasp.org/Top10/

    Attributes:
        OWASP_TOP_10_2021: Full mapping of categories with descriptions.
        FINDING_TYPE_MAPPING: Maps specific finding types to OWASP categories.
    """

    OWASP_TOP_10_2021 = {
        "A01": {
            "id": "A01:2021",
            "name": "Broken Access Control",
            "description": (
                "Access control enforces policy such that users cannot act "
                "outside of their intended permissions. Failures typically lead "
                "to unauthorized information disclosure, modification, or "
                "destruction of all data or performing a business function "
                "outside the user's limits."
            ),
            "reference": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "cwe_ids": ["CWE-200", "CWE-201", "CWE-352", "CWE-566", "CWE-639"],
            "impact": "HIGH",
            "prevalence": "VERY HIGH",
            "examples": [
                "IDOR (Insecure Direct Object References)",
                "Bypassing access control by modifying URL parameters",
                "Missing function-level access control",
                "CORS misconfiguration allowing unauthorized access",
                "Force browsing to authenticated pages",
            ],
        },
        "A02": {
            "id": "A02:2021",
            "name": "Cryptographic Failures",
            "description": (
                "Failures related to cryptography which often lead to exposure "
                "of sensitive data. Previously known as 'Sensitive Data Exposure'. "
                "Includes use of deprecated algorithms, weak key generation, "
                "missing encryption for sensitive data in transit and at rest."
            ),
            "reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "cwe_ids": ["CWE-259", "CWE-327", "CWE-331", "CWE-325"],
            "impact": "HIGH",
            "prevalence": "HIGH",
            "examples": [
                "Transmitting data in clear text (HTTP, FTP, SMTP)",
                "Using deprecated cryptographic algorithms (MD5, SHA1)",
                "Weak or default cryptographic keys",
                "Missing TLS enforcement",
                "Improper certificate validation",
            ],
        },
        "A03": {
            "id": "A03:2021",
            "name": "Injection",
            "description": (
                "An application is vulnerable to injection when user-supplied "
                "data is not validated, filtered, or sanitized. This includes "
                "SQL injection, NoSQL injection, OS command injection, LDAP "
                "injection, and Cross-Site Scripting (XSS)."
            ),
            "reference": "https://owasp.org/Top10/A03_2021-Injection/",
            "cwe_ids": ["CWE-79", "CWE-89", "CWE-73", "CWE-77", "CWE-78"],
            "impact": "CRITICAL",
            "prevalence": "HIGH",
            "examples": [
                "SQL Injection in login forms",
                "Cross-Site Scripting (XSS) - reflected, stored, DOM",
                "Command injection in file operations",
                "LDAP injection in directory services",
                "NoSQL injection in MongoDB queries",
            ],
        },
        "A04": {
            "id": "A04:2021",
            "name": "Insecure Design",
            "description": (
                "Insecure design refers to risks related to design and "
                "architectural flaws. It calls for more use of threat modeling, "
                "secure design patterns, and reference architectures. This is "
                "different from insecure implementation."
            ),
            "reference": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
            "cwe_ids": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
            "impact": "HIGH",
            "prevalence": "MEDIUM",
            "examples": [
                "Missing rate limiting on sensitive operations",
                "Credential recovery allowing account enumeration",
                "Lack of anti-automation controls",
                "Business logic flaws in transaction handling",
                "Missing fraud detection mechanisms",
            ],
        },
        "A05": {
            "id": "A05:2021",
            "name": "Security Misconfiguration",
            "description": (
                "The application might be vulnerable if missing appropriate "
                "security hardening, has unnecessary features enabled, default "
                "accounts unchanged, overly informative error messages, or "
                "security settings not set to secure values."
            ),
            "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "cwe_ids": ["CWE-16", "CWE-611", "CWE-614", "CWE-756"],
            "impact": "MEDIUM",
            "prevalence": "VERY HIGH",
            "examples": [
                "Default credentials on admin panels",
                "Directory listing enabled",
                "Verbose error messages with stack traces",
                "Missing security headers",
                "Unnecessary HTTP methods enabled",
            ],
        },
        "A06": {
            "id": "A06:2021",
            "name": "Vulnerable and Outdated Components",
            "description": (
                "Components such as libraries, frameworks, and software modules "
                "run with the same privileges as the application. If a vulnerable "
                "component is exploited, it can cause serious data loss or "
                "server takeover."
            ),
            "reference": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "cwe_ids": ["CWE-1104", "CWE-937"],
            "impact": "HIGH",
            "prevalence": "HIGH",
            "examples": [
                "Using jQuery with known XSS vulnerabilities",
                "Running outdated Apache/Nginx with CVEs",
                "Unpatched CMS installations",
                "Legacy JavaScript libraries",
                "Deprecated framework versions",
            ],
        },
        "A07": {
            "id": "A07:2021",
            "name": "Identification and Authentication Failures",
            "description": (
                "Confirmation of user identity, authentication, and session "
                "management is critical. Weaknesses may allow attackers to "
                "compromise passwords, keys, session tokens, or exploit "
                "implementation flaws to assume identities."
            ),
            "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "cwe_ids": ["CWE-287", "CWE-384", "CWE-613", "CWE-640"],
            "impact": "HIGH",
            "prevalence": "MEDIUM",
            "examples": [
                "Credential stuffing attacks possible",
                "Weak password policies",
                "Session fixation vulnerabilities",
                "Missing multi-factor authentication",
                "Exposed session tokens in URLs",
            ],
        },
        "A08": {
            "id": "A08:2021",
            "name": "Software and Data Integrity Failures",
            "description": (
                "Software and data integrity failures relate to code and "
                "infrastructure that does not protect against integrity "
                "violations. This includes insecure CI/CD pipelines, "
                "auto-update without integrity verification, and insecure "
                "deserialization."
            ),
            "reference": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "cwe_ids": ["CWE-345", "CWE-353", "CWE-426", "CWE-502"],
            "impact": "HIGH",
            "prevalence": "MEDIUM",
            "examples": [
                "Insecure deserialization of user data",
                "CI/CD pipeline without integrity checks",
                "Auto-update without signature verification",
                "Unsigned or unverified plugins",
                "Subresource integrity missing on CDN resources",
            ],
        },
        "A09": {
            "id": "A09:2021",
            "name": "Security Logging and Monitoring Failures",
            "description": (
                "Without logging and monitoring, breaches cannot be detected. "
                "Insufficient logging, detection, monitoring, and active "
                "response occurs any time auditable events are not logged, "
                "warnings are not generated, or incident response plans are missing."
            ),
            "reference": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
            "impact": "MEDIUM",
            "prevalence": "HIGH",
            "examples": [
                "Login failures not logged",
                "Lack of intrusion detection",
                "Missing alerting thresholds",
                "Logs not monitored for suspicious activity",
                "No incident response plan",
            ],
        },
        "A10": {
            "id": "A10:2021",
            "name": "Server-Side Request Forgery (SSRF)",
            "description": (
                "SSRF flaws occur when a web application fetches a remote "
                "resource without validating the user-supplied URL. It allows "
                "an attacker to coerce the application to send crafted requests "
                "to unexpected destinations, even through firewalls or VPNs."
            ),
            "reference": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
            "cwe_ids": ["CWE-918"],
            "impact": "CRITICAL",
            "prevalence": "MEDIUM",
            "examples": [
                "Accessing internal services through URL parameters",
                "Reading cloud metadata endpoints",
                "Port scanning internal networks",
                "Bypassing access controls via server requests",
                "Accessing restricted APIs from trusted IP",
            ],
        },
    }

    # Mapping from finding types to OWASP categories
    FINDING_TYPE_MAPPING = {
        # A01 - Broken Access Control
        "cors": "A01",
        "cors_misconfig": "A01",
        "idor": "A01",
        "idor_patterns": "A01",
        "broken_access_control": "A01",
        "403_bypass": "A01",
        "directory_traversal": "A01",
        "path_traversal": "A01",
        "forced_browsing": "A01",
        "privilege_escalation": "A01",
        "open_redirect": "A01",
        "clickjacking": "A01",
        # A02 - Cryptographic Failures
        "ssl_tls": "A02",
        "weak_crypto": "A02",
        "insecure_cookie": "A02",
        "cookie_security": "A02",
        "missing_hsts": "A02",
        "clear_text_transmission": "A02",
        "weak_cipher": "A02",
        "expired_certificate": "A02",
        "self_signed_cert": "A02",
        # A03 - Injection
        "xss": "A03",
        "xss_reflected": "A03",
        "xss_stored": "A03",
        "xss_dom": "A03",
        "sqli": "A03",
        "sql_injection": "A03",
        "command_injection": "A03",
        "crlf_injection": "A03",
        "header_injection": "A03",
        "host_header": "A03",
        "template_injection": "A03",
        "ldap_injection": "A03",
        "parameter_pollution": "A03",
        # A04 - Insecure Design
        "rate_limiting": "A04",
        "rate_limit": "A04",
        "business_logic": "A04",
        "missing_anti_automation": "A04",
        "account_enumeration": "A04",
        "insecure_design": "A04",
        # A05 - Security Misconfiguration
        "headers": "A05",
        "security_headers": "A05",
        "missing_headers": "A05",
        "information_disclosure": "A05",
        "info_disclosure": "A05",
        "http_methods": "A05",
        "directory_listing": "A05",
        "verbose_errors": "A05",
        "debug_enabled": "A05",
        "default_credentials": "A05",
        "sensitive_files": "A05",
        "graphql_introspection": "A05",
        "api_versioning": "A05",
        "waf": "A05",
        # A06 - Vulnerable and Outdated Components
        "outdated_component": "A06",
        "vulnerable_library": "A06",
        "deprecated_framework": "A06",
        "known_vulnerability": "A06",
        "outdated_software": "A06",
        "dependency": "A06",
        # A07 - Identification and Authentication Failures
        "authentication": "A07",
        "session_fixation": "A07",
        "weak_password_policy": "A07",
        "credential_exposure": "A07",
        "jwt_weakness": "A07",
        "token_leak": "A07",
        "session_management": "A07",
        # A08 - Software and Data Integrity Failures
        "insecure_deserialization": "A08",
        "sri_missing": "A08",
        "supply_chain": "A08",
        "unsigned_update": "A08",
        "integrity_failure": "A08",
        # A09 - Security Logging and Monitoring Failures
        "logging_failure": "A09",
        "missing_monitoring": "A09",
        "log_injection": "A09",
        # A10 - Server-Side Request Forgery
        "ssrf": "A10",
        "ssrf_indicators": "A10",
        "url_inclusion": "A10",
        # General/misc categories
        "cache_poisoning": "A05",
        "request_smuggling": "A05",
        "subdomain_takeover": "A01",
        "broken_link_hijacking": "A01",
        "xxe": "A03",
        "xxe_indicators": "A03",
    }

    def __init__(self):
        """Initialize the OWASP mapper."""
        pass

    def map_finding(self, finding_type: str) -> str:
        """
        Map a finding type to its OWASP Top 10 2021 category.

        Args:
            finding_type: The vulnerability type/category identifier.

        Returns:
            OWASP category code (e.g., "A01") or "Unknown" if not mapped.
        """
        normalized = finding_type.lower().replace(" ", "_").replace("-", "_")
        return self.FINDING_TYPE_MAPPING.get(normalized, "A05")

    def get_category_description(self, category: str) -> str:
        """
        Get the full description for an OWASP category.

        Args:
            category: OWASP category code (e.g., "A01").

        Returns:
            Category description string, or empty string if not found.
        """
        cat_upper = category.upper()
        if cat_upper in self.OWASP_TOP_10_2021:
            cat_data = self.OWASP_TOP_10_2021[cat_upper]
            return f"{cat_data['name']}: {cat_data['description']}"
        return ""

    def get_category_name(self, category: str) -> str:
        """
        Get just the name for an OWASP category.

        Args:
            category: OWASP category code (e.g., "A01").

        Returns:
            Category name string.
        """
        cat_upper = category.upper()
        if cat_upper in self.OWASP_TOP_10_2021:
            return self.OWASP_TOP_10_2021[cat_upper]["name"]
        return "Unknown"

    def get_category_reference(self, category: str) -> str:
        """
        Get the OWASP reference URL for a category.

        Args:
            category: OWASP category code.

        Returns:
            URL to the OWASP Top 10 page for this category.
        """
        cat_upper = category.upper()
        if cat_upper in self.OWASP_TOP_10_2021:
            return self.OWASP_TOP_10_2021[cat_upper]["reference"]
        return "https://owasp.org/Top10/"

    def generate_owasp_summary(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Generate a summary of findings mapped to OWASP categories.

        Args:
            findings: List of Finding objects or dicts with finding_type.

        Returns:
            Dictionary with counts per OWASP category and overall summary.
        """
        category_counts = {}
        category_findings = {}

        for finding in findings:
            if hasattr(finding, "finding_type"):
                ftype = finding.finding_type
            elif isinstance(finding, dict):
                ftype = finding.get("finding_type", "unknown")
            else:
                continue

            category = self.map_finding(ftype)
            category_counts[category] = category_counts.get(category, 0) + 1

            if category not in category_findings:
                category_findings[category] = []
            category_findings[category].append(finding)

        # Build summary with full category info
        summary = {
            "total_findings": len(findings),
            "categories_affected": len(category_counts),
            "category_breakdown": {},
        }

        for cat_code in sorted(category_counts.keys()):
            cat_info = self.OWASP_TOP_10_2021.get(cat_code, {})
            summary["category_breakdown"][cat_code] = {
                "name": cat_info.get("name", "Unknown"),
                "count": category_counts[cat_code],
                "impact": cat_info.get("impact", "UNKNOWN"),
                "reference": cat_info.get("reference", ""),
            }

        return summary

    def get_all_categories(self) -> List[Dict[str, str]]:
        """
        Get all OWASP Top 10 2021 categories.

        Returns:
            List of dictionaries with category info.
        """
        categories = []
        for code, data in self.OWASP_TOP_10_2021.items():
            categories.append({
                "code": code,
                "id": data["id"],
                "name": data["name"],
                "reference": data["reference"],
            })
        return categories


# =============================================================================
# RISK SCORER
# =============================================================================


class RiskScorer:
    """
    Risk scoring and prioritization engine.

    Calculates risk scores based on likelihood and impact, generates
    risk matrices, and prioritizes remediation efforts based on
    overall risk to the target.

    Attributes:
        LIKELIHOOD_LEVELS: Valid likelihood values and their numeric weights.
        IMPACT_LEVELS: Valid impact values and their numeric weights.
        RISK_LEVELS: Risk level boundaries for aggregate scoring.
    """

    LIKELIHOOD_LEVELS = {
        "VERY_LOW": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "VERY_HIGH": 5,
    }

    IMPACT_LEVELS = {
        "NEGLIGIBLE": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5,
    }

    RISK_LEVELS = {
        "NEGLIGIBLE": (0, 4),
        "LOW": (5, 9),
        "MEDIUM": (10, 14),
        "HIGH": (15, 19),
        "CRITICAL": (20, 25),
    }

    # Severity to likelihood mapping (default assumption)
    SEVERITY_LIKELIHOOD_MAP = {
        "CRITICAL": "VERY_HIGH",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "VERY_LOW",
    }

    # Severity to impact mapping (default assumption)
    SEVERITY_IMPACT_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "NEGLIGIBLE",
    }

    # Effort estimation by finding type
    REMEDIATION_EFFORT = {
        "missing_headers": "quick-win",
        "security_headers": "quick-win",
        "headers": "quick-win",
        "cookie_security": "quick-win",
        "insecure_cookie": "quick-win",
        "clickjacking": "quick-win",
        "hsts_missing": "quick-win",
        "missing_hsts": "quick-win",
        "cors": "medium",
        "cors_misconfig": "medium",
        "ssl_tls": "medium",
        "rate_limiting": "medium",
        "rate_limit": "medium",
        "information_disclosure": "medium",
        "info_disclosure": "medium",
        "http_methods": "quick-win",
        "directory_listing": "quick-win",
        "graphql_introspection": "quick-win",
        "api_versioning": "medium",
        "sensitive_files": "medium",
        "open_redirect": "medium",
        "crlf_injection": "medium",
        "host_header": "medium",
        "parameter_pollution": "medium",
        "xss": "complex",
        "xss_reflected": "medium",
        "xss_stored": "complex",
        "sqli": "complex",
        "sql_injection": "complex",
        "ssrf": "complex",
        "xxe": "complex",
        "idor": "complex",
        "idor_patterns": "complex",
        "broken_access_control": "complex",
        "subdomain_takeover": "medium",
        "cache_poisoning": "complex",
        "request_smuggling": "complex",
        "business_logic": "complex",
        "403_bypass": "medium",
        "path_traversal": "complex",
        "waf": "medium",
    }

    def __init__(self):
        """Initialize the risk scorer."""
        self._cvss = CVSSCalculator()

    def calculate_risk(self, likelihood: str, impact: str) -> int:
        """
        Calculate risk score from likelihood and impact.

        Uses a multiplicative model: Risk = Likelihood x Impact.

        Args:
            likelihood: Likelihood level string (VERY_LOW to VERY_HIGH).
            impact: Impact level string (NEGLIGIBLE to CRITICAL).

        Returns:
            Risk score as integer (1-25).
        """
        l_value = self.LIKELIHOOD_LEVELS.get(likelihood.upper(), 3)
        i_value = self.IMPACT_LEVELS.get(impact.upper(), 3)
        return l_value * i_value

    def risk_level_from_score(self, score: int) -> str:
        """
        Determine risk level label from numeric score.

        Args:
            score: Risk score (1-25).

        Returns:
            Risk level string: NEGLIGIBLE, LOW, MEDIUM, HIGH, or CRITICAL.
        """
        for level, (low, high) in self.RISK_LEVELS.items():
            if low <= score <= high:
                return level
        return "MEDIUM"

    def calculate_aggregate_risk(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Calculate aggregate risk level for a collection of findings.

        Considers the highest individual risk, the count of high-severity
        findings, and the breadth of attack surface exposed.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Dictionary with overall risk level, score, and breakdown.
        """
        if not findings:
            return {
                "overall_risk": "NEGLIGIBLE",
                "overall_score": 0,
                "max_individual_risk": 0,
                "finding_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "risk_factors": [],
            }

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        max_risk = 0
        risk_scores = []

        for finding in findings:
            if hasattr(finding, "severity"):
                severity = finding.severity.upper()
            elif isinstance(finding, dict):
                severity = finding.get("severity", "INFO").upper()
            else:
                severity = "INFO"

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Calculate individual risk
            likelihood = self.SEVERITY_LIKELIHOOD_MAP.get(severity, "MEDIUM")
            impact = self.SEVERITY_IMPACT_MAP.get(severity, "MEDIUM")
            risk = self.calculate_risk(likelihood, impact)
            risk_scores.append(risk)
            max_risk = max(max_risk, risk)

        # Calculate weighted aggregate
        # Formula: weighted average with bonus for critical mass
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        critical_bonus = min(severity_counts.get("CRITICAL", 0) * 2, 5)
        high_bonus = min(severity_counts.get("HIGH", 0), 3)
        aggregate = min(int(avg_risk + critical_bonus + high_bonus), 25)

        # Determine risk factors
        risk_factors = []
        if severity_counts.get("CRITICAL", 0) > 0:
            risk_factors.append("Critical vulnerabilities present")
        if severity_counts.get("HIGH", 0) >= 3:
            risk_factors.append("Multiple high-severity findings")
        if len(findings) > 20:
            risk_factors.append("Large number of findings indicates broad attack surface")
        if severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0) > 5:
            risk_factors.append("High concentration of severe issues")

        return {
            "overall_risk": self.risk_level_from_score(aggregate),
            "overall_score": aggregate,
            "max_individual_risk": max_risk,
            "finding_count": len(findings),
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "medium_count": severity_counts.get("MEDIUM", 0),
            "low_count": severity_counts.get("LOW", 0),
            "info_count": severity_counts.get("INFO", 0),
            "risk_factors": risk_factors,
            "average_risk_score": round(avg_risk, 1),
        }

    def generate_risk_matrix(self) -> Dict[str, Any]:
        """
        Generate a full risk matrix for visualization.

        Returns:
            Dictionary representing the 5x5 risk matrix with labels.
        """
        matrix = {
            "rows": list(self.IMPACT_LEVELS.keys()),
            "columns": list(self.LIKELIHOOD_LEVELS.keys()),
            "cells": [],
        }

        for impact_name, impact_val in self.IMPACT_LEVELS.items():
            row = []
            for likelihood_name, likelihood_val in self.LIKELIHOOD_LEVELS.items():
                score = impact_val * likelihood_val
                level = self.risk_level_from_score(score)
                row.append({
                    "score": score,
                    "level": level,
                    "likelihood": likelihood_name,
                    "impact": impact_name,
                })
            matrix["cells"].append(row)

        return matrix

    def prioritize_remediation(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """
        Prioritize findings for remediation based on risk and effort.

        Produces an ordered list with estimated effort for each fix.
        Quick wins (high impact, low effort) are prioritized first.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Ordered list of findings with priority and effort metadata.
        """
        prioritized = []

        for finding in findings:
            if hasattr(finding, "finding_type"):
                ftype = finding.finding_type
                severity = finding.severity.upper()
                title = finding.title
                url = finding.url
                remediation = finding.remediation
            elif isinstance(finding, dict):
                ftype = finding.get("finding_type", "unknown")
                severity = finding.get("severity", "INFO").upper()
                title = finding.get("title", "Unknown")
                url = finding.get("url", "")
                remediation = finding.get("remediation", "")
            else:
                continue

            # Calculate risk score
            likelihood = self.SEVERITY_LIKELIHOOD_MAP.get(severity, "MEDIUM")
            impact = self.SEVERITY_IMPACT_MAP.get(severity, "MEDIUM")
            risk_score = self.calculate_risk(likelihood, impact)

            # Determine effort
            normalized_type = ftype.lower().replace(" ", "_").replace("-", "_")
            effort = self.REMEDIATION_EFFORT.get(normalized_type, "medium")

            # Priority scoring: higher risk + lower effort = higher priority
            effort_multiplier = {"quick-win": 3, "medium": 2, "complex": 1}
            priority_score = risk_score * effort_multiplier.get(effort, 2)

            prioritized.append({
                "finding_type": ftype,
                "severity": severity,
                "title": title,
                "url": url,
                "remediation": remediation,
                "risk_score": risk_score,
                "risk_level": self.risk_level_from_score(risk_score),
                "effort": effort,
                "priority_score": priority_score,
            })

        # Sort by priority score descending (highest priority first)
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)

        # Add priority rank
        for i, item in enumerate(prioritized):
            item["priority_rank"] = i + 1

        return prioritized

    def estimate_total_effort(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Estimate total remediation effort across all findings.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Dictionary with effort breakdown and time estimates.
        """
        effort_counts = {"quick-win": 0, "medium": 0, "complex": 0}
        effort_hours = {"quick-win": 2, "medium": 8, "complex": 24}

        for finding in findings:
            if hasattr(finding, "finding_type"):
                ftype = finding.finding_type
            elif isinstance(finding, dict):
                ftype = finding.get("finding_type", "unknown")
            else:
                continue

            normalized = ftype.lower().replace(" ", "_").replace("-", "_")
            effort = self.REMEDIATION_EFFORT.get(normalized, "medium")
            effort_counts[effort] = effort_counts.get(effort, 0) + 1

        total_hours = sum(
            count * effort_hours[effort]
            for effort, count in effort_counts.items()
        )

        return {
            "effort_breakdown": effort_counts,
            "estimated_hours": total_hours,
            "estimated_days": round(total_hours / 8, 1),
            "estimated_sprints": round(total_hours / 40, 1),
            "quick_wins_first": effort_counts.get("quick-win", 0),
        }


# =============================================================================
# HTML REPORT TEMPLATE
# =============================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monster Security Report - {target}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --bg-card: #1e2a4a;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0b0;
            --text-muted: #6c7293;
            --accent-blue: #4fc3f7;
            --accent-purple: #7c4dff;
            --accent-green: #00e676;
            --severity-critical: #ff1744;
            --severity-high: #ff5722;
            --severity-medium: #ffc107;
            --severity-low: #4fc3f7;
            --severity-info: #69f0ae;
            --border-color: #2d3a5e;
            --hover-bg: #243352;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            --radius: 8px;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 0;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px 30px;
        }}

        header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            padding: 30px;
            border-radius: var(--radius);
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }}

        header h1 {{
            font-size: 2.2em;
            color: var(--accent-blue);
            margin-bottom: 5px;
            font-weight: 700;
        }}

        header .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1em;
        }}

        header .meta {{
            display: flex;
            gap: 30px;
            margin-top: 15px;
            flex-wrap: wrap;
        }}

        header .meta span {{
            color: var(--text-muted);
            font-size: 0.9em;
        }}

        header .meta span strong {{
            color: var(--text-primary);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: var(--radius);
            text-align: center;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card.critical .value {{ color: var(--severity-critical); }}
        .stat-card.high .value {{ color: var(--severity-high); }}
        .stat-card.medium .value {{ color: var(--severity-medium); }}
        .stat-card.low .value {{ color: var(--severity-low); }}
        .stat-card.info .value {{ color: var(--severity-info); }}
        .stat-card.total .value {{ color: var(--accent-purple); }}

        .section {{
            background: var(--bg-card);
            border-radius: var(--radius);
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid var(--border-color);
        }}

        .section h2 {{
            color: var(--accent-blue);
            font-size: 1.4em;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}

        .section h3 {{
            color: var(--text-primary);
            font-size: 1.1em;
            margin-bottom: 10px;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-critical {{ background: var(--severity-critical); color: white; }}
        .badge-high {{ background: var(--severity-high); color: white; }}
        .badge-medium {{ background: var(--severity-medium); color: #1a1a2e; }}
        .badge-low {{ background: var(--severity-low); color: #1a1a2e; }}
        .badge-info {{ background: var(--severity-info); color: #1a1a2e; }}

        .chart-container {{
            margin: 20px 0;
            padding: 15px;
        }}

        .bar-chart {{
            display: flex;
            align-items: flex-end;
            gap: 8px;
            height: 150px;
            padding: 10px 0;
            border-bottom: 2px solid var(--border-color);
        }}

        .bar-chart .bar {{
            flex: 1;
            min-width: 60px;
            border-radius: 4px 4px 0 0;
            position: relative;
            transition: opacity 0.2s;
            cursor: pointer;
        }}

        .bar-chart .bar:hover {{ opacity: 0.8; }}

        .bar-chart .bar .bar-label {{
            position: absolute;
            bottom: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.75em;
            color: var(--text-secondary);
            white-space: nowrap;
        }}

        .bar-chart .bar .bar-value {{
            position: absolute;
            top: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.85em;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .controls {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .controls label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}

        .controls select, .controls input {{
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.9em;
        }}

        .controls select:focus, .controls input:focus {{
            outline: none;
            border-color: var(--accent-blue);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}

        table th {{
            background: var(--bg-secondary);
            color: var(--accent-blue);
            padding: 12px 15px;
            text-align: left;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            cursor: pointer;
            user-select: none;
            border-bottom: 2px solid var(--border-color);
        }}

        table th:hover {{
            background: var(--hover-bg);
        }}

        table th::after {{
            content: ' \\2195';
            opacity: 0.4;
        }}

        table th.sorted-asc::after {{ content: ' \\2191'; opacity: 1; }}
        table th.sorted-desc::after {{ content: ' \\2193'; opacity: 1; }}

        table td {{
            padding: 10px 15px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9em;
        }}

        table tr:hover {{
            background: var(--hover-bg);
        }}

        .finding-detail {{
            display: none;
            background: var(--bg-secondary);
            padding: 15px 20px;
            margin: 5px 0 10px 0;
            border-radius: var(--radius);
            border-left: 3px solid var(--accent-blue);
        }}

        .finding-detail.expanded {{
            display: block;
        }}

        .finding-detail p {{
            margin: 8px 0;
            color: var(--text-secondary);
        }}

        .finding-detail .label {{
            color: var(--accent-blue);
            font-weight: 600;
            display: inline-block;
            min-width: 120px;
        }}

        .collapsible {{
            cursor: pointer;
            padding: 12px 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }}

        .collapsible:hover {{
            background: var(--hover-bg);
        }}

        .collapsible::after {{
            content: '\\25BC';
            font-size: 0.8em;
            transition: transform 0.3s;
            color: var(--text-muted);
        }}

        .collapsible.active::after {{
            transform: rotate(180deg);
        }}

        .collapsible-content {{
            display: none;
            padding: 15px 20px;
            margin-bottom: 10px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 var(--radius) var(--radius);
        }}

        .collapsible-content.show {{ display: block; }}

        .risk-matrix {{
            display: grid;
            grid-template-columns: auto repeat(5, 1fr);
            gap: 2px;
            margin: 20px 0;
        }}

        .risk-matrix .cell {{
            padding: 12px;
            text-align: center;
            font-size: 0.8em;
            font-weight: 600;
            border-radius: 3px;
        }}

        .risk-matrix .header-cell {{
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: 8px;
            font-size: 0.75em;
        }}

        .risk-matrix .risk-negligible {{ background: #1b5e20; color: white; }}
        .risk-matrix .risk-low {{ background: #2e7d32; color: white; }}
        .risk-matrix .risk-medium {{ background: #f57f17; color: white; }}
        .risk-matrix .risk-high {{ background: #e65100; color: white; }}
        .risk-matrix .risk-critical {{ background: #b71c1c; color: white; }}

        .timeline {{
            position: relative;
            padding-left: 30px;
            margin: 20px 0;
        }}

        .timeline::before {{
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border-color);
        }}

        .timeline-item {{
            position: relative;
            margin-bottom: 15px;
            padding: 10px 15px;
            background: var(--bg-secondary);
            border-radius: var(--radius);
            border: 1px solid var(--border-color);
        }}

        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -24px;
            top: 15px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-blue);
            border: 2px solid var(--bg-primary);
        }}

        .timeline-item .time {{
            color: var(--text-muted);
            font-size: 0.8em;
        }}

        .timeline-item .event {{
            color: var(--text-primary);
            font-weight: 500;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 0.85em;
            margin-top: 30px;
            border-top: 1px solid var(--border-color);
        }}

        @media (max-width: 768px) {{
            .container {{ padding: 10px 15px; }}
            header h1 {{ font-size: 1.5em; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .controls {{ flex-direction: column; align-items: stretch; }}
            table {{ font-size: 0.8em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Monster Security Report</h1>
            <p class="subtitle">Automated Reconnaissance & Vulnerability Assessment</p>
            <div class="meta">
                <span><strong>Target:</strong> {target}</span>
                <span><strong>Date:</strong> {date}</span>
                <span><strong>Duration:</strong> {duration}</span>
                <span><strong>Version:</strong> Monster v{version}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card total"><div class="value">{total_findings}</div><div class="label">Total Findings</div></div>
            <div class="stat-card critical"><div class="value">{critical_count}</div><div class="label">Critical</div></div>
            <div class="stat-card high"><div class="value">{high_count}</div><div class="label">High</div></div>
            <div class="stat-card medium"><div class="value">{medium_count}</div><div class="label">Medium</div></div>
            <div class="stat-card low"><div class="value">{low_count}</div><div class="label">Low</div></div>
            <div class="stat-card info"><div class="value">{info_count}</div><div class="label">Info</div></div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>{executive_summary}</p>
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <div class="bar-chart" id="severity-chart">
                    {severity_chart_bars}
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Risk Matrix</h2>
            {risk_matrix_html}
        </div>

        <div class="section">
            <h2>Findings ({total_findings})</h2>
            <div class="controls">
                <label for="severity-filter">Filter by Severity:</label>
                <select id="severity-filter" onchange="filterFindings()">
                    <option value="all">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                </select>
                <label for="search-input">Search:</label>
                <input type="text" id="search-input" placeholder="Search findings..." oninput="searchFindings()">
            </div>
            <table id="findings-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Severity</th>
                        <th onclick="sortTable(1)">Title</th>
                        <th onclick="sortTable(2)">Type</th>
                        <th onclick="sortTable(3)">URL</th>
                        <th onclick="sortTable(4)">CVSS</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_table_rows}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Scan Timeline</h2>
            <div class="timeline">
                {timeline_html}
            </div>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>
            {detailed_findings_html}
        </div>

        <footer>
            <p>Generated by Monster v{version} | {date} | Confidential Security Assessment</p>
        </footer>
    </div>

    <script>
        // Table sorting functionality
        let sortDirection = {{}};

        function sortTable(colIndex) {{
            const table = document.getElementById('findings-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr.finding-row'));
            const headers = table.querySelectorAll('th');

            // Toggle direction
            sortDirection[colIndex] = !sortDirection[colIndex];
            const ascending = sortDirection[colIndex];

            // Update header classes
            headers.forEach((h, i) => {{
                h.classList.remove('sorted-asc', 'sorted-desc');
                if (i === colIndex) {{
                    h.classList.add(ascending ? 'sorted-asc' : 'sorted-desc');
                }}
            }});

            // Severity order for proper sorting
            const severityOrder = {{'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}};

            rows.sort((a, b) => {{
                let aVal = a.cells[colIndex].textContent.trim();
                let bVal = b.cells[colIndex].textContent.trim();

                if (colIndex === 0) {{
                    aVal = severityOrder[aVal] !== undefined ? severityOrder[aVal] : 5;
                    bVal = severityOrder[bVal] !== undefined ? severityOrder[bVal] : 5;
                }} else if (colIndex === 4) {{
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                }}

                if (aVal < bVal) return ascending ? -1 : 1;
                if (aVal > bVal) return ascending ? 1 : -1;
                return 0;
            }});

            // Re-append rows with their detail rows
            rows.forEach(row => {{
                tbody.appendChild(row);
                const detailId = row.getAttribute('data-detail');
                if (detailId) {{
                    const detail = document.getElementById(detailId);
                    if (detail) tbody.appendChild(detail);
                }}
            }});
        }}

        // Filtering functionality
        function filterFindings() {{
            const filter = document.getElementById('severity-filter').value;
            const rows = document.querySelectorAll('#findings-table tbody tr.finding-row');

            rows.forEach(row => {{
                const severity = row.cells[0].textContent.trim();
                const detailId = row.getAttribute('data-detail');
                const detail = detailId ? document.getElementById(detailId) : null;

                if (filter === 'all' || severity === filter) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                    if (detail) detail.style.display = 'none';
                }}
            }});
        }}

        // Search functionality
        function searchFindings() {{
            const query = document.getElementById('search-input').value.toLowerCase();
            const rows = document.querySelectorAll('#findings-table tbody tr.finding-row');

            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                const detailId = row.getAttribute('data-detail');
                const detail = detailId ? document.getElementById(detailId) : null;

                if (text.includes(query) || query === '') {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                    if (detail) detail.style.display = 'none';
                }}
            }});
        }}

        // Collapsible sections
        function toggleCollapsible(element) {{
            element.classList.toggle('active');
            const content = element.nextElementSibling;
            if (content) content.classList.toggle('show');
        }}

        // Toggle finding details
        function toggleDetail(rowId) {{
            const detail = document.getElementById('detail-' + rowId);
            if (detail) detail.classList.toggle('expanded');
        }}

        // Initialize: add click handlers to finding rows
        document.addEventListener('DOMContentLoaded', function() {{
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                row.style.cursor = 'pointer';
                row.addEventListener('click', function() {{
                    const detailId = this.getAttribute('data-detail');
                    if (detailId) {{
                        const detail = document.getElementById(detailId);
                        if (detail) detail.classList.toggle('expanded');
                    }}
                }});
            }});

            const collapsibles = document.querySelectorAll('.collapsible');
            collapsibles.forEach(c => {{
                c.addEventListener('click', function() {{ toggleCollapsible(this); }});
            }});
        }});
    </script>
</body>
</html>"""


# =============================================================================
# REPORT GENERATOR CLASS
# =============================================================================


class ReportGenerator:
    """
    Comprehensive report generator for security assessment results.

    Generates professional reports in multiple formats including JSON,
    Markdown, HTML (interactive with dark theme), CSV, and platform-specific
    bug bounty templates. Also provides remediation planning and scan
    comparison functionality.

    Attributes:
        output_dir: Directory for generated reports.
        cvss_calc: CVSSCalculator instance.
        owasp_mapper: OWASPMapper instance.
        risk_scorer: RiskScorer instance.
        file_manager: FileManager for atomic file writes.
        color: ColorOutput for terminal feedback.
    """

    def __init__(self, output_dir: str = "./monster_output"):
        """
        Initialize the report generator.

        Args:
            output_dir: Directory where reports will be saved.
                Creates the directory if it does not exist.
        """
        self.output_dir = output_dir
        self.cvss_calc = CVSSCalculator()
        self.owasp_mapper = OWASPMapper()
        self.risk_scorer = RiskScorer()
        self.file_manager = FileManager(output_dir)
        self.color = ColorOutput()

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Report subdirectories
        self.reports_dir = os.path.join(output_dir, "reports")
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

    def generate_full_report(
        self,
        scan_results: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Generate all report types from scan results.

        Orchestrates the generation of JSON, Markdown, HTML, CSV reports
        along with remediation plans and executive summaries.

        Args:
            scan_results: Dictionary containing all scan module results.
                Expected keys: "findings", "recon", "js_analysis",
                "target", "param_mining", "cookie_analysis".
            metadata: Scan metadata including timestamps, duration, etc.
                Expected keys: "target", "start_time", "end_time",
                "duration", "modules_run", "version".

        Returns:
            Dictionary mapping report type to file path.
        """
        ColorOutput.section_header("REPORT GENERATION")
        ColorOutput.info("Generating comprehensive security reports...")

        generated_reports = {}

        # Generate JSON report
        try:
            json_path = self.generate_json_report(scan_results, metadata)
            generated_reports["json"] = json_path
            ColorOutput.success(f"JSON report: {json_path}")
        except Exception as e:
            ColorOutput.error(f"JSON report generation failed: {e}")

        # Generate Markdown report
        try:
            md_path = self.generate_markdown_report(scan_results, metadata)
            generated_reports["markdown"] = md_path
            ColorOutput.success(f"Markdown report: {md_path}")
        except Exception as e:
            ColorOutput.error(f"Markdown report generation failed: {e}")

        # Generate HTML report
        try:
            html_path = self.generate_html_report(scan_results, metadata)
            generated_reports["html"] = html_path
            ColorOutput.success(f"HTML report: {html_path}")
        except Exception as e:
            ColorOutput.error(f"HTML report generation failed: {e}")

        # Generate CSV export
        try:
            findings = scan_results.get("findings", [])
            if findings:
                csv_path = self.generate_csv_export(findings)
                generated_reports["csv"] = csv_path
                ColorOutput.success(f"CSV export: {csv_path}")
        except Exception as e:
            ColorOutput.error(f"CSV export failed: {e}")

        # Generate remediation plan
        try:
            findings = scan_results.get("findings", [])
            if findings:
                remed_path = self.generate_remediation_plan(findings)
                generated_reports["remediation"] = remed_path
                ColorOutput.success(f"Remediation plan: {remed_path}")
        except Exception as e:
            ColorOutput.error(f"Remediation plan failed: {e}")

        ColorOutput.info(f"Generated {len(generated_reports)} reports in {self.reports_dir}")
        return generated_reports

    def generate_json_report(
        self,
        scan_results: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        """
        Generate a comprehensive JSON report.

        Creates a structured JSON file containing all findings,
        metadata, OWASP mapping, risk assessment, and statistics.

        Args:
            scan_results: All scan module results.
            metadata: Scan metadata.

        Returns:
            Path to the generated JSON file.
        """
        findings = scan_results.get("findings", [])

        # Convert findings to dicts if they are objects
        findings_data = []
        for f in findings:
            if hasattr(f, "to_dict"):
                findings_data.append(f.to_dict())
            elif isinstance(f, dict):
                findings_data.append(f)
            else:
                findings_data.append({"title": str(f)})

        # Build OWASP summary
        owasp_summary = self.owasp_mapper.generate_owasp_summary(findings)

        # Build risk assessment
        risk_assessment = self.risk_scorer.calculate_aggregate_risk(findings)

        # Severity statistics
        severity_stats = self._calculate_severity_stats(findings)

        # Build the report
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "Monster v2.0.0",
                "report_format_version": "1.0",
                "target": metadata.get("target", "unknown"),
                "scan_start": metadata.get("start_time", ""),
                "scan_end": metadata.get("end_time", ""),
                "scan_duration": metadata.get("duration", ""),
                "modules_run": metadata.get("modules_run", []),
            },
            "executive_summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_stats,
                "overall_risk": risk_assessment.get("overall_risk", "UNKNOWN"),
                "risk_score": risk_assessment.get("overall_score", 0),
                "risk_factors": risk_assessment.get("risk_factors", []),
            },
            "owasp_mapping": owasp_summary,
            "risk_assessment": risk_assessment,
            "findings": findings_data,
            "recon_summary": scan_results.get("recon", {}),
            "js_analysis_summary": scan_results.get("js_analysis", {}),
            "param_mining_summary": scan_results.get("param_mining", {}),
            "cookie_analysis_summary": scan_results.get("cookie_analysis", {}),
        }

        # Write to file
        target_safe = self._safe_filename(metadata.get("target", "report"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monster_report_{target_safe}_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return filepath

    def generate_markdown_report(
        self,
        scan_results: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        """
        Generate a professional Markdown report.

        Creates a well-formatted Markdown document with tables,
        severity breakdowns, executive summary, and detailed findings.

        Args:
            scan_results: All scan module results.
            metadata: Scan metadata.

        Returns:
            Path to the generated Markdown file.
        """
        findings = scan_results.get("findings", [])
        severity_stats = self._calculate_severity_stats(findings)
        risk_assessment = self.risk_scorer.calculate_aggregate_risk(findings)
        owasp_summary = self.owasp_mapper.generate_owasp_summary(findings)

        target = metadata.get("target", "Unknown")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = metadata.get("duration", "N/A")

        lines = []
        lines.append(f"# Monster Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {target}")
        lines.append(f"**Date:** {date_str}")
        lines.append(f"**Duration:** {duration}")
        lines.append(f"**Generator:** Monster v2.0.0")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(self.generate_executive_summary(scan_results, metadata))
        lines.append("")

        # Risk Assessment
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(f"**Overall Risk Level:** {risk_assessment.get('overall_risk', 'N/A')}")
        lines.append(f"**Risk Score:** {risk_assessment.get('overall_score', 0)}/25")
        lines.append("")
        if risk_assessment.get("risk_factors"):
            lines.append("**Risk Factors:**")
            for factor in risk_assessment["risk_factors"]:
                lines.append(f"- {factor}")
            lines.append("")

        # Severity Summary Table
        lines.append("## Findings Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {severity_stats.get('CRITICAL', 0)} |")
        lines.append(f"| High | {severity_stats.get('HIGH', 0)} |")
        lines.append(f"| Medium | {severity_stats.get('MEDIUM', 0)} |")
        lines.append(f"| Low | {severity_stats.get('LOW', 0)} |")
        lines.append(f"| Info | {severity_stats.get('INFO', 0)} |")
        lines.append(f"| **Total** | **{len(findings)}** |")
        lines.append("")

        # OWASP Mapping
        lines.append("## OWASP Top 10 Mapping")
        lines.append("")
        lines.append("| Category | Name | Count |")
        lines.append("|----------|------|-------|")
        breakdown = owasp_summary.get("category_breakdown", {})
        for cat_code in sorted(breakdown.keys()):
            cat_data = breakdown[cat_code]
            lines.append(f"| {cat_code} | {cat_data.get('name', '')} | {cat_data.get('count', 0)} |")
        lines.append("")

        # Detailed Findings
        lines.append("## Detailed Findings")
        lines.append("")

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                (f.severity if hasattr(f, "severity") else f.get("severity", "INFO")).upper(), 5
            )
        )

        for i, finding in enumerate(sorted_findings, 1):
            if hasattr(finding, "title"):
                title = finding.title
                severity = finding.severity
                ftype = finding.finding_type
                url = finding.url
                description = finding.description
                evidence = finding.evidence
                remediation = finding.remediation
                cvss = finding.cvss_score
                cwe = finding.cwe_id
            elif isinstance(finding, dict):
                title = finding.get("title", "Unknown")
                severity = finding.get("severity", "INFO")
                ftype = finding.get("finding_type", "unknown")
                url = finding.get("url", "")
                description = finding.get("description", "")
                evidence = finding.get("evidence", "")
                remediation = finding.get("remediation", "")
                cvss = finding.get("cvss_score", 0)
                cwe = finding.get("cwe_id", "")
            else:
                continue

            lines.append(f"### {i}. [{severity.upper()}] {title}")
            lines.append("")
            lines.append(f"- **Type:** {ftype}")
            lines.append(f"- **Severity:** {severity}")
            lines.append(f"- **URL:** {url}")
            if cvss:
                lines.append(f"- **CVSS Score:** {cvss}")
            if cwe:
                lines.append(f"- **CWE:** {cwe}")
            lines.append("")
            if description:
                lines.append(f"**Description:** {description}")
                lines.append("")
            if evidence:
                lines.append(f"**Evidence:**")
                lines.append(f"```")
                lines.append(evidence[:500])
                lines.append(f"```")
                lines.append("")
            if remediation:
                lines.append(f"**Remediation:** {remediation}")
                lines.append("")
            lines.append("---")
            lines.append("")

        # Remediation Summary
        prioritized = self.risk_scorer.prioritize_remediation(findings)
        if prioritized:
            lines.append("## Remediation Priority")
            lines.append("")
            lines.append("| Priority | Title | Severity | Effort | Risk Score |")
            lines.append("|----------|-------|----------|--------|------------|")
            for item in prioritized[:20]:
                lines.append(
                    f"| {item['priority_rank']} | {item['title'][:40]} | "
                    f"{item['severity']} | {item['effort']} | {item['risk_score']} |"
                )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Report generated by Monster v2.0.0 on {date_str}*")
        lines.append("")

        # Write to file
        target_safe = self._safe_filename(metadata.get("target", "report"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monster_report_{target_safe}_{timestamp}.md"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return filepath

    def generate_html_report(
        self,
        scan_results: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        """
        Generate an interactive HTML report with dark theme.

        Creates a single-file HTML report with:
        - Inline CSS for dark theme styling
        - Inline JavaScript for table sorting, filtering, and interactivity
        - Severity statistics and chart
        - Risk matrix visualization
        - Collapsible detailed findings
        - Responsive design

        Args:
            scan_results: All scan module results.
            metadata: Scan metadata.

        Returns:
            Path to the generated HTML file.
        """
        findings = scan_results.get("findings", [])
        severity_stats = self._calculate_severity_stats(findings)
        target = metadata.get("target", "Unknown")
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = metadata.get("duration", "N/A")

        from monster import VERSION

        # Build severity chart bars
        max_count = max(severity_stats.values()) if severity_stats else 1
        chart_bars = ""
        severity_colors = {
            "CRITICAL": "var(--severity-critical)",
            "HIGH": "var(--severity-high)",
            "MEDIUM": "var(--severity-medium)",
            "LOW": "var(--severity-low)",
            "INFO": "var(--severity-info)",
        }
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_stats.get(sev, 0)
            height_pct = (count / max_count * 100) if max_count > 0 else 0
            color = severity_colors.get(sev, "var(--accent-blue)")
            chart_bars += (
                f'<div class="bar" style="height: {max(height_pct, 2)}%; '
                f'background: {color};">'
                f'<span class="bar-value">{count}</span>'
                f'<span class="bar-label">{sev}</span>'
                f'</div>\n'
            )

        # Build findings table rows
        table_rows = ""
        detailed_findings = ""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                (f.severity if hasattr(f, "severity") else f.get("severity", "INFO")).upper(), 5
            )
        )

        for i, finding in enumerate(sorted_findings):
            if hasattr(finding, "title"):
                title = finding.title
                severity = finding.severity.upper()
                ftype = finding.finding_type
                url = finding.url
                description = finding.description
                evidence = finding.evidence
                remediation = finding.remediation
                cvss = finding.cvss_score
            elif isinstance(finding, dict):
                title = finding.get("title", "Unknown")
                severity = finding.get("severity", "INFO").upper()
                ftype = finding.get("finding_type", "unknown")
                url = finding.get("url", "")
                description = finding.get("description", "")
                evidence = finding.get("evidence", "")
                remediation = finding.get("remediation", "")
                cvss = finding.get("cvss_score", 0)
            else:
                continue

            badge_class = f"badge-{severity.lower()}"
            url_display = url[:60] + "..." if len(url) > 60 else url

            table_rows += (
                f'<tr class="finding-row" data-detail="detail-{i}">'
                f'<td><span class="severity-badge {badge_class}">{severity}</span></td>'
                f'<td>{self._html_escape(title)}</td>'
                f'<td>{self._html_escape(ftype)}</td>'
                f'<td title="{self._html_escape(url)}">{self._html_escape(url_display)}</td>'
                f'<td>{cvss}</td>'
                f'</tr>\n'
                f'<tr id="detail-{i}" class="finding-detail">'
                f'<td colspan="5">'
                f'<p><span class="label">Description:</span> {self._html_escape(description)}</p>'
                f'<p><span class="label">Evidence:</span> {self._html_escape(evidence[:300])}</p>'
                f'<p><span class="label">Remediation:</span> {self._html_escape(remediation)}</p>'
                f'</td></tr>\n'
            )

            # Collapsible detailed section
            detailed_findings += (
                f'<div class="collapsible">'
                f'<span><span class="severity-badge {badge_class}">{severity}</span> '
                f'{self._html_escape(title)}</span></div>\n'
                f'<div class="collapsible-content">'
                f'<p><strong>Type:</strong> {self._html_escape(ftype)}</p>'
                f'<p><strong>URL:</strong> {self._html_escape(url)}</p>'
                f'<p><strong>Description:</strong> {self._html_escape(description)}</p>'
                f'<p><strong>Evidence:</strong> <code>{self._html_escape(evidence[:500])}</code></p>'
                f'<p><strong>Remediation:</strong> {self._html_escape(remediation)}</p>'
                f'<p><strong>CVSS:</strong> {cvss}</p>'
                f'</div>\n'
            )

        # Build risk matrix HTML
        risk_matrix_html = self._generate_risk_matrix_html()

        # Build timeline
        timeline_html = self._generate_timeline(metadata)

        # Executive summary text
        exec_summary = self.generate_executive_summary(scan_results, metadata)

        # Fill in template
        html_content = HTML_TEMPLATE.format(
            target=self._html_escape(target),
            date=date_str,
            duration=duration,
            version=VERSION,
            total_findings=len(findings),
            critical_count=severity_stats.get("CRITICAL", 0),
            high_count=severity_stats.get("HIGH", 0),
            medium_count=severity_stats.get("MEDIUM", 0),
            low_count=severity_stats.get("LOW", 0),
            info_count=severity_stats.get("INFO", 0),
            executive_summary=self._html_escape(exec_summary),
            severity_chart_bars=chart_bars,
            risk_matrix_html=risk_matrix_html,
            findings_table_rows=table_rows,
            timeline_html=timeline_html,
            detailed_findings_html=detailed_findings,
        )

        # Write to file
        target_safe = self._safe_filename(metadata.get("target", "report"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monster_report_{target_safe}_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath

    def generate_executive_summary(
        self,
        scan_results: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        """
        Generate a high-level executive summary of the assessment.

        Provides a management-friendly overview of the security posture
        including key metrics, top risks, and recommended next steps.

        Args:
            scan_results: All scan module results.
            metadata: Scan metadata.

        Returns:
            Executive summary as a formatted string.
        """
        findings = scan_results.get("findings", [])
        severity_stats = self._calculate_severity_stats(findings)
        risk_assessment = self.risk_scorer.calculate_aggregate_risk(findings)
        target = metadata.get("target", "Unknown")

        critical = severity_stats.get("CRITICAL", 0)
        high = severity_stats.get("HIGH", 0)
        medium = severity_stats.get("MEDIUM", 0)
        total = len(findings)
        overall_risk = risk_assessment.get("overall_risk", "UNKNOWN")

        summary_parts = []
        summary_parts.append(
            f"A comprehensive security assessment was conducted against {target}. "
            f"The assessment identified a total of {total} findings across "
            f"multiple severity levels."
        )

        if critical > 0:
            summary_parts.append(
                f"IMMEDIATE ATTENTION REQUIRED: {critical} critical-severity "
                f"finding(s) were identified that pose significant risk to "
                f"the application and its users."
            )
        if high > 0:
            summary_parts.append(
                f"{high} high-severity finding(s) require prompt remediation "
                f"to prevent potential exploitation."
            )
        if medium > 0:
            summary_parts.append(
                f"{medium} medium-severity finding(s) should be addressed "
                f"in the near-term security roadmap."
            )

        summary_parts.append(
            f"The overall risk level for this target is assessed as "
            f"{overall_risk}. "
        )

        if risk_assessment.get("risk_factors"):
            summary_parts.append(
                "Key risk factors include: "
                + "; ".join(risk_assessment["risk_factors"][:3])
                + "."
            )

        return " ".join(summary_parts)

    def generate_hackerone_template(self, finding: Any) -> str:
        """
        Generate a HackerOne-formatted bug report template.

        Creates a structured report following HackerOne submission
        guidelines with Summary, Steps to Reproduce, Impact, and
        Supporting Material sections.

        Args:
            finding: A Finding object or dict with vulnerability details.

        Returns:
            Formatted string suitable for HackerOne submission.
        """
        if hasattr(finding, "title"):
            title = finding.title
            severity = finding.severity
            ftype = finding.finding_type
            url = finding.url
            description = finding.description
            evidence = finding.evidence
            remediation = finding.remediation
            cvss = finding.cvss_score
            cwe = finding.cwe_id
        elif isinstance(finding, dict):
            title = finding.get("title", "Unknown Vulnerability")
            severity = finding.get("severity", "MEDIUM")
            ftype = finding.get("finding_type", "unknown")
            url = finding.get("url", "")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            remediation = finding.get("remediation", "")
            cvss = finding.get("cvss_score", 0)
            cwe = finding.get("cwe_id", "")
        else:
            return ""

        # Map to OWASP category
        owasp_cat = self.owasp_mapper.map_finding(ftype)
        owasp_name = self.owasp_mapper.get_category_name(owasp_cat)

        # Get CVSS vector if not provided
        cvss_vector = ""
        if not cvss:
            cvss_vector = self.cvss_calc.get_vector_for_type(ftype)
            if cvss_vector:
                cvss = self.cvss_calc.calculate_base_score(cvss_vector)

        template = f"""## Summary

**Title:** {title}
**Severity:** {severity}
**CVSS Score:** {cvss}
**CWE:** {cwe}
**OWASP Category:** {owasp_cat} - {owasp_name}

{description}

## Steps To Reproduce

1. Navigate to: {url}
2. Observe the following behavior:

{evidence}

## Impact

This vulnerability could allow an attacker to exploit {ftype} on the target
application. The severity is rated as {severity} based on the potential
impact to confidentiality, integrity, and availability of the system.

**Risk Assessment:**
- Severity: {severity}
- CVSS Score: {cvss}/10.0
- OWASP Category: {owasp_cat} - {owasp_name}

If exploited, this could lead to:
- Unauthorized access to sensitive data
- Compromise of user accounts or sessions
- Degradation of application security posture

## Supporting Material

**Affected URL:** {url}
**Finding Type:** {ftype}
**Evidence:**
```
{evidence[:1000]}
```

**Recommended Fix:**
{remediation}

## Suggested Severity

{severity} ({cvss}/10.0 CVSS)
"""
        return template

    def generate_bugcrowd_template(self, finding: Any) -> str:
        """
        Generate a Bugcrowd-formatted vulnerability report template.

        Creates a structured report following Bugcrowd VRT taxonomy
        and submission guidelines.

        Args:
            finding: A Finding object or dict with vulnerability details.

        Returns:
            Formatted string suitable for Bugcrowd submission.
        """
        if hasattr(finding, "title"):
            title = finding.title
            severity = finding.severity
            ftype = finding.finding_type
            url = finding.url
            description = finding.description
            evidence = finding.evidence
            remediation = finding.remediation
            cvss = finding.cvss_score
        elif isinstance(finding, dict):
            title = finding.get("title", "Unknown Vulnerability")
            severity = finding.get("severity", "MEDIUM")
            ftype = finding.get("finding_type", "unknown")
            url = finding.get("url", "")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            remediation = finding.get("remediation", "")
            cvss = finding.get("cvss_score", 0)
        else:
            return ""

        # Bugcrowd severity mapping (P1-P5)
        severity_map = {
            "CRITICAL": "P1",
            "HIGH": "P2",
            "MEDIUM": "P3",
            "LOW": "P4",
            "INFO": "P5",
        }
        bugcrowd_priority = severity_map.get(severity.upper(), "P3")

        template = f"""# Vulnerability Report

## Title
{title}

## Priority
{bugcrowd_priority} ({severity})

## VRT Category
{ftype}

## URL / Location
{url}

## Description
{description}

## Steps to Reproduce
1. Access the target URL: {url}
2. Observe the following security issue:
   - Type: {ftype}
   - Severity: {severity}

## Proof of Concept
```
{evidence[:1000]}
```

## Impact Statement
This {ftype} vulnerability at {url} is rated {severity} (Priority: {bugcrowd_priority}).
If exploited, an attacker could leverage this vulnerability to compromise
the security of the application and its users.

CVSS Base Score: {cvss}/10.0

## Remediation Recommendation
{remediation}

## Additional Context
- Discovery Tool: Monster v2.0.0
- Assessment Date: {datetime.now().strftime('%Y-%m-%d')}
- OWASP Category: {self.owasp_mapper.map_finding(ftype)} - {self.owasp_mapper.get_category_name(self.owasp_mapper.map_finding(ftype))}
"""
        return template

    def generate_intigriti_template(self, finding: Any) -> str:
        """
        Generate an Intigriti-formatted vulnerability report template.

        Creates a structured report following Intigriti submission
        guidelines and severity classification.

        Args:
            finding: A Finding object or dict with vulnerability details.

        Returns:
            Formatted string suitable for Intigriti submission.
        """
        if hasattr(finding, "title"):
            title = finding.title
            severity = finding.severity
            ftype = finding.finding_type
            url = finding.url
            description = finding.description
            evidence = finding.evidence
            remediation = finding.remediation
            cvss = finding.cvss_score
            cwe = finding.cwe_id
        elif isinstance(finding, dict):
            title = finding.get("title", "Unknown Vulnerability")
            severity = finding.get("severity", "MEDIUM")
            ftype = finding.get("finding_type", "unknown")
            url = finding.get("url", "")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            remediation = finding.get("remediation", "")
            cvss = finding.get("cvss_score", 0)
            cwe = finding.get("cwe_id", "")
        else:
            return ""

        owasp_cat = self.owasp_mapper.map_finding(ftype)
        owasp_name = self.owasp_mapper.get_category_name(owasp_cat)

        template = f"""# Security Vulnerability Report

## Vulnerability Title
{title}

## Severity
{severity} (CVSS: {cvss}/10.0)

## Vulnerability Type
{ftype}

## Affected Endpoint
{url}

## CWE Classification
{cwe}

## OWASP Classification
{owasp_cat} - {owasp_name}

## Description
{description}

## Reproduction Steps

### Prerequisites
- Web browser with developer tools
- Network proxy (optional)

### Steps
1. Navigate to {url}
2. The following security issue was identified:
   {ftype} - {title}

### Expected Behavior
The application should properly validate and sanitize all inputs,
implement appropriate security controls, and follow security best practices.

### Actual Behavior
{description}

## Proof of Concept

### Evidence
```
{evidence[:1000]}
```

## Impact Assessment

### Confidentiality Impact
Potential exposure of sensitive information through {ftype}.

### Integrity Impact
Possible modification of data or application behavior.

### Availability Impact
Potential degradation of service or denial of access.

## Remediation Suggestions
{remediation}

## References
- OWASP Top 10: {self.owasp_mapper.get_category_reference(owasp_cat)}
- CWE: https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html

## Additional Information
- Tool: Monster v2.0.0
- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return template

    def generate_csv_export(self, findings: List[Any]) -> str:
        """
        Export findings to CSV format for spreadsheet analysis.

        Creates a CSV file with all findings data suitable for
        import into Excel, Google Sheets, or other analysis tools.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Path to the generated CSV file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"monster_findings_{timestamp}.csv"
        filepath = os.path.join(self.reports_dir, filename)

        headers = [
            "ID", "Severity", "Title", "Type", "URL",
            "Description", "Evidence", "Remediation",
            "CVSS Score", "CWE", "OWASP Category",
            "Risk Level", "Effort",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for i, finding in enumerate(findings, 1):
                if hasattr(finding, "title"):
                    ftype = finding.finding_type
                    severity = finding.severity
                    title = finding.title
                    url = finding.url
                    description = finding.description
                    evidence = finding.evidence
                    remediation = finding.remediation
                    cvss = finding.cvss_score
                    cwe = finding.cwe_id
                elif isinstance(finding, dict):
                    ftype = finding.get("finding_type", "unknown")
                    severity = finding.get("severity", "INFO")
                    title = finding.get("title", "Unknown")
                    url = finding.get("url", "")
                    description = finding.get("description", "")
                    evidence = finding.get("evidence", "")
                    remediation = finding.get("remediation", "")
                    cvss = finding.get("cvss_score", 0)
                    cwe = finding.get("cwe_id", "")
                else:
                    continue

                owasp_cat = self.owasp_mapper.map_finding(ftype)
                owasp_name = self.owasp_mapper.get_category_name(owasp_cat)
                risk_level = self.risk_scorer.risk_level_from_score(
                    self.risk_scorer.calculate_risk(
                        self.risk_scorer.SEVERITY_LIKELIHOOD_MAP.get(severity.upper(), "MEDIUM"),
                        self.risk_scorer.SEVERITY_IMPACT_MAP.get(severity.upper(), "MEDIUM"),
                    )
                )
                effort = self.risk_scorer.REMEDIATION_EFFORT.get(
                    ftype.lower().replace(" ", "_").replace("-", "_"), "medium"
                )

                writer.writerow([
                    i, severity, title, ftype, url,
                    description[:200], evidence[:200], remediation[:200],
                    cvss, cwe, f"{owasp_cat} - {owasp_name}",
                    risk_level, effort,
                ])

        return filepath

    def generate_remediation_plan(self, findings: List[Any]) -> str:
        """
        Generate a prioritized remediation plan.

        Creates a structured document with findings organized by
        effort level and priority, including time estimates and
        recommended fix sequence.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Path to the generated remediation plan file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"remediation_plan_{timestamp}.md"
        filepath = os.path.join(self.reports_dir, filename)

        prioritized = self.risk_scorer.prioritize_remediation(findings)
        effort_estimate = self.risk_scorer.estimate_total_effort(findings)

        lines = []
        lines.append("# Remediation Plan")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")

        # Effort summary
        lines.append("## Effort Estimate")
        lines.append("")
        lines.append(f"- **Quick Wins:** {effort_estimate['effort_breakdown'].get('quick-win', 0)} items")
        lines.append(f"- **Medium Effort:** {effort_estimate['effort_breakdown'].get('medium', 0)} items")
        lines.append(f"- **Complex Fixes:** {effort_estimate['effort_breakdown'].get('complex', 0)} items")
        lines.append(f"- **Estimated Total Hours:** {effort_estimate['estimated_hours']}")
        lines.append(f"- **Estimated Days:** {effort_estimate['estimated_days']}")
        lines.append(f"- **Estimated Sprints (2 week):** {effort_estimate['estimated_sprints']}")
        lines.append("")

        # Phase 1: Quick Wins
        lines.append("## Phase 1: Quick Wins (1-2 hours each)")
        lines.append("")
        lines.append("These items can be addressed quickly with minimal risk:")
        lines.append("")
        lines.append("| # | Title | Severity | Risk Score |")
        lines.append("|---|-------|----------|------------|")
        phase1 = [p for p in prioritized if p["effort"] == "quick-win"]
        for i, item in enumerate(phase1, 1):
            lines.append(f"| {i} | {item['title'][:50]} | {item['severity']} | {item['risk_score']} |")
        lines.append("")
        if phase1:
            lines.append("**Recommended Actions:**")
            for item in phase1[:5]:
                if item.get("remediation"):
                    lines.append(f"- **{item['title'][:40]}:** {item['remediation'][:100]}")
            lines.append("")

        # Phase 2: Medium Effort
        lines.append("## Phase 2: Medium Effort (4-8 hours each)")
        lines.append("")
        lines.append("These items require moderate development effort:")
        lines.append("")
        lines.append("| # | Title | Severity | Risk Score |")
        lines.append("|---|-------|----------|------------|")
        phase2 = [p for p in prioritized if p["effort"] == "medium"]
        for i, item in enumerate(phase2, 1):
            lines.append(f"| {i} | {item['title'][:50]} | {item['severity']} | {item['risk_score']} |")
        lines.append("")
        if phase2:
            lines.append("**Recommended Actions:**")
            for item in phase2[:5]:
                if item.get("remediation"):
                    lines.append(f"- **{item['title'][:40]}:** {item['remediation'][:100]}")
            lines.append("")

        # Phase 3: Complex
        lines.append("## Phase 3: Complex Fixes (1-3 days each)")
        lines.append("")
        lines.append("These items require significant development and testing effort:")
        lines.append("")
        lines.append("| # | Title | Severity | Risk Score |")
        lines.append("|---|-------|----------|------------|")
        phase3 = [p for p in prioritized if p["effort"] == "complex"]
        for i, item in enumerate(phase3, 1):
            lines.append(f"| {i} | {item['title'][:50]} | {item['severity']} | {item['risk_score']} |")
        lines.append("")
        if phase3:
            lines.append("**Recommended Actions:**")
            for item in phase3[:5]:
                if item.get("remediation"):
                    lines.append(f"- **{item['title'][:40]}:** {item['remediation'][:100]}")
            lines.append("")

        # Priority order (all)
        lines.append("## Full Priority Order")
        lines.append("")
        lines.append("| Rank | Title | Severity | Effort | Risk | Priority Score |")
        lines.append("|------|-------|----------|--------|------|----------------|")
        for item in prioritized[:30]:
            lines.append(
                f"| {item['priority_rank']} | {item['title'][:35]} | "
                f"{item['severity']} | {item['effort']} | "
                f"{item['risk_level']} | {item['priority_score']} |"
            )
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Generated by Monster v2.0.0 - Remediation Planning Module*")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return filepath

    def generate_comparison_report(
        self,
        current: Dict[str, Any],
        previous: Dict[str, Any],
    ) -> str:
        """
        Generate a comparison report between two scans.

        Shows new findings, resolved findings, and unchanged findings
        to track security posture over time.

        Args:
            current: Current scan results dict.
            previous: Previous scan results dict.

        Returns:
            Formatted comparison report string.
        """
        current_findings = current.get("findings", [])
        previous_findings = previous.get("findings", [])

        # Create fingerprints for matching
        def fingerprint(f):
            if hasattr(f, "title"):
                return f"{f.finding_type}:{f.url}:{f.title}"
            elif isinstance(f, dict):
                return f"{f.get('finding_type', '')}:{f.get('url', '')}:{f.get('title', '')}"
            return str(f)

        current_fps = {fingerprint(f): f for f in current_findings}
        previous_fps = {fingerprint(f): f for f in previous_findings}

        new_findings = [current_fps[fp] for fp in current_fps if fp not in previous_fps]
        resolved_findings = [previous_fps[fp] for fp in previous_fps if fp not in current_fps]
        unchanged_findings = [current_fps[fp] for fp in current_fps if fp in previous_fps]

        lines = []
        lines.append("# Scan Comparison Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Previous | Current | Change |")
        lines.append(f"|--------|----------|---------|--------|")
        lines.append(f"| Total Findings | {len(previous_findings)} | {len(current_findings)} | {len(current_findings) - len(previous_findings):+d} |")
        lines.append(f"| New Findings | - | {len(new_findings)} | +{len(new_findings)} |")
        lines.append(f"| Resolved | {len(resolved_findings)} | - | -{len(resolved_findings)} |")
        lines.append(f"| Unchanged | - | {len(unchanged_findings)} | 0 |")
        lines.append("")

        # New findings (security regressions)
        if new_findings:
            lines.append("## New Findings (Regressions)")
            lines.append("")
            lines.append("These issues were not present in the previous scan:")
            lines.append("")
            for f in new_findings:
                if hasattr(f, "title"):
                    lines.append(f"- [{f.severity}] {f.title} - {f.url}")
                elif isinstance(f, dict):
                    lines.append(f"- [{f.get('severity', 'INFO')}] {f.get('title', '')} - {f.get('url', '')}")
            lines.append("")

        # Resolved findings (improvements)
        if resolved_findings:
            lines.append("## Resolved Findings (Improvements)")
            lines.append("")
            lines.append("These issues have been fixed since the previous scan:")
            lines.append("")
            for f in resolved_findings:
                if hasattr(f, "title"):
                    lines.append(f"- [{f.severity}] {f.title} - {f.url}")
                elif isinstance(f, dict):
                    lines.append(f"- [{f.get('severity', 'INFO')}] {f.get('title', '')} - {f.get('url', '')}")
            lines.append("")

        # Unchanged
        if unchanged_findings:
            lines.append("## Unchanged Findings")
            lines.append("")
            lines.append(f"{len(unchanged_findings)} findings remain unchanged from the previous scan.")
            lines.append("")

        # Trend analysis
        lines.append("## Trend Analysis")
        lines.append("")
        if len(new_findings) > len(resolved_findings):
            lines.append("**TREND: DEGRADING** - More new issues discovered than resolved.")
        elif len(resolved_findings) > len(new_findings):
            lines.append("**TREND: IMPROVING** - More issues resolved than new ones found.")
        else:
            lines.append("**TREND: STABLE** - Security posture remains relatively unchanged.")
        lines.append("")

        return "\n".join(lines)

    def _calculate_severity_stats(self, findings: List[Any]) -> Dict[str, int]:
        """
        Calculate severity distribution statistics.

        Args:
            findings: List of Finding objects or dicts.

        Returns:
            Dictionary mapping severity levels to counts.
        """
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in findings:
            if hasattr(finding, "severity"):
                severity = finding.severity.upper()
            elif isinstance(finding, dict):
                severity = finding.get("severity", "INFO").upper()
            else:
                severity = "INFO"

            if severity in stats:
                stats[severity] += 1
            else:
                stats["INFO"] += 1

        return stats

    def _generate_timeline(self, metadata: Dict[str, Any]) -> str:
        """
        Generate HTML timeline from scan metadata.

        Args:
            metadata: Scan metadata with timing information.

        Returns:
            HTML string for the timeline section.
        """
        events = metadata.get("timeline", [])

        if not events:
            # Generate default timeline from metadata
            start = metadata.get("start_time", "")
            end = metadata.get("end_time", "")
            modules = metadata.get("modules_run", [])

            events = []
            if start:
                events.append({"time": start, "event": "Scan started"})
            for module in modules:
                events.append({"time": "", "event": f"Module executed: {module}"})
            if end:
                events.append({"time": end, "event": "Scan completed"})

        html_parts = []
        for event in events:
            time_str = event.get("time", "")
            event_str = event.get("event", "")
            html_parts.append(
                f'<div class="timeline-item">'
                f'<span class="time">{self._html_escape(str(time_str))}</span> '
                f'<span class="event">{self._html_escape(str(event_str))}</span>'
                f'</div>'
            )

        return "\n".join(html_parts) if html_parts else '<div class="timeline-item"><span class="event">No timeline data available</span></div>'

    def _format_finding_detail(self, finding: Any) -> str:
        """
        Format a single finding for detailed display.

        Args:
            finding: A Finding object or dict.

        Returns:
            Formatted string with all finding details.
        """
        if hasattr(finding, "title"):
            title = finding.title
            severity = finding.severity
            ftype = finding.finding_type
            url = finding.url
            description = finding.description
            evidence = finding.evidence
            remediation = finding.remediation
            cvss = finding.cvss_score
            cwe = finding.cwe_id
        elif isinstance(finding, dict):
            title = finding.get("title", "Unknown")
            severity = finding.get("severity", "INFO")
            ftype = finding.get("finding_type", "unknown")
            url = finding.get("url", "")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            remediation = finding.get("remediation", "")
            cvss = finding.get("cvss_score", 0)
            cwe = finding.get("cwe_id", "")
        else:
            return str(finding)

        owasp_cat = self.owasp_mapper.map_finding(ftype)
        owasp_name = self.owasp_mapper.get_category_name(owasp_cat)

        detail = f"""
[{severity}] {title}
{'=' * 60}
Type:        {ftype}
URL:         {url}
CVSS Score:  {cvss}
CWE:         {cwe}
OWASP:       {owasp_cat} - {owasp_name}

Description:
{description}

Evidence:
{evidence[:500]}

Remediation:
{remediation}
{'=' * 60}
"""
        return detail

    def _generate_risk_matrix_html(self) -> str:
        """
        Generate an HTML risk matrix visualization.

        Returns:
            HTML string representing a 5x5 risk matrix with color coding.
        """
        matrix = self.risk_scorer.generate_risk_matrix()
        impact_labels = list(reversed(matrix["rows"]))
        likelihood_labels = matrix["columns"]

        html = '<div class="risk-matrix">\n'

        # Header row
        html += '<div class="header-cell"></div>\n'
        for likelihood in likelihood_labels:
            html += f'<div class="header-cell">{likelihood.replace("_", " ")}</div>\n'

        # Data rows (reversed so highest impact is at top)
        for impact in impact_labels:
            html += f'<div class="header-cell">{impact.replace("_", " ")}</div>\n'
            impact_val = self.risk_scorer.IMPACT_LEVELS[impact]
            for likelihood in likelihood_labels:
                likelihood_val = self.risk_scorer.LIKELIHOOD_LEVELS[likelihood]
                score = impact_val * likelihood_val
                level = self.risk_scorer.risk_level_from_score(score)
                css_class = f"risk-{level.lower()}"
                html += f'<div class="cell {css_class}">{score}</div>\n'

        html += '</div>\n'
        return html

    def _get_html_template(self) -> str:
        """
        Get the full HTML report template.

        Returns:
            HTML template string with placeholders for report data.
        """
        return HTML_TEMPLATE

    @staticmethod
    def _safe_filename(name: str) -> str:
        """
        Convert a string to a safe filename.

        Args:
            name: Input string (e.g., domain name).

        Returns:
            Sanitized string suitable for use as a filename.
        """
        # Remove protocol
        name = re.sub(r'^https?://', '', name)
        # Replace unsafe characters
        name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
        # Limit length
        return name[:50]

    @staticmethod
    def _html_escape(text: str) -> str:
        """
        Escape HTML special characters.

        Args:
            text: Input text that may contain HTML characters.

        Returns:
            HTML-safe string.
        """
        if not text:
            return ""
        text = str(text)
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#x27;")
        return text
