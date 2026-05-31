"""
Super Monster v2 - Domain Classifier

Classifies domains/subdomains into categories (payment, auth, api, admin, cdn, web)
based on prefix matching and keyword patterns from config. Determines which security
tests are relevant for each domain type.
"""

from .config import DOMAIN_TYPES, SCAN_TESTS_PER_TYPE, SEVERITY_RULES


# Risk level priority for tie-breaking when multiple types match
RISK_PRIORITY = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


class DomainClassifier:
    """
    Classifies domains into security-relevant categories to enable
    targeted scanning. Uses prefix matching and keyword analysis
    from DOMAIN_TYPES configuration.
    """

    def __init__(self):
        """Initialize the classifier with domain type definitions."""
        self._domain_types = DOMAIN_TYPES
        self._scan_tests = SCAN_TESTS_PER_TYPE
        self._severity_rules = SEVERITY_RULES
        self._cache = {}

    def classify_domain(self, domain: str) -> str:
        """
        Classify a single domain into a category.

        Checks if any DOMAIN_TYPES prefixes match the start of the subdomain.
        If multiple match, uses risk_level priority (critical > high > medium > low).
        Defaults to 'web' if no prefix matches.

        Args:
            domain: The domain string to classify (e.g., 'payment.tw.coupang.com')

        Returns:
            The domain type string (e.g., 'payment', 'auth', 'api', etc.)
        """
        if domain in self._cache:
            return self._cache[domain]

        # Extract the subdomain prefix (everything before the main domain)
        domain_lower = domain.lower().strip()

        # Find all matching types
        matches = []

        for dtype, config in self._domain_types.items():
            # Check prefix matches
            prefixes = config.get("prefixes", [])
            for prefix in prefixes:
                if domain_lower.startswith(prefix):
                    risk = config.get("risk_level", "medium")
                    matches.append((dtype, risk, "prefix"))
                    break

            # Check keyword matches in the subdomain portion
            keywords = config.get("keywords", [])
            # Get the first segment of the domain as the subdomain indicator
            first_segment = domain_lower.split(".")[0]
            for keyword in keywords:
                if keyword == first_segment:
                    risk = config.get("risk_level", "medium")
                    matches.append((dtype, risk, "keyword"))
                    break

        if not matches:
            # Default to web if no prefix or keyword matches
            result = "web"
        elif len(matches) == 1:
            result = matches[0][0]
        else:
            # Multiple matches - use risk level priority (critical > high > medium > low)
            # Prefix matches take precedence over keyword matches
            prefix_matches = [m for m in matches if m[2] == "prefix"]
            if prefix_matches:
                matches = prefix_matches

            # Sort by risk priority (lower number = higher priority)
            matches.sort(key=lambda m: RISK_PRIORITY.get(m[1], 99))
            result = matches[0][0]

        self._cache[domain] = result
        return result

    def classify_domains(self, domains: list) -> dict:
        """
        Classify a list of domains into their respective categories.

        Args:
            domains: List of domain strings to classify.

        Returns:
            Dictionary mapping each domain to its classified type.
        """
        classified = {}
        for domain in domains:
            if not domain or not isinstance(domain, str):
                continue
            classified[domain] = self.classify_domain(domain)
        return classified

    def get_tests_for_domain(self, domain: str) -> list:
        """
        Get the list of security tests appropriate for a domain.

        Determines the domain type and returns the corresponding
        test list from SCAN_TESTS_PER_TYPE.

        Args:
            domain: The domain to get tests for.

        Returns:
            List of test names to run against this domain.
        """
        domain_type = self.classify_domain(domain)
        return self._scan_tests.get(domain_type, self._scan_tests.get("web", []))

    def get_tests_for_type(self, domain_type: str) -> list:
        """
        Get the list of security tests for a given domain type.

        Args:
            domain_type: The domain type (payment, auth, api, etc.)

        Returns:
            List of test names for that type.
        """
        return self._scan_tests.get(domain_type, self._scan_tests.get("web", []))

    def get_severity(self, finding_type: str, domain_type: str) -> str:
        """
        Look up the severity for a finding type on a specific domain type.

        Uses SEVERITY_RULES from config to determine appropriate severity.
        Falls back to 'medium' if no specific rule is defined.

        Args:
            finding_type: The type of finding (e.g., 'cors', 'csp')
            domain_type: The domain category (e.g., 'payment', 'auth')

        Returns:
            Severity string: 'critical', 'high', 'medium', 'low', or 'info'
        """
        key = (finding_type.lower(), domain_type.lower())
        return self._severity_rules.get(key, "medium")

    def summarize_classification(self, classified: dict) -> dict:
        """
        Group domains by type for display purposes.

        Args:
            classified: Dictionary of domain -> type mappings
                        (as returned by classify_domains)

        Returns:
            Dictionary mapping each type to a list of domains of that type.
            Example: {'payment': ['payment.tw.coupang.com'], 'cdn': ['cdn.example.com']}
        """
        summary = {}
        for domain, dtype in classified.items():
            if dtype not in summary:
                summary[dtype] = []
            summary[dtype].append(domain)
        return summary

    def get_domain_info(self, domain: str) -> dict:
        """
        Get full classification info for a single domain.

        Args:
            domain: The domain to get info for.

        Returns:
            Dictionary with type, tests, risk_level, and description.
        """
        domain_type = self.classify_domain(domain)
        type_config = self._domain_types.get(domain_type, {})
        tests = self.get_tests_for_type(domain_type)

        return {
            "domain": domain,
            "type": domain_type,
            "risk_level": type_config.get("risk_level", "medium"),
            "description": type_config.get("description", "Unknown domain type"),
            "tests": tests,
            "test_count": len(tests),
        }

    def get_type_stats(self, classified: dict) -> dict:
        """
        Get statistics about classified domains.

        Args:
            classified: Dictionary of domain -> type mappings.

        Returns:
            Dictionary with count per type and risk breakdown.
        """
        stats = {
            "total": len(classified),
            "by_type": {},
            "by_risk": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }

        for domain, dtype in classified.items():
            if dtype not in stats["by_type"]:
                stats["by_type"][dtype] = 0
            stats["by_type"][dtype] += 1

            risk = self._domain_types.get(dtype, {}).get("risk_level", "medium")
            if risk in stats["by_risk"]:
                stats["by_risk"][risk] += 1

        return stats

    def get_high_value_targets(self, classified: dict) -> list:
        """
        Extract domains classified as critical or high risk.

        Args:
            classified: Dictionary of domain -> type mappings.

        Returns:
            List of (domain, type, risk_level) tuples for high-value targets.
        """
        targets = []
        for domain, dtype in classified.items():
            risk = self._domain_types.get(dtype, {}).get("risk_level", "medium")
            if risk in ("critical", "high"):
                targets.append((domain, dtype, risk))

        # Sort critical first, then high
        targets.sort(key=lambda t: RISK_PRIORITY.get(t[2], 99))
        return targets

    def clear_cache(self):
        """Clear the classification cache."""
        self._cache = {}
