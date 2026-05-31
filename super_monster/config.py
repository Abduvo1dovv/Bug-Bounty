"""
Super Monster v1.0.0 Configuration Module

Comprehensive configuration for the bug bounty intelligence engine including:
- Scoring weights for finding prioritization
- Domain classification and tier assignments
- Correlation rules and confidence thresholds
- Retest intervals by severity level
- Notification thresholds and dispatch rules
- Duplicate probability estimates per finding type
- Color constants using colorama for terminal output
- Attack surface scoring parameters
- Bug bounty platform payout estimates
- CVSS vector component weights
- Finding lifecycle state machine configuration
"""

import os
from pathlib import Path

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


# =============================================================================
# GENERAL CONSTANTS
# =============================================================================

TOOL_NAME = "Super Monster"
TOOL_VERSION = "1.0.0"
TOOL_BANNER = f"{TOOL_NAME} v{TOOL_VERSION}"
DEFAULT_DB_PATH = "super_monster_findings.json"
DEFAULT_OUTPUT_DIR = "super_output"
DEFAULT_REPORTS_DIR = "monster_output/reports"
MAX_WORKERS = 8
REQUEST_TIMEOUT = 30
RATE_LIMIT_DELAY = 1.5
MAX_RETRIES = 3
FINGERPRINT_ALGORITHM = "sha256"
DB_FORMAT_VERSION = "1.0.0"
REPORT_FORMAT_VERSION = "1.0.0"


# =============================================================================
# SCORING WEIGHTS - Used by prioritizer to rank findings
# =============================================================================

# Primary scoring weights (must sum to 1.0)
SCORING_WEIGHTS = {
    "cvss_base": 0.25,
    "exploitability": 0.20,
    "business_impact": 0.25,
    "bug_bounty_value": 0.15,
    "correlation_bonus": 0.15,
}

# Sub-weights for exploitability scoring
EXPLOITABILITY_WEIGHTS = {
    "attack_vector_network": 1.0,
    "attack_vector_adjacent": 0.7,
    "attack_vector_local": 0.5,
    "attack_vector_physical": 0.2,
    "attack_complexity_low": 1.0,
    "attack_complexity_high": 0.5,
    "privileges_required_none": 1.0,
    "privileges_required_low": 0.7,
    "privileges_required_high": 0.3,
    "user_interaction_none": 1.0,
    "user_interaction_required": 0.6,
    "scope_changed": 1.0,
    "scope_unchanged": 0.7,
    "exploit_code_maturity_high": 1.0,
    "exploit_code_maturity_functional": 0.8,
    "exploit_code_maturity_poc": 0.6,
    "exploit_code_maturity_unproven": 0.3,
}

# Business impact multipliers based on asset criticality
BUSINESS_IMPACT_MULTIPLIERS = {
    "authentication_bypass": 2.5,
    "payment_data_exposure": 2.8,
    "pii_data_leak": 2.2,
    "admin_access": 3.0,
    "rce_achieved": 3.5,
    "database_access": 2.7,
    "api_key_exposure": 2.0,
    "session_hijack": 2.3,
    "privilege_escalation": 2.6,
    "data_modification": 2.1,
    "service_disruption": 1.5,
    "information_disclosure": 1.2,
    "default_impact": 1.0,
}

# Correlation bonus multipliers when findings chain together
CORRELATION_BONUS_MULTIPLIERS = {
    "chain_length_2": 1.3,
    "chain_length_3": 1.6,
    "chain_length_4": 2.0,
    "chain_length_5_plus": 2.5,
    "same_endpoint": 1.2,
    "same_domain": 1.1,
    "cross_domain": 1.4,
    "escalation_path": 1.8,
    "data_exfil_path": 2.0,
    "auth_bypass_chain": 2.2,
}


# =============================================================================
# DOMAIN CLASSIFICATION - Tier assignments for target subdomains
# =============================================================================

DOMAIN_TIERS = {
    "tier_1_critical": {
        "description": "Payment, authentication, and core API systems",
        "multiplier": 3.0,
        "keywords": [
            "pay", "payment", "billing", "checkout", "stripe", "paypal",
            "auth", "login", "sso", "oauth", "identity", "iam", "session",
            "api", "gateway", "graphql", "rest", "core",
            "admin", "manage", "console", "dashboard", "control",
            "vault", "secrets", "keys", "crypto", "certificate",
        ],
        "patterns": [
            r"^pay(ment)?[s]?\.",
            r"^auth[n]?\.",
            r"^api(-v?\d+)?\.",
            r"^admin\.",
            r"^sso\.",
            r"^oauth\.",
            r"^identity\.",
            r"^billing\.",
            r"^checkout\.",
        ],
    },
    "tier_2_high": {
        "description": "User data, internal tools, and databases",
        "multiplier": 2.0,
        "keywords": [
            "user", "account", "profile", "member", "customer",
            "data", "db", "database", "store", "storage", "backup",
            "internal", "intranet", "corp", "private", "staff",
            "mail", "email", "smtp", "imap",
            "upload", "file", "media", "cdn", "asset",
        ],
        "patterns": [
            r"^user[s]?\.",
            r"^account[s]?\.",
            r"^db\.",
            r"^internal\.",
            r"^mail\.",
            r"^upload\.",
            r"^file[s]?\.",
            r"^cdn\.",
        ],
    },
    "tier_3_medium": {
        "description": "Public-facing web apps and services",
        "multiplier": 1.5,
        "keywords": [
            "www", "web", "app", "mobile", "m",
            "shop", "store", "catalog", "product",
            "blog", "news", "content", "cms",
            "support", "help", "docs", "wiki",
            "search", "analytics", "track", "monitor",
        ],
        "patterns": [
            r"^www\.",
            r"^app\.",
            r"^m\.",
            r"^shop\.",
            r"^blog\.",
            r"^support\.",
            r"^docs\.",
        ],
    },
    "tier_4_low": {
        "description": "Development, staging, and test environments",
        "multiplier": 1.0,
        "keywords": [
            "dev", "develop", "staging", "stage", "test", "testing",
            "qa", "uat", "sandbox", "demo", "preview", "beta",
            "ci", "cd", "build", "jenkins", "gitlab", "github",
            "debug", "local", "tmp", "temp",
        ],
        "patterns": [
            r"^dev\.",
            r"^stag(e|ing)\.",
            r"^test\.",
            r"^qa\.",
            r"^demo\.",
            r"^beta\.",
            r"^ci\.",
        ],
    },
    "tier_5_info": {
        "description": "Static assets, marketing, and low-value targets",
        "multiplier": 0.5,
        "keywords": [
            "static", "assets", "img", "images", "css", "js",
            "marketing", "promo", "campaign", "landing",
            "status", "health", "ping", "heartbeat",
            "legacy", "old", "deprecated", "archive",
        ],
        "patterns": [
            r"^static\.",
            r"^assets\.",
            r"^img\.",
            r"^status\.",
            r"^legacy\.",
        ],
    },
}

# Default tier for unclassified domains
DEFAULT_DOMAIN_TIER = "tier_3_medium"
DEFAULT_DOMAIN_MULTIPLIER = 1.5


# =============================================================================
# CORRELATION RULES - Patterns for chaining findings together
# =============================================================================

CORRELATION_RULES = {
    "auth_bypass_chain": {
        "description": "Authentication bypass leading to data access",
        "required_types": ["auth_bypass", "idor", "broken_access_control"],
        "optional_types": ["session_fixation", "csrf", "privilege_escalation"],
        "min_findings": 2,
        "confidence_threshold": 0.7,
        "severity_boost": "CRITICAL",
        "chain_description": "Authentication weakness enables unauthorized data access",
    },
    "ssrf_to_cloud": {
        "description": "SSRF leading to cloud metadata access",
        "required_types": ["ssrf"],
        "optional_types": ["info_disclosure", "cloud_metadata", "credential_exposure"],
        "min_findings": 1,
        "confidence_threshold": 0.8,
        "severity_boost": "CRITICAL",
        "chain_description": "SSRF enables cloud infrastructure compromise",
    },
    "xss_to_account_takeover": {
        "description": "XSS leading to session theft or account takeover",
        "required_types": ["xss_stored", "xss_reflected"],
        "optional_types": ["session_hijack", "cookie_theft", "csrf"],
        "min_findings": 1,
        "confidence_threshold": 0.6,
        "severity_boost": "HIGH",
        "chain_description": "XSS enables session theft and account compromise",
    },
    "sqli_data_exfil": {
        "description": "SQL injection enabling data exfiltration",
        "required_types": ["sqli", "sqli_blind", "sqli_error"],
        "optional_types": ["data_exposure", "pii_leak", "credential_dump"],
        "min_findings": 1,
        "confidence_threshold": 0.85,
        "severity_boost": "CRITICAL",
        "chain_description": "SQL injection allows database extraction",
    },
    "cors_data_theft": {
        "description": "CORS misconfiguration enabling cross-origin data theft",
        "required_types": ["cors"],
        "optional_types": ["sensitive_data_exposure", "api_data_leak"],
        "min_findings": 1,
        "confidence_threshold": 0.65,
        "severity_boost": "HIGH",
        "chain_description": "CORS weakness allows attacker-controlled origin to steal data",
    },
    "open_redirect_phishing": {
        "description": "Open redirect enabling credential phishing",
        "required_types": ["open_redirect"],
        "optional_types": ["phishing", "credential_theft", "oauth_redirect"],
        "min_findings": 1,
        "confidence_threshold": 0.5,
        "severity_boost": "MEDIUM",
        "chain_description": "Open redirect abused for phishing campaigns",
    },
    "subdomain_takeover_chain": {
        "description": "Subdomain takeover enabling further attacks",
        "required_types": ["subdomain_takeover"],
        "optional_types": ["cookie_scope", "cors", "phishing", "xss_stored"],
        "min_findings": 1,
        "confidence_threshold": 0.75,
        "severity_boost": "HIGH",
        "chain_description": "Subdomain control enables cookie theft and phishing",
    },
    "info_leak_to_access": {
        "description": "Information disclosure leading to system access",
        "required_types": ["info_disclosure", "credential_exposure", "api_key_leak"],
        "optional_types": ["auth_bypass", "admin_access", "rce"],
        "min_findings": 2,
        "confidence_threshold": 0.6,
        "severity_boost": "HIGH",
        "chain_description": "Leaked credentials/keys enable unauthorized access",
    },
    "file_upload_rce": {
        "description": "Unrestricted file upload leading to code execution",
        "required_types": ["file_upload", "unrestricted_upload"],
        "optional_types": ["rce", "webshell", "path_traversal"],
        "min_findings": 1,
        "confidence_threshold": 0.8,
        "severity_boost": "CRITICAL",
        "chain_description": "File upload bypass enables remote code execution",
    },
    "idor_mass_data": {
        "description": "IDOR enabling mass data enumeration",
        "required_types": ["idor", "broken_access_control"],
        "optional_types": ["pii_leak", "data_exposure", "enumeration"],
        "min_findings": 1,
        "confidence_threshold": 0.7,
        "severity_boost": "HIGH",
        "chain_description": "IDOR allows enumeration of all user records",
    },
    "race_condition_abuse": {
        "description": "Race condition enabling duplicate transactions",
        "required_types": ["race_condition"],
        "optional_types": ["payment_bypass", "privilege_escalation", "quota_bypass"],
        "min_findings": 1,
        "confidence_threshold": 0.7,
        "severity_boost": "HIGH",
        "chain_description": "Race condition enables financial or privilege abuse",
    },
    "header_injection_chain": {
        "description": "Header injection enabling cache poisoning or response splitting",
        "required_types": ["header_injection", "crlf_injection"],
        "optional_types": ["cache_poisoning", "xss_stored", "response_splitting"],
        "min_findings": 1,
        "confidence_threshold": 0.65,
        "severity_boost": "HIGH",
        "chain_description": "Header injection leads to cache poisoning affecting all users",
    },
}

# Confidence thresholds for correlation decisions
CONFIDENCE_THRESHOLDS = {
    "definite": 0.90,
    "highly_likely": 0.80,
    "likely": 0.70,
    "possible": 0.60,
    "speculative": 0.50,
    "minimum_report": 0.55,
    "minimum_correlate": 0.45,
}


# =============================================================================
# RETEST INTERVALS - Time between retests based on severity
# =============================================================================

RETEST_INTERVALS = {
    "CRITICAL": {
        "initial_hours": 24,
        "followup_hours": 48,
        "max_retests": 10,
        "escalation_after": 3,
        "description": "Retest critical findings daily, escalate after 3 failed fixes",
    },
    "HIGH": {
        "initial_hours": 72,
        "followup_hours": 168,
        "max_retests": 7,
        "escalation_after": 4,
        "description": "Retest high findings every 3 days, then weekly",
    },
    "MEDIUM": {
        "initial_hours": 168,
        "followup_hours": 336,
        "max_retests": 5,
        "escalation_after": 5,
        "description": "Retest medium findings weekly, then bi-weekly",
    },
    "LOW": {
        "initial_hours": 336,
        "followup_hours": 672,
        "max_retests": 3,
        "escalation_after": 3,
        "description": "Retest low findings bi-weekly, then monthly",
    },
    "INFO": {
        "initial_hours": 720,
        "followup_hours": 1440,
        "max_retests": 2,
        "escalation_after": 2,
        "description": "Retest informational findings monthly",
    },
}

# Retest status values
RETEST_STATUS = {
    "pending": "Awaiting retest",
    "in_progress": "Currently retesting",
    "fixed": "Vulnerability confirmed fixed",
    "not_fixed": "Vulnerability still present",
    "partially_fixed": "Mitigation applied but bypass possible",
    "regressed": "Previously fixed, now vulnerable again",
    "wontfix": "Vendor marked as accepted risk",
    "duplicate": "Duplicate of another finding",
    "invalid": "False positive confirmed",
}


# =============================================================================
# NOTIFICATION THRESHOLDS - When to alert based on findings
# =============================================================================

NOTIFICATION_THRESHOLDS = {
    "immediate": {
        "description": "Send immediately upon discovery",
        "min_severity": "CRITICAL",
        "min_cvss": 9.0,
        "conditions": ["rce", "auth_bypass", "sqli", "admin_access"],
        "channels": ["webhook", "email", "slack"],
    },
    "urgent": {
        "description": "Send within 1 hour",
        "min_severity": "HIGH",
        "min_cvss": 7.0,
        "conditions": ["xss_stored", "ssrf", "idor", "privilege_escalation"],
        "channels": ["webhook", "slack"],
    },
    "standard": {
        "description": "Send in daily digest",
        "min_severity": "MEDIUM",
        "min_cvss": 4.0,
        "conditions": ["cors", "open_redirect", "info_disclosure"],
        "channels": ["email"],
    },
    "low_priority": {
        "description": "Send in weekly summary",
        "min_severity": "LOW",
        "min_cvss": 0.0,
        "conditions": ["missing_headers", "cookie_flags", "version_disclosure"],
        "channels": ["email"],
    },
    "batch_threshold": 5,
    "digest_interval_hours": 24,
    "max_notifications_per_hour": 20,
    "quiet_hours_start": 23,
    "quiet_hours_end": 7,
    "escalation_timeout_hours": 4,
}

# Webhook configuration defaults
WEBHOOK_CONFIG = {
    "timeout": 10,
    "max_retries": 3,
    "retry_delay": 5,
    "headers": {"Content-Type": "application/json"},
    "max_payload_size": 65536,
    "verify_ssl": True,
}

# Slack message formatting
SLACK_CONFIG = {
    "max_message_length": 4000,
    "color_critical": "#FF0000",
    "color_high": "#FF6600",
    "color_medium": "#FFCC00",
    "color_low": "#0099FF",
    "color_info": "#999999",
    "emoji_critical": ":rotating_light:",
    "emoji_high": ":warning:",
    "emoji_medium": ":large_orange_diamond:",
    "emoji_low": ":information_source:",
    "emoji_info": ":page_facing_up:",
}


# =============================================================================
# DUPLICATE PROBABILITY - Likelihood of a finding being a dupe per type
# =============================================================================

DUPE_PROBABILITY = {
    "cors": {
        "base_probability": 0.40,
        "same_domain_boost": 0.30,
        "same_endpoint_boost": 0.50,
        "description": "CORS misconfigs often affect multiple endpoints on same domain",
    },
    "missing_headers": {
        "base_probability": 0.70,
        "same_domain_boost": 0.80,
        "same_endpoint_boost": 0.95,
        "description": "Missing security headers typically affect entire domain",
    },
    "xss_reflected": {
        "base_probability": 0.20,
        "same_domain_boost": 0.15,
        "same_endpoint_boost": 0.85,
        "description": "Reflected XSS on different params are usually distinct",
    },
    "xss_stored": {
        "base_probability": 0.15,
        "same_domain_boost": 0.10,
        "same_endpoint_boost": 0.70,
        "description": "Stored XSS in different contexts are usually distinct",
    },
    "sqli": {
        "base_probability": 0.25,
        "same_domain_boost": 0.20,
        "same_endpoint_boost": 0.80,
        "description": "SQLi on different params usually distinct but same endpoint high dupe",
    },
    "idor": {
        "base_probability": 0.30,
        "same_domain_boost": 0.25,
        "same_endpoint_boost": 0.75,
        "description": "IDOR on different resources may be same root cause",
    },
    "ssrf": {
        "base_probability": 0.25,
        "same_domain_boost": 0.20,
        "same_endpoint_boost": 0.85,
        "description": "SSRF on same endpoint is likely same vuln",
    },
    "open_redirect": {
        "base_probability": 0.45,
        "same_domain_boost": 0.35,
        "same_endpoint_boost": 0.90,
        "description": "Open redirects on same param are dupes",
    },
    "info_disclosure": {
        "base_probability": 0.50,
        "same_domain_boost": 0.40,
        "same_endpoint_boost": 0.90,
        "description": "Info disclosure often server-wide config issue",
    },
    "subdomain_takeover": {
        "base_probability": 0.05,
        "same_domain_boost": 0.05,
        "same_endpoint_boost": 0.95,
        "description": "Each subdomain takeover is unique",
    },
    "auth_bypass": {
        "base_probability": 0.20,
        "same_domain_boost": 0.35,
        "same_endpoint_boost": 0.80,
        "description": "Auth bypass may share root cause across endpoints",
    },
    "csrf": {
        "base_probability": 0.35,
        "same_domain_boost": 0.50,
        "same_endpoint_boost": 0.85,
        "description": "CSRF often affects multiple actions on same domain",
    },
    "cookie_flags": {
        "base_probability": 0.80,
        "same_domain_boost": 0.90,
        "same_endpoint_boost": 0.99,
        "description": "Cookie flag issues are domain-wide",
    },
    "version_disclosure": {
        "base_probability": 0.75,
        "same_domain_boost": 0.85,
        "same_endpoint_boost": 0.99,
        "description": "Version disclosure is server-wide",
    },
    "default": {
        "base_probability": 0.25,
        "same_domain_boost": 0.20,
        "same_endpoint_boost": 0.70,
        "description": "Default probability for unknown finding types",
    },
}


# =============================================================================
# BUG BOUNTY PAYOUT ESTIMATES - Expected values by severity and platform
# =============================================================================

BOUNTY_ESTIMATES = {
    "CRITICAL": {
        "min": 5000,
        "max": 50000,
        "median": 15000,
        "platform_ranges": {
            "hackerone": {"min": 5000, "max": 100000, "median": 20000},
            "bugcrowd": {"min": 3000, "max": 50000, "median": 12000},
            "intigriti": {"min": 2000, "max": 25000, "median": 8000},
            "synack": {"min": 5000, "max": 30000, "median": 15000},
            "yeswehack": {"min": 2000, "max": 20000, "median": 7000},
        },
    },
    "HIGH": {
        "min": 1000,
        "max": 15000,
        "median": 5000,
        "platform_ranges": {
            "hackerone": {"min": 1500, "max": 25000, "median": 7500},
            "bugcrowd": {"min": 1000, "max": 15000, "median": 4000},
            "intigriti": {"min": 750, "max": 10000, "median": 3000},
            "synack": {"min": 1500, "max": 12000, "median": 5000},
            "yeswehack": {"min": 750, "max": 8000, "median": 2500},
        },
    },
    "MEDIUM": {
        "min": 250,
        "max": 5000,
        "median": 1500,
        "platform_ranges": {
            "hackerone": {"min": 500, "max": 7500, "median": 2000},
            "bugcrowd": {"min": 250, "max": 5000, "median": 1000},
            "intigriti": {"min": 200, "max": 3000, "median": 750},
            "synack": {"min": 500, "max": 5000, "median": 1500},
            "yeswehack": {"min": 200, "max": 3000, "median": 750},
        },
    },
    "LOW": {
        "min": 50,
        "max": 1000,
        "median": 300,
        "platform_ranges": {
            "hackerone": {"min": 100, "max": 2000, "median": 500},
            "bugcrowd": {"min": 50, "max": 1000, "median": 250},
            "intigriti": {"min": 50, "max": 750, "median": 200},
            "synack": {"min": 100, "max": 1000, "median": 300},
            "yeswehack": {"min": 50, "max": 500, "median": 150},
        },
    },
    "INFO": {
        "min": 0,
        "max": 250,
        "median": 50,
        "platform_ranges": {
            "hackerone": {"min": 0, "max": 500, "median": 100},
            "bugcrowd": {"min": 0, "max": 250, "median": 50},
            "intigriti": {"min": 0, "max": 200, "median": 50},
            "synack": {"min": 0, "max": 200, "median": 50},
            "yeswehack": {"min": 0, "max": 150, "median": 25},
        },
    },
}


# =============================================================================
# SEVERITY LEVELS AND CVSS MAPPING
# =============================================================================

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

CVSS_TO_SEVERITY = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9): "HIGH",
    (4.0, 6.9): "MEDIUM",
    (0.1, 3.9): "LOW",
    (0.0, 0.0): "INFO",
}

# CVSS v3.1 base metric values
CVSS_METRICS = {
    "attack_vector": {
        "NETWORK": 0.85,
        "ADJACENT": 0.62,
        "LOCAL": 0.55,
        "PHYSICAL": 0.20,
    },
    "attack_complexity": {
        "LOW": 0.77,
        "HIGH": 0.44,
    },
    "privileges_required": {
        "NONE": 0.85,
        "LOW": 0.62,
        "HIGH": 0.27,
    },
    "user_interaction": {
        "NONE": 0.85,
        "REQUIRED": 0.62,
    },
    "scope": {
        "CHANGED": 1.0,
        "UNCHANGED": 0.0,
    },
    "confidentiality_impact": {
        "HIGH": 0.56,
        "LOW": 0.22,
        "NONE": 0.0,
    },
    "integrity_impact": {
        "HIGH": 0.56,
        "LOW": 0.22,
        "NONE": 0.0,
    },
    "availability_impact": {
        "HIGH": 0.56,
        "LOW": 0.22,
        "NONE": 0.0,
    },
}


# =============================================================================
# FINDING TYPE CLASSIFICATIONS
# =============================================================================

FINDING_TYPE_SEVERITY_MAP = {
    "rce": "CRITICAL",
    "sqli": "CRITICAL",
    "sqli_blind": "HIGH",
    "sqli_error": "HIGH",
    "auth_bypass": "CRITICAL",
    "ssrf": "HIGH",
    "ssrf_blind": "MEDIUM",
    "xss_stored": "HIGH",
    "xss_reflected": "MEDIUM",
    "xss_dom": "MEDIUM",
    "idor": "HIGH",
    "broken_access_control": "HIGH",
    "privilege_escalation": "CRITICAL",
    "file_upload": "HIGH",
    "unrestricted_upload": "CRITICAL",
    "path_traversal": "HIGH",
    "lfi": "HIGH",
    "rfi": "CRITICAL",
    "xxe": "HIGH",
    "ssti": "HIGH",
    "deserialization": "CRITICAL",
    "cors": "MEDIUM",
    "csrf": "MEDIUM",
    "open_redirect": "LOW",
    "subdomain_takeover": "HIGH",
    "header_injection": "MEDIUM",
    "crlf_injection": "MEDIUM",
    "cache_poisoning": "HIGH",
    "clickjacking": "LOW",
    "session_fixation": "MEDIUM",
    "session_hijack": "HIGH",
    "cookie_theft": "HIGH",
    "info_disclosure": "LOW",
    "credential_exposure": "CRITICAL",
    "api_key_leak": "HIGH",
    "pii_leak": "HIGH",
    "data_exposure": "MEDIUM",
    "missing_headers": "INFO",
    "cookie_flags": "LOW",
    "version_disclosure": "INFO",
    "directory_listing": "LOW",
    "backup_file": "MEDIUM",
    "debug_endpoint": "MEDIUM",
    "default_credentials": "CRITICAL",
    "weak_password": "MEDIUM",
    "race_condition": "HIGH",
    "business_logic": "HIGH",
    "payment_bypass": "CRITICAL",
    "rate_limiting": "LOW",
    "dos": "MEDIUM",
    "phishing": "LOW",
    "email_spoofing": "LOW",
    "cloud_metadata": "HIGH",
    "dns_misconfiguration": "LOW",
    "tls_misconfiguration": "LOW",
    "jwt_vulnerability": "HIGH",
    "graphql_introspection": "LOW",
    "websocket_hijack": "MEDIUM",
    "prototype_pollution": "MEDIUM",
}

# CWE mapping for common finding types
CWE_MAPPING = {
    "rce": "CWE-94",
    "sqli": "CWE-89",
    "sqli_blind": "CWE-89",
    "sqli_error": "CWE-89",
    "auth_bypass": "CWE-287",
    "ssrf": "CWE-918",
    "xss_stored": "CWE-79",
    "xss_reflected": "CWE-79",
    "xss_dom": "CWE-79",
    "idor": "CWE-639",
    "broken_access_control": "CWE-284",
    "privilege_escalation": "CWE-269",
    "file_upload": "CWE-434",
    "unrestricted_upload": "CWE-434",
    "path_traversal": "CWE-22",
    "lfi": "CWE-98",
    "rfi": "CWE-98",
    "xxe": "CWE-611",
    "ssti": "CWE-1336",
    "deserialization": "CWE-502",
    "cors": "CWE-942",
    "csrf": "CWE-352",
    "open_redirect": "CWE-601",
    "subdomain_takeover": "CWE-284",
    "header_injection": "CWE-113",
    "crlf_injection": "CWE-93",
    "cache_poisoning": "CWE-349",
    "clickjacking": "CWE-1021",
    "session_fixation": "CWE-384",
    "info_disclosure": "CWE-200",
    "credential_exposure": "CWE-798",
    "api_key_leak": "CWE-798",
    "pii_leak": "CWE-359",
    "missing_headers": "CWE-693",
    "cookie_flags": "CWE-614",
    "version_disclosure": "CWE-200",
    "directory_listing": "CWE-548",
    "default_credentials": "CWE-1393",
    "race_condition": "CWE-362",
    "business_logic": "CWE-840",
    "jwt_vulnerability": "CWE-347",
    "graphql_introspection": "CWE-200",
    "prototype_pollution": "CWE-1321",
}


# =============================================================================
# COLOR CONSTANTS - Terminal output colors using colorama
# =============================================================================

class Colors:
    """Centralized color definitions for consistent terminal output."""

    # Severity colors
    CRITICAL = Fore.RED + Style.BRIGHT
    HIGH = Fore.RED
    MEDIUM = Fore.YELLOW
    LOW = Fore.CYAN
    INFO = Fore.WHITE

    # Status colors
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    FIXED = Fore.GREEN
    NOT_FIXED = Fore.RED
    PENDING = Fore.YELLOW
    IN_PROGRESS = Fore.CYAN

    # UI element colors
    BANNER = Fore.MAGENTA + Style.BRIGHT
    HEADER = Fore.CYAN + Style.BRIGHT
    SUBHEADER = Fore.CYAN
    LABEL = Fore.WHITE + Style.BRIGHT
    VALUE = Fore.WHITE
    DIMMED = Style.DIM
    HIGHLIGHT = Fore.YELLOW + Style.BRIGHT
    ACCENT = Fore.MAGENTA

    # Finding type colors
    VULNERABILITY = Fore.RED
    MISCONFIGURATION = Fore.YELLOW
    INFORMATION = Fore.BLUE
    RECON = Fore.GREEN

    # Progress colors
    PROGRESS_BAR = Fore.GREEN
    PROGRESS_TEXT = Fore.WHITE
    TIMER = Fore.CYAN + Style.DIM
    COUNT = Fore.WHITE + Style.BRIGHT

    # Report colors
    SCORE_HIGH = Fore.RED + Style.BRIGHT
    SCORE_MEDIUM = Fore.YELLOW + Style.BRIGHT
    SCORE_LOW = Fore.GREEN + Style.BRIGHT

    # Reset
    RESET = Style.RESET_ALL

    @classmethod
    def severity_color(cls, severity):
        """Get color for a given severity level."""
        severity_map = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
            "INFO": cls.INFO,
        }
        return severity_map.get(severity.upper(), cls.INFO)

    @classmethod
    def status_color(cls, status):
        """Get color for a given finding status."""
        status_map = {
            "new": cls.WARNING,
            "reported": cls.IN_PROGRESS,
            "fixed": cls.FIXED,
            "not_fixed": cls.NOT_FIXED,
            "partially_fixed": cls.PENDING,
            "regressed": cls.ERROR,
            "wontfix": cls.DIMMED,
            "duplicate": cls.DIMMED,
            "invalid": cls.DIMMED,
        }
        return status_map.get(status.lower(), cls.VALUE)

    @classmethod
    def score_color(cls, score):
        """Get color based on numeric score (0-10)."""
        if score >= 7.0:
            return cls.SCORE_HIGH
        elif score >= 4.0:
            return cls.SCORE_MEDIUM
        else:
            return cls.SCORE_LOW


# =============================================================================
# FINDING LIFECYCLE STATE MACHINE
# =============================================================================

FINDING_STATES = {
    "new": {
        "description": "Newly discovered finding, not yet triaged",
        "allowed_transitions": ["reported", "duplicate", "invalid"],
        "color": "WARNING",
    },
    "reported": {
        "description": "Reported to the program/vendor",
        "allowed_transitions": ["fixed", "not_fixed", "partially_fixed", "wontfix", "duplicate"],
        "color": "IN_PROGRESS",
    },
    "fixed": {
        "description": "Confirmed fixed by vendor",
        "allowed_transitions": ["regressed"],
        "color": "FIXED",
    },
    "not_fixed": {
        "description": "Retest confirmed still vulnerable",
        "allowed_transitions": ["fixed", "partially_fixed", "wontfix"],
        "color": "NOT_FIXED",
    },
    "partially_fixed": {
        "description": "Mitigation applied but bypass exists",
        "allowed_transitions": ["fixed", "not_fixed"],
        "color": "PENDING",
    },
    "regressed": {
        "description": "Was fixed but vulnerability has returned",
        "allowed_transitions": ["fixed", "reported"],
        "color": "ERROR",
    },
    "wontfix": {
        "description": "Vendor accepted risk, will not fix",
        "allowed_transitions": ["reported"],
        "color": "DIMMED",
    },
    "duplicate": {
        "description": "Duplicate of another finding",
        "allowed_transitions": [],
        "color": "DIMMED",
    },
    "invalid": {
        "description": "Confirmed false positive",
        "allowed_transitions": ["new"],
        "color": "DIMMED",
    },
}


# =============================================================================
# ATTACK SURFACE PARAMETERS
# =============================================================================

ATTACK_SURFACE_WEIGHTS = {
    "open_ports": 0.15,
    "web_endpoints": 0.25,
    "api_endpoints": 0.20,
    "authentication_points": 0.20,
    "file_upload_points": 0.10,
    "third_party_integrations": 0.10,
}

ATTACK_SURFACE_RISK_LEVELS = {
    "massive": {"min_score": 80, "description": "Extremely large attack surface, high risk"},
    "large": {"min_score": 60, "description": "Large attack surface, elevated risk"},
    "moderate": {"min_score": 40, "description": "Moderate attack surface, standard risk"},
    "small": {"min_score": 20, "description": "Small attack surface, lower risk"},
    "minimal": {"min_score": 0, "description": "Minimal attack surface, lowest risk"},
}


# =============================================================================
# REPORT OUTPUT CONFIGURATION
# =============================================================================

REPORT_FORMATS = ["json", "markdown", "html", "csv"]
DEFAULT_REPORT_FORMAT = "json"

REPORT_SECTIONS = {
    "executive_summary": True,
    "severity_breakdown": True,
    "finding_details": True,
    "correlation_chains": True,
    "attack_plans": True,
    "retest_status": True,
    "timeline": True,
    "recommendations": True,
    "appendix": True,
}

# Maximum items per section in reports
REPORT_LIMITS = {
    "max_findings_per_page": 50,
    "max_correlation_chains": 25,
    "max_attack_plans": 10,
    "max_timeline_entries": 100,
    "max_recommendations": 20,
    "truncate_evidence_at": 2000,
    "truncate_description_at": 1000,
}


# =============================================================================
# DIFF ENGINE CONFIGURATION
# =============================================================================

DIFF_CONFIG = {
    "highlight_new": True,
    "highlight_fixed": True,
    "highlight_changed": True,
    "show_unchanged": False,
    "group_by": "severity",
    "sort_by": "severity_desc",
    "include_metadata_diff": True,
    "include_recon_diff": True,
    "similarity_threshold": 0.85,
    "fuzzy_match_url": True,
    "ignore_timestamp_changes": True,
}


# =============================================================================
# PLATFORM-SPECIFIC CONFIGURATIONS
# =============================================================================

PLATFORM_CONFIG = {
    "hackerone": {
        "severity_mapping": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "INFO"},
        "asset_types": ["URL", "DOMAIN", "IP", "CIDR", "SOURCE_CODE", "MOBILE"],
        "max_report_length": 10000,
        "supports_cvss": True,
        "supports_cwe": True,
    },
    "bugcrowd": {
        "severity_mapping": {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM", "P4": "LOW", "P5": "INFO"},
        "asset_types": ["website", "api", "mobile", "hardware", "other"],
        "max_report_length": 8000,
        "supports_cvss": True,
        "supports_cwe": True,
    },
    "intigriti": {
        "severity_mapping": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"},
        "asset_types": ["web", "mobile", "api", "network"],
        "max_report_length": 10000,
        "supports_cvss": True,
        "supports_cwe": True,
    },
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_severity_from_cvss(cvss_score):
    """Convert a CVSS score to a severity level string."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0.0:
        return "LOW"
    return "INFO"


def get_domain_tier(subdomain):
    """Classify a subdomain into a tier based on keywords and patterns."""
    import re as _re
    subdomain_lower = subdomain.lower()

    for tier_name, tier_config in DOMAIN_TIERS.items():
        for keyword in tier_config["keywords"]:
            if keyword in subdomain_lower:
                return tier_name, tier_config["multiplier"]
        for pattern in tier_config["patterns"]:
            if _re.search(pattern, subdomain_lower):
                return tier_name, tier_config["multiplier"]

    return DEFAULT_DOMAIN_TIER, DEFAULT_DOMAIN_MULTIPLIER


def get_dupe_probability(finding_type, same_domain=False, same_endpoint=False):
    """Calculate duplicate probability for a finding type."""
    config = DUPE_PROBABILITY.get(finding_type, DUPE_PROBABILITY["default"])
    probability = config["base_probability"]

    if same_endpoint:
        probability = config["same_endpoint_boost"]
    elif same_domain:
        probability = config["same_domain_boost"]

    return min(probability, 0.99)


def get_retest_interval(severity, retest_count=0):
    """Get the retest interval in hours for a severity level."""
    config = RETEST_INTERVALS.get(severity, RETEST_INTERVALS["MEDIUM"])
    if retest_count == 0:
        return config["initial_hours"]
    return config["followup_hours"]


def get_bounty_estimate(severity, platform="hackerone"):
    """Get estimated bounty range for a severity on a platform."""
    sev_config = BOUNTY_ESTIMATES.get(severity, BOUNTY_ESTIMATES["INFO"])
    if platform in sev_config.get("platform_ranges", {}):
        return sev_config["platform_ranges"][platform]
    return {"min": sev_config["min"], "max": sev_config["max"], "median": sev_config["median"]}


def get_notification_level(severity, cvss_score, finding_type):
    """Determine notification urgency level for a finding."""
    if severity == "CRITICAL" or cvss_score >= 9.0:
        return "immediate"
    if finding_type in NOTIFICATION_THRESHOLDS["immediate"]["conditions"]:
        return "immediate"
    if severity == "HIGH" or cvss_score >= 7.0:
        return "urgent"
    if finding_type in NOTIFICATION_THRESHOLDS["urgent"]["conditions"]:
        return "urgent"
    if severity == "MEDIUM" or cvss_score >= 4.0:
        return "standard"
    return "low_priority"


def validate_state_transition(current_state, new_state):
    """Check if a finding state transition is valid."""
    if current_state not in FINDING_STATES:
        return False
    allowed = FINDING_STATES[current_state]["allowed_transitions"]
    return new_state in allowed


def calculate_priority_score(finding):
    """Calculate a composite priority score for a finding dict."""
    cvss = finding.get("cvss_score", 0.0)
    severity = finding.get("severity", "INFO")
    finding_type = finding.get("finding_type", "")

    # Base CVSS component
    cvss_component = (cvss / 10.0) * SCORING_WEIGHTS["cvss_base"]

    # Exploitability estimate based on finding type
    exploitability_map = {
        "rce": 1.0, "sqli": 0.9, "auth_bypass": 0.95, "ssrf": 0.8,
        "xss_stored": 0.7, "idor": 0.85, "file_upload": 0.75,
        "deserialization": 0.8, "ssti": 0.75, "xxe": 0.7,
    }
    exploit_score = exploitability_map.get(finding_type, 0.5)
    exploit_component = exploit_score * SCORING_WEIGHTS["exploitability"]

    # Business impact from severity
    impact_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3, "INFO": 0.1}
    impact_score = impact_map.get(severity, 0.3)
    impact_component = impact_score * SCORING_WEIGHTS["business_impact"]

    # Bug bounty value estimate
    bounty_config = BOUNTY_ESTIMATES.get(severity, BOUNTY_ESTIMATES["INFO"])
    bounty_normalized = min(bounty_config["median"] / 20000.0, 1.0)
    bounty_component = bounty_normalized * SCORING_WEIGHTS["bug_bounty_value"]

    # Correlation bonus (0 if not part of a chain)
    correlation_ids = finding.get("correlation_ids", [])
    if len(correlation_ids) >= 4:
        corr_multiplier = 1.0
    elif len(correlation_ids) >= 2:
        corr_multiplier = 0.6
    elif len(correlation_ids) >= 1:
        corr_multiplier = 0.3
    else:
        corr_multiplier = 0.0
    corr_component = corr_multiplier * SCORING_WEIGHTS["correlation_bonus"]

    total = cvss_component + exploit_component + impact_component + bounty_component + corr_component
    return round(min(total * 10, 10.0), 2)
