"""
Super Monster v2 Configuration

Domain classification rules, scan methodology mappings, severity rules,
timing constants, color definitions, and verification thresholds.
"""

# =============================================================================
# DOMAIN TYPE CLASSIFICATION
# =============================================================================
# Maps domain categories to their identifying prefixes/keywords.
# Used by the classifier to determine what type of target a subdomain is,
# which directly controls which tests get run against it.

DOMAIN_TYPES = {
    "payment": {
        "description": "Payment processing and checkout systems",
        "prefixes": ["payment.", "pay.", "checkout.", "billing."],
        "keywords": ["payment", "pay", "checkout", "billing", "transaction", "invoice"],
        "risk_level": "critical",
    },
    "auth": {
        "description": "Authentication and identity management systems",
        "prefixes": ["auth.", "login.", "sso.", "id.", "member.", "mauth."],
        "keywords": ["auth", "login", "sso", "identity", "oauth", "session", "member"],
        "risk_level": "critical",
    },
    "api": {
        "description": "API endpoints and backend services",
        "prefixes": ["api.", "rs-open-api.", "cmapi.", "cart-front-api."],
        "keywords": ["api", "rest", "graphql", "gateway", "service", "backend"],
        "risk_level": "high",
    },
    "admin": {
        "description": "Administrative panels and management interfaces",
        "prefixes": ["admin.", "manage.", "dashboard.", "partners."],
        "keywords": ["admin", "manage", "dashboard", "panel", "console", "backoffice"],
        "risk_level": "critical",
    },
    "cdn": {
        "description": "Content delivery and static asset servers",
        "prefixes": ["cdn.", "static.", "assets.", "media.", "img."],
        "keywords": ["cdn", "static", "assets", "media", "images", "files"],
        "risk_level": "low",
    },
    "web": {
        "description": "Public-facing web applications and storefronts",
        "prefixes": ["www.", "m.", "shop.", "pages.", "review."],
        "keywords": ["www", "web", "shop", "store", "pages", "mobile", "review"],
        "risk_level": "medium",
    },
}


# =============================================================================
# SCAN TESTS PER DOMAIN TYPE
# =============================================================================
# Maps each domain type to the specific security tests that should be run.
# This ensures we focus effort on tests most likely to find real issues
# for each type of service, reducing noise and scan time.

SCAN_TESTS_PER_TYPE = {
    "payment": [
        "csp",
        "cookie_security",
        "clickjacking",
        "cors",
        "hsts",
        "server_disclosure",
    ],
    "auth": [
        "cors",
        "cookie_security",
        "hsts",
        # session_fixation removed: the check compares two unauthenticated GETs
        # and flags unchanged cookies, which is expected server behavior. Real
        # session fixation detection requires a login-state transition that
        # cannot be tested without credentials. Its 0.6 confidence also falls
        # below the 0.80 verification threshold, wasting scan time.
        "server_disclosure",
    ],
    "api": [
        "cors",
        "api_exposure",
        "hsts",
        "server_disclosure",
        "graphql",
    ],
    "admin": [
        "api_exposure",
        "default_creds_hints",
        "server_disclosure",
        "hsts",
    ],
    "cdn": [
        "subdomain_takeover",
        "cors",
    ],
    "web": [
        "open_redirect",
        "csp",
        "clickjacking",
        "cors",
        "server_disclosure",
    ],
}


# =============================================================================
# SEVERITY RULES
# =============================================================================
# Maps (finding_type, domain_type) combinations to severity levels.
# The same finding can have different severity depending on where it is found.
# For example, missing HSTS on a payment domain is critical, but on a CDN it
# might only be informational.

SEVERITY_RULES = {
    # CORS misconfigurations
    ("cors", "payment"): "critical",
    ("cors", "auth"): "critical",
    ("cors", "api"): "high",
    ("cors", "admin"): "high",
    ("cors", "cdn"): "low",
    ("cors", "web"): "medium",

    # Cookie security issues
    ("cookie_security", "payment"): "critical",
    ("cookie_security", "auth"): "critical",
    ("cookie_security", "api"): "high",
    ("cookie_security", "admin"): "high",
    ("cookie_security", "cdn"): "info",
    ("cookie_security", "web"): "medium",

    # Content Security Policy
    ("csp", "payment"): "high",
    ("csp", "auth"): "high",
    ("csp", "api"): "medium",
    ("csp", "admin"): "high",
    ("csp", "cdn"): "low",
    ("csp", "web"): "medium",

    # Clickjacking (X-Frame-Options)
    ("clickjacking", "payment"): "critical",
    ("clickjacking", "auth"): "high",
    ("clickjacking", "api"): "medium",
    ("clickjacking", "admin"): "high",
    ("clickjacking", "cdn"): "info",
    ("clickjacking", "web"): "medium",

    # HSTS
    ("hsts", "payment"): "critical",
    ("hsts", "auth"): "critical",
    ("hsts", "api"): "high",
    ("hsts", "admin"): "high",
    ("hsts", "cdn"): "low",
    ("hsts", "web"): "medium",

    # Server disclosure
    ("server_disclosure", "payment"): "medium",
    ("server_disclosure", "auth"): "medium",
    ("server_disclosure", "api"): "medium",
    ("server_disclosure", "admin"): "high",
    ("server_disclosure", "cdn"): "low",
    ("server_disclosure", "web"): "low",

    # Session fixation
    ("session_fixation", "payment"): "critical",
    ("session_fixation", "auth"): "critical",
    ("session_fixation", "api"): "high",
    ("session_fixation", "admin"): "high",
    ("session_fixation", "cdn"): "info",
    ("session_fixation", "web"): "medium",

    # API exposure
    ("api_exposure", "payment"): "critical",
    ("api_exposure", "auth"): "critical",
    ("api_exposure", "api"): "high",
    ("api_exposure", "admin"): "critical",
    ("api_exposure", "cdn"): "medium",
    ("api_exposure", "web"): "medium",

    # Default credentials hints
    ("default_creds_hints", "payment"): "critical",
    ("default_creds_hints", "auth"): "critical",
    ("default_creds_hints", "api"): "high",
    ("default_creds_hints", "admin"): "critical",
    ("default_creds_hints", "cdn"): "medium",
    ("default_creds_hints", "web"): "high",

    # GraphQL exposure
    ("graphql", "payment"): "high",
    ("graphql", "auth"): "high",
    ("graphql", "api"): "high",
    ("graphql", "admin"): "critical",
    ("graphql", "cdn"): "medium",
    ("graphql", "web"): "medium",

    # Subdomain takeover
    ("subdomain_takeover", "payment"): "critical",
    ("subdomain_takeover", "auth"): "critical",
    ("subdomain_takeover", "api"): "critical",
    ("subdomain_takeover", "admin"): "critical",
    ("subdomain_takeover", "cdn"): "high",
    ("subdomain_takeover", "web"): "critical",

    # Open redirect
    ("open_redirect", "payment"): "high",
    ("open_redirect", "auth"): "high",
    ("open_redirect", "api"): "medium",
    ("open_redirect", "admin"): "high",
    ("open_redirect", "cdn"): "low",
    ("open_redirect", "web"): "medium",
}


# =============================================================================
# TIMING AND RESOURCE CONSTANTS
# =============================================================================

# Request timeout in seconds
REQUEST_TIMEOUT = 10

# Delay between requests to the same host (rate limiting)
RATE_LIMIT_DELAY = 1.0

# Maximum concurrent threads for scanning
MAX_THREADS = 5

# Maximum total scan time in seconds (30 minutes)
MAX_SCAN_TIME = 1800

# Maximum retries for failed requests
MAX_RETRIES = 3

# Retry backoff factor (exponential)
RETRY_BACKOFF = 2.0

# Maximum number of subdomains to scan in a single session
MAX_SUBDOMAINS = 500

# Connection pool size per host
POOL_CONNECTIONS = 10

# DNS resolution timeout
DNS_TIMEOUT = 5


# =============================================================================
# VERIFICATION THRESHOLDS
# =============================================================================
# Minimum confidence levels required before a finding is reported as verified.
# Each test type has a threshold (0.0 to 1.0). Findings below this confidence
# are either discarded or marked as "needs manual review".

VERIFICATION_THRESHOLDS = {
    "cors": 0.85,
    "cookie_security": 0.80,
    "csp": 0.75,
    "clickjacking": 0.90,
    "hsts": 0.95,
    "server_disclosure": 0.70,
    "session_fixation": 0.80,
    "api_exposure": 0.75,
    "default_creds_hints": 0.60,
    "graphql": 0.85,
    "subdomain_takeover": 0.90,
    "open_redirect": 0.80,
}

# Minimum number of verification attempts before accepting a finding
MIN_VERIFICATION_ATTEMPTS = 2

# Maximum verification attempts before giving up
MAX_VERIFICATION_ATTEMPTS = 5

# Time to wait between verification attempts (seconds)
VERIFICATION_DELAY = 2.0


# =============================================================================
# OUTPUT AND REPORTING
# =============================================================================

# Default output directory
OUTPUT_DIR = "super_monster_output"

# Report formats
REPORT_FORMATS = ["json", "md", "html"]

# Maximum findings per report before summary mode
MAX_FINDINGS_DETAILED = 100

# Minimum severity to include in report by default
MIN_REPORT_SEVERITY = "low"

# Severity ordering (for sorting)
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# =============================================================================
# USER AGENT ROTATION
# =============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]


# =============================================================================
# COLORS CLASS
# =============================================================================

class Colors:
    """Terminal color constants using colorama with graceful fallback."""

    try:
        from colorama import Fore, Style, init
        init(autoreset=True)

        # Severity colors
        CRITICAL = Fore.RED + Style.BRIGHT
        HIGH = Fore.RED
        MEDIUM = Fore.YELLOW
        LOW = Fore.CYAN
        INFO = Fore.WHITE

        # Banner and UI colors
        BANNER = Fore.CYAN + Style.BRIGHT
        HEADER = Fore.GREEN + Style.BRIGHT
        SUBHEADER = Fore.GREEN
        SUCCESS = Fore.GREEN + Style.BRIGHT
        WARNING = Fore.YELLOW + Style.BRIGHT
        ERROR = Fore.RED + Style.BRIGHT
        PROGRESS = Fore.BLUE + Style.BRIGHT
        DIM = Style.DIM
        BOLD = Style.BRIGHT

        # Domain type colors
        PAYMENT = Fore.RED + Style.BRIGHT
        AUTH = Fore.MAGENTA + Style.BRIGHT
        API = Fore.BLUE + Style.BRIGHT
        ADMIN = Fore.RED
        CDN = Fore.CYAN
        WEB = Fore.GREEN

        # Reset
        RESET = Style.RESET_ALL

    except ImportError:
        # Fallback when colorama is not available
        CRITICAL = ""
        HIGH = ""
        MEDIUM = ""
        LOW = ""
        INFO = ""

        BANNER = ""
        HEADER = ""
        SUBHEADER = ""
        SUCCESS = ""
        WARNING = ""
        ERROR = ""
        PROGRESS = ""
        DIM = ""
        BOLD = ""

        PAYMENT = ""
        AUTH = ""
        API = ""
        ADMIN = ""
        CDN = ""
        WEB = ""

        RESET = ""

    @classmethod
    def severity_color(cls, severity):
        """Return the color string for a given severity level."""
        severity_map = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return severity_map.get(severity.lower(), cls.RESET)

    @classmethod
    def domain_color(cls, domain_type):
        """Return the color string for a given domain type."""
        domain_map = {
            "payment": cls.PAYMENT,
            "auth": cls.AUTH,
            "api": cls.API,
            "admin": cls.ADMIN,
            "cdn": cls.CDN,
            "web": cls.WEB,
        }
        return domain_map.get(domain_type.lower(), cls.RESET)


# =============================================================================
# BANNER
# =============================================================================

BANNER = f"""{Colors.BANNER}
  ____                         __  __                 _              ____  
 / ___| _   _ _ __   ___ _ __|  \\/  | ___  _ __  ___| |_ ___ _ __ |___ \\ 
 \\___ \\| | | | '_ \\ / _ \\ '__| |\\/| |/ _ \\| '_ \\/ __| __/ _ \\ '__|  __) |
  ___) | |_| | |_) |  __/ |  | |  | | (_) | | | \\__ \\ ||  __/ |   / __/ 
 |____/ \\__,_| .__/ \\___|_|  |_|  |_|\\___/|_| |_|___/\\__\\___|_|  |_____|
             |_|                                                          
{Colors.RESET}
{Colors.HEADER}  Elite Adaptive Bug Bounty Scanner v2.0.0{Colors.RESET}
{Colors.DIM}  Intelligent target classification | Inline verification | Zero false positives{Colors.RESET}
"""
