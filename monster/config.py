"""
Monster - Configuration, patterns, and constants.

All configurable settings, regex patterns for secret detection, subdomain
takeover fingerprints, technology signatures, and API key management.
"""

import json
import os

# ---------------------------------------------------------------------------
# General Settings
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

RATE_LIMIT_DELAY = 1.0
MAX_THREADS = 10
TIMEOUT = 10

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 9090, 8000, 8888, 4443]

# ---------------------------------------------------------------------------
# Secret Detection Patterns
# ---------------------------------------------------------------------------

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Firebase Config": r"(?i)firebase[a-z0-9-]+\.firebaseio\.com",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token (ghp)": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Token (gho)": r"gho_[0-9a-zA-Z]{36}",
    "GitHub Token (ghu)": r"ghu_[0-9a-zA-Z]{36}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Private Key": r"-----BEGIN[A-Z ]*PRIVATE KEY-----",
    "Database Connection String": (
        r"(?i)(mongodb|postgres|mysql|redis|mssql)"
        r"://[^\s'\",;]+"
    ),
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[0-9a-zA-Z]{16,}['\"]?",
    "Generic Secret": r"(?i)(secret|secret[_-]?key)\s*[=:]\s*['\"]?[0-9a-zA-Z]{16,}['\"]?",
    "Generic Password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
    "Heroku API Key": r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
}

# ---------------------------------------------------------------------------
# Subdomain Takeover Fingerprints
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "cnames": ["github.io", "githubusercontent.com"],
        "fingerprints": ["There isn't a GitHub Pages site here"],
    },
    "Amazon S3": {
        "cnames": ["s3.amazonaws.com", "s3-website", ".s3."],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    "Heroku": {
        "cnames": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": [
            "No such app",
            "herokucdn.com/error-pages",
            "There's nothing here, yet.",
        ],
    },
    "Azure": {
        "cnames": [
            "azurewebsites.net",
            "cloudapp.net",
            "azurefd.net",
            "blob.core.windows.net",
            "azure-api.net",
            "trafficmanager.net",
        ],
        "fingerprints": ["404 Web Site not found"],
    },
    "Shopify": {
        "cnames": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable"],
    },
    "Fastly": {
        "cnames": ["fastly.net", "fastlylb.net"],
        "fingerprints": ["Fastly error: unknown domain"],
    },
    "Pantheon": {
        "cnames": ["pantheonsite.io"],
        "fingerprints": ["404 error unknown site"],
    },
    "Tumblr": {
        "cnames": ["domains.tumblr.com"],
        "fingerprints": ["There's nothing here.", "Whatever you were looking for"],
    },
    "Cargo Collective": {
        "cnames": ["cargocollective.com"],
        "fingerprints": ["404 Not Found"],
    },
    "Fly.io": {
        "cnames": ["fly.dev", "edgeapp.net", "shw.io"],
        "fingerprints": ["404 Not Found"],
    },
    "Surge.sh": {
        "cnames": ["surge.sh"],
        "fingerprints": ["project not found"],
    },
    "Wordpress.com": {
        "cnames": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
    },
    "Unbounce": {
        "cnames": ["unbouncepages.com"],
        "fingerprints": ["The requested URL was not found on this server"],
    },
    "HubSpot": {
        "cnames": ["sites.hubspot.net"],
        "fingerprints": ["Domain not found"],
    },
    "Ghost": {
        "cnames": ["ghost.io"],
        "fingerprints": ["Domain is not configured"],
    },
    "Bitbucket": {
        "cnames": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
    },
    "Zendesk": {
        "cnames": ["zendesk.com"],
        "fingerprints": ["Help Center Closed"],
    },
    "TeamWork": {
        "cnames": ["teamwork.com"],
        "fingerprints": ["Oops - We didn't find your site"],
    },
    "Readme.io": {
        "cnames": ["readme.io"],
        "fingerprints": ["Project doesnt exist"],
    },
    "Tilda": {
        "cnames": ["tilda.ws"],
        "fingerprints": ["Please renew your subscription"],
    },
    "Netlify": {
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
    },
    "Vercel": {
        "cnames": ["vercel.app", "now.sh"],
        "fingerprints": ["DEPLOYMENT_NOT_FOUND"],
    },
}

# ---------------------------------------------------------------------------
# Security Headers to Check
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
    "X-Permitted-Cross-Domain-Policies",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

# ---------------------------------------------------------------------------
# CORS Test Origins
# ---------------------------------------------------------------------------

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://{target}.evil.com",
    "https://evil-{target}",
]

# ---------------------------------------------------------------------------
# Technology Signatures
# ---------------------------------------------------------------------------

TECH_SIGNATURES = {
    "headers": {
        "Server": {
            "nginx": "Nginx",
            "apache": "Apache",
            "microsoft-iis": "IIS",
            "cloudflare": "Cloudflare",
            "litespeed": "LiteSpeed",
            "openresty": "OpenResty",
            "gunicorn": "Python/Gunicorn",
            "uvicorn": "Python/Uvicorn",
            "cowboy": "Erlang/Cowboy",
        },
        "X-Powered-By": {
            "express": "Node.js/Express",
            "php": "PHP",
            "asp.net": "ASP.NET",
            "next.js": "Next.js",
            "nuxt": "Nuxt.js",
            "django": "Django",
            "flask": "Flask",
            "ruby": "Ruby",
            "java": "Java",
        },
    },
    "cookies": {
        "JSESSIONID": "Java",
        "PHPSESSID": "PHP",
        "ASP.NET_SessionId": "ASP.NET",
        "__cfduid": "Cloudflare",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "rack.session": "Ruby/Rack",
        "connect.sid": "Node.js/Express",
        "_rails": "Ruby on Rails",
    },
    "body": {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "/wp-json/": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "react": "React",
        "angular": "Angular",
        "vue": "Vue.js",
        "__next": "Next.js",
        "__nuxt": "Nuxt.js",
        "gatsby": "Gatsby",
        "svelte": "Svelte",
        "ember": "Ember.js",
        "shopify": "Shopify",
        "squarespace": "Squarespace",
        "wix.com": "Wix",
    },
}

# ---------------------------------------------------------------------------
# Google Dork Templates
# ---------------------------------------------------------------------------

GOOGLE_DORK_TEMPLATES = [
    "site:{domain}",
    "site:{domain} inurl:admin",
    "site:{domain} inurl:login",
    "site:{domain} inurl:dashboard",
    "site:{domain} inurl:api",
    "site:{domain} filetype:sql",
    "site:{domain} filetype:env",
    "site:{domain} filetype:log",
    "site:{domain} filetype:xml",
    "site:{domain} filetype:json",
    "site:{domain} filetype:conf",
    "site:{domain} filetype:bak",
    "site:{domain} filetype:txt password",
    "site:{domain} inurl:wp-content",
    "site:{domain} inurl:wp-admin",
    "site:{domain} intitle:index.of",
    "site:{domain} ext:php intitle:phpinfo",
    "site:{domain} inurl:config",
    "site:{domain} inurl:setup",
    "site:{domain} inurl:install",
    "site:{domain} intext:sql syntax near",
    "site:{domain} intext:error in your SQL syntax",
    "site:{domain} inurl:redirect",
    "site:{domain} inurl:callback",
    "site:{domain} inurl:token",
]

# ---------------------------------------------------------------------------
# Shodan Query Templates
# ---------------------------------------------------------------------------

SHODAN_QUERY_TEMPLATES = [
    "hostname:{domain}",
    "ssl.cert.subject.cn:{domain}",
    "org:\"{org}\"",
    "http.title:\"{domain}\"",
    "ssl:{domain}",
]

# ---------------------------------------------------------------------------
# Redirect Parameters
# ---------------------------------------------------------------------------

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "next",
    "dest",
    "destination",
    "redir",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnTo",
    "return_to",
    "go",
    "goto",
    "target",
    "link",
    "out",
    "continue",
    "callback",
    "forward",
    "path",
    "data",
    "reference",
    "site",
    "view",
    "page",
]

# ---------------------------------------------------------------------------
# Information Disclosure Paths
# ---------------------------------------------------------------------------

INFO_DISCLOSURE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/phpinfo.php",
    "/info.php",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    "/config.json",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/debug/vars",
    "/actuator/env",
    "/actuator/health",
    "/trace",
    "/.htaccess",
    "/web.config",
    "/elmah.axd",
    "/WEB-INF/web.xml",
]

# ---------------------------------------------------------------------------
# API Key Management
# ---------------------------------------------------------------------------

_CONFIG_DIR = os.path.expanduser("~/.monster")
_CONFIG_FILE = os.path.join(_CONFIG_DIR, "config.json")


def load_api_keys():
    """
    Load API keys from environment variables or ~/.monster/config.json.

    Environment variables take precedence over config file values.

    Returns:
        dict: Mapping of service names to API key values.
    """
    keys = {
        "virustotal": None,
        "securitytrails": None,
        "shodan": None,
    }

    # Try loading from config file first
    if os.path.isfile(_CONFIG_FILE):
        try:
            with open(_CONFIG_FILE, "r") as f:
                data = json.load(f)
            keys["virustotal"] = data.get("virustotal_api_key")
            keys["securitytrails"] = data.get("securitytrails_api_key")
            keys["shodan"] = data.get("shodan_api_key")
        except (json.JSONDecodeError, IOError, OSError):
            pass

    # Environment variables override config file
    env_virustotal = os.environ.get("VIRUSTOTAL_API_KEY")
    if env_virustotal:
        keys["virustotal"] = env_virustotal

    env_securitytrails = os.environ.get("SECURITYTRAILS_API_KEY")
    if env_securitytrails:
        keys["securitytrails"] = env_securitytrails

    env_shodan = os.environ.get("SHODAN_API_KEY")
    if env_shodan:
        keys["shodan"] = env_shodan

    return keys
