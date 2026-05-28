"""
analyzer.py — Analysis Engine for SENTINEL
Processes raw scan data into structured findings with:
- Severity ratings (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- OWASP mapping
- GDPR / PCI DSS / SEBI compliance mapping
- POC code generation helpers
- Business impact & remediation text
"""

import re
import json
import urllib.parse
from typing import Any
from colorama import Fore

try:
    from googlesearch import search as google_search
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
def _finding(title, severity, detail, owasp=None, remediation="",
              business_impact="", poc=None, compliance=None) -> dict:
    """Factory for a normalised finding dict."""
    return {
        "title"          : title,
        "severity"       : severity,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "detail"         : detail,
        "owasp"          : owasp or "",       # e.g. "A05:2021 – Security Misconfiguration"
        "remediation"    : remediation,
        "business_impact": business_impact,
        "poc"            : poc or "",
        "compliance"     : compliance or []   # e.g. ["GDPR Art.32", "PCI DSS 6.5.10"]
    }

# ──────────────────────────────────────────────────────────────────────────────
# Regex patterns for secret/API key detection
SECRET_PATTERNS = {
    "AWS Access Key"          : r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key"          : r"(?i)aws_secret[_\-]?access_key\s*=\s*['\"]?([A-Za-z0-9/+]{40})",
    "Google API Key"          : r"AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth"            : r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GitHub Token"            : r"ghp_[A-Za-z0-9]{36}",
    "Generic API Key"         : r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})",
    "Bearer Token"            : r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
    "Basic Auth in URL"       : r"https?://[^:]+:[^@]+@",
    "Private Key Header"      : r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token"               : r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
    "Stripe Secret Key"       : r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key"  : r"pk_live_[0-9a-zA-Z]{24}",
    "Slack Token"             : r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "Mailchimp API Key"       : r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Twilio Account SID"      : r"AC[a-z0-9]{32}",
    "Firebase URL"            : r"https://[a-z0-9-]+\.firebaseio\.com",
    "MongoDB Connection"      : r"mongodb(\+srv)?://[^:]+:[^@]+@",
    "Database Password"       : r"(?i)(db_pass|database_password|db_password)\s*[=:]\s*['\"]?.{6,}",
    "SendGrid API Key"        : r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "HubSpot API Key"         : r"(?i)hubspot.*api[_-]?key\s*[=:]\s*['\"]?[a-z0-9-]{36}",
    "Razorpay Key"            : r"rzp_(live|test)_[A-Za-z0-9]{14}",
    "PayPal Client ID"        : r"(?i)paypal.*client[_-]?id\s*[=:]\s*['\"]?[A-Za-z0-9-]{20,}",
    "Internal IP"             : r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    "Admin Path Leak"         : r"(?i)(href|src|action)\s*=\s*['\"]/?(/admin|/panel|/dashboard|/manage|/backend)['\"]",
}

ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin/login",
    "/admin/dashboard", "/panel", "/cpanel", "/dashboard",
    "/manage", "/management", "/backend", "/wp-admin",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin",
    "/phpmyadmin/", "/adminer", "/adminer.php",
    "/manager/html", "/joomla/administrator",
    "/user/login", "/moderator", "/superadmin",
    "/controlpanel", "/webadmin", "/siteadmin",
    "/admin1", "/admin2", "/portal/admin",
]

# ──────────────────────────────────────────────────────────────────────────────
class Analyzer:

    def __init__(self, url, headers, ssl, tech, dns, cookies,
                 ports, forms, graphql, skip_dork=False):
        self.url        = url
        self.headers    = headers
        self.ssl        = ssl
        self.tech       = tech
        self.dns        = dns
        self.cookies    = cookies
        self.ports      = ports
        self.forms      = forms
        self.graphql    = graphql
        self.skip_dork  = skip_dork
        self.host       = urllib.parse.urlparse(url).hostname or ""
        self._body_cache: str | None = None

    # ── helper ────────────────────────────────────────────────────────────────
    def _body(self) -> str:
        if self._body_cache is None:
            import requests, warnings
            warnings.filterwarnings("ignore")
            try:
                r = requests.get(self.url, timeout=15, verify=False,
                                 headers={"User-Agent": "Mozilla/5.0"})
                self._body_cache = r.text
            except Exception:
                self._body_cache = ""
        return self._body_cache

    # ── A. Security Headers ───────────────────────────────────────────────────
    def analyze_headers(self) -> list:
        findings = []
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}

        # Security header checklist
        REQUIRED = {
            "strict-transport-security": {
                "sev": "HIGH",
                "title": "Missing HSTS Header",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "impact": "Allows downgrade attacks; user traffic can be intercepted over HTTP.",
                "compliance": ["PCI DSS 4.2.1", "GDPR Art.32"]
            },
            "x-frame-options": {
                "sev": "HIGH",
                "title": "Missing X-Frame-Options Header",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors 'none'",
                "impact": "Site is vulnerable to Clickjacking attacks.",
                "compliance": ["OWASP A05", "PCI DSS 6.5.9"]
            },
            "x-content-type-options": {
                "sev": "MEDIUM",
                "title": "Missing X-Content-Type-Options Header",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add: X-Content-Type-Options: nosniff",
                "impact": "Browsers may MIME-sniff and execute non-script content as scripts.",
                "compliance": ["OWASP A05"]
            },
            "content-security-policy": {
                "sev": "HIGH",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "owasp": "A03:2021 – Injection",
                "remediation": "Implement a strict CSP: Content-Security-Policy: default-src 'self'",
                "impact": "No protection against XSS; attackers can inject arbitrary scripts.",
                "compliance": ["GDPR Art.32", "PCI DSS 6.5.7"]
            },
            "referrer-policy": {
                "sev": "MEDIUM",
                "title": "Missing Referrer-Policy Header",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
                "impact": "Sensitive URLs may be leaked to third-party sites via Referer header.",
                "compliance": ["GDPR Art.5"]
            },
            "permissions-policy": {
                "sev": "LOW",
                "title": "Missing Permissions-Policy Header",
                "owasp": "A05:2021 – Security Misconfiguration",
                "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                "impact": "Browser features (camera, mic, GPS) may be accessed without restriction.",
                "compliance": ["GDPR Art.25"]
            },
            "x-xss-protection": {
                "sev": "LOW",
                "title": "Missing X-XSS-Protection Header (Legacy)",
                "owasp": "A03:2021 – Injection",
                "remediation": "Add: X-XSS-Protection: 1; mode=block (also deploy CSP)",
                "impact": "Legacy XSS filter disabled in older browsers.",
                "compliance": ["PCI DSS 6.5.7"]
            },
            "cache-control": {
                "sev": "MEDIUM",
                "title": "Missing or Weak Cache-Control Header",
                "owasp": "A02:2021 – Cryptographic Failures",
                "remediation": "Add: Cache-Control: no-store for sensitive pages",
                "impact": "Sensitive data may be cached by browsers or proxies.",
                "compliance": ["PCI DSS 3.3", "GDPR Art.32"]
            }
        }

        for header_name, meta in REQUIRED.items():
            if header_name not in hdrs:
                findings.append(_finding(
                    title           = meta["title"],
                    severity        = meta["sev"],
                    detail          = f"Header '{header_name}' is absent from HTTP response.",
                    owasp           = meta["owasp"],
                    remediation     = meta["remediation"],
                    business_impact = meta["impact"],
                    compliance      = meta["compliance"]
                ))

        # Information Disclosure
        info_headers = ["server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "x-generator"]
        for h in info_headers:
            if h in hdrs and hdrs[h]:
                findings.append(_finding(
                    title       = f"Server Information Disclosure via '{h}' header",
                    severity    = "MEDIUM",
                    detail      = f"'{h}: {hdrs[h]}' reveals server technology/version.",
                    owasp       = "A05:2021 – Security Misconfiguration",
                    remediation = f"Remove or mask the '{h}' response header from server config.",
                    business_impact = "Attackers can fingerprint server version and target known CVEs.",
                    compliance  = ["OWASP A05", "PCI DSS 6.5"]
                ))

        return findings

    # ── B. CSP Analysis ───────────────────────────────────────────────────────
    def analyze_csp(self) -> list:
        findings = []
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}
        csp  = hdrs.get("content-security-policy", "")

        if not csp:
            findings.append(_finding(
                "No CSP Defined", "HIGH",
                "Content-Security-Policy header is completely absent.",
                "A03:2021 – Injection",
                "Implement: Content-Security-Policy: default-src 'self'; script-src 'self'",
                "Full XSS exploitation possible; external scripts can be injected.",
                compliance=["PCI DSS 6.5.7", "GDPR Art.32"]
            ))
            return findings

        # Check unsafe directives
        UNSAFE = {
            "unsafe-inline"     : ("HIGH",   "Allows inline script/style execution — XSS risk."),
            "unsafe-eval"       : ("HIGH",   "Allows eval() — code injection risk."),
            "unsafe-hashes"     : ("MEDIUM", "Allows hashed inline scripts — partially unsafe."),
            "*"                 : ("HIGH",   "Wildcard (*) in CSP allows any source — defeats CSP."),
            "http:"             : ("MEDIUM", "CSP allows HTTP sources — man-in-the-middle risk."),
            "data:"             : ("MEDIUM", "data: URI in script-src allows XSS via data URIs."),
        }
        for keyword, (sev, detail) in UNSAFE.items():
            if keyword in csp:
                findings.append(_finding(
                    f"Unsafe CSP Directive: '{keyword}'", sev, detail,
                    "A03:2021 – Injection",
                    f"Remove '{keyword}' from CSP; use nonces or hashes instead.",
                    "Attackers can bypass CSP to inject and execute malicious scripts.",
                    compliance=["PCI DSS 6.5.7"]
                ))

        # Missing directives
        IMPORTANT_DIRECTIVES = ["default-src", "script-src", "object-src",
                                 "frame-ancestors", "base-uri", "form-action"]
        for directive in IMPORTANT_DIRECTIVES:
            if directive not in csp:
                findings.append(_finding(
                    f"CSP Missing Directive: '{directive}'", "MEDIUM",
                    f"'{directive}' is not defined in CSP.",
                    "A05:2021 – Security Misconfiguration",
                    f"Add '{directive}' to your CSP for complete protection.",
                    f"Without '{directive}', browsers fall back to defaults which may be permissive.",
                    compliance=["OWASP A05"]
                ))

        return findings

    # ── C. OWASP Top 10 ───────────────────────────────────────────────────────
    def analyze_owasp(self) -> list:
        findings = []
        body = self._body()
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}

        # A01 – Broken Access Control
        for port_info in self.ports.get("open_ports", []):
            port = port_info["port"]
            svc  = port_info.get("service", "")
            if port in [3306, 5432, 27017, 6379, 1433, 5900]:
                findings.append(_finding(
                    f"Database/Management Port {port} ({svc}) Open to Internet",
                    "CRITICAL",
                    f"Port {port} ({svc}) is publicly reachable — direct DB access possible.",
                    "A01:2021 – Broken Access Control",
                    f"Restrict port {port} to internal/VPN access using firewall rules.",
                    "Direct database access allows data exfiltration, ransomware, and full compromise.",
                    compliance=["PCI DSS 1.3", "GDPR Art.32", "SEBI CSCRF"]
                ))

        # A02 – Cryptographic Failures
        if not self.ssl.get("enabled"):
            findings.append(_finding(
                "No HTTPS / TLS Encryption", "CRITICAL",
                "Site is served over plain HTTP — all data in transit is unencrypted.",
                "A02:2021 – Cryptographic Failures",
                "Migrate to HTTPS using a valid TLS 1.2+ certificate.",
                "User credentials, session tokens, and PII transmitted in plaintext.",
                compliance=["PCI DSS 4.2.1", "GDPR Art.32", "SEBI CSCRF"]
            ))

        if self.ssl.get("cert_expired"):
            findings.append(_finding(
                "SSL Certificate Expired", "CRITICAL",
                f"Certificate expired on: {self.ssl.get('cert_expiry')}",
                "A02:2021 – Cryptographic Failures",
                "Renew the SSL certificate immediately.",
                "Browser warnings deter users; expired cert may enable MITM attacks.",
                compliance=["PCI DSS 4.2.1", "GDPR Art.32"]
            ))

        if self.ssl.get("cert_self_signed"):
            findings.append(_finding(
                "Self-Signed SSL Certificate", "HIGH",
                "Certificate is self-signed — not trusted by browsers.",
                "A02:2021 – Cryptographic Failures",
                "Replace with a CA-signed certificate (Let's Encrypt is free).",
                "Users see security warnings; susceptible to MITM attacks.",
                compliance=["PCI DSS 4.2.1"]
            ))

        # A03 – Injection (GraphQL introspection)
        if self.graphql.get("graphql_introspection"):
            findings.append(_finding(
                "GraphQL Introspection Enabled (Production)",
                "HIGH",
                "GraphQL introspection is enabled — full schema exposed to attackers.",
                "A03:2021 – Injection",
                "Disable introspection in production; use query depth/complexity limits.",
                "Attackers can enumerate all types, queries, mutations and craft targeted attacks.",
                poc='curl -s -X POST -H "Content-Type: application/json" '
                    f'-d \'{{"query":"{{__schema{{types{{name}}}}}}"}} \' {self.graphql.get("graphql_endpoints", [self.url])[0]}',
                compliance=["OWASP A03"]
            ))

        # A05 – Security Misconfiguration
        if self.tech.get("raw_builtwith", {}).get("cms"):
            cms = self.tech.get("cms", "")
            if "wordpress" in cms.lower():
                findings.append(_finding(
                    "WordPress Detected – Version Exposure Risk", "MEDIUM",
                    f"WordPress CMS detected: {cms}. Versions are fingerprinted via meta tags.",
                    "A05:2021 – Security Misconfiguration",
                    "Hide WP version; keep core + plugins updated; use a WAF.",
                    "Outdated WordPress is one of the most commonly exploited platforms.",
                    poc=f"curl {self.url}/wp-json/wp/v2/users/ | jq '.[].name'",
                    compliance=["PCI DSS 6.3", "SEBI CSCRF"]
                ))

        # A06 – Vulnerable & Outdated Components
        for js_lib in self.tech.get("js_libraries", []):
            if any(old in js_lib.lower() for old in ["jquery/1.", "jquery/2.", "bootstrap/3."]):
                findings.append(_finding(
                    f"Outdated JS Library Detected: {js_lib}", "MEDIUM",
                    f"'{js_lib}' is an outdated version with known XSS/prototype-pollution CVEs.",
                    "A06:2021 – Vulnerable and Outdated Components",
                    "Upgrade to the latest stable version.",
                    "Known CVEs in old JS libraries are trivially exploitable for XSS.",
                    compliance=["PCI DSS 6.3.3"]
                ))

        # A07 – Identification & Authentication
        for form in self.forms.get("forms", []):
            if form.get("is_login"):
                if not form.get("has_csrf"):
                    findings.append(_finding(
                        "Login Form Missing CSRF Token", "HIGH",
                        f"Login form at {self.url} has no visible CSRF token field.",
                        "A07:2021 – Identification and Authentication Failures",
                        "Implement CSRF tokens (Synchronizer Token Pattern) on all state-changing forms.",
                        "Attackers can perform Cross-Site Request Forgery to log in on behalf of users.",
                        compliance=["OWASP A07", "PCI DSS 6.5.9"]
                    ))
                if form.get("method") == "GET":
                    findings.append(_finding(
                        "Login Form Uses GET Method", "HIGH",
                        "Credentials submitted via GET appear in server logs and browser history.",
                        "A07:2021 – Identification and Authentication Failures",
                        "Change form method to POST and use HTTPS.",
                        "Credentials leak to access logs, proxies, and browser history.",
                        compliance=["OWASP A07", "PCI DSS 6.5.10"]
                    ))

        # Autocomplete on password fields
        for form in self.forms.get("forms", []):
            if form.get("is_login") and form.get("autocomplete", "on") != "off":
                findings.append(_finding(
                    "Password Field Autocomplete Enabled", "LOW",
                    "Login form does not disable autocomplete — browsers may cache credentials.",
                    "A07:2021 – Identification and Authentication Failures",
                    "Add autocomplete='off' to sensitive forms.",
                    "Shared/public devices may cache and reveal stored credentials.",
                    compliance=["PCI DSS 8.2.1"]
                ))

        # A09 – Security Logging & Monitoring (check error pages)
        if "debug" in body.lower() or "traceback" in body.lower() or \
           "exception" in body.lower() or "stack trace" in body.lower():
            findings.append(_finding(
                "Application Debug/Error Information Exposed", "HIGH",
                "Debug information, stack traces, or error messages exposed in page response.",
                "A09:2021 – Security Logging and Monitoring Failures",
                "Disable debug mode in production; implement custom error pages.",
                "Internal paths, DB structure, and code logic revealed to attackers.",
                compliance=["OWASP A09", "PCI DSS 6.5"]
            ))

        return findings

    # ── D. Clickjacking ───────────────────────────────────────────────────────
    def analyze_clickjacking(self) -> list:
        findings = []
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}
        xfo  = hdrs.get("x-frame-options", "")
        csp  = hdrs.get("content-security-policy", "")

        no_xfo             = not xfo
        no_csp_frame       = "frame-ancestors" not in csp
        clickjack_possible = no_xfo and no_csp_frame

        if clickjack_possible:
            poc_html = f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking POC – SENTINEL</title></head>
<body style="margin:0;padding:0;">
  <h2 style="color:red;">⚠ Clickjacking POC – {self.url}</h2>
  <p>The iframe below loads the target site. In a real attack, a deceptive overlay would sit on top.</p>
  <iframe src="{self.url}"
          style="width:100%;height:700px;border:3px solid red;opacity:0.8;"
          title="Clickjacking POC">
  </iframe>
  <p style="color:gray;font-size:12px;">
    POC generated by SENTINEL | For authorized reporting only.
  </p>
</body>
</html>"""
            findings.append(_finding(
                title       = "Clickjacking Vulnerability – Site Frameable by External Domains",
                severity    = "HIGH",
                detail      = (
                    "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' is set. "
                    "The site can be embedded in a malicious iframe, enabling clickjacking attacks."
                ),
                owasp       = "A05:2021 – Security Misconfiguration",
                remediation = (
                    "Option 1 (Recommended): Add CSP header:\n"
                    "  Content-Security-Policy: frame-ancestors 'none';\n"
                    "Option 2: Add header:\n"
                    "  X-Frame-Options: DENY"
                ),
                business_impact = (
                    "Clickjacking can trick users into performing unintended actions "
                    "(fund transfers, account changes) by overlaying invisible iframes "
                    "on seemingly legitimate content. High risk for fintech / banking portals."
                ),
                poc         = poc_html,
                compliance  = ["OWASP A05", "PCI DSS 6.5.9", "SEBI CSCRF 2.0"]
            ))
        elif xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(_finding(
                "Weak X-Frame-Options Value",
                "MEDIUM",
                f"X-Frame-Options is set to '{xfo}' — only DENY or SAMEORIGIN are secure.",
                "A05:2021 – Security Misconfiguration",
                "Set X-Frame-Options: DENY  or use CSP frame-ancestors 'none'.",
                "Partial clickjacking protection; some embedding scenarios may still work.",
                compliance=["OWASP A05"]
            ))
        else:
            findings.append(_finding(
                "Clickjacking Protection Present", "INFO",
                f"X-Frame-Options: '{xfo}' | CSP frame-ancestors: {'present' if not no_csp_frame else 'absent'}",
                compliance=["OWASP A05"]
            ))

        return findings

    # ── E. GDPR ───────────────────────────────────────────────────────────────
    def analyze_gdpr(self) -> list:
        findings = []
        body = self._body().lower()
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}

        # Cookie consent
        consent_indicators = ["cookie-consent", "cookieconsent", "gdpr", "consent",
                               "cookie policy", "cookie notice", "we use cookies"]
        has_consent = any(ind in body for ind in consent_indicators)
        if not has_consent:
            findings.append(_finding(
                "No Cookie Consent Banner Detected",
                "HIGH",
                "No GDPR-compliant cookie consent mechanism found on the page.",
                "A05:2021 – Security Misconfiguration",
                "Implement a cookie consent solution (e.g., OneTrust, CookieBot, custom).",
                "Non-compliant with GDPR Article 7 and ePrivacy Directive — regulatory fines up to €20M or 4% of global turnover.",
                compliance=["GDPR Art.7", "GDPR Art.13", "ePrivacy Directive"]
            ))

        # Privacy policy
        privacy_indicators = ["privacy policy", "privacy-policy", "data protection",
                               "datenschutz", "politique de confidentialité"]
        has_privacy = any(ind in body for ind in privacy_indicators)
        if not has_privacy:
            findings.append(_finding(
                "No Privacy Policy Link Found",
                "HIGH",
                "No link to a Privacy Policy page detected on the homepage.",
                "A05:2021 – Security Misconfiguration",
                "Publish a GDPR-compliant Privacy Policy and link it from every page.",
                "Breach of GDPR Art.13/14 disclosure obligations; subject to regulatory action.",
                compliance=["GDPR Art.13", "GDPR Art.14"]
            ))

        # Third-party trackers
        trackers = {
            "Google Analytics"   : ["google-analytics.com", "googletagmanager.com", "gtag("],
            "Facebook Pixel"     : ["connect.facebook.net", "fbq("],
            "HotJar"             : ["hotjar.com"],
            "FullStory"          : ["fullstory.com"],
            "Intercom"           : ["intercom.io"],
            "Mixpanel"           : ["mixpanel.com"],
            "Segment"            : ["segment.com", "segment.io"],
            "LinkedIn Insight"   : ["linkedin.com/analytics"],
            "Twitter/X Pixel"    : ["analytics.twitter.com"],
        }
        found_trackers = []
        for name, patterns in trackers.items():
            if any(p in body for p in patterns):
                found_trackers.append(name)

        if found_trackers:
            findings.append(_finding(
                f"Third-Party Tracking Scripts Detected: {', '.join(found_trackers)}",
                "MEDIUM",
                f"The following trackers were found: {', '.join(found_trackers)}. Under GDPR, these require explicit user consent before loading.",
                "A05:2021 – Security Misconfiguration",
                "Load tracking scripts only after obtaining explicit, informed user consent (opt-in, not opt-out).",
                "Illegal data transfer to third parties without consent — GDPR Art.6, Art.44 violations.",
                compliance=["GDPR Art.6", "GDPR Art.44", "ePrivacy"]
            ))

        # HTTPS for PII
        if not self.ssl.get("enabled"):
            findings.append(_finding(
                "PII Transmitted Without Encryption (No HTTPS)",
                "CRITICAL",
                "Personal data may be transmitted in plaintext over HTTP.",
                "A02:2021 – Cryptographic Failures",
                "Implement HTTPS/TLS 1.2+ for all pages handling personal data.",
                "Direct violation of GDPR Art.32 requirement for appropriate technical measures.",
                compliance=["GDPR Art.32", "GDPR Art.5(1)(f)"]
            ))

        return findings

    # ── F. PCI DSS ────────────────────────────────────────────────────────────
    def analyze_pci_dss(self) -> list:
        findings = []
        body = self._body().lower()

        # Payment form detection
        payment_indicators = ["card number", "cardnumber", "cvv", "expiry",
                               "expiration", "billing", "credit card", "debit card",
                               "payment", "checkout", "razorpay", "stripe", "payu",
                               "ccavenue", "paypal", "visa", "mastercard"]
        has_payment = any(ind in body for ind in payment_indicators)

        if has_payment:
            if not self.ssl.get("enabled"):
                findings.append(_finding(
                    "Payment Page Served Over HTTP (PCI DSS Violation)",
                    "CRITICAL",
                    "Payment/card data form detected on non-HTTPS page.",
                    "A02:2021 – Cryptographic Failures",
                    "All cardholder data environments must use TLS 1.2 or higher.",
                    "Automatic PCI DSS non-compliance; card data can be intercepted.",
                    compliance=["PCI DSS 4.2.1", "PCI DSS 6.4.1"]
                ))
            if self.ssl.get("version") in ("TLSv1", "TLSv1.1"):
                findings.append(_finding(
                    "Payment Page Uses Deprecated TLS Version",
                    "CRITICAL",
                    f"Payment page uses {self.ssl.get('version')} which is deprecated by PCI DSS v4.",
                    "A02:2021 – Cryptographic Failures",
                    "Upgrade to TLS 1.2 minimum (TLS 1.3 recommended).",
                    "Direct PCI DSS v4 violation; card data in transit at risk.",
                    compliance=["PCI DSS 4.2.1"]
                ))

            # Check for open ports near card systems
            for port_info in self.ports.get("open_ports", []):
                if port_info["port"] in [23, 21]:
                    findings.append(_finding(
                        f"Insecure Protocol Port {port_info['port']} Open (PCI DSS)",
                        "CRITICAL",
                        f"Port {port_info['port']} ({port_info.get('service')}) — Telnet/FTP are forbidden in cardholder data environments.",
                        "A05:2021 – Security Misconfiguration",
                        f"Disable port {port_info['port']}; use SSH/SFTP instead.",
                        "PCI DSS explicitly prohibits insecure protocols in CDE.",
                        compliance=["PCI DSS 2.2.7", "PCI DSS 4.2.1"]
                    ))

        # HSTS for PCI
        hdrs = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}
        if "strict-transport-security" not in hdrs:
            findings.append(_finding(
                "HSTS Missing – PCI DSS Requirement",
                "HIGH",
                "HSTS header absent; TLS downgrade attacks possible.",
                "A05:2021 – Security Misconfiguration",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "PCI DSS 4.2.1 requires strong TLS; HSTS prevents downgrade.",
                compliance=["PCI DSS 4.2.1", "PCI DSS 6.4.1"]
            ))

        return findings

    # ── G. Leak Detection ─────────────────────────────────────────────────────
    def analyze_leaks(self) -> list:
        findings = []
        body = self._body()
        url  = self.url

        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                # Sanitize: mask the actual secret value in finding
                masked = []
                for m in matches[:3]:  # max 3 samples
                    s = m if isinstance(m, str) else m[0] if m else ""
                    masked.append(s[:6] + "****" + s[-4:] if len(s) > 12 else "****")
                findings.append(_finding(
                    title       = f"Sensitive Data Leak: {secret_name}",
                    severity    = "CRITICAL",
                    detail      = f"Pattern matched in page source. Sample (masked): {', '.join(masked)}",
                    owasp       = "A02:2021 – Cryptographic Failures",
                    remediation = (
                        f"1. Immediately revoke/rotate any leaked {secret_name}.\n"
                        "2. Move secrets to environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager).\n"
                        "3. Audit git history for committed secrets (use git-secrets, truffleHog)."
                    ),
                    business_impact = (
                        f"Leaked {secret_name} allows attackers to directly access backend services, "
                        "cloud infrastructure, payment gateways, or communications APIs — leading to "
                        "data breach, financial loss, and regulatory penalties."
                    ),
                    poc = f"View page source at {url} and search for pattern: {pattern[:50]}...",
                    compliance = ["PCI DSS 3.3", "GDPR Art.32", "SEBI CSCRF", "OWASP A02"]
                ))

        # Check JavaScript files for leaks
        import requests as req
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body, "lxml")
            js_urls = []
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("/"):
                    src = self.url + src
                elif not src.startswith("http"):
                    src = self.url + "/" + src
                js_urls.append(src)

            for js_url in js_urls[:10]:  # limit to 10 JS files
                try:
                    r = req.get(js_url, timeout=10, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"})
                    js_body = r.text
                    for secret_name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, js_body)
                        if matches:
                            masked_v = "****"
                            findings.append(_finding(
                                title    = f"Secret Leaked in JS File: {secret_name}",
                                severity = "CRITICAL",
                                detail   = f"Found in JS file: {js_url}",
                                owasp    = "A02:2021 – Cryptographic Failures",
                                remediation = "Never embed secrets in client-side JS. Use server-side proxies.",
                                business_impact = "Any visitor can extract the API key from the JS bundle.",
                                poc = f"curl {js_url} | grep -oP '{pattern[:40]}...'",
                                compliance = ["PCI DSS 3.3", "GDPR Art.32", "OWASP A02"]
                            ))
                            break
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    # ── H. Admin Panels ───────────────────────────────────────────────────────
    def analyze_admin_panels(self) -> list:
        findings = []
        import requests as req

        for path in ADMIN_PATHS:
            try:
                r = req.get(
                    self.url + path,
                    timeout=8, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=True
                )
                if r.status_code == 200:
                    findings.append(_finding(
                        title       = f"Exposed Admin/Panel Page: {path}",
                        severity    = "HIGH",
                        detail      = f"HTTP 200 received for {self.url + path} — admin interface accessible.",
                        owasp       = "A01:2021 – Broken Access Control",
                        remediation = (
                            "1. Restrict admin paths to internal IPs / VPN only.\n"
                            "2. Implement MFA on all admin interfaces.\n"
                            "3. Rename admin paths to non-guessable routes.\n"
                            "4. Add IP allowlisting."
                        ),
                        business_impact = (
                            "Exposed admin panels allow brute-force, credential stuffing, and "
                            "unauthorized access to backend management — potential for complete site compromise."
                        ),
                        poc = f"curl -I {self.url + path}",
                        compliance  = ["OWASP A01", "PCI DSS 7.2", "SEBI CSCRF"]
                    ))
                elif r.status_code == 401:
                    findings.append(_finding(
                        title    = f"Admin Panel Found (Auth Protected): {path}",
                        severity = "MEDIUM",
                        detail   = f"HTTP 401 at {self.url + path} — admin interface exists but requires authentication.",
                        owasp    = "A01:2021 – Broken Access Control",
                        remediation = "Ensure MFA is enforced; restrict to VPN/internal networks.",
                        business_impact = "Publicly reachable login interface subject to brute-force.",
                        poc = f"curl -I {self.url + path}",
                        compliance = ["OWASP A01", "PCI DSS 7.2"]
                    ))
            except Exception:
                pass

        return findings

    # ── I. External Content & Scraping Protection ─────────────────────────────
    def analyze_external_content(self) -> list:
        findings = []
        body     = self._body()
        hdrs     = {k.lower(): v for k, v in self.headers.get("headers", {}).items()}

        # External script domains
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "lxml")
        external_scripts = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src.startswith("http") and self.host not in src:
                external_scripts.append(src)

        if external_scripts:
            without_sri = [s for s in external_scripts
                           if not script.get("integrity")]
            if without_sri:
                findings.append(_finding(
                    "External Scripts Loaded Without Subresource Integrity (SRI)",
                    "MEDIUM",
                    f"{len(without_sri)} external script(s) loaded without SRI check: {', '.join(without_sri[:3])}",
                    "A08:2021 – Software and Data Integrity Failures",
                    "Add integrity= and crossorigin=anonymous attributes to all external script tags.",
                    "Compromised CDN can push malicious JS to all users of your site.",
                    compliance=["OWASP A08", "PCI DSS 6.4.3"]
                ))

        # Scraping protection
        scraping_indicators = ["robots.txt", "x-robots-tag", "noindex", "recaptcha",
                                "hcaptcha", "cloudflare", "cf-ray"]
        body_lower = body.lower()
        hdr_str    = " ".join(hdrs.values()).lower()
        has_protection = any(
            ind in body_lower or ind in hdr_str for ind in scraping_indicators
        )
        if not has_protection:
            findings.append(_finding(
                "No Data Scraping Protection Detected",
                "LOW",
                "No rate-limiting, CAPTCHA, or bot-detection mechanism found.",
                "A05:2021 – Security Misconfiguration",
                "Implement rate limiting (nginx limit_req), CAPTCHA on forms, and bot-detection (Cloudflare Bot Management).",
                "Competitors or malicious actors can scrape proprietary data, PII lists, or pricing.",
                compliance=["GDPR Art.32"]
            ))

        # CORS check
        cors_hdr = hdrs.get("access-control-allow-origin", "")
        if cors_hdr == "*":
            findings.append(_finding(
                "Overly Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                "HIGH",
                "CORS wildcard (*) allows any domain to make cross-origin requests.",
                "A05:2021 – Security Misconfiguration",
                "Restrict CORS to specific trusted origins; never use * for authenticated endpoints.",
                "Cross-origin attackers can read API responses and steal user data.",
                poc=f'curl -H "Origin: https://evil.com" -I {self.url}',
                compliance=["OWASP A05", "PCI DSS 6.5"]
            ))

        return findings

    # ── J. Google Dorking ─────────────────────────────────────────────────────
    def analyze_google_dork(self) -> list:
        findings = []
        if self.skip_dork:
            findings.append(_finding(
                "Google Dorking Skipped", "INFO",
                "Skipped via --no-dork flag."
            ))
            return findings

        if not GOOGLE_AVAILABLE:
            findings.append(_finding(
                "Google Dorking Module Not Available", "INFO",
                "Install 'googlesearch-python' to enable OSINT dorking."
            ))
            return findings

        domain = self.host
        dorks = {
            "Exposed Login Pages"      : f'site:{domain} inurl:login',
            "Exposed Config Files"     : f'site:{domain} ext:env | ext:config | ext:yml | ext:json "password"',
            "Exposed Admin Panels"     : f'site:{domain} inurl:admin | inurl:panel | inurl:dashboard',
            "Indexed Backup Files"     : f'site:{domain} ext:bak | ext:old | ext:backup | ext:sql',
            "API Key Exposure"         : f'site:{domain} "api_key" | "apikey" | "access_token"',
            "Database Dumps"           : f'site:{domain} ext:sql | ext:db | ext:dump',
            "Error Pages with Stack"   : f'site:{domain} "stack trace" | "syntax error" | "unhandled exception"',
            "Exposed Git Repos"        : f'site:{domain} inurl:.git',
            "Open Directories"         : f'site:{domain} intitle:"Index of"',
            "Cloud Buckets"            : f'site:{domain} site:s3.amazonaws.com | site:storage.googleapis.com',
        }

        for dork_name, query in dorks.items():
            try:
                results = list(google_search(query, num_results=3, sleep_interval=2))
                if results:
                    findings.append(_finding(
                        title       = f"Google Dork Hit: {dork_name}",
                        severity    = "HIGH",
                        detail      = f"Query: {query}\nResults found: {len(results)}\nURLs: {chr(10).join(results[:3])}",
                        owasp       = "A05:2021 – Security Misconfiguration",
                        remediation = (
                            "1. Use robots.txt to disallow sensitive paths.\n"
                            "2. Request URL removal via Google Search Console.\n"
                            "3. Add 'noindex' meta tag to sensitive pages.\n"
                            "4. Audit and remove exposed files immediately."
                        ),
                        business_impact = f"'{dork_name}' exposed via Google search — publicly reachable without authentication.",
                        poc = f"Google search: {query}",
                        compliance = ["OWASP A05", "GDPR Art.32", "PCI DSS 12.3", "SEBI CSCRF"]
                    ))
                else:
                    findings.append(_finding(
                        title    = f"Google Dork Clean: {dork_name}",
                        severity = "INFO",
                        detail   = f"No results for: {query}"
                    ))
            except Exception as e:
                findings.append(_finding(
                    title    = f"Google Dork Error: {dork_name}",
                    severity = "INFO",
                    detail   = f"Error: {e}"
                ))

        return findings
