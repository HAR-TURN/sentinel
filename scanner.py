"""
scanner.py — Core Scanning Modules for SENTINEL
Handles: HTTP, SSL, DNS, Ports, Cookies, Forms, GraphQL, Tech Detection
All methods are PASSIVE / non-destructive.
"""

import re
import ssl
import json
import socket
import hashlib
import datetime
import warnings
import urllib.parse
from typing import Any

import requests
import dns.resolver
import dns.dnssec
import dns.query
import dns.name
import nmap
import whois
import tldextract
import builtwith
from bs4 import BeautifulSoup
from colorama import Fore

warnings.filterwarnings("ignore")

HEADERS_UA = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

TIMEOUT = 15   # seconds — keep passive / polite

# ──────────────────────────────────────────────────────────────────────────────
class Scanner:
    """Passive scanner — gathers raw data for the Analyzer."""

    def __init__(self, url: str, skip_ports: bool = False):
        self.url         = url.rstrip("/")
        self.skip_ports  = skip_ports
        self.parsed      = urllib.parse.urlparse(self.url)
        self.host        = self.parsed.hostname or ""
        self.port        = self.parsed.port
        self.scheme      = self.parsed.scheme
        self.session     = requests.Session()
        self.session.headers.update(HEADERS_UA)
        self.session.verify = False   # allow self-signed for non-prod targets
        self._response   = None       # cached main page response

    # ── helpers ───────────────────────────────────────────────────────────────
    def _get(self, path: str = "", **kwargs) -> requests.Response | None:
        target = self.url + path if path else self.url
        try:
            r = self.session.get(target, timeout=TIMEOUT,
                                 allow_redirects=True, **kwargs)
            return r
        except Exception as e:
            print(Fore.RED + f"      [!] GET {target} failed: {e}")
            return None

    def _get_response(self) -> requests.Response | None:
        if self._response is None:
            self._response = self._get()
        return self._response

    # ── 1. HTTP Headers ───────────────────────────────────────────────────────
    def scan_headers(self) -> dict:
        """Return all response headers + redirect chain."""
        result = {
            "status_code"    : None,
            "headers"        : {},
            "redirect_chain" : [],
            "server"         : "",
            "powered_by"     : "",
            "final_url"      : ""
        }
        try:
            r = self._get()
            if r is None:
                return result
            self._response = r
            result["status_code"] = r.status_code
            result["headers"]     = dict(r.headers)
            result["server"]      = r.headers.get("Server", "")
            result["powered_by"]  = r.headers.get("X-Powered-By", "")
            result["final_url"]   = r.url

            # Redirect chain
            for h in r.history:
                result["redirect_chain"].append({
                    "url"   : h.url,
                    "status": h.status_code
                })
        except Exception as e:
            result["error"] = str(e)
        return result

    # ── 2. SSL / TLS ──────────────────────────────────────────────────────────
    def scan_ssl(self) -> dict:
        result = {
            "enabled"           : False,
            "version"           : "",
            "cipher"            : "",
            "cert_issuer"       : "",
            "cert_subject"      : "",
            "cert_expiry"       : "",
            "cert_san"          : [],
            "cert_expired"      : False,
            "cert_self_signed"  : False,
            "hsts"              : False,
            "hsts_max_age"      : 0,
            "hsts_subdomains"   : False,
            "hsts_preload"      : False,
            "vulnerabilities"   : []
        }
        if self.scheme != "https":
            result["vulnerabilities"].append("Site not using HTTPS")
            return result

        port = self.port or 443
        ctx  = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            with socket.create_connection((self.host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    result["enabled"] = True
                    result["version"] = ssock.version() or ""
                    result["cipher"]  = ssock.cipher()[0] if ssock.cipher() else ""
                    cert = ssock.getpeercert()
                    if cert:
                        # Subject
                        subj = dict(x[0] for x in cert.get("subject", []))
                        result["cert_subject"] = subj.get("commonName", "")
                        # Issuer
                        iss  = dict(x[0] for x in cert.get("issuer", []))
                        result["cert_issuer"]  = iss.get("organizationName", "")
                        result["cert_self_signed"] = (
                            result["cert_subject"] == result["cert_issuer"]
                        )
                        # Expiry
                        expiry_str = cert.get("notAfter", "")
                        if expiry_str:
                            expiry_dt = datetime.datetime.strptime(
                                expiry_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            result["cert_expiry"]  = expiry_dt.isoformat()
                            result["cert_expired"] = expiry_dt < datetime.datetime.utcnow()
                        # SAN
                        result["cert_san"] = [
                            v for _, v in cert.get("subjectAltName", [])
                        ]

                    # Weak protocols
                    if result["version"] in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        result["vulnerabilities"].append(
                            f"Weak TLS/SSL version: {result['version']}"
                        )

        except Exception as e:
            result["error"] = str(e)

        # HSTS from headers
        r = self._get_response()
        if r:
            hsts_hdr = r.headers.get("Strict-Transport-Security", "")
            if hsts_hdr:
                result["hsts"] = True
                ma = re.search(r"max-age=(\d+)", hsts_hdr)
                result["hsts_max_age"]      = int(ma.group(1)) if ma else 0
                result["hsts_subdomains"]   = "includeSubDomains" in hsts_hdr
                result["hsts_preload"]      = "preload" in hsts_hdr

        return result

    # ── 3. Technology Detection ───────────────────────────────────────────────
    def scan_technologies(self) -> dict:
        result = {
            "technologies" : [],
            "cms"          : "",
            "cdn"          : "",
            "framework"    : "",
            "server"       : "",
            "js_libraries" : [],
            "analytics"    : [],
            "raw_builtwith": {}
        }
        try:
            bw = builtwith.parse(self.url)
            result["raw_builtwith"] = bw

            # CMS detection
            cms_keys = ["cms", "blog", "ecommerce"]
            for key in cms_keys:
                if key in bw:
                    result["cms"] = ", ".join(bw[key])
                    break

            # CDN
            cdn_keys = ["cdn"]
            for key in cdn_keys:
                if key in bw:
                    result["cdn"] = ", ".join(bw[key])

            # Web frameworks
            for key in ["web-frameworks", "javascript-frameworks"]:
                if key in bw:
                    result["framework"] += ", ".join(bw[key]) + " "

            # JS libraries
            if "javascript" in bw:
                result["js_libraries"] = bw["javascript"]

            # Analytics
            if "analytics" in bw:
                result["analytics"] = bw["analytics"]

            # Web server
            if "web-servers" in bw:
                result["server"] = ", ".join(bw["web-servers"])

        except Exception as e:
            result["error"] = str(e)

        # Supplement with header-based detection
        r = self._get_response()
        if r:
            body = r.text.lower()
            hdr  = dict(r.headers)

            # Manual CMS fingerprinting
            cms_signatures = {
                "WordPress"  : ["wp-content", "wp-includes", "wordpress"],
                "Joomla"     : ["joomla", "/components/com_"],
                "Drupal"     : ["drupal", "sites/default/files"],
                "Shopify"    : ["shopify", "cdn.shopify.com"],
                "Wix"        : ["wix.com", "wixstatic.com"],
                "HubSpot"    : ["hubspot", "hs-scripts.com"],
                "Magento"    : ["magento", "mage/cookies.js"],
                "PrestaShop" : ["prestashop"],
                "Ghost"      : ["ghost.io", "ghost/"],
                "Squarespace": ["squarespace"],
                "Webflow"    : ["webflow.com"],
            }
            detected_cms = []
            for cms_name, sigs in cms_signatures.items():
                if any(sig in body for sig in sigs):
                    detected_cms.append(cms_name)

            if detected_cms and not result["cms"]:
                result["cms"] = ", ".join(detected_cms)
            elif detected_cms:
                result["cms"] += " | Manual: " + ", ".join(detected_cms)

            # Cloudflare
            if "cf-ray" in {k.lower(): v for k, v in hdr.items()}:
                result["cdn"] = "Cloudflare"

            # Version hints from headers
            server_hdr = hdr.get("Server", "")
            powered_by = hdr.get("X-Powered-By", "")
            result["server_version"] = server_hdr
            result["powered_by"]     = powered_by

            # JS lib fingerprinting from body
            js_sigs = {
                "jQuery"    : r"jquery[/-](\d+\.\d+\.\d+)",
                "React"     : r"react[/-](\d+\.\d+\.\d+)",
                "Angular"   : r"angular[/-](\d+\.\d+\.\d+)",
                "Vue.js"    : r"vue[/-](\d+\.\d+\.\d+)",
                "Bootstrap" : r"bootstrap[/-](\d+\.\d+\.\d+)",
                "Lodash"    : r"lodash[/-](\d+\.\d+\.\d+)",
            }
            for lib, pattern in js_sigs.items():
                m = re.search(pattern, body)
                entry = f"{lib} {m.group(1)}" if m else None
                if entry and entry not in result["js_libraries"]:
                    result["js_libraries"].append(entry if m else lib)

        return result

    # ── 4. DNS & DNSSEC ───────────────────────────────────────────────────────
    def scan_dns(self) -> dict:
        result = {
            "a_records"    : [],
            "mx_records"   : [],
            "ns_records"   : [],
            "txt_records"  : [],
            "spf"          : "",
            "dmarc"        : "",
            "dkim_hint"    : "",
            "dnssec"       : False,
            "dnssec_detail": "",
            "whois"        : {},
            "caa_records"  : []
        }
        domain = self.host

        # A records
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                key = f"{rtype.lower()}_records"
                if rtype == "A":
                    result["a_records"] = [r.address for r in answers]
                elif rtype == "AAAA":
                    result.setdefault("aaaa_records", [r.address for r in answers])
                elif rtype == "MX":
                    result["mx_records"] = [str(r.exchange) for r in answers]
                elif rtype == "NS":
                    result["ns_records"] = [str(r.target) for r in answers]
                elif rtype == "TXT":
                    txts = [r.to_text().strip('"') for r in answers]
                    result["txt_records"] = txts
                    result["spf"]   = next((t for t in txts if "v=spf1"  in t), "")
                    result["dmarc"] = next((t for t in txts if "v=DMARC1" in t), "")
                elif rtype == "CAA":
                    result["caa_records"] = [r.to_text() for r in answers]
            except Exception:
                pass

        # DMARC (separate lookup)
        try:
            dmarc_ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=10)
            result["dmarc"] = " ".join(r.to_text().strip('"') for r in dmarc_ans)
        except Exception:
            pass

        # DNSSEC
        try:
            request = dns.message.make_query(domain, dns.rdatatype.DNSKEY,
                                              want_dnssec=True)
            response = dns.query.udp(request, "8.8.8.8", timeout=10)
            if response.rcode() == 0:
                answer = response.answer
                if len(answer) >= 2:
                    result["dnssec"]        = True
                    result["dnssec_detail"] = "DNSSEC DNSKEY + RRSIG found"
                else:
                    result["dnssec_detail"] = "DNSKEY not found or DNSSEC not configured"
        except Exception as e:
            result["dnssec_detail"] = f"DNSSEC check error: {e}"

        # WHOIS
        try:
            w = whois.whois(domain)
            result["whois"] = {
                "registrar"     : str(w.registrar or ""),
                "creation_date" : str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers"  : w.name_servers or [],
                "org"           : str(w.org or "")
            }
        except Exception:
            pass

        return result

    # ── 5. Cookies ────────────────────────────────────────────────────────────
    def scan_cookies(self) -> list:
        cookies = []
        r = self._get_response()
        if r is None:
            return cookies

        for cookie in r.cookies:
            cookies.append({
                "name"      : cookie.name,
                "value"     : cookie.value[:40] + "..." if len(cookie.value) > 40 else cookie.value,
                "domain"    : cookie.domain,
                "path"      : cookie.path,
                "secure"    : cookie.secure,
                "httponly"  : cookie.has_nonstandard_attr("HttpOnly") or
                              "httponly" in str(cookie._rest).lower(),
                "samesite"  : cookie._rest.get("SameSite", "Not Set"),
                "expires"   : cookie.expires,
                "session"   : cookie.expires is None
            })
        return cookies

    # ── 6. Port Scanning ──────────────────────────────────────────────────────
    def scan_ports(self) -> dict:
        result = {"open_ports": [], "scan_type": "passive_nmap", "error": ""}
        if self.skip_ports:
            result["error"] = "Port scan skipped (--no-ports flag)"
            return result

        COMMON_PORTS = (
            "21,22,23,25,53,80,110,143,443,445,993,995,"
            "1433,3306,3389,5432,5900,6379,8080,8443,8888,"
            "9200,27017"
        )
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.host, ports=COMMON_PORTS,
                    arguments="-sV --open -T2 --max-retries 1")

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        state = nm[host][proto][port]["state"]
                        if state == "open":
                            result["open_ports"].append({
                                "port"   : port,
                                "proto"  : proto,
                                "state"  : state,
                                "service": nm[host][proto][port]["name"],
                                "version": nm[host][proto][port]["version"],
                                "product": nm[host][proto][port]["product"]
                            })
        except Exception as e:
            result["error"] = str(e)

        return result

    # ── 7. Forms & Login Pages ────────────────────────────────────────────────
    def scan_forms_and_logins(self) -> dict:
        result = {
            "forms"         : [],
            "login_pages"   : [],
            "found_on"      : self.url,
            "total_forms"   : 0
        }
        r = self._get_response()
        if r is None:
            return result

        soup = BeautifulSoup(r.text, "lxml")
        forms = soup.find_all("form")
        result["total_forms"] = len(forms)

        for form in forms:
            inputs = form.find_all("input")
            fields = []
            is_login = False
            has_csrf = False

            for inp in inputs:
                itype = inp.get("type", "text").lower()
                iname = inp.get("name", "")
                iid   = inp.get("id", "")
                fields.append({
                    "type" : itype,
                    "name" : iname,
                    "id"   : iid
                })
                if itype == "password":
                    is_login = True
                if "csrf" in iname.lower() or "token" in iname.lower():
                    has_csrf = True

            form_entry = {
                "action"       : form.get("action", ""),
                "method"       : form.get("method", "GET").upper(),
                "fields"       : fields,
                "is_login"     : is_login,
                "has_csrf"     : has_csrf,
                "autocomplete" : form.get("autocomplete", "on")
            }
            result["forms"].append(form_entry)
            if is_login:
                result["login_pages"].append(self.url)

        # Probe common login paths
        LOGIN_PATHS = [
            "/login", "/signin", "/admin", "/admin/login",
            "/wp-login.php", "/wp-admin", "/user/login",
            "/auth/login", "/account/login", "/panel",
            "/dashboard", "/administrator", "/cpanel",
            "/webmail", "/phpmyadmin", "/adminer.php",
            "/manager/html"  # Tomcat
        ]
        for path in LOGIN_PATHS:
            resp = self._get(path)
            if resp and resp.status_code in (200, 401, 403):
                result["login_pages"].append(self.url + path)

        result["login_pages"] = list(set(result["login_pages"]))
        return result

    # ── 8. GraphQL & API Endpoints ────────────────────────────────────────────
    def scan_graphql_and_apis(self) -> dict:
        result = {
            "graphql_endpoints" : [],
            "api_endpoints"     : [],
            "graphql_introspection": False,
            "swagger_found"     : False,
            "openapi_found"     : False
        }

        GRAPHQL_PATHS = [
            "/graphql", "/graphiql", "/api/graphql",
            "/v1/graphql", "/query", "/gql"
        ]
        for path in GRAPHQL_PATHS:
            r = self._get(path)
            if r and r.status_code in (200, 400):
                result["graphql_endpoints"].append(self.url + path)
                # Introspection probe
                try:
                    introspect = {"query": "{__schema{types{name}}}"}
                    ri = self.session.post(
                        self.url + path,
                        json=introspect,
                        timeout=TIMEOUT
                    )
                    if ri.status_code == 200 and "__schema" in ri.text:
                        result["graphql_introspection"] = True
                except Exception:
                    pass

        API_PATHS = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/v1", "/v2", "/swagger.json",
            "/swagger-ui.html", "/openapi.json", "/api-docs",
            "/.well-known/openid-configuration"
        ]
        for path in API_PATHS:
            r = self._get(path)
            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "html" in ct:
                    result["api_endpoints"].append(self.url + path)
                if "swagger" in r.text.lower():
                    result["swagger_found"] = True
                if "openapi" in r.text.lower():
                    result["openapi_found"] = True

        return result
