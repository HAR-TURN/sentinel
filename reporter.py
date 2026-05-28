"""
reporter.py — Report Generator for SENTINEL
Generates:
  - Detailed HTML report (SEBI / VAPT compliance ready)
  - JSON machine-readable report
  - Separate POC HTML file with clickjacking iframe + code snippets
"""

import os
import json
import datetime
import urllib.parse
from jinja2 import Template
from colorama import Fore

# ──────────────────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#dc3545",
    "HIGH"    : "#fd7e14",
    "MEDIUM"  : "#ffc107",
    "LOW"     : "#0dcaf0",
    "INFO"    : "#6c757d"
}

# ──────────────────────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SENTINEL Security Report – {{ meta.target }}</title>
<style>
  :root {
    --critical : #dc3545; --high    : #fd7e14;
    --medium   : #ffc107; --low     : #0dcaf0;
    --info     : #6c757d; --bg      : #0d1117;
    --surface  : #161b22; --border  : #30363d;
    --text      : #e6edf3; --muted   : #8b949e;
    --green     : #3fb950; --accent  : #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px; line-height: 1.6;
  }
  /* Header */
  .report-header {
    background: linear-gradient(135deg,#0d1117 0%,#161b22 100%);
    border-bottom: 2px solid var(--accent);
    padding: 40px 60px;
  }
  .report-header h1 { font-size: 2.5rem; color: var(--accent); }
  .report-header .subtitle { color: var(--muted); font-size: 1rem; margin-top: 6px; }
  .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr));
    gap: 16px; margin-top: 28px;
  }
  .meta-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .meta-card label { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .meta-card .value { font-size: 1rem; font-weight: 600; margin-top: 4px; word-break: break-all; }
  /* Severity Summary */
  .severity-bar {
    display: flex; gap: 16px; padding: 24px 60px;
    background: var(--surface); border-bottom: 1px solid var(--border); flex-wrap: wrap;
  }
  .sev-pill {
    padding: 8px 20px; border-radius: 999px; font-weight: 700;
    font-size: 1rem; display: flex; align-items: center; gap: 8px;
  }
  /* Sections */
  main { max-width: 1400px; margin: 0 auto; padding: 40px 60px; }
  h2.section-title {
    font-size: 1.4rem; color: var(--accent);
    border-bottom: 1px solid var(--border); padding-bottom: 10px;
    margin: 40px 0 20px;
  }
  /* Finding Cards */
  .finding-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 20px; overflow: hidden;
  }
  .finding-header {
    display: flex; align-items: center; gap: 14px;
    padding: 16px 20px; border-bottom: 1px solid var(--border); cursor: pointer;
  }
  .sev-badge {
    padding: 4px 12px; border-radius: 6px; font-size: 12px;
    font-weight: 700; color: #fff; min-width: 80px; text-align: center;
  }
  .finding-title { font-weight: 600; font-size: 15px; flex: 1; }
  .finding-owasp { font-size: 11px; color: var(--muted); }
  .finding-body { padding: 20px; display: none; }
  .finding-body.open { display: block; }
  .finding-body h4 { color: var(--muted); font-size: 11px; text-transform: uppercase; margin: 16px 0 6px; }
  .finding-body h4:first-child { margin-top: 0; }
  .finding-body p, .finding-body ul { font-size: 13px; color: var(--text); }
  .finding-body ul { padding-left: 18px; }
  pre.poc {
    background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
    padding: 14px; overflow-x: auto; font-size: 12px; color: #a8ff78;
    white-space: pre-wrap; word-break: break-all;
  }
  .compliance-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
  .comp-tag {
    background: #1f2d3d; border: 1px solid var(--accent); color: var(--accent);
    border-radius: 4px; padding: 2px 8px; font-size: 11px;
  }
  /* Tech Table */
  table { width: 100%; border-collapse: collapse; }
  th, td {
    text-align: left; padding: 10px 14px;
    border-bottom: 1px solid var(--border); font-size: 13px;
  }
  th { background: var(--surface); color: var(--muted); font-size: 11px; text-transform: uppercase; }
  tr:hover td { background: rgba(88,166,255,0.05); }
  /* Footer */
  footer {
    text-align: center; padding: 30px;
    color: var(--muted); font-size: 12px;
    border-top: 1px solid var(--border); margin-top: 60px;
  }
  /* Responsive */
  @media (max-width: 768px) {
    .report-header, main { padding: 20px; }
    .severity-bar { padding: 16px 20px; }
  }
</style>
</head>
<body>

<!-- ── Report Header ─────────────────────────────────────────────────────── -->
<div class="report-header">
  <h1>🛡 SENTINEL Security Report</h1>
  <div class="subtitle">Passive Web Security & Compliance Assessment</div>
  <div class="meta-grid">
    <div class="meta-card"><label>Target URL</label><div class="value">{{ meta.target }}</div></div>
    <div class="meta-card"><label>Scan Started</label><div class="value">{{ meta.scan_start }}</div></div>
    <div class="meta-card"><label>Scan Duration</label><div class="value">{{ meta.duration }}</div></div>
    <div class="meta-card"><label>Tool</label><div class="value">{{ meta.tool }}</div></div>
    <div class="meta-card"><label>Total Findings</label><div class="value">{{ total_findings }}</div></div>
    <div class="meta-card"><label>Report Generated</label><div class="value">{{ now }}</div></div>
  </div>
</div>

<!-- ── Severity Summary ──────────────────────────────────────────────────── -->
<div class="severity-bar">
  {% for sev, color in [('CRITICAL','#dc3545'),('HIGH','#fd7e14'),('MEDIUM','#ffc107'),('LOW','#0dcaf0'),('INFO','#6c757d')] %}
  <div class="sev-pill" style="background:{{ color }}20; border:2px solid {{ color }}; color:{{ color }};">
    {{ sev }}: {{ counts.get(sev, 0) }}
  </div>
  {% endfor %}
</div>

<main>

<!-- ── Technology Stack ──────────────────────────────────────────────────── -->
<h2 class="section-title">🔍 Technology Stack Detected</h2>
<table>
  <thead><tr><th>Component</th><th>Detected Value</th></tr></thead>
  <tbody>
    <tr><td>CMS</td><td>{{ scan.tech.cms or 'Not detected' }}</td></tr>
    <tr><td>CDN / WAF</td><td>{{ scan.tech.cdn or 'Not detected' }}</td></tr>
    <tr><td>Framework</td><td>{{ scan.tech.framework or 'Not detected' }}</td></tr>
    <tr><td>Web Server (Header)</td><td>{{ scan.tech.server_version or scan.headers.server or 'Not disclosed' }}</td></tr>
    <tr><td>Powered By</td><td>{{ scan.tech.powered_by or scan.headers.powered_by or 'Not disclosed' }}</td></tr>
    <tr><td>JS Libraries</td><td>{{ scan.tech.js_libraries | join(', ') or 'None detected' }}</td></tr>
    <tr><td>Analytics</td><td>{{ scan.tech.analytics | join(', ') or 'None detected' }}</td></tr>
    <tr><td>Raw BuiltWith</td><td>{{ scan.tech.raw_builtwith | tojson(indent=2) }}</td></tr>
  </tbody>
</table>

<!-- ── SSL / TLS ─────────────────────────────────────────────────────────── -->
<h2 class="section-title">🔒 SSL / TLS Configuration</h2>
<table>
  <thead><tr><th>Property</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>HTTPS Enabled</td><td>{{ '✅ Yes' if scan.ssl.enabled else '❌ No' }}</td></tr>
    <tr><td>TLS Version</td><td>{{ scan.ssl.version or 'N/A' }}</td></tr>
    <tr><td>Cipher Suite</td><td>{{ scan.ssl.cipher or 'N/A' }}</td></tr>
    <tr><td>Certificate Issuer</td><td>{{ scan.ssl.cert_issuer or 'N/A' }}</td></tr>
    <tr><td>Certificate Subject</td><td>{{ scan.ssl.cert_subject or 'N/A' }}</td></tr>
    <tr><td>Certificate Expiry</td><td>{{ scan.ssl.cert_expiry or 'N/A' }}</td></tr>
    <tr><td>Certificate Expired</td><td>{{ '❌ YES – CRITICAL' if scan.ssl.cert_expired else '✅ No' }}</td></tr>
    <tr><td>Self-Signed</td><td>{{ '⚠ YES' if scan.ssl.cert_self_signed else '✅ No' }}</td></tr>
    <tr><td>HSTS Enabled</td><td>{{ '✅ Yes' if scan.ssl.hsts else '❌ No' }}</td></tr>
    <tr><td>HSTS max-age</td><td>{{ scan.ssl.hsts_max_age }}</td></tr>
    <tr><td>HSTS includeSubDomains</td><td>{{ '✅ Yes' if scan.ssl.hsts_subdomains else '❌ No' }}</td></tr>
    <tr><td>HSTS Preload</td><td>{{ '✅ Yes' if scan.ssl.hsts_preload else '❌ No' }}</td></tr>
    <tr><td>SAN Domains</td><td>{{ scan.ssl.cert_san | join(', ') or 'N/A' }}</td></tr>
    {% for vuln in scan.ssl.vulnerabilities %}
    <tr><td colspan="2" style="color:#dc3545;">⚠ {{ vuln }}</td></tr>
    {% endfor %}
  </tbody>
</table>

<!-- ── DNS / DNSSEC ──────────────────────────────────────────────────────── -->
<h2 class="section-title">🌐 DNS & DNSSEC</h2>
<table>
  <thead><tr><th>Record Type</th><th>Values</th></tr></thead>
  <tbody>
    <tr><td>A Records</td><td>{{ scan.dns.a_records | join(', ') }}</td></tr>
    <tr><td>MX Records</td><td>{{ scan.dns.mx_records | join(', ') or 'None' }}</td></tr>
    <tr><td>NS Records</td><td>{{ scan.dns.ns_records | join(', ') }}</td></tr>
    <tr><td>SPF</td><td>{{ scan.dns.spf or '❌ Not configured' }}</td></tr>
    <tr><td>DMARC</td><td>{{ scan.dns.dmarc or '❌ Not configured' }}</td></tr>
    <tr><td>CAA Records</td><td>{{ scan.dns.caa_records | join(', ') or '❌ Not configured' }}</td></tr>
    <tr><td>DNSSEC</td><td>{{ '✅ Enabled' if scan.dns.dnssec else '❌ Not Enabled' }}</td></tr>
    <tr><td>DNSSEC Detail</td><td>{{ scan.dns.dnssec_detail }}</td></tr>
    {% if scan.dns.whois %}
    <tr><td>Registrar</td><td>{{ scan.dns.whois.registrar }}</td></tr>
    <tr><td>Domain Expires</td><td>{{ scan.dns.whois.expiration_date }}</td></tr>
    {% endif %}
  </tbody>
</table>

<!-- ── Cookies ───────────────────────────────────────────────────────────── -->
<h2 class="section-title">🍪 Cookies Analysis</h2>
{% if scan.cookies %}
<table>
  <thead>
    <tr>
      <th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th>
      <th>Session</th><th>Domain</th><th>Path</th>
    </tr>
  </thead>
  <tbody>
    {% for c in scan.cookies %}
    <tr>
      <td>{{ c.name }}</td>
      <td>{{ '✅' if c.secure else '❌' }}</td>
      <td>{{ '✅' if c.httponly else '❌' }}</td>
      <td>{{ c.samesite }}</td>
      <td>{{ '✅' if c.session else '❌' }}</td>
      <td>{{ c.domain }}</td>
      <td>{{ c.path }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<p style="color:var(--muted);">No cookies set by this page.</p>
{% endif %}

<!-- ── Open Ports ────────────────────────────────────────────────────────── -->
<h2 class="section-title">🔌 Open Ports</h2>
{% if scan.ports.open_ports %}
<table>
  <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version/Product</th><th>Risk</th></tr></thead>
  <tbody>
    {% for p in scan.ports.open_ports %}
    <tr>
      <td>{{ p.port }}</td>
      <td>{{ p.proto }}</td>
      <td>{{ p.service }}</td>
      <td>{{ p.version }} {{ p.product }}</td>
      <td>
        {% if p.port in [21,23,3306,5432,27017,6379,1433,5900] %}
        <span style="color:#dc3545; font-weight:700;">HIGH RISK</span>
        {% elif p.port in [80,8080,8888] %}
        <span style="color:#ffc107;">MEDIUM</span>
        {% else %}
        <span style="color:#6c757d;">INFO</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% elif scan.ports.error %}
<p style="color:var(--muted);">{{ scan.ports.error }}</p>
{% else %}
<p style="color:var(--muted);">No unusual open ports detected.</p>
{% endif %}

<!-- ── Forms & Login ─────────────────────────────────────────────────────── -->
<h2 class="section-title">📋 Forms & Login Pages</h2>
<p><strong>Total Forms Found:</strong> {{ scan.forms.total_forms }}</p>
{% if scan.forms.login_pages %}
<p><strong>Login Pages:</strong></p>
<ul>{% for lp in scan.forms.login_pages %}<li>{{ lp }}</li>{% endfor %}</ul>
{% endif %}
{% if scan.forms.forms %}
<table style="margin-top:12px;">
  <thead><tr><th>Action</th><th>Method</th><th>Login?</th><th>CSRF?</th><th>Autocomplete</th></tr></thead>
  <tbody>
    {% for f in scan.forms.forms %}
    <tr>
      <td>{{ f.action or '(same page)' }}</td>
      <td>{{ f.method }}</td>
      <td>{{ '🔐 Yes' if f.is_login else 'No' }}</td>
      <td>{{ '✅' if f.has_csrf else '❌ Missing' }}</td>
      <td>{{ f.autocomplete }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- ── GraphQL / API ─────────────────────────────────────────────────────── -->
<h2 class="section-title">⚡ GraphQL & API Endpoints</h2>
<table>
  <thead><tr><th>Check</th><th>Result</th></tr></thead>
  <tbody>
    <tr><td>GraphQL Endpoints</td><td>{{ scan.graphql.graphql_endpoints | join(', ') or 'None found' }}</td></tr>
    <tr><td>GraphQL Introspection</td><td>{{ '⚠ ENABLED (HIGH risk)' if scan.graphql.graphql_introspection else 'Disabled / Not found' }}</td></tr>
    <tr><td>API Endpoints</td><td>{{ scan.graphql.api_endpoints | join(', ') or 'None found' }}</td></tr>
    <tr><td>Swagger / OpenAPI</td><td>{{ '⚠ Found' if scan.graphql.swagger_found or scan.graphql.openapi_found else 'Not found' }}</td></tr>
  </tbody>
</table>

<!-- ── All Findings ──────────────────────────────────────────────────────── -->
<h2 class="section-title">🚨 Security Findings</h2>
<p style="color:var(--muted); margin-bottom:20px;">Click any finding to expand details, remediation steps, POC, and compliance tags.</p>

{% for category, items in findings.items() %}
  {% if items %}
  <h3 style="color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:1px;margin:28px 0 12px;">
    ◆ {{ category.replace('_', ' ').title() }}
  </h3>
  {% for finding in items | sort(attribute='severity', key=lambda s: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(s,5)) %}
    {% set sev = finding.severity %}
    {% set color = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#ffc107','LOW':'#0dcaf0','INFO':'#6c757d'}.get(sev,'#6c757d') %}
    <div class="finding-card">
      <div class="finding-header" onclick="toggle(this)">
        <span class="sev-badge" style="background:{{ color }};">{{ sev }}</span>
        <div>
          <div class="finding-title">{{ finding.title }}</div>
          {% if finding.owasp %}<div class="finding-owasp">{{ finding.owasp }}</div>{% endif %}
        </div>
        <span style="color:var(--muted);font-size:18px;">▼</span>
      </div>
      <div class="finding-body">
        <h4>Detail</h4>
        <p>{{ finding.detail }}</p>

        {% if finding.business_impact %}
        <h4>Business Impact</h4>
        <p>{{ finding.business_impact }}</p>
        {% endif %}

        {% if finding.remediation %}
        <h4>Remediation</h4>
        <pre style="background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;color:#a8ff78;white-space:pre-wrap;">{{ finding.remediation }}</pre>
        {% endif %}

        {% if finding.poc %}
        <h4>Proof of Concept (POC)</h4>
        <pre class="poc">{{ finding.poc }}</pre>
        {% endif %}

        {% if finding.compliance %}
        <h4>Compliance References</h4>
        <div class="compliance-tags">
          {% for tag in finding.compliance %}
          <span class="comp-tag">{{ tag }}</span>
          {% endfor %}
        </div>
        {% endif %}
      </div>
    </div>
  {% endfor %}
  {% endif %}
{% endfor %}

<!-- ── Executive Summary ─────────────────────────────────────────────────── -->
<h2 class="section-title">📊 Executive Summary</h2>
<table>
  <thead><tr><th>Severity</th><th>Count</th><th>Action Required</th></tr></thead>
  <tbody>
    <tr><td style="color:#dc3545;font-weight:700;">CRITICAL</td><td>{{ counts.get('CRITICAL',0) }}</td><td>Immediate remediation — within 24 hours</td></tr>
    <tr><td style="color:#fd7e14;font-weight:700;">HIGH</td><td>{{ counts.get('HIGH',0) }}</td><td>Remediate within 7 days</td></tr>
    <tr><td style="color:#ffc107;font-weight:700;">MEDIUM</td><td>{{ counts.get('MEDIUM',0) }}</td><td>Remediate within 30 days</td></tr>
    <tr><td style="color:#0dcaf0;font-weight:700;">LOW</td><td>{{ counts.get('LOW',0) }}</td><td>Remediate in next release cycle</td></tr>
    <tr><td style="color:#6c757d;">INFO</td><td>{{ counts.get('INFO',0) }}</td><td>Review and document</td></tr>
  </tbody>
</table>

<p style="margin-top:20px; color:var(--muted); font-size:13px;">
  <strong>Disclaimer:</strong> This report was generated by SENTINEL for authorized security assessment only.
  All findings are based on passive analysis and may not represent the full attack surface.
  This report is suitable for inclusion in VAPT reports, SEBI CSCRF submissions, GDPR DPIAs, and PCI DSS audit evidence.
</p>

</main>

<footer>
  Generated by SENTINEL v2.0 | Passive Security Recon Tool | {{ now }} |
  For authorized use only — not for distribution without permission.
</footer>

<script>
function toggle(el) {
  const body = el.nextElementSibling;
  body.classList.toggle('open');
  const arrow = el.querySelector('span:last-child');
  arrow.textContent = body.classList.contains('open') ? '▲' : '▼';
}
</script>
</body>
</html>"""

# ──────────────────────────────────────────────────────────────────────────────
class Reporter:
    def __init__(self, report: dict, output_dir: str):
        self.report     = report
        self.output_dir = output_dir
        self.target     = report["meta"]["target"]
        self.safe_name  = (
            urllib.parse.urlparse(self.target).netloc
            .replace(":", "_").replace("/", "_")
            .replace(".", "_")
        )
        self.timestamp  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _count_severities(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for items in self.report["findings"].values():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and "severity" in item:
                        sev = item["severity"].upper()
                        if sev in counts:
                            counts[sev] += 1
        return counts

    def _total_findings(self) -> int:
        return sum(self._count_severities().values())

    # ── HTML Report ───────────────────────────────────────────────────────────
    def generate_html(self) -> str:
        template  = Template(HTML_TEMPLATE)
        counts    = self._count_severities()
        html_out  = template.render(
            meta           = self.report["meta"],
            scan           = self.report["scan"],
            findings       = self.report["findings"],
            counts         = counts,
            total_findings = self._total_findings(),
            now            = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        path = os.path.join(
            self.output_dir,
            f"SENTINEL_{self.safe_name}_{self.timestamp}.html"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_out)
        return path

    # ── JSON Report ───────────────────────────────────────────────────────────
    def generate_json(self) -> str:
        path = os.path.join(
            self.output_dir,
            f"SENTINEL_{self.safe_name}_{self.timestamp}.json"
        )
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2, default=str)
        return path

    # ── POC File ──────────────────────────────────────────────────────────────
    def generate_poc(self) -> str:
        """Generate a standalone HTML file containing all POCs."""
        poc_items = []
        for category, items in self.report["findings"].items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("poc"):
                        poc_items.append({
                            "category": category,
                            "title"   : item["title"],
                            "severity": item["severity"],
                            "poc"     : item["poc"],
                            "remediation": item.get("remediation", ""),
                            "compliance" : item.get("compliance", [])
                        })

        poc_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SENTINEL POC File – {self.target}</title>
<style>
  body {{ background:#0d1117; color:#e6edf3; font-family:monospace; padding:40px; }}
  h1 {{ color:#58a6ff; }} h2 {{ color:#f78166; margin-top:40px; }}
  h3 {{ color:#e3b341; }} pre {{ background:#161b22; border:1px solid #30363d;
  padding:16px; border-radius:8px; overflow-x:auto; white-space:pre-wrap; color:#a8ff78; }}
  .tag {{ display:inline-block; background:#1f2d3d; border:1px solid #58a6ff;
  color:#58a6ff; border-radius:4px; padding:2px 8px; font-size:11px; margin:2px; }}
  .warn {{ color:#dc3545; }}
</style>
</head>
<body>
<h1>🛡 SENTINEL POC Report</h1>
<p><strong>Target:</strong> {self.target}</p>
<p><strong>Generated:</strong> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
<p class="warn">⚠ This file contains Proof-of-Concept code for AUTHORIZED security reporting ONLY.
Do not execute or share without explicit authorization.</p>
<hr style="border-color:#30363d;"/>
"""
        if not poc_items:
            poc_html += "<p>No POC items generated for this scan.</p>"
        else:
            for i, poc in enumerate(poc_items, 1):
                sev_color = {
                    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                    "MEDIUM"  : "#ffc107", "LOW" : "#0dcaf0", "INFO": "#6c757d"
                }.get(poc["severity"], "#6c757d")
                poc_html += f"""
<h2>POC #{i} – {poc['title']}</h2>
<p><strong>Severity:</strong> <span style="color:{sev_color};font-weight:700;">{poc['severity']}</span></p>
<p><strong>Category:</strong> {poc['category'].replace('_', ' ').title()}</p>
<h3>POC Code / Steps</h3>
<pre>{poc['poc']}</pre>
<h3>Remediation</h3>
<pre>{poc['remediation']}</pre>
<h3>Compliance References</h3>
{''.join(f'<span class="tag">{t}</span>' for t in poc['compliance'])}
<hr style="border-color:#30363d;margin-top:30px;"/>
"""

        poc_html += "</body></html>"

        path = os.path.join(
            self.output_dir,
            f"SENTINEL_{self.safe_name}_{self.timestamp}_POC.html"
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(poc_html)
        return path
