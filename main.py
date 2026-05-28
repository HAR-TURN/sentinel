#!/usr/bin/env python3
"""
SENTINEL - Passive Web Security Recon & Compliance Scanner
Author: Open Source | GitHub Ready
License: MIT (For authorized testing only)
"""

import argparse
import sys
import os
import json
import datetime
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

# ── Local modules ──────────────────────────────────────────────────────────────
from scanner import Scanner
from analyzer import Analyzer
from reporter import Reporter

# ──────────────────────────────────────────────────────────────────────────────
BANNER = pyfiglet.figlet_format("SENTINEL", font="slant")
VERSION = "2.0.0"
AUTHOR  = "Passive Security Recon Tool | OWASP + GDPR + PCI DSS + SEBI Ready"

def print_banner():
    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + f"  Version : {VERSION}")
    print(Fore.YELLOW + f"  {AUTHOR}")
    print(Fore.RED    + "\n  [!] For AUTHORIZED & EDUCATIONAL use ONLY. Never scan without permission.\n")
    print(Fore.WHITE  + "─" * 70 + "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description="SENTINEL - Passive Web Security & Compliance Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-u", "--url",
        help="Target URL (e.g. https://example.com or https://trade.swift.co.in:8443/app/)",
        required=False
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing list of URLs (one per line)",
        required=False
    )
    parser.add_argument(
        "-o", "--output",
        help="Output directory for reports (default: ./reports/)",
        default="./reports"
    )
    parser.add_argument(
        "--no-ports",
        help="Skip port scanning (faster, stealthier)",
        action="store_true"
    )
    parser.add_argument(
        "--no-dork",
        help="Skip Google dorking",
        action="store_true"
    )
    parser.add_argument(
        "--format",
        help="Report format: html | json | both (default: both)",
        choices=["html", "json", "both"],
        default="both"
    )
    parser.add_argument(
        "--threads",
        help="Number of concurrent threads (default: 5)",
        type=int,
        default=5
    )
    return parser.parse_args()

def confirm_authorization(url: str) -> bool:
    print(Fore.RED + f"\n  ⚠  You are about to scan: {url}")
    print(Fore.RED + "  This tool is for AUTHORIZED use ONLY.")
    consent = input(Fore.YELLOW + "\n  Do you confirm you have WRITTEN AUTHORIZATION to scan this target? [yes/no]: ").strip().lower()
    return consent == "yes"

def run_scan(url: str, args, report_dir: str):
    """Full scan pipeline for a single URL."""
    print(Fore.CYAN + f"\n  ▶  Starting scan for: {url}")
    print(Fore.WHITE + "─" * 70)

    scan_start = datetime.datetime.utcnow()

    # ── Phase 1: Scanning ──────────────────────────────────────────────────────
    scanner = Scanner(url, skip_ports=args.no_ports)

    print(Fore.GREEN + "\n  [1/8] ► HTTP Headers & Server Info ...")
    headers_data       = scanner.scan_headers()

    print(Fore.GREEN + "  [2/8] ► SSL/TLS Configuration ...")
    ssl_data           = scanner.scan_ssl()

    print(Fore.GREEN + "  [3/8] ► Technology & CMS Detection ...")
    tech_data          = scanner.scan_technologies()

    print(Fore.GREEN + "  [4/8] ► DNSSEC & DNS Records ...")
    dns_data           = scanner.scan_dns()

    print(Fore.GREEN + "  [5/8] ► Cookies Analysis ...")
    cookie_data        = scanner.scan_cookies()

    print(Fore.GREEN + "  [6/8] ► Port Scanning (passive) ...")
    port_data          = scanner.scan_ports()

    print(Fore.GREEN + "  [7/8] ► Form & Login Page Detection ...")
    form_data          = scanner.scan_forms_and_logins()

    print(Fore.GREEN + "  [8/8] ► GraphQL & API Endpoint Detection ...")
    graphql_data       = scanner.scan_graphql_and_apis()

    # ── Phase 2: Analysis ──────────────────────────────────────────────────────
    analyzer = Analyzer(
        url=url,
        headers=headers_data,
        ssl=ssl_data,
        tech=tech_data,
        dns=dns_data,
        cookies=cookie_data,
        ports=port_data,
        forms=form_data,
        graphql=graphql_data,
        skip_dork=args.no_dork
    )

    print(Fore.MAGENTA + "\n  [A] ► Security Headers Analysis ...")
    header_findings    = analyzer.analyze_headers()

    print(Fore.MAGENTA + "  [B] ► CSP Analysis ...")
    csp_findings       = analyzer.analyze_csp()

    print(Fore.MAGENTA + "  [C] ► OWASP Top 10 Checks ...")
    owasp_findings     = analyzer.analyze_owasp()

    print(Fore.MAGENTA + "  [D] ► Clickjacking & X-Frame-Options ...")
    clickjack_findings = analyzer.analyze_clickjacking()

    print(Fore.MAGENTA + "  [E] ► GDPR Compliance Check ...")
    gdpr_findings      = analyzer.analyze_gdpr()

    print(Fore.MAGENTA + "  [F] ► PCI DSS Compliance Check ...")
    pci_findings       = analyzer.analyze_pci_dss()

    print(Fore.MAGENTA + "  [G] ► API Key & Sensitive Data Leak Detection ...")
    leak_findings      = analyzer.analyze_leaks()

    print(Fore.MAGENTA + "  [H] ► Admin/Panel Path Detection ...")
    admin_findings     = analyzer.analyze_admin_panels()

    print(Fore.MAGENTA + "  [I] ► External Content & Scraping Protection ...")
    ext_findings       = analyzer.analyze_external_content()

    print(Fore.MAGENTA + "  [J] ► Google Dorking (OSINT) ...")
    dork_findings      = analyzer.analyze_google_dork()

    scan_end = datetime.datetime.utcnow()

    # ── Aggregate all results ──────────────────────────────────────────────────
    full_report = {
        "meta": {
            "target"    : url,
            "scan_start": scan_start.isoformat() + "Z",
            "scan_end"  : scan_end.isoformat() + "Z",
            "duration"  : str(scan_end - scan_start),
            "tool"      : f"SENTINEL v{VERSION}"
        },
        "scan": {
            "headers"   : headers_data,
            "ssl"       : ssl_data,
            "tech"      : tech_data,
            "dns"       : dns_data,
            "cookies"   : cookie_data,
            "ports"     : port_data,
            "forms"     : form_data,
            "graphql"   : graphql_data
        },
        "findings": {
            "header_security"      : header_findings,
            "csp"                  : csp_findings,
            "owasp"                : owasp_findings,
            "clickjacking"         : clickjack_findings,
            "gdpr"                 : gdpr_findings,
            "pci_dss"              : pci_findings,
            "leaks"                : leak_findings,
            "admin_panels"         : admin_findings,
            "external_content"     : ext_findings,
            "google_dork"          : dork_findings
        }
    }

    # ── Phase 3: Reporting ─────────────────────────────────────────────────────
    reporter = Reporter(full_report, report_dir)

    print(Fore.BLUE + "\n  [R] ► Generating Reports & POC ...")
    saved_files = []

    if args.format in ("html", "both"):
        html_path = reporter.generate_html()
        saved_files.append(html_path)
        print(Fore.GREEN + f"       ✔  HTML Report : {html_path}")

    if args.format in ("json", "both"):
        json_path = reporter.generate_json()
        saved_files.append(json_path)
        print(Fore.GREEN + f"       ✔  JSON Report : {json_path}")

    poc_path = reporter.generate_poc()
    saved_files.append(poc_path)
    print(Fore.GREEN + f"       ✔  POC File   : {poc_path}")

    # ── Terminal Summary ───────────────────────────────────────────────────────
    print_summary(full_report)
    return full_report

def print_summary(report: dict):
    """Print a colour-coded terminal summary."""
    findings = report["findings"]
    url      = report["meta"]["target"]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for category, items in findings.items():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and "severity" in item:
                    sev = item["severity"].upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

    total = sum(severity_counts.values())
    print(Fore.WHITE + "\n" + "─" * 70)
    print(Fore.CYAN  + f"  SCAN COMPLETE: {url}")
    print(Fore.WHITE + f"  Duration     : {report['meta']['duration']}")
    print(Fore.WHITE + f"  Total Issues : {total}")
    print()
    color_map = {
        "CRITICAL": Fore.RED,
        "HIGH"    : Fore.LIGHTRED_EX,
        "MEDIUM"  : Fore.YELLOW,
        "LOW"     : Fore.LIGHTYELLOW_EX,
        "INFO"    : Fore.CYAN
    }
    for sev, count in severity_counts.items():
        bar = "█" * min(count, 40)
        print(f"  {color_map[sev]}{sev:<10}{Style.RESET_ALL} │ {color_map[sev]}{bar} {count}{Style.RESET_ALL}")
    print(Fore.WHITE + "─" * 70 + "\n")

def main():
    print_banner()
    args = parse_args()

    # ── Collect targets ────────────────────────────────────────────────────────
    targets = []

    if args.url:
        targets.append(args.url.strip())
    elif args.file:
        if not os.path.isfile(args.file):
            print(Fore.RED + f"  [✗] File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as fh:
            targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    else:
        # Interactive mode
        url_input = input(Fore.YELLOW + "  Enter target URL: ").strip()
        if url_input:
            targets.append(url_input)
        else:
            print(Fore.RED + "  [✗] No target specified. Use -u <url> or -f <file>.")
            sys.exit(1)

    # ── Ensure report directory ────────────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)

    # ── Process each target ────────────────────────────────────────────────────
    all_reports = []
    for url in targets:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not confirm_authorization(url):
            print(Fore.RED + f"  [✗] Skipping {url} – authorization not confirmed.\n")
            continue

        try:
            report = run_scan(url, args, args.output)
            all_reports.append(report)
        except KeyboardInterrupt:
            print(Fore.RED + "\n  [!] Scan interrupted by user.")
            break
        except Exception as exc:
            print(Fore.RED + f"  [✗] Error scanning {url}: {exc}")
            import traceback; traceback.print_exc()

    print(Fore.CYAN + f"\n  ✔  All scans complete. Reports saved in: {args.output}\n")

if __name__ == "__main__":
    main()
