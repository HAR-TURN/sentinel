# `README.md`

```md
# 🛡 SENTINEL
> Passive Web Security Recon & Compliance Scanner

![Python](https://img.shields.io/badge/Python-3.10+-red?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-red?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)
![Repo](https://img.shields.io/badge/GitHub-RN%2Fsentinel-red?style=flat-square&logo=github)

> ⚠️ **For authorized and educational use only. Never scan without permission.**

---

## ⚙️ Requirements

- Linux (any distro)
- Python 3.10+
- Nmap installed

---

## 🚀 Setup & Install

**Step 1 — Clone the repo**
```bash
git clone https://github.com/HAR-TURN/sentinel
cd sentinel
```

**Step 2 — Install system dependencies**
```bash
sudo apt-get update && sudo apt-get install -y nmap wkhtmltopdf python3-pip python3-venv
```

**Step 3 — Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Step 4 — Install Python dependencies**
```bash
pip install -r requirements.txt
```

---

## ▶️ Run

```bash
# Single URL
python3 main.py -u https://example.com

# Multiple URLs from file
python3 main.py -f targets.txt

# Custom output folder
python3 main.py -u https://example.com -o ./reports

# Skip port scan
python3 main.py -u https://example.com --no-ports

# Skip Google dorking
python3 main.py -u https://example.com --no-dork

# JSON report only
python3 main.py -u https://example.com --format json

# Both HTML + JSON (default)
python3 main.py -u https://example.com --format both
```

---

## 📁 Output

Reports saved in `./reports/` folder:

```
reports/
├── SENTINEL_example_com_TIMESTAMP.html       ← Full visual report
├── SENTINEL_example_com_TIMESTAMP.json       ← Machine-readable
└── SENTINEL_example_com_TIMESTAMP_POC.html   ← POC file
```

---

## 🗂️ Files

```
sentinel/
├── main.py           ← Entry point
├── scanner.py        ← Scanning modules
├── analyzer.py       ← OWASP / GDPR / PCI checks
├── reporter.py       ← Report generator
└── requirements.txt  ← Dependencies
```

---

## ✅ What It Checks

- HTTP Headers · SSL/TLS · HSTS · CSP · Cookies
- DNSSEC · SPF · DMARC · WHOIS
- CMS & Tech Stack Detection (WordPress, Shopify, Wix, Cloudflare…)
- Open Ports · Admin Panel Discovery
- GraphQL Introspection · API Endpoints · Swagger
- API Key & Secret Leak Detection (20+ patterns)
- Clickjacking POC · CORS Misconfiguration
- OWASP Top 10 · GDPR · PCI DSS · SEBI CSCRF
- Google Dorking (OSINT)

---

## ⚠️ Legal

> Use only on systems you **own** or have **written authorization** to test.  
> Unauthorized scanning may violate CFAA, IT Act 2000, GDPR and other laws.

---

<p align="center">
  <b>SENTINEL</b> · Built for security professionals · <a href="https://github.com/HAR-TURN/sentinel">github.com/RN/sentinel</a>
</p>
```
