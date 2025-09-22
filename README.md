# 🚀 Domain Analysis Tool

**Comprehensive reconnaissance for domains & subdomains — DNS, ports, HTTP headers, JS secret scanning, SSL checks, and Excel reports.**

---


> A fast, extensible Python script to help security engineers and bug bounty hunters collect domain intelligence and export results into a single .xlsx report.

---

## 🔍 Key Features

* **DNS Enumeration** — A, AAAA, CNAME, MX, NS, TXT records
* **Port Scanning** — Check common ports (HTTP, HTTPS, FTP, SSH, etc.)
* **HTTP / HTTPS Analysis** — Status codes, headers, directory listing detection
* **JavaScript Secret Scanning** — Crawl linked `.js` files and flag probable secrets via regex
* **SSL Certificate Checking** — Issuer, validity, expiry, and basic health
* **Excel Export** — Clean, reviewable `.xlsx` output for triage and reporting

---

## ⚙️ Requirements

* Python 3.6+
* Recommended packages (install with pip):

```bash
pip install dnspython requests openpyxl beautifulsoup4
```

Or install from bundled `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## 🧰 Installation

```bash
git clone https://github.com/3xoa-offsec/domainanalysis.git
cd domainanalysis
```

---

## ▶️ Quick Start

1. Create a text file with one domain or subdomain per line (e.g. `domains.txt`):

```
example.com
sub.example.com
```

2. Run the tool:

```bash
python domain_analysis.py
```

3. Follow interactive prompts:

* Input file name (e.g., `domains.txt`)
* Output Excel file name (e.g., `results.xlsx`)
* Max concurrent threads (default: 10)

4. Open the generated `results.xlsx` to review findings.

---

## 📝 Output

The Excel report contains organized sheets / columns for:

* DNS records
* Open ports detected
* HTTP/HTTPS details (status, headers, directory listing warnings)
* SSL certificate metadata (issuer, expiry, status)
* JavaScript files scanned and any **potential** secrets found
* Notes / potential issues

---

## 🛡️ Security & Ethics

This tool is intended **only** for authorized testing, internal security assessments, or educational use. Unauthorized scanning of systems you do not own or have explicit permission to test may be illegal. Always get written permission before scanning third-party infrastructure.

---

## ⚠️ Notes & Limitations

* **False Positives:** The JS secret detection uses illustrative regexes and may return false positives. Validate findings manually before action.
* **SSL Verification:** The script suppresses `InsecureRequestWarning` when encountering self-signed certs. Interpret such results carefully.
* **Threading:** Increasing thread count speeds up scans but can overload networks or cause timeouts. Tune according to your environment.
* **Permissions:** Respect `robots.txt` and the target's policy when crawling resources.

---

## 🛠️ Customization Tips

* Extend the port list for custom services.
* Improve regex patterns for secret scanning to reduce false positives.
* Add output filters or a CLI flag wrapper for non-interactive batch use.

---

## 🧪 Example

Interactive run (example):

```
$ python domain_analysis.py
Enter input file: domains.txt
Enter output file: results.xlsx
Max threads [10]: 20
Processing 12 domains...
Done. Results saved to results.xlsx
```

---

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome:

1. Fork the repo
2. Create a feature branch
3. Open a pull request

If you add major features (e.g., improved scanning engine, better parsing), include tests and documentation.

---

## 📜 License

This project is released under the **MIT License**. See `LICENSE` for details.

---

## 🙋 Author

3xoa-offsec — Open-source offensive tooling and utilities.

---

