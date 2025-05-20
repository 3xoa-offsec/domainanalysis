Domain Analysis Tool
Overview
The Domain Analysis Tool is a Python script designed to perform comprehensive network reconnaissance on a list of domains or subdomains. It gathers DNS records, scans for open ports, checks HTTP/HTTPS headers, scans JavaScript files for potential secrets, and verifies SSL certificates. Results are exported to an Excel file for easy analysis.
Features

DNS Enumeration: Retrieves A, AAAA, CNAME, MX, NS, and TXT records.
Port Scanning: Checks for open ports from a predefined list (e.g., HTTP, HTTPS, FTP).
HTTP/HTTPS Analysis: Captures status codes, headers, and checks for directory listing exposure.
JavaScript Secret Scanning: Scans linked JavaScript files for potential secrets (e.g., API keys, passwords) using regex patterns.
SSL Certificate Checking: Retrieves issuer, expiry date, and status of SSL certificates.
Excel Output: Generates a detailed report in .xlsx format with all findings.

Requirements

Python 3.6+
Required Python packages:pip install dnspython requests openpyxl beautifulsoup4


Input file containing a list of domains/subdomains (one per line).

Installation

Clone this repository:git clone https://github.com/your-username/domain-analysis.git
cd domain-analysis


Install dependencies:pip install -r requirements.txt

Or manually install:pip install dnspython requests openpyxl beautifulsoup4



Usage

Prepare a text file (e.g., domains.txt) with one domain or subdomain per line.
Run the script:python domain_analysis.py


Follow the prompts:
Enter the input file name (e.g., domains.txt).
Enter the output Excel file name (e.g., results.xlsx).
Specify the maximum number of concurrent threads (default: 10).


The script will process each domain and generate an Excel file with the results.

Example
Input file (domains.txt):
example.com
sub.example.com

Run the script:
python domain_analysis.py

Output:An Excel file (e.g., results.xlsx) containing columns for DNS records, open ports, HTTP/HTTPS details, SSL certificate info, potential issues, and JavaScript secret findings.
Notes

Secret Scanning: The regex patterns for secret detection are illustrative and may produce false positives. Refine them for production use.
SSL Verification: The script suppresses InsecureRequestWarning for self-signed certificates during HTTP/HTTPS requests.
Threading: Adjust the number of threads based on your system's capabilities to avoid timeouts or excessive load.
Permissions: Ensure you have permission to scan the target domains, as unauthorized scanning may violate terms of service or laws.

License
This project is licensed under the MIT License.
Disclaimer
This tool is for educational and authorized use only. Use responsibly and ensure compliance with applicable laws and regulations.
