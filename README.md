# Automated Email Forensic Analyzer

## Overview

The **Automated Email Forensic Analyzer** is a Python-based Command-Line Interface (CLI) tool designed to accelerate the workflow of Security Operations Center (SOC) analysts and incident responders. It automates the parsing of `.eml` files, extracts routing data and hidden payloads, and enriches Indicators of Compromise (IOCs) using industry-standard Threat Intelligence APIs.

This tool prioritizes Operational Security (OpSec) by safely defanging extracted IPs and URLs, and outputs structured JSON reports compatible with SIEM ingestion.

## Key Features

* **Automated MIME Parsing:** Unpacks email layers to extract Sender, Reply-To, and hidden URLs within plaintext and HTML bodies.
* **Authentication Validation:** Parses `Authentication-Results` headers to immediately flag failed SPF, DKIM, and DMARC checks.
* **Threat Intelligence Integration:**

  * **IPinfo:** Enriches extracted public IPv4 routing addresses with geolocation, organization, and ASN data.
  * **VirusTotal (vt-py):** Queries payload URLs against dozens of security vendors to identify malicious and suspicious links.
* **OpSec Enforcement:** Automatically defangs IOCs (e.g., `117\[.]121\[.]214\[.]50`, `hxxp://malicious\[.]com`) to prevent accidental execution during analysis or ticketing.
* **JSON Report Generation:** Compiles findings into a timestamped, structured `.json` file for chain-of-custody preservation and downstream automation.
* **Secure Credential Management:** Supports local `.env` files and dynamic CLI arguments to prevent hardcoded API keys.

## Prerequisites

* Python 3.8+
* Free API Key from [IPinfo.io](https://ipinfo.io/)
* Free API Key from [VirusTotal](https://www.virustotal.com/)

## Installation

1. **Clone the repository:**

```bash
   git clone https://github.com/wian1374-dev/Email-Forensic-Analyzer.git
   cd Email-Forensic-Analyzer
   ```

2. **Install dependencies:**

```bash
   pip install -r requirements.txt
   ```

## Configuration (Secure Secrets)

To avoid passing API keys in the terminal every time, create a file named `.env` in the root directory of the project.

Add your API keys to the `.env` file:

```env
IPINFO_TOKEN=your_ipinfo_token_here
VT_TOKEN=your_virustotal_token_here
```

## Usage

Run the script via the command line, pointing it to a raw `.eml` file.

**Basic execution (using `.env` for keys):**

```bash
python Email_Header_Analysis.py -f suspicious_email.eml
```

**Override or provide API keys directly via CLI:**

```bash
python Email_Header_Analysis.py -f suspicious_email.eml -a YOUR_IPINFO_KEY -vt YOUR_VT_KEY
```

### Command Line Arguments

|Flag|Name|Description|Required|
|-|-|-|-|
|`-f`|`--file`|Path to the `.eml` file to analyze.|Yes|
|`-a`|`--api`|IPinfo API Token.|No (Falls back to `.env`)|
|`-vt`|`--virustotal`|VirusTotal API Key.|No (Falls back to `.env`)|

## Output Example

The script prints a clean summary to the terminal and offers to save a highly detailed, timestamped JSON report (e.g., `email_forensic_report_20261029_141630.json`).

```text
ALERT: Failed authentication checks detected: \['spf=fail', 'dmarc=fail']
Sender Information: attacker@spoofed-domain.com
Sender IP Address: 117\[.]121\[.]214\[.]50
Sender Location: Unknown City, Beijing, CN

Payload URL: hxxps://secure-login-update\[.]com/auth
VT Score: 12 Malicious, 4 Suspicious

Would you like to save these findings in a JSON report? (y/n): y
Report saved to email\_forensic\_report\_20261029\_141630.json
```

## Disclaimer

This tool is for educational and authorized forensic analysis purposes only. Do not use this tool on systems or networks you do not own or have explicit permission to test.

