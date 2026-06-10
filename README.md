# APK Security Auditor

A lightweight Android APK Static Analysis Tool developed by **IMRAN SARWER**.

## Overview

APK Security Auditor is a Python-based Android security assessment tool that performs static analysis on APK files. It combines APKTool and JADX to identify common security weaknesses, insecure configurations, exposed components, and risky coding practices.

The tool generates professional TXT, JSON, and HTML reports with risk scoring and OWASP MASVS mappings.

---

## Features

### Manifest Analysis

* Debuggable application detection
* Backup enabled detection
* Exported Activities, Services, Receivers, Providers
* Dangerous permission identification
* Deep Link discovery
* Custom permission analysis
* Cleartext traffic detection

### Source Code Analysis

* Smali code scanning
* JADX Java source scanning
* Hardcoded secrets detection
* API key discovery
* JWT token detection
* Firebase endpoint discovery
* Weak cryptography detection
* Runtime command execution checks
* WebView security checks
* SharedPreferences analysis
* External storage usage detection

### Reporting

* TXT Report
* JSON Report
* HTML Report
* Risk Score Calculation
* OWASP MASVS Mapping
* APK Hashing (MD5, SHA1, SHA256)

---

## Requirements

* Python 3
* APKTool
* JADX
* Java Runtime Environment (JRE)

Install dependencies:

```bash
sudo apt update

sudo apt install -y \
python3 \
python3-pip \
apktool \
jadx \
default-jre
```

---

## Usage

```bash
python3 apk_auditor.py app.apk
```

Example:

```bash
python3 apk_auditor.py samples/test.apk
```

---

## Output

Reports are generated automatically:

```text
reports/
├── app_report.txt
├── app_report.json
└── app_report.html
```

---

## Sample Findings

* App is debuggable
* Backup is enabled
* Exported Activities
* Hardcoded Secrets
* Weak Cryptography
* Insecure HTTP URLs
* SharedPreferences Usage
* External Storage Access

---

## Project Structure

```text
APK-Security-Auditor/
│
├── apk_auditor.py
├── README.md
├── samples/
├── reports/
├── output/
└── screenshots/
```

---

## Roadmap

Future versions will include:

* VirusTotal Integration
* MobSF Integration
* SSL Pinning Detection
* Firebase Security Analysis
* APK Signing Verification
* Frida Detection
* Root Detection Analysis
* PDF Report Generation
* CVSS Scoring
* MITRE ATT&CK Mapping

---

## Author

**IMRAN SARWER**

Android Application Security Research Project

Developed for learning Android Security, Static Analysis, and Secure Mobile Application Assessment.

---

## Disclaimer

This tool is intended for educational purposes, security research, and authorized security assessments only.

Always obtain proper authorization before analyzing third-party applications.
