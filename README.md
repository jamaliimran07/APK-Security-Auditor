# APK Security Auditor

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-green)
![Version](https://img.shields.io/badge/Version-v2.3.2-orange)
![Android](https://img.shields.io/badge/Android-Security-brightgreen)

A lightweight Android APK Static Analysis Tool developed by **IMRAN SARWER**.

---

## Overview

APK Security Auditor is a Python-based Android Security Assessment Tool that performs static analysis on Android APK files.

The tool leverages **APKTool** and **JADX** to identify security weaknesses, insecure configurations, exposed components, hardcoded secrets, weak cryptography, and risky coding practices.

It generates professional reports with risk scoring and OWASP MASVS mappings to help security researchers and penetration testers assess Android applications.

---

## Key Features

### Android Manifest Analysis

- Debuggable Application Detection
- Backup Enabled Detection
- Exported Activities Detection
- Exported Services Detection
- Exported Receivers Detection
- Exported Providers Detection
- Dangerous Permissions Analysis
- Deep Link Discovery
- Custom Permission Analysis
- Cleartext Traffic Detection
- Network Security Configuration Analysis

---

### Source Code Analysis

#### Smali Analysis

- Hardcoded Secrets Detection
- API Key Discovery
- JWT Token Detection
- Firebase Endpoint Detection
- SharedPreferences Usage Detection
- External Storage Usage Detection
- Runtime Command Execution Detection
- WebView Security Checks
- Weak Cryptography Detection

#### JADX Java Source Analysis

- Decompiled Java Source Inspection
- Security Pattern Detection
- Risky API Usage Detection
- Storage Security Checks
- Network Security Checks

---

### Reporting Features

- TXT Report Generation
- JSON Report Generation
- HTML Report Generation
- APK Hashing

  - MD5
  - SHA1
  - SHA256

- Risk Score Calculation
- OWASP MASVS Mapping
- Executive Summary Generation

---

## Screenshots

### HTML Security Report

![HTML Report](html-reports.png)

---

### Security Findings

![Security Findings](findings.png)

---

### Generated Reports

![Reports](reports.png)

---

## Installation

### Requirements

- Python 3
- APKTool
- JADX
- Java Runtime Environment (JRE)

### Install Dependencies

```bash
sudo apt update

sudo apt install -y \
python3 \
python3-pip \
apktool \
jadx \
default-jre
```

Verify Installation:

```bash
python3 --version
apktool --version
jadx --version
java -version
```

---

## Usage

Analyze an APK:

```bash
python3 apk_auditor.py app.apk
```

Example:

```bash
python3 apk_auditor.py samples/test.apk
```

---

## Output

After execution, the tool automatically generates:

```text
reports/
├── app_report.txt
├── app_report.json
└── app_report.html
```

---

## Example Findings

The tool can detect:

- Debuggable Applications
- Backup Enabled Applications
- Exported Components
- Hardcoded Secrets
- Weak Cryptography
- Insecure HTTP URLs
- SharedPreferences Usage
- External Storage Access
- Firebase Endpoints
- Runtime Command Execution
- WebView Security Issues

---

## Project Structure

```text
APK-Security-Auditor/
│
├── apk_auditor.py
├── README.md
├── .gitignore
│
├── reports/
├── output/
├── screenshots/
│
├── findings.png
├── html-reports.png
└── reports.png
```

---

## Current Capabilities

| Feature | Status |
|----------|----------|
| APKTool Integration | ✅ |
| JADX Integration | ✅ |
| Manifest Analysis | ✅ |
| Smali Analysis | ✅ |
| Java Source Analysis | ✅ |
| Risk Scoring | ✅ |
| HTML Reports | ✅ |
| JSON Reports | ✅ |
| OWASP MASVS Mapping | ✅ |

---

## Roadmap (v3.0)

Future improvements:

- VirusTotal API Integration
- MobSF Integration
- SSL Pinning Detection
- APK Certificate Analysis
- APK Signing Verification
- Firebase Misconfiguration Checks
- Frida Detection
- Root Detection Analysis
- Emulator Detection
- PDF Report Generation
- CVSS Scoring
- MITRE ATT&CK Mapping

---

## Author

### IMRAN SARWER

Cyber Security Student | Android Security Researcher

Developed as a practical Android Application Security Analysis project to strengthen Mobile Security, Secure Coding Review, and Static Analysis skills.

GitHub:
https://github.com/jamaliimran07

---

## Disclaimer

This tool is intended for:

- Educational Purposes
- Security Research
- Authorized Security Assessments

Always obtain proper authorization before testing or analyzing third-party applications.

The author assumes no responsibility for misuse of this tool.

---

⭐ If you find this project useful, consider giving it a star.
