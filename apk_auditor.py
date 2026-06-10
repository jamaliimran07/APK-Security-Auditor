import os
import sys
import subprocess
import re
import json
import html
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime

AUTHOR = "IMRAN SARWER"
TOOL_NAME = "APK Security Auditor"
VERSION = "2.3.2"

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def banner():
    print(r"""
      █████╗ ██████╗ ██╗  ██╗
     ██╔══██╗██╔══██╗██║ ██╔╝
     ███████║██████╔╝█████╔╝
     ██╔══██║██╔═══╝ ██╔═██╗
     ██║  ██║██║     ██║  ██╗
     ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝

          SECURITY AUDITOR
    ════════════════════════════════
      Android Application Scanner
      Static APK + JADX Source Scan
    ════════════════════════════════

      Created By : IMRAN-SARWER
      Version    : 2.3.2
      Platform   : Linux / Kali
    """)

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def command_exists(cmd):
    return run_cmd(f"command -v {cmd}").returncode == 0

def add_finding(findings, severity, category, issue, evidence, recommendation, owasp):
    findings.append({
        "severity": severity,
        "category": category,
        "issue": issue,
        "evidence": evidence,
        "recommendation": recommendation,
        "owasp": owasp
    })

def get_attr(element, attr):
    return element.attrib.get(ANDROID_NS + attr)

def parse_manifest(manifest_path):
    try:
        return ET.parse(manifest_path).getroot()
    except Exception:
        return None

def calculate_file_hashes(file_path):
    hashes = {"md5": "Unknown", "sha1": "Unknown", "sha256": "Unknown"}

    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        hashes["md5"] = md5.hexdigest()
        hashes["sha1"] = sha1.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception:
        pass

    return hashes

def calculate_risk(findings):
    score = 0

    for f in findings:
        if f["severity"] == "HIGH":
            score += 15
        elif f["severity"] == "MEDIUM":
            score += 5
        elif f["severity"] == "LOW":
            score += 2
        elif f["severity"] == "INFO":
            score += 1

    score = min(score, 95)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return score, level

def print_terminal_table(findings, metadata):
    score, level = calculate_risk(findings)

    high = sum(1 for x in findings if x["severity"] == "HIGH")
    medium = sum(1 for x in findings if x["severity"] == "MEDIUM")
    low = sum(1 for x in findings if x["severity"] == "LOW")
    info = sum(1 for x in findings if x["severity"] == "INFO")

    print("\n" + "=" * 72)
    print("SCAN SUMMARY")
    print("=" * 72)
    print(f"{'Package':<22}: {metadata.get('package', 'Unknown')}")
    print(f"{'App Label':<22}: {metadata.get('app_label', 'Unknown')}")
    print(f"{'Version Name':<22}: {metadata.get('version_name', 'Unknown')}")
    print(f"{'Version Code':<22}: {metadata.get('version_code', 'Unknown')}")
    print(f"{'Min SDK':<22}: {metadata.get('min_sdk', 'Unknown')}")
    print(f"{'Target SDK':<22}: {metadata.get('target_sdk', 'Unknown')}")
    print(f"{'JADX Scan':<22}: {metadata.get('jadx_scan', 'Not Run')}")
    print(f"{'Risk Score':<22}: {score}/100 ({level})")
    print("-" * 72)
    print(f"{'Severity':<15}{'Count':<10}")
    print("-" * 72)
    print(f"{'HIGH':<15}{high:<10}")
    print(f"{'MEDIUM':<15}{medium:<10}")
    print(f"{'LOW':<15}{low:<10}")
    print(f"{'INFO':<15}{info:<10}")
    print("=" * 72 + "\n")

def extract_app_label_from_resources(decompiled_dir, raw_label):
    if not raw_label:
        return "Unknown"

    if not raw_label.startswith("@string/"):
        return raw_label

    string_name = raw_label.replace("@string/", "")
    strings_path = os.path.join(decompiled_dir, "res", "values", "strings.xml")

    if not os.path.exists(strings_path):
        return raw_label

    try:
        root = ET.parse(strings_path).getroot()

        for string in root.findall("string"):
            if string.attrib.get("name") == string_name:
                return string.text if string.text else raw_label
    except Exception:
        return raw_label

    return raw_label

def scan_manifest(manifest_path, findings, metadata, decompiled_dir):
    root = parse_manifest(manifest_path)

    with open(manifest_path, "r", errors="ignore") as f:
        data = f.read()

    if root is not None:
        metadata["package"] = root.attrib.get("package", "Unknown")
        metadata["version_name"] = root.attrib.get(ANDROID_NS + "versionName", "Unknown")
        metadata["version_code"] = root.attrib.get(ANDROID_NS + "versionCode", "Unknown")

        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            metadata["min_sdk"] = get_attr(uses_sdk, "minSdkVersion") or "Unknown"
            metadata["target_sdk"] = get_attr(uses_sdk, "targetSdkVersion") or "Unknown"

    package_name = metadata.get("package", "")

    if 'android:debuggable="true"' in data:
        add_finding(
            findings,
            "HIGH",
            "Manifest",
            "App is debuggable",
            'android:debuggable="true"',
            "Disable debugging in production builds.",
            "OWASP MASVS-CODE / Security Misconfiguration"
        )

    if 'android:allowBackup="true"' in data:
        add_finding(
            findings,
            "MEDIUM",
            "Manifest",
            "Backup is allowed",
            'android:allowBackup="true"',
            "Set android:allowBackup=false for sensitive apps.",
            "OWASP MASVS-STORAGE"
        )

    if 'android:usesCleartextTraffic="true"' in data:
        add_finding(
            findings,
            "HIGH",
            "Network",
            "Cleartext traffic is enabled",
            'android:usesCleartextTraffic="true"',
            "Disable cleartext traffic and enforce HTTPS.",
            "OWASP MASVS-NETWORK"
        )

    match = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', data)
    if match:
        metadata["network_security_config"] = match.group(1) + ".xml"
        add_finding(
            findings,
            "INFO",
            "Network",
            "Network Security Config found",
            f"@xml/{match.group(1)}",
            "Review network security config for cleartext or trust anchors.",
            "OWASP MASVS-NETWORK"
        )

    dangerous_permissions = [
        "READ_SMS",
        "SEND_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "RECORD_AUDIO",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE",
        "READ_CALL_LOG",
        "WRITE_CALL_LOG",
        "CALL_PHONE"
    ]

    for perm in dangerous_permissions:
        if perm in data:
            add_finding(
                findings,
                "INFO",
                "Permissions",
                "Dangerous permission used",
                perm,
                "Check whether this permission is required.",
                "OWASP MASVS-PLATFORM"
            )

    if root is None:
        return

    app = root.find("application")
    if app is None:
        return

    raw_label = get_attr(app, "label")
    metadata["app_label"] = extract_app_label_from_resources(decompiled_dir, raw_label)

    component_tags = {
        "activity": "Activity",
        "service": "Service",
        "receiver": "Receiver",
        "provider": "Provider"
    }

    for tag, label in component_tags.items():
        for comp in app.findall(tag):
            name = get_attr(comp, "name") or "Unknown"
            exported = get_attr(comp, "exported")
            permission = get_attr(comp, "permission")

            full_name = name
            if name.startswith(".") and package_name:
                full_name = package_name + name

            is_app_component = package_name in full_name if package_name else True

            if exported == "true" and is_app_component:
                severity = "MEDIUM"

                if permission is None:
                    severity = "HIGH"

                add_finding(
                    findings,
                    severity,
                    "Exported Component",
                    f"Exported {label} found",
                    f"{label}: {full_name}, permission: {permission if permission else 'None'}",
                    "Restrict exported components or protect them with permissions.",
                    "OWASP MASVS-PLATFORM"
                )

            for intent_filter in comp.findall("intent-filter"):
                for data_tag in intent_filter.findall("data"):
                    scheme = get_attr(data_tag, "scheme")
                    host = get_attr(data_tag, "host")
                    path = get_attr(data_tag, "path")

                    if scheme or host:
                        add_finding(
                            findings,
                            "INFO",
                            "Deep Link",
                            f"Deep link found in {label}",
                            f"{full_name} -> scheme={scheme}, host={host}, path={path}",
                            "Validate deep link input and avoid exposing sensitive flows.",
                            "OWASP MASVS-PLATFORM"
                        )

    for perm in root.findall("permission"):
        perm_name = get_attr(perm, "name") or "Unknown"
        protection = get_attr(perm, "protectionLevel") or "Unknown"

        add_finding(
            findings,
            "INFO",
            "Custom Permission",
            "Custom permission declared",
            f"{perm_name}, protectionLevel={protection}",
            "Use signature-level protection for sensitive permissions.",
            "OWASP MASVS-PLATFORM"
        )

def scan_network_security_config(decompiled_dir, metadata, findings):
    config_file = metadata.get("network_security_config")

    if not config_file:
        return

    config_path = os.path.join(decompiled_dir, "res", "xml", config_file)

    if not os.path.exists(config_path):
        return

    with open(config_path, "r", errors="ignore") as f:
        data = f.read()

    if 'cleartextTrafficPermitted="true"' in data:
        add_finding(
            findings,
            "HIGH",
            "Network Security Config",
            "Cleartext traffic permitted in network security config",
            config_file,
            "Set cleartextTrafficPermitted=false.",
            "OWASP MASVS-NETWORK"
        )

    if "trust-anchors" in data and "@raw" in data:
        add_finding(
            findings,
            "MEDIUM",
            "Network Security Config",
            "Custom trust anchors detected",
            config_file,
            "Verify custom CA certificates are required and secure.",
            "OWASP MASVS-NETWORK"
        )

    if "debug-overrides" in data:
        add_finding(
            findings,
            "MEDIUM",
            "Network Security Config",
            "Debug overrides found",
            config_file,
            "Remove debug trust overrides from production apps.",
            "OWASP MASVS-NETWORK"
        )

def should_ignore_file(relative_path, package_path):
    ignored = [
        "original/META-INF",
        "LICENSE",
        "NOTICE",
        "androidx/",
        "kotlin/",
        "kotlinx/",
        "okhttp3/",
        "okio/",
        "retrofit2/",
        "com/google/",
        "com/android/",
        "res/values-",
        "res/color",
        "res/drawable",
        "res/mipmap"
    ]

    if any(x in relative_path for x in ignored):
        return True

    if relative_path.startswith("smali") and package_path:
        if package_path not in relative_path:
            return True

    return False

def scan_text_files(scan_dir, findings, metadata, source_type):
    package_name = metadata.get("package", "")
    package_path = package_name.replace(".", "/") if package_name != "Unknown" else ""

    url_pattern = r'http://[^\s"\'<>]+'
    https_pattern = r'https://[^\s"\'<>]+'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    secret_patterns = {
        "Google API Key": r'AIza[0-9A-Za-z\-_]{20,}',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Bearer Token": r'(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}',
        "JWT Token": r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        "Hardcoded Password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
        "Generic API Key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{10,}["\']',
        "Firebase URL": r'https?://[A-Za-z0-9\-]+\.firebaseio\.com[^\s"\'<>]*'
    }

    weak_crypto_patterns = {
        "MD5": r'(?i)(MessageDigest\.getInstance\("MD5"\)|getInstance\("MD5"\))',
        "SHA1": r'(?i)(MessageDigest\.getInstance\("SHA-1"\)|getInstance\("SHA1"\)|getInstance\("SHA-1"\))',
        "DES": r'(?i)(Cipher\.getInstance\("DES"|getInstance\("DES"|DESede)',
        "RC4": r'(?i)(Cipher\.getInstance\("RC4"|getInstance\("RC4")'
    }

    risky_patterns = {
        "Runtime Command Execution": r'Runtime\.getRuntime\(\)|\.exec\(',
        "WebView JavaScript Enabled": r'setJavaScriptEnabled\(true\)',
        "JavaScript Interface Exposed": r'addJavascriptInterface\(',
        "Insecure Trust Manager": r'X509TrustManager|checkServerTrusted',
        "Hostname Verification Disabled": r'HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER',
        "SharedPreferences Usage": r'SharedPreferences|getSharedPreferences',
        "Root Detection Logic": r'(?i)(/system/bin/su|/system/xbin/su|magisk|busybox|superuser)',
        "SSL Pinning Logic": r'CertificatePinner|pinning|checkServerTrusted',
        "Clipboard Usage": r'ClipboardManager|getPrimaryClip|setPrimaryClip',
        "External Storage Usage": r'getExternalStorageDirectory|getExternalFilesDir',
        "WebView File Access": r'setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs\(true\)'
    }

    positive_patterns = {
        "Biometric API Usage": r'BiometricPrompt|FingerprintManager',
        "AES Usage Detected": r'Cipher\.getInstance\("AES|AES/GCM|AES/CBC',
        "RSA Usage Detected": r'Cipher\.getInstance\("RSA|KeyPairGenerator',
        "SSL Pinning Feature Detected": r'CertificatePinner'
    }

    for root, dirs, files in os.walk(scan_dir):
        for file in files:
            file_path = os.path.join(root, file)

            if file_path.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".so", ".dex", ".arsc", ".class")):
                continue

            relative_path = file_path.replace(scan_dir + "/", "")

            if source_type == "SMALI":
                if should_ignore_file(relative_path, package_path):
                    continue

            if source_type == "JADX":
                if package_path and package_path not in relative_path:
                    continue

            try:
                with open(file_path, "r", errors="ignore") as f:
                    data = f.read()
            except Exception:
                continue

            source_label = f"{source_type}: {relative_path}"

            for url in set(re.findall(url_pattern, data)):
                if any(x in url for x in ["schemas.android.com", "www.w3.org", "apache.org/licenses", "localhost", "127.0.0.1"]):
                    continue

                add_finding(
                    findings,
                    "MEDIUM",
                    "Network",
                    "Insecure HTTP URL found",
                    f"{url} in {source_label}",
                    "Use HTTPS instead of HTTP.",
                    "OWASP MASVS-NETWORK"
                )

            for url in set(re.findall(https_pattern, data)):
                if "firebaseio.com" in url:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "Cloud/Firebase",
                        "Firebase endpoint found",
                        f"{url} in {source_label}",
                        "Check Firebase database rules and access control.",
                        "OWASP MASVS-NETWORK / STORAGE"
                    )

            for ip in set(re.findall(ip_pattern, data)):
                if ip.startswith(("127.", "0.", "255.")):
                    continue

                add_finding(
                    findings,
                    "LOW",
                    "Network",
                    "Hardcoded IP address found",
                    f"{ip} in {source_label}",
                    "Avoid hardcoded IPs in production apps.",
                    "OWASP MASVS-NETWORK"
                )

            for secret_name, pattern in secret_patterns.items():
                if re.search(pattern, data):
                    add_finding(
                        findings,
                        "HIGH",
                        "Secrets",
                        f"{secret_name} found",
                        f"Possible secret in {source_label}",
                        "Remove secrets from source code and rotate exposed keys.",
                        "OWASP MASVS-STORAGE"
                    )

            for crypto_name, pattern in weak_crypto_patterns.items():
                if re.search(pattern, data):
                    add_finding(
                        findings,
                        "MEDIUM",
                        "Crypto",
                        f"Weak cryptography detected: {crypto_name}",
                        f"{crypto_name} usage in {source_label}",
                        "Use modern algorithms like AES-GCM and SHA-256/SHA-3.",
                        "OWASP MASVS-CRYPTO"
                    )

            for risky_name, pattern in risky_patterns.items():
                if re.search(pattern, data):
                    severity = "MEDIUM"

                    if risky_name in [
                        "Runtime Command Execution",
                        "JavaScript Interface Exposed",
                        "Hostname Verification Disabled",
                        "WebView File Access"
                    ]:
                        severity = "HIGH"

                    add_finding(
                        findings,
                        severity,
                        "Code",
                        risky_name,
                        f"Pattern found in {source_label}",
                        "Review this implementation carefully.",
                        "OWASP MASVS-CODE / PLATFORM"
                    )

            for positive_name, pattern in positive_patterns.items():
                if re.search(pattern, data):
                    add_finding(
                        findings,
                        "INFO",
                        "Security Feature",
                        positive_name,
                        f"Pattern found in {source_label}",
                        "This may indicate security-related implementation. Verify correct usage.",
                        "OWASP MASVS-CRYPTO / AUTH"
                    )

def run_jadx_scan(apk_path, jadx_dir, metadata):
    if not command_exists("jadx"):
        metadata["jadx_scan"] = "Skipped - jadx not installed"
        return False

    if os.path.exists(jadx_dir):
        run_cmd(f"rm -rf '{jadx_dir}'")

    os.makedirs(jadx_dir, exist_ok=True)

    cmd = f"timeout 180 jadx --no-res --no-debug-info -d '{jadx_dir}' '{apk_path}' > /dev/null 2>&1"
    result = subprocess.run(cmd, shell=True)

    if os.path.exists(jadx_dir) and os.listdir(jadx_dir):
        metadata["jadx_scan"] = "Completed"
        return True

    metadata["jadx_scan"] = "Failed"
    metadata["jadx_error"] = "JADX failed or timed out. Try increasing timeout or scanning a smaller APK."
    return False

def remove_duplicate_findings(findings):
    seen = set()
    clean = []

    for item in findings:
        key = (
            item["severity"],
            item["category"],
            item["issue"],
            item["evidence"]
        )

        if key not in seen:
            seen.add(key)
            clean.append(item)

    return clean

def save_txt_report(findings, report_path, apk_name, metadata):
    score, level = calculate_risk(findings)

    with open(report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write(f"{TOOL_NAME} v{VERSION}\n")
        f.write(f"Created by: {AUTHOR}\n")
        f.write(f"APK Name: {apk_name}\n")
        f.write(f"App Label: {metadata.get('app_label', 'Unknown')}\n")
        f.write(f"Package: {metadata.get('package', 'Unknown')}\n")
        f.write(f"Version Name: {metadata.get('version_name', 'Unknown')}\n")
        f.write(f"Version Code: {metadata.get('version_code', 'Unknown')}\n")
        f.write(f"Min SDK: {metadata.get('min_sdk', 'Unknown')}\n")
        f.write(f"Target SDK: {metadata.get('target_sdk', 'Unknown')}\n")
        f.write(f"JADX Scan: {metadata.get('jadx_scan', 'Not Run')}\n")

        if metadata.get("jadx_error"):
            f.write(f"JADX Error: {metadata.get('jadx_error')}\n")

        f.write(f"MD5: {metadata.get('md5', 'Unknown')}\n")
        f.write(f"SHA1: {metadata.get('sha1', 'Unknown')}\n")
        f.write(f"SHA256: {metadata.get('sha256', 'Unknown')}\n")
        f.write(f"Scan Time: {datetime.now()}\n")
        f.write("=" * 70 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 70 + "\n")
        f.write(f"Overall Risk Score: {score}/100\n")
        f.write(f"Risk Level: {level}\n")
        f.write(f"Total Findings: {len(findings)}\n")
        f.write(f"High: {sum(1 for x in findings if x['severity'] == 'HIGH')}\n")
        f.write(f"Medium: {sum(1 for x in findings if x['severity'] == 'MEDIUM')}\n")
        f.write(f"Low: {sum(1 for x in findings if x['severity'] == 'LOW')}\n")
        f.write(f"Info: {sum(1 for x in findings if x['severity'] == 'INFO')}\n\n")

        if not findings:
            f.write("No major issues found.\n")
            return

        f.write("DETAILED FINDINGS\n")
        f.write("-" * 70 + "\n\n")

        for i, item in enumerate(findings, start=1):
            f.write(f"[{i}] Severity: {item['severity']}\n")
            f.write(f"Category: {item['category']}\n")
            f.write(f"Issue: {item['issue']}\n")
            f.write(f"Evidence: {item['evidence']}\n")
            f.write(f"OWASP Mapping: {item['owasp']}\n")
            f.write(f"Recommendation: {item['recommendation']}\n")
            f.write("-" * 70 + "\n")

def save_json_report(findings, report_path, apk_name, metadata):
    score, level = calculate_risk(findings)

    report = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "apk_name": apk_name,
        "metadata": metadata,
        "scan_time": str(datetime.now()),
        "risk_score": score,
        "risk_level": level,
        "summary": {
            "total": len(findings),
            "high": sum(1 for x in findings if x["severity"] == "HIGH"),
            "medium": sum(1 for x in findings if x["severity"] == "MEDIUM"),
            "low": sum(1 for x in findings if x["severity"] == "LOW"),
            "info": sum(1 for x in findings if x["severity"] == "INFO")
        },
        "findings": findings
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

def save_html_report(findings, report_path, apk_name, metadata):
    score, level = calculate_risk(findings)

    rows = ""

    for i, item in enumerate(findings, start=1):
        rows += f"""
        <tr>
            <td>{i}</td>
            <td>{html.escape(item['severity'])}</td>
            <td>{html.escape(item['category'])}</td>
            <td>{html.escape(item['issue'])}</td>
            <td>{html.escape(item['evidence'])}</td>
            <td>{html.escape(item['owasp'])}</td>
            <td>{html.escape(item['recommendation'])}</td>
        </tr>
        """

    html_data = f"""
<!DOCTYPE html>
<html>
<head>
    <title>APK Security Auditor Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            padding: 25px;
        }}
        .container {{
            background: white;
            padding: 25px;
            border-radius: 10px;
        }}
        h1 {{
            color: #222;
        }}
        .badge {{
            padding: 8px 12px;
            border-radius: 6px;
            background: #222;
            color: white;
            display: inline-block;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            font-size: 13px;
        }}
        th {{
            background: #222;
            color: white;
        }}
        tr:nth-child(even) {{
            background: #f2f2f2;
        }}
        .meta {{
            background: #f1f1f1;
            padding: 12px;
            border-radius: 6px;
            font-size: 14px;
            word-break: break-all;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>APK Security Auditor v{VERSION}</h1>
    <p><b>Created by:</b> {html.escape(AUTHOR)}</p>

    <div class="meta">
        <p><b>APK:</b> {html.escape(apk_name)}</p>
        <p><b>App Label:</b> {html.escape(metadata.get('app_label', 'Unknown'))}</p>
        <p><b>Package:</b> {html.escape(metadata.get('package', 'Unknown'))}</p>
        <p><b>Version:</b> {html.escape(metadata.get('version_name', 'Unknown'))}</p>
        <p><b>Min SDK:</b> {html.escape(metadata.get('min_sdk', 'Unknown'))}</p>
        <p><b>Target SDK:</b> {html.escape(metadata.get('target_sdk', 'Unknown'))}</p>
        <p><b>JADX Scan:</b> {html.escape(metadata.get('jadx_scan', 'Not Run'))}</p>
        <p><b>MD5:</b> {html.escape(metadata.get('md5', 'Unknown'))}</p>
        <p><b>SHA1:</b> {html.escape(metadata.get('sha1', 'Unknown'))}</p>
        <p><b>SHA256:</b> {html.escape(metadata.get('sha256', 'Unknown'))}</p>
    </div>

    <p><b>Risk Score:</b> <span class="badge">{score}/100 - {level}</span></p>
    <p><b>Total Findings:</b> {len(findings)}</p>

    <table>
        <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Category</th>
            <th>Issue</th>
            <th>Evidence</th>
            <th>OWASP</th>
            <th>Recommendation</th>
        </tr>
        {rows}
    </table>
</div>
</body>
</html>
"""

    with open(report_path, "w") as f:
        f.write(html_data)

def create_screenshot_readme():
    os.makedirs("screenshots", exist_ok=True)

    with open("screenshots/README.txt", "w") as f:
        f.write("APK Security Auditor Screenshots\n")
        f.write("================================\n\n")
        f.write("Suggested screenshots:\n")
        f.write("1. Terminal banner and scan summary\n")
        f.write("2. HTML report opened in browser\n")
        f.write("3. Reports folder showing TXT, JSON, and HTML files\n\n")
        f.write("Command:\n")
        f.write("firefox reports/test_report.html\n")

def main():
    if len(sys.argv) != 2:
        banner()
        print("Usage: python3 apk_auditor.py app.apk")
        sys.exit(1)

    apk_path = sys.argv[1]
    apk_path = os.path.abspath(apk_path)

    if not os.path.exists(apk_path):
        banner()
        print("APK file not found.")
        sys.exit(1)

    os.makedirs("output", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    create_screenshot_readme()

    apk_name = os.path.basename(apk_path).replace(".apk", "")
    out_dir = os.path.abspath(f"output/{apk_name}")
    jadx_dir = os.path.abspath(f"output/{apk_name}_jadx")
 
    banner()

    file_hashes = calculate_file_hashes(apk_path)

    print("[+] Decompiling APK with apktool...")
    run_cmd(f"apktool d -f '{apk_path}' -o '{out_dir}' > /dev/null 2>&1")

    manifest_path = f"{out_dir}/AndroidManifest.xml"

    if not os.path.exists(manifest_path):
        print("Manifest not found.")
        sys.exit(1)

    findings = []

    metadata = {
        "package": "Unknown",
        "app_label": "Unknown",
        "version_name": "Unknown",
        "version_code": "Unknown",
        "min_sdk": "Unknown",
        "target_sdk": "Unknown",
        "network_security_config": None,
        "jadx_scan": "Not Run",
        "md5": file_hashes["md5"],
        "sha1": file_hashes["sha1"],
        "sha256": file_hashes["sha256"]
    }

    print("[+] Scanning AndroidManifest.xml...")
    scan_manifest(manifest_path, findings, metadata, out_dir)

    print("[+] Scanning Network Security Config...")
    scan_network_security_config(out_dir, metadata, findings)

    print("[+] Scanning smali/app source files...")
    scan_text_files(out_dir, findings, metadata, "SMALI")

    print("[+] Running JADX Java source scan...")

    if run_jadx_scan(apk_path, jadx_dir, metadata):
        scan_text_files(jadx_dir, findings, metadata, "JADX")
    else:
        print("[!] JADX failed. Check report for error details.")

    findings = remove_duplicate_findings(findings)

    print_terminal_table(findings, metadata)

    txt_report = f"reports/{apk_name}_report.txt"
    json_report = f"reports/{apk_name}_report.json"
    html_report = f"reports/{apk_name}_report.html"

    save_txt_report(findings, txt_report, apk_name, metadata)
    save_json_report(findings, json_report, apk_name, metadata)
    save_html_report(findings, html_report, apk_name, metadata)

    score, level = calculate_risk(findings)

    print("[+] Full scan completed.")
    print(f"[+] Risk Score: {score}/100 ({level})")
    print(f"[+] TXT Report : {txt_report}")
    print(f"[+] JSON Report: {json_report}")
    print(f"[+] HTML Report: {html_report}")
    print("[+] Screenshots guide created: screenshots/README.txt")

if __name__ == "__main__":
    main()
