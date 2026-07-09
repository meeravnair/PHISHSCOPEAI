"""
PhishScope AI - Security Report Generator
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module compiles analysis results and exports reports in multiple formats:
JSON, CSV, HTML, and Markdown/PDF-equivalent text.
"""

import os
import json
import csv
from datetime import datetime
from models import ScanResult
from utils import clean_filename
from config import REPORTS_DIR, DEVELOPER_NAME, DEVELOPER_GITHUB

class ReportGenerator:
    """Handles formatting and export logic for threat analysis reports."""

    @staticmethod
    def generate_all_reports(result: ScanResult) -> dict:
        """
        Generates and saves JSON, CSV, HTML, and Markdown reports.
        
        Args:
            result (ScanResult): The threat analysis results.
            
        Returns:
            dict: File paths for all exported formats.
        """
        if not result.is_valid_url:
            return {}

        os.makedirs(REPORTS_DIR, exist_ok=True)
        
        # Generate safe unique filename prefix
        timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        url_slug = clean_filename(result.url)
        base_name = f"phishscope_{url_slug}_{timestamp_slug}"

        paths = {
            "json": os.path.join(REPORTS_DIR, f"{base_name}.json"),
            "csv": os.path.join(REPORTS_DIR, f"{base_name}.csv"),
            "html": os.path.join(REPORTS_DIR, f"{base_name}.html"),
            "markdown": os.path.join(REPORTS_DIR, f"{base_name}.md")
        }

        # 1. Export JSON Report
        ReportGenerator._export_json(result, paths["json"])

        # 2. Export CSV Report
        ReportGenerator._export_csv(result, paths["csv"])

        # 3. Export HTML Report
        ReportGenerator._export_html(result, paths["html"])

        # 4. Export Markdown Report
        ReportGenerator._export_markdown(result, paths["markdown"])

        return paths

    @staticmethod
    def _export_json(result: ScanResult, path: str):
        """Saves scan result as structured JSON."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=4)
        except Exception as e:
            print(f"[-] Failed to write JSON report: {e}")

    @staticmethod
    def _export_csv(result: ScanResult, path: str):
        """Saves key metrics as a flat CSV row."""
        try:
            feats = result.features
            r_details = result.risk_details
            ssl_c = result.ssl_details
            dom = result.domain_details
            
            headers = [
                "url", "timestamp", "risk_score", "risk_level", "ml_prediction", "ml_confidence",
                "url_length", "entropy", "dot_count", "hyphen_count", "subdomain_count",
                "ssl_valid", "ssl_issuer", "recently_registered", "is_blacklisted"
            ]
            
            row = [
                result.url,
                result.timestamp,
                r_details.final_score if r_details else "N/A",
                r_details.risk_level if r_details else "N/A",
                result.ml_prediction,
                f"{result.ml_confidence * 100:.2f}%",
                feats.url_length if feats else "N/A",
                feats.entropy_score if feats else "N/A",
                feats.dot_count if feats else "N/A",
                feats.hyphen_count if feats else "N/A",
                dom.subdomain_count if dom else "N/A",
                ssl_c.certificate_valid if ssl_c else "N/A",
                ssl_c.issuer if ssl_c and ssl_c.issuer else "None",
                dom.recently_registered if dom else "N/A",
                dom.is_blacklisted if dom else "N/A"
            ]

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerow(row)
        except Exception as e:
            print(f"[-] Failed to write CSV report: {e}")

    @staticmethod
    def _export_markdown(result: ScanResult, path: str):
        """Saves a rich text/markdown cybersecurity report (PDF alternative)."""
        try:
            r_details = result.risk_details
            feats = result.features
            ssl_c = result.ssl_details
            dom = result.domain_details

            md_content = f"""# PhishScope AI Security Threat Report
**Generated on:** {result.timestamp}
**Target URL:** {result.url}
**Developed By:** {DEVELOPER_NAME} | [GitHub]({DEVELOPER_GITHUB})

---

## 1. Executive Summary
- **Risk Score:** {r_details.final_score}/100
- **Severity Band:** **{r_details.risk_level.upper()}**
- **Machine Learning Classification:** {result.ml_prediction} ({result.ml_confidence * 100:.1f}% confidence)

### Diagnostic Overview
{result.ai_explanation}

### Remediation Recommendation
> **{result.ai_recommendation}**

---

## 2. Risk Deductions Matrix
Below are the negative risk factors identified by the PhishScope AI Risk Engine:
"""
            if r_details and r_details.reasons:
                for reason in r_details.reasons:
                    md_content += f"- {reason}\n"
            else:
                md_content += "- No risk factors detected (Score: 100/100)\n"

            md_content += f"""
---

## 3. Detailed Metrics Analysis

### A. Lexical URL Features
- **URL Length:** {feats.url_length} characters
- **Host Length:** {feats.hostname_length} characters
- **Subdomain Count:** {dom.subdomain_count}
- **Dot Count:** {feats.dot_count}
- **Digit Count:** {feats.digit_count}
- **Hyphen Count:** {feats.hyphen_count}
- **Special Character Count:** {feats.special_char_count}
- **Shannon Entropy Score:** {feats.entropy_score:.4f}

### B. SSL/TLS Verification
- **HTTPS Enabled:** {"Yes" if result.url.lower().startswith("https") else "No"}
- **SSL Certificate Exists:** {"Yes" if ssl_c.certificate_exists else "No"}
- **SSL Certificate Valid:** {"Yes" if ssl_c.certificate_valid else "No"}
- **Issuer:** {ssl_c.issuer or "N/A"}
- **Days to Expiration:** {ssl_c.days_until_expiry if ssl_c.days_until_expiry is not None else "N/A"}
- **Hostname Match:** {"Yes" if ssl_c.hostname_match else "No"}
- **SSL Diagnostic Msg:** {ssl_c.ssl_error_message or "None"}

### C. Domain Reputation and Intelligence
- **IP Address Used:** {"Yes" if dom.is_ip_address else "No"}
- **Suspicious TLD Extension:** {"Yes (." + dom.tld + ")" if dom.is_suspicious_tld else "No"}
- **Typosquatting Detected:** {"Yes" if dom.is_typosquatting else "No"}
- **Impersonated Brand:** {dom.impersonated_brand.upper() if dom.impersonated_brand else "None"}
- **Homograph Vector:** {"Yes" if dom.is_homograph_attack else "No"}
- **Registration Age:** {dom.age_in_days if dom.age_in_days is not None else "N/A"} days (Registered on: {dom.registration_date or "Unknown"})
- **Blacklist Match:** {"Yes" if dom.is_blacklisted else "No"}
- **Suspicious Keywords Found:** {", ".join(dom.suspicious_keywords_found) if dom.suspicious_keywords_found else "None"}

---
*Disclaimer: This report is generated dynamically by PhishScope AI heuristics and Machine Learning models. Use for threat intelligence purposes.*
"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(md_content)
        except Exception as e:
            print(f"[-] Failed to write Markdown report: {e}")

    @staticmethod
    def _export_html(result: ScanResult, path: str):
        """Saves a rich, print-ready HTML dashboard report."""
        try:
            r_details = result.risk_details
            feats = result.features
            ssl_c = result.ssl_details
            dom = result.domain_details
            
            # Choose color styling based on severity level
            sev_color = "#10B981"  # green
            if r_details.risk_level == "Critical":
                sev_color = "#EF4444"  # red
            elif r_details.risk_level == "High":
                sev_color = "#F97316"  # orange
            elif r_details.risk_level == "Medium":
                sev_color = "#F59E0B"  # yellow
            elif r_details.risk_level == "Low":
                sev_color = "#3B82F6"  # blue

            # Dynamic list of deductions
            deductions_list = "".join([f"<li>{r}</li>" for r in r_details.reasons]) if r_details.reasons else "<li>No risk deductions applied.</li>"
            
            # Dynamic keywords
            keywords_badge = ", ".join([f"<span class='badge'>{kw}</span>" for kw in dom.suspicious_keywords_found]) if dom.suspicious_keywords_found else "None"

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishScope AI Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --accent-color: {sev_color};
            --border-color: #334155;
        }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
        }}
        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand h1 {{
            margin: 0;
            color: #ef4444;
            font-size: 28px;
        }}
        .brand p {{
            margin: 5px 0 0 0;
            color: #94a3b8;
            font-size: 14px;
        }}
        .meta-info {{
            text-align: right;
            font-size: 13px;
            color: #94a3b8;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        .card h3 {{
            margin-top: 0;
            color: #3b82f6;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }}
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 8px solid var(--accent-color);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            margin: 0 auto 15px auto;
            background: rgba(0,0,0,0.2);
        }}
        .score-num {{
            font-size: 36px;
            font-weight: bold;
            color: var(--text-color);
        }}
        .score-label {{
            font-size: 12px;
            color: #94a3b8;
            text-transform: uppercase;
        }}
        .severity {{
            text-align: center;
            font-size: 20px;
            font-weight: bold;
            color: var(--accent-color);
            margin: 0;
        }}
        .recommendation {{
            background: rgba(239, 68, 68, 0.1);
            border-left: 4px solid #ef4444;
            padding: 15px;
            border-radius: 4px;
            margin-top: 20px;
            font-weight: bold;
        }}
        .recommendation.safe {{
            background: rgba(16, 185, 129, 0.1);
            border-left: 4px solid #10b981;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        table td, table th {{
            padding: 8px 12px;
            font-size: 14px;
            border-bottom: 1px solid var(--border-color);
        }}
        table th {{
            text-align: left;
            color: #94a3b8;
        }}
        .badge {{
            background: #ef4444;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            color: white;
        }}
        footer {{
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 15px;
            text-align: center;
            font-size: 12px;
            color: #64748b;
        }}
        @media print {{
            body {{
                background-color: white;
                color: black;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
                border: none;
                width: 100%;
                max-width: 100%;
                padding: 0;
            }}
            .card {{
                border: 1px solid #ddd;
                background: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>PhishScope AI</h1>
                <p>Threat Intelligence & Risk Assessment Platform</p>
            </div>
            <div class="meta-info">
                <strong>Audit Time:</strong> {result.timestamp}<br>
                <strong>Target:</strong> {result.url}
            </div>
        </header>

        <section class="grid">
            <div class="card" style="display: flex; flex-direction: column; justify-content: center;">
                <div class="score-circle">
                    <span class="score-num">{r_details.final_score}</span>
                    <span class="score-label">Risk Score</span>
                </div>
                <p class="severity">{r_details.risk_level.upper()} RISK BAND</p>
            </div>
            <div class="card">
                <h3>Analysis Verdict</h3>
                <p><strong>ML Prediction:</strong> {result.ml_prediction} ({result.ml_confidence * 100:.1f}% confidence)</p>
                <div class="recommendation {'safe' if r_details.final_score >= 60 else ''}">
                    {result.ai_recommendation}
                </div>
            </div>
        </section>

        <section class="card" style="margin-bottom: 20px;">
            <h3>Threat Analysis Summary</h3>
            <p style="white-space: pre-line;">{result.ai_explanation}</p>
        </section>

        <section class="grid">
            <div class="card">
                <h3>Risk Deductions Applied</h3>
                <ul>
                    {deductions_list}
                </ul>
            </div>
            <div class="card">
                <h3>SSL Certificate Verification</h3>
                <table>
                    <tr><td>Certificate Exists</td><td><strong>{'Yes' if ssl_c.certificate_exists else 'No'}</strong></td></tr>
                    <tr><td>Certificate Valid</td><td><strong>{'Yes' if ssl_c.certificate_valid else 'No'}</strong></td></tr>
                    <tr><td>Issuer</td><td>{ssl_c.issuer or 'None'}</td></tr>
                    <tr><td>Expiry Date</td><td>{ssl_c.certificate_expiry or 'N/A'}</td></tr>
                    <tr><td>Hostname Match</td><td><strong>{'Yes' if ssl_c.hostname_match else 'No'}</strong></td></tr>
                </table>
            </div>
        </section>

        <section class="grid">
            <div class="card">
                <h3>Domain Reputation & DNS</h3>
                <table>
                    <tr><td>Using IP Address</td><td>{'Yes ('+dom.ip_version+')' if dom.is_ip_address else 'No'}</td></tr>
                    <tr><td>Suspicious TLD</td><td>{'Yes (.'+dom.tld+')' if dom.is_suspicious_tld else 'No'}</td></tr>
                    <tr><td>Typosquatting Match</td><td>{'Yes (' + dom.impersonated_brand + ')' if dom.is_typosquatting else 'No'}</td></tr>
                    <tr><td>Punycode / Homograph</td><td>{'Yes' if dom.is_homograph_attack else 'No'}</td></tr>
                    <tr><td>Registration Date</td><td>{dom.registration_date or 'Unknown'}</td></tr>
                    <tr><td>Domain Age (Days)</td><td>{dom.age_in_days if dom.age_in_days is not None else 'Unknown'}</td></tr>
                    <tr><td>Keywords Detected</td><td>{keywords_badge}</td></tr>
                    <tr><td>Matches Blacklist</td><td><strong>{'Yes' if dom.is_blacklisted else 'No'}</strong></td></tr>
                </table>
            </div>
            <div class="card">
                <h3>Lexical URL Features</h3>
                <table>
                    <tr><td>URL Length</td><td>{feats.url_length} chars</td></tr>
                    <tr><td>Hostname Length</td><td>{feats.hostname_length} chars</td></tr>
                    <tr><td>Path Length</td><td>{feats.path_length} chars</td></tr>
                    <tr><td>Query Length</td><td>{feats.query_length} chars</td></tr>
                    <tr><td>Dot Count</td><td>{feats.dot_count}</td></tr>
                    <tr><td>Hyphen Count</td><td>{feats.hyphen_count}</td></tr>
                    <tr><td>Digit Count</td><td>{feats.digit_count}</td></tr>
                    <tr><td>Special Char Count</td><td>{feats.special_char_count}</td></tr>
                    <tr><td>Shannon Entropy</td><td>{feats.entropy_score:.4f}</td></tr>
                </table>
            </div>
        </section>

        <footer>
            Developed by {DEVELOPER_NAME} &bull; <a href="{DEVELOPER_GITHUB}" style="color: #64748b;">GitHub Profile</a> &bull; PhishScope AI Product &copy; {datetime.now().year}
        </footer>
    </div>
</body>
</html>
"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[-] Failed to write HTML report: {e}")
