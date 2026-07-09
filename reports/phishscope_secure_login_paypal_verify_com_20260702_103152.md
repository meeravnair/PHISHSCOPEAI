# PhishScope AI Security Threat Report
**Generated on:** 2026-07-02 05:01:36 UTC
**Target URL:** http://secure-login-paypal-verify.com
**Developed By:** Meera V Nair | [GitHub](https://github.com/meeravnair)

---

## 1. Executive Summary
- **Risk Score:** 0/100
- **Severity Band:** **CRITICAL**
- **Machine Learning Classification:** Phishing (97.7% confidence)

### Diagnostic Overview
The URL exhibits several high-risk characteristics:

 - It uses excessive hyphens (3 hyphens) in the address structure to mimic subdomains.
 - The URL has a high character randomness score (Entropy: 4.34), suggesting randomized paths or subdomains.
 - The domain name is highly similar to, and appears to impersonate, the popular brand 'PAYPAL' (Typosquatting detected).
 - The domain hostname explicitly contains sensitive phishing-related keywords (login, verify, secure, paypal).
 - The target matches our security intelligence blacklist database (Domain match).
 - The site does not implement HTTPS or lacks a valid SSL/TLS certificate, meaning credentials sent to it are unencrypted.
 - Our Machine Learning classification models flagged this URL as PHISHING with a confidence level of 1.0%.

### Remediation Recommendation
> **CRITICAL ACTION: Do NOT visit this website. It contains severe security indicators. Close any open tabs and block the domain on your network filters.**

---

## 2. Risk Deductions Matrix
Below are the negative risk factors identified by the PhishScope AI Risk Engine:
- Unencrypted connection (HTTP only) (-20 pts)
- Excessive hyphens in URL (3 hyphens) (-10 pts)
- High entropy randomness in URL (4.3374) (-10 pts)
- Suspicious phishing keywords found in hostname (-15 pts)
- Typosquatting target matching brand 'paypal' (-15 pts)
- Reputation blacklist matched (Domain) (-30 pts)
- Machine Learning classified URL as suspicious/phishing (-25 pts)

---

## 3. Detailed Metrics Analysis

### A. Lexical URL Features
- **URL Length:** 37 characters
- **Host Length:** 30 characters
- **Subdomain Count:** 0
- **Dot Count:** 1
- **Digit Count:** 0
- **Hyphen Count:** 3
- **Special Character Count:** 4
- **Shannon Entropy Score:** 4.3374

### B. SSL/TLS Verification
- **HTTPS Enabled:** No
- **SSL Certificate Exists:** No
- **SSL Certificate Valid:** No
- **Issuer:** N/A
- **Days to Expiration:** N/A
- **Hostname Match:** No
- **SSL Diagnostic Msg:** URL uses unencrypted HTTP protocol

### C. Domain Reputation and Intelligence
- **IP Address Used:** No
- **Suspicious TLD Extension:** No
- **Typosquatting Detected:** Yes
- **Impersonated Brand:** PAYPAL
- **Homograph Vector:** No
- **Registration Age:** N/A days (Registered on: Unknown)
- **Blacklist Match:** Yes
- **Suspicious Keywords Found:** login, verify, secure, paypal

---
*Disclaimer: This report is generated dynamically by PhishScope AI heuristics and Machine Learning models. Use for threat intelligence purposes.*
