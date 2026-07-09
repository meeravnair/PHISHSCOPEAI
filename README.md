 PhishScope AI
### Intelligent AI-Powered Phishing URL Detection & Analysis Platform

PhishScope AI is a production-ready cybersecurity tool that detects phishing websites by combining **rule-based security analysis** with **Machine Learning**. It analyzes URLs using structural features, SSL/TLS validation, DNS intelligence, WHOIS information, entropy analysis, and phishing heuristics to identify malicious websites.

Unlike traditional URL scanners, PhishScope AI explains **why** a URL is considered suspicious and generates professional security reports with actionable recommendations.

---

## Developer

**Meera V Nair**

🔗 GitHub: https://github.com/meeravnair

---

# Features

- URL Structure Analysis
- DNS & WHOIS Investigation
- SSL/TLS Certificate Validation
- Shannon Entropy Analysis
- Suspicious Keyword Detection
- URL Shortener Detection
- IP Address Detection
- Local Threat Intelligence (Blacklist)
- Machine Learning Phishing Detection
- AI-Based Risk Explanation
- Interactive Flask Dashboard
- HTML, JSON, CSV & Markdown Reports
- Rich Command Line Interface

---

#  Screenshots

## Dashboard

<img width="377" height="387" alt="Screenshot 2026-07-02 102226" src="https://github.com/user-attachments/assets/1e8bd32b-886e-45e3-b579-846c185f4f91" />
<img width="468" height="238" alt="Screenshot 2026-07-02 102235" src="https://github.com/user-attachments/assets/574a50da-fa45-4722-886f-c7e76f4b2409" />

---

## Scan Result


<img width="893" height="455" alt="Screenshot 2026-07-02 102038" src="https://github.com/user-attachments/assets/0d51a4aa-6031-4a0e-add7-be7b6e3a0993" />
<img width="950" height="478" alt="Screenshot 2026-07-02 103518" src="https://github.com/user-attachments/assets/bc6a4df4-9b80-4091-9489-73d88fc38100" />


---

## Terminal Interface

<img width="436" height="215" alt="Screenshot 2026-07-02 102022" src="https://github.com/user-attachments/assets/f612c338-e9f4-4287-8527-76f1e5ec71fb" />

---

# Project Structure

```text
PhishScopeAI/
│
├── app.py
├── scanner.py
├── validator.py
├── analyzer.py
├── ssl_checker.py
├── url_features.py
├── ml_model.py
├── ai_summary.py
├── risk_engine.py
├── report.py
├── config.py
├── logger.py
├── utils.py
├── models.py
│
├── dataset/
│   └── phishing_urls.csv
│
├── trained_model/
│   └── phishing_model.pkl
│
├── templates/
│   ├── index.html
│   ├── result.html
│   └── report.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── reports/
│
├── screenshots/
│
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

# How It Works

```text
User Input URL
        │
        ▼
URL Validation
        │
        ▼
Feature Extraction
        │
        ▼
SSL & HTTPS Analysis
        │
        ▼
DNS & WHOIS Lookup
        │
        ▼
Blacklist & Heuristic Checks
        │
        ▼
Machine Learning Prediction
        │
        ▼
Risk Score Calculation
        │
        ▼
AI Summary Generation
        │
        ▼
HTML / JSON / CSV Report
```

---

# Machine Learning Pipeline

PhishScope AI extracts multiple security-related URL features and uses them to classify URLs as **Safe**, **Suspicious**, or **Phishing**.

### Extracted Features

- URL Length
- Shannon Entropy
- HTTPS Usage
- Number of Hyphens
- Number of Digits
- Number of Subdomains
- Number of Special Characters
- IP Address Usage
- Suspicious Keywords

### Models

- Logistic Regression
- Decision Tree
- Random Forest *(Default)*

The best-performing model is automatically saved for future scans using **Joblib**.

---

# Risk Analysis

The platform evaluates multiple indicators to calculate an overall security score.

| Check | Risk Impact |
|---------|------------|
| HTTP Only | High |
| Expired SSL | High |
| IP Address in URL | High |
| URL Shortener | Medium |
| Suspicious Keywords | Medium |
| High Entropy | Medium |
| Excessive Hyphens | Low |
| Recently Registered Domain | High |
| Blacklisted Domain | Critical |

---

# Installation

Clone the repository

```bash
git clone https://github.com/meeravnair/PhishScopeAI.git

cd PhishScopeAI
```

Create a virtual environment

```bash
python -m venv venv
```

Activate it

### Windows

```powershell
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

### Command Line

```bash
python scanner.py --url https://example.com
```

Train the Machine Learning model

```bash
python scanner.py --train
```

Save output

```bash
python scanner.py --url https://example.com --output report.json
```

---

### Flask Dashboard

```bash
python app.py
```

Open

```
http://127.0.0.1:5000
```

---

# Reports

PhishScope AI automatically generates professional reports in:

- HTML
- JSON
- CSV
- Markdown

Each report contains:

- URL Details
- Risk Score
- SSL Information
- Domain Intelligence
- Machine Learning Prediction
- AI Summary
- Security Recommendations

---

# Future Improvements

- VirusTotal Integration
- PhishTank Integration
- Google Safe Browsing API
- Browser Extension
- Email Phishing Detection
- QR Code Phishing Scanner
- Real-Time Threat Intelligence
- Deep Learning (LSTM / Transformer)
- Docker Support
- REST API

---

# Tech Stack

- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- Requests
- BeautifulSoup
- Jinja2
- HTML
- CSS
- JavaScript
- Joblib
- Colorama

---

# License

This project is licensed under the **MIT License**.

---

## Developed By

**Meera V Nair**

🔗 GitHub: https://github.com/meeravnair




