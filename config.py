"""
PhishScope AI - Configuration Module
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module centralizes all configuration settings, threshold values, risk scoring weights, 
and file paths for the PhishScope AI application.
"""

import os

# Base Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR = os.path.join(BASE_DIR, "trained_model")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Ensure required directories exist
for directory in [DATASET_DIR, MODEL_DIR, REPORTS_DIR, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# File Paths
DATASET_PATH = os.path.join(DATASET_DIR, "phishing_urls.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
LOG_FILE_PATH = os.path.join(LOGS_DIR, "phishscope.log")

# Web Server Settings
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = True

# Developer Information
DEVELOPER_NAME = "Meera V Nair"
DEVELOPER_GITHUB = "https://github.com/meeravnair"

# Detection Heuristics List
SUSPICIOUS_TLDS = {
    "zip", "fit", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", 
    "click", "link", "cn", "ru", "info", "date", "loan", "men", "support", "online"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "paypal", "amazon", "bank",
    "signin", "wallet", "crypto", "gift", "reward", "invoice", "payment", "bonus",
    "free", "confirm", "recover", "password", "banking", "verification", "support",
    "online", "portal", "service", "ebay", "netflix", "microsoft", "apple", "google",
    "chase", "wells Fargo", "security", "webscr", "submit", "credential", "auth"
]

TARGET_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix", "facebook",
    "chase", "bankofamerica", "wellsfargo", "citibank", "coinbase", "binance",
    "steam", "ebay", "instagram", "twitter", "linkedin", "yahoo", "outlook"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "rb.gy", "ow.ly", "buff.ly", "cutt.ly",
    "t.co", "is.gd", "tiny.cc", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "bit.do",
    "cur.lv", "shorturl.at"
}

# Local Blacklist (For domains, IPs, and full URLs)
LOCAL_BLACKLIST = {
    "domains": {
        "phishing-test-domain.com",
        "malicious-site.net",
        "secure-login-paypal-verify.com",
        "crypto-reward-free.org"
    },
    "ips": {
        "192.168.100.250",
        "10.0.0.99",
        "185.220.101.5"
    },
    "urls": {
        "http://phishing-test-domain.com/login",
        "https://malicious-site.net/verify/account",
        "http://192.168.100.250/signin"
    }
}

# Risk Engine Deductions
RISK_BASE_SCORE = 100

DEDUCTIONS = {
    "HTTP_ONLY": 20,
    "IP_ADDRESS_USED": 20,
    "SSL_EXPIRED_OR_INVALID": 20,
    "EXCESSIVE_HYPHENS": 10,
    "LONG_URL": 10,
    "URL_SHORTENER": 10,
    "SUSPICIOUS_KEYWORDS": 15,
    "HIGH_ENTROPY": 10,
    "BLACKLISTED_MATCH": 30,
    "RECENT_REGISTRATION": 15,
    "ML_PHISHING_PREDICTION": 25,
    "TYPOSQUATTING_DETECTED": 15,
    "HOMOGRAPH_ATTACK": 20,
    "EXCESSIVE_SUBDOMAINS": 10
}

# Feature Extraction Limits
LONG_URL_THRESHOLD = 75
EXCESSIVE_HYPHENS_THRESHOLD = 3
EXCESSIVE_SUBDOMAINS_THRESHOLD = 4
HIGH_ENTROPY_THRESHOLD = 4.2
RECENT_REGISTRATION_DAYS_THRESHOLD = 90  # Considered recent if registered within 90 days
