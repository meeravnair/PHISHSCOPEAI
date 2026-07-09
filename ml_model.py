"""
PhishScope AI - Machine Learning Classifier Module
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module generates a sample dataset if missing, trains multiple classifiers 
(Logistic Regression, Decision Tree, Random Forest), compares their accuracy, 
saves the best model, and runs prediction classifications.
"""

import os
import csv
import socket
import joblib
import numpy as np
import pandas as pd
import urllib.parse
import tldextract
from typing import Dict, Tuple, List, Optional

# Offline TLDExtract instance to prevent SSL errors during internet fetches
tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from config import MODEL_PATH, DATASET_PATH, SUSPICIOUS_KEYWORDS, URL_SHORTENERS
from url_features import URLFeatureExtractor
from utils import calculate_entropy
from logger import get_logger

logger = get_logger("ml_model")

class PhishingMLClassifier:
    """Handles dataset generation, model comparison, training, and predicting."""

    FEATURE_NAMES = [
        "url_length",
        "entropy",
        "is_https",
        "hyphen_count",
        "digit_count",
        "subdomain_count",
        "special_char_count",
        "is_ip",
        "suspicious_words_count"
    ]

    def __init__(self):
        self.model = None
        self.scaler = None
        self._load_model()

    @staticmethod
    def generate_default_dataset():
        """Creates a default synthetic/representative dataset CSV if it doesn't exist."""
        if os.path.exists(DATASET_PATH):
            logger.debug("Dataset CSV already exists. Skipping default creation.")
            return

        os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
        
        # Structure: url, label (1 for Phishing/Suspicious, 0 for Safe)
        sample_urls = [
            # Safe URLs
            ("https://google.com", 0),
            ("https://github.com", 0),
            ("https://wikipedia.org", 0),
            ("https://amazon.com", 0),
            ("https://paypal.com", 0),
            ("https://microsoft.com", 0),
            ("https://apple.com", 0),
            ("https://netflix.com", 0),
            ("https://stackoverflow.com", 0),
            ("https://python.org", 0),
            ("https://linkedin.com", 0),
            ("https://cnn.com", 0),
            ("https://medium.com", 0),
            ("https://reddit.com", 0),
            ("https://zoom.us", 0),
            ("https://slack.com", 0),
            ("https://spotify.com", 0),
            ("https://nytimes.com", 0),
            ("https://salesforce.com", 0),
            ("https://dropbox.com", 0),
            ("https://bitbucket.org", 0),
            ("https://cloudflare.com", 0),
            ("https://digitalocean.com", 0),
            ("https://coursera.org", 0),
            ("https://udemy.com", 0),
            
            # Phishing / Suspicious URLs
            ("http://paypal-security-update-verification.com/login", 1),
            ("http://signin-amazon-update-account-security.info", 1),
            ("http://192.168.100.250/signin.php?email=user@domain.com", 1),
            ("http://secure-login-chase-bank-verify-profile.net/auth", 1),
            ("http://free-crypto-reward-binance.com/claim-bonus", 1),
            ("http://netflix-billing-renew-invoice.xyz/payment", 1),
            ("http://wallet-recover-crypto-key.gq/login", 1),
            ("https://paypal-verify-account-support.online/security", 1),
            ("http://apple-icloud-security-alert-verify.top", 1),
            ("http://facebook-security-check-login.fit/verify", 1),
            ("http://steam-community-gift-inventory-trade.link/login", 1),
            ("http://wells-fargo-signin-verify-portal.cn/home", 1),
            ("http://ebay-member-invoice-payment.work/confirm", 1),
            ("http://10.0.0.99/secure/update", 1),
            ("https://coinbase-auth-wallet-recovery.club", 1),
            ("http://verify-bankofamerica-card-activation.xyz", 1),
            ("http://paypal.com.verify.accounts-security-update.xyz/signin", 1),
            ("http://recover-password-reset-account.cf", 1),
            ("http://chase-bank-verification-billing-secure.date", 1),
            ("http://amazon-gift-card-free-rewards.men", 1),
            ("http://microsoft-office-outlook-webmail-update.support", 1),
            ("http://login-confirm-identity-verification.ga", 1),
            ("http://invoice-payment-overdue-download-pdf.ru", 1),
            ("http://secure-webscr-paypal-login.cf/webscr", 1),
            ("http://binance-bonus-rewards-free-gift.gq", 1)
        ]
        
        try:
            with open(DATASET_PATH, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["url", "label"])
                for url, label in sample_urls:
                    writer.writerow([url, label])
            logger.info(f"Generated default dataset with {len(sample_urls)} samples at {DATASET_PATH}")
        except Exception as e:
            logger.error(f"Failed to write default dataset CSV: {e}")

    def extract_features_from_url(self, url: str) -> np.ndarray:
        """
        Extracts the target feature vector from a single URL.
        
        Args:
            url (str): The URL under analysis.
            
        Returns:
            np.ndarray: Evaluated numerical feature vector.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.split(":")[0]

        # 1. URL Length
        url_len = len(url)

        # 2. Entropy
        entropy = calculate_entropy(url)

        # 3. HTTPS
        is_https = 1 if parsed.scheme.lower() == "https" else 0

        # 4. Hyphen count
        hyphens = url.count("-")

        # 5. Digit count
        digits = sum(c.isdigit() for c in url)

        # 6. Subdomain count
        ext = tld_extractor(url)
        subdomains = len(ext.subdomain.split(".")) if ext.subdomain else 0

        # 7. Special Characters Count
        import re
        specials = len(re.findall(r"[^a-zA-Z0-9\.\/]", url))

        # 8. IP usage
        # Simple test if hostname looks like IP
        is_ip = 0
        for family in [socket.AF_INET, socket.AF_INET6]:
            try:
                socket.inet_pton(family, hostname)
                is_ip = 1
                break
            except socket.error:
                pass

        # 9. Suspicious words count
        suspicious_words = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url.lower())

        return np.array([
            url_len,
            entropy,
            is_https,
            hyphens,
            digits,
            subdomains,
            specials,
            is_ip,
            suspicious_words
        ], dtype=float)

    def train_models(self) -> Dict[str, float]:
        """
        Loads the dataset, trains Logistic Regression, Decision Tree, 
        and Random Forest, compares them, saves the best.
        
        Returns:
            Dict[str, float]: Accuracies of the models.
        """
        self.generate_default_dataset()

        logger.info("Loading training dataset...")
        df = pd.read_csv(DATASET_PATH)

        if len(df) == 0:
            raise ValueError("Dataset is empty. Cannot train models.")

        # Extract features for all entries
        features_list = []
        labels_list = []

        logger.info("Extracting numerical feature matrices...")
        for _, row in df.iterrows():
            url = row['url']
            label = int(row['label'])
            vec = self.extract_features_from_url(url)
            features_list.append(vec)
            labels_list.append(label)

        X = np.array(features_list)
        y = np.array(labels_list)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Standardize features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Initialize classifiers
        models = {
            "Logistic Regression": LogisticRegression(random_state=42),
            "Decision Tree": DecisionTreeClassifier(random_state=42),
            "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
        }

        results = {}
        best_acc = 0.0
        best_model_name = ""
        best_model = None

        logger.info("Evaluating ML models...")
        for name, clf in models.items():
            clf.fit(X_train_scaled, y_train)
            preds = clf.predict(X_test_scaled)
            acc = accuracy_score(y_test, preds)
            results[name] = acc
            logger.info(f"Model: {name} | Validation Accuracy: {acc:.4f}")
            
            # Print detailed report for visualization in logs
            logger.debug(f"\nClassification Report for {name}:\n{classification_report(y_test, preds)}")

            if acc > best_acc:
                best_acc = acc
                best_model_name = name
                best_model = clf

        logger.info(f"Selected Best Model: {best_model_name} with Accuracy {best_acc:.4f}")

        # Save model, scaler, and metadata package
        self.model = best_model
        self.scaler = scaler
        
        # Save model pack
        model_package = {
            "model_name": best_model_name,
            "accuracy": best_acc,
            "scaler": scaler,
            "model": best_model,
            "features": self.FEATURE_NAMES
        }
        
        try:
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            joblib.dump(model_package, MODEL_PATH)
            logger.info(f"Successfully saved trained model package to {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to persist model pickle: {e}")

        return results

    def _load_model(self):
        """Loads the serialized model package from disk."""
        if os.path.exists(MODEL_PATH):
            try:
                pkg = joblib.load(MODEL_PATH)
                self.model = pkg["model"]
                self.scaler = pkg["scaler"]
                logger.debug(f"Loaded existing model package (Algorithm: {pkg.get('model_name')}, Accuracy: {pkg.get('accuracy'):.4f})")
            except Exception as e:
                logger.warning(f"Could not load serialized model: {e}. Re-training required.")
                self.model = None
                self.scaler = None

    def predict(self, url: str) -> Tuple[str, float]:
        """
        Classifies a URL and outputs safety prediction and confidence score.
        
        Args:
            url (str): The URL to test.
            
        Returns:
            Tuple[str, float]: (Prediction: "Safe", "Suspicious", "Phishing", Confidence Score 0.0 - 1.0)
        """
        # If model is not loaded, run training automatically
        if self.model is None or self.scaler is None:
            logger.info("No pre-trained model package found. Initiating auto-training...")
            try:
                self.train_models()
            except Exception as e:
                logger.error(f"Auto-training failed: {e}. Falling back to default heuristics prediction.")
                # Basic rule-based fallback if ML pipeline breaks completely
                suspicious_count = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url.lower())
                if suspicious_count >= 2:
                    return "Phishing", 0.85
                elif suspicious_count == 1:
                    return "Suspicious", 0.60
                else:
                    return "Safe", 0.90

        # Extract features
        features = self.extract_features_from_url(url).reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features)

        # Predict probability
        try:
            probs = self.model.predict_proba(features_scaled)[0]
            # label 1 = phishing, label 0 = safe
            phish_prob = probs[1]
            safe_prob = probs[0]
            
            if phish_prob >= 0.70:
                return "Phishing", phish_prob
            elif phish_prob >= 0.40:
                return "Suspicious", phish_prob
            else:
                return "Safe", safe_prob
        except Exception as e:
            logger.error(f"ML prediction calculation error: {e}")
            # Classify fallback
            pred = self.model.predict(features_scaled)[0]
            return ("Phishing", 0.80) if pred == 1 else ("Safe", 0.80)
