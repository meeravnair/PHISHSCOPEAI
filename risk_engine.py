"""
PhishScope AI - Risk Assessment Engine
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module implements a weighted points-deduction system that aggregates
lexical, domain, SSL, blacklist, and ML findings to yield a final security risk score.
"""

from typing import Dict, List
from config import RISK_BASE_SCORE, DEDUCTIONS, LONG_URL_THRESHOLD, EXCESSIVE_HYPHENS_THRESHOLD, EXCESSIVE_SUBDOMAINS_THRESHOLD, HIGH_ENTROPY_THRESHOLD
from models import URLExtractedFeatures, SSLCertificateDetails, DomainAnalysisDetails, RiskAnalysisDetails

class RiskEngine:
    """Aggregates all threat findings and calculates standard numeric risk levels."""

    @staticmethod
    def calculate_risk(
        features: URLExtractedFeatures,
        ssl: SSLCertificateDetails,
        domain: DomainAnalysisDetails,
        ml_prediction: str
    ) -> RiskAnalysisDetails:
        """
        Processes scan details, applies weighted score deductions, and maps risk bands.
        
        Args:
            features (URLExtractedFeatures): Lexical URL traits.
            ssl (SSLCertificateDetails): SSL configuration.
            domain (DomainAnalysisDetails): Domain metadata and threat intel.
            ml_prediction (str): Machine Learning prediction label.
            
        Returns:
            RiskAnalysisDetails: Object containing final score, risk band, and deduction details.
        """
        score = RISK_BASE_SCORE
        deductions: Dict[str, int] = {}
        reasons: List[str] = []

        # Helper to apply deductions safely
        def deduct(key: str, condition: bool, description: str):
            nonlocal score
            if condition:
                weight = DEDUCTIONS.get(key, 10)
                score -= weight
                deductions[key] = weight
                reasons.append(f"{description} (-{weight} pts)")

        # 1. HTTP vs HTTPS Check
        deduct("HTTP_ONLY", not ssl.certificate_exists, "Unencrypted connection (HTTP only)")

        # 2. IP Address Usage
        deduct("IP_ADDRESS_USED", domain.is_ip_address, "Direct IP address usage in URL")

        # 3. SSL certificate integrity
        if ssl.certificate_exists:
            deduct("SSL_EXPIRED_OR_INVALID", not ssl.certificate_valid, "Invalid/Expired SSL Certificate")

        # 4. Lexical Traits
        deduct("LONG_URL", features.url_length >= LONG_URL_THRESHOLD, f"URL exceeds safe length threshold ({features.url_length} chars)")
        deduct("EXCESSIVE_HYPHENS", features.hyphen_count >= EXCESSIVE_HYPHENS_THRESHOLD, f"Excessive hyphens in URL ({features.hyphen_count} hyphens)")
        deduct("HIGH_ENTROPY", features.entropy_score >= HIGH_ENTROPY_THRESHOLD, f"High entropy randomness in URL ({features.entropy_score})")

        # 5. Domain Metrics
        deduct("URL_SHORTENER", domain.is_url_shortener, "Redirection/Shortener domain detected")
        deduct("SUSPICIOUS_KEYWORDS", len(domain.suspicious_keywords_found) > 0, "Suspicious phishing keywords found in hostname")
        deduct("RECENT_REGISTRATION", domain.recently_registered, f"Recently registered domain (Age: {domain.age_in_days} days)")
        deduct("TYPOSQUATTING_DETECTED", domain.is_typosquatting, f"Typosquatting target matching brand '{domain.impersonated_brand}'")
        deduct("HOMOGRAPH_ATTACK", domain.is_homograph_attack, "IDN Homograph/Punycode character attack indicator")
        deduct("EXCESSIVE_SUBDOMAINS", domain.subdomain_count >= EXCESSIVE_SUBDOMAINS_THRESHOLD, f"Too many subdomain layers ({domain.subdomain_count})")

        # 6. Blacklist Match
        deduct("BLACKLISTED_MATCH", domain.is_blacklisted, f"Reputation blacklist matched ({domain.blacklist_match_type})")

        # 7. Machine Learning Prediction
        deduct("ML_PHISHING_PREDICTION", ml_prediction in ["Phishing", "Suspicious"], f"Machine Learning classified URL as suspicious/phishing")

        # Bounds check final score to be in range [0, 100]
        final_score = max(0, min(RISK_BASE_SCORE, score))

        # Risk Classification mapping
        # 0-20 Critical, 21-40 High, 41-60 Medium, 61-80 Low, 81-100 Safe
        if final_score <= 20:
            risk_level = "Critical"
        elif final_score <= 40:
            risk_level = "High"
        elif final_score <= 60:
            risk_level = "Medium"
        elif final_score <= 80:
            risk_level = "Low"
        else:
            risk_level = "Safe"

        return RiskAnalysisDetails(
            base_score=RISK_BASE_SCORE,
            final_score=final_score,
            risk_level=risk_level,
            deductions=deductions,
            reasons=reasons
        )
