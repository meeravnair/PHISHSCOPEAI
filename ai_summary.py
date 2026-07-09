"""
PhishScope AI - Local AI-Style Summary Generator
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module compiles the heuristics findings, SSL details, domain details, 
and ML predictions to construct structured, human-readable explanations 
and strategic security recommendations.
"""

from typing import List, Tuple
from models import URLExtractedFeatures, SSLCertificateDetails, DomainAnalysisDetails

class AISummaryGenerator:
    """Generates professional executive summaries detailing why a URL is suspicious or safe."""

    @staticmethod
    def generate_summary(
        features: URLExtractedFeatures,
        ssl: SSLCertificateDetails,
        domain: DomainAnalysisDetails,
        ml_prediction: str,
        ml_confidence: float
    ) -> Tuple[str, str]:
        """
        Synthesizes raw scanner data and ML classification into structured reports.
        
        Args:
            features (URLExtractedFeatures): Extracted lexical stats.
            ssl (SSLCertificateDetails): Retrieved SSL state.
            domain (DomainAnalysisDetails): Threat Intel stats.
            ml_prediction (str): ML status tag (Safe, Suspicious, Phishing).
            ml_confidence (float): Confidence score (0.0 to 100.0).
            
        Returns:
            Tuple[str, str]: (Executive summary markdown text, Security Recommendations text)
        """
        reasons = []

        # 1. Evaluate Lexical and Feature indicators
        if features.url_length >= 75:
            reasons.append(f"The URL length is unusually long ({features.url_length} characters), which is common in obfuscated links.")
        if features.hyphen_count >= 3:
            reasons.append(f"It uses excessive hyphens ({features.hyphen_count} hyphens) in the address structure to mimic subdomains.")
        if features.dot_count >= 4:
            reasons.append(f"The host structure contains multiple dot delimiters ({features.dot_count} dots), suggesting deep subdomain nesting.")
        if features.entropy_score >= 4.2:
            reasons.append(f"The URL has a high character randomness score (Entropy: {features.entropy_score:.2f}), suggesting randomized paths or subdomains.")

        # 2. Evaluate Domain and Host indicators
        if domain.is_ip_address:
            reasons.append(f"The URL uses a direct IP address ({domain.domain_name}) instead of a standard registered domain name, bypassing DNS reputation lookups.")
        if domain.is_url_shortener:
            reasons.append("It uses a known URL shortening redirection service, masking the final destination.")
        if domain.is_suspicious_tld:
            reasons.append(f"The domain resides on a suspicious or low-cost Top-Level Domain (TLD) extension (.{domain.tld}), commonly abused by attackers.")
        if domain.is_typosquatting and domain.impersonated_brand:
            reasons.append(f"The domain name is highly similar to, and appears to impersonate, the popular brand '{domain.impersonated_brand.upper()}' (Typosquatting detected).")
        if domain.is_homograph_attack:
            reasons.append("The domain name contains characters from different alphabets or Punycode formats (IDN Homograph attack vector).")
        if domain.suspicious_keywords_found:
            keywords_str = ", ".join(domain.suspicious_keywords_found)
            reasons.append(f"The domain hostname explicitly contains sensitive phishing-related keywords ({keywords_str}).")
        if domain.recently_registered and domain.age_in_days is not None:
            reasons.append(f"The domain was recently registered ({domain.age_in_days} days ago), which fits the profile of temporary attack infrastructure.")
        if domain.is_blacklisted:
            reasons.append(f"The target matches our security intelligence blacklist database ({domain.blacklist_match_type} match).")

        # 3. Evaluate SSL and HTTPS indicators
        if not ssl.certificate_exists:
            reasons.append("The site does not implement HTTPS or lacks a valid SSL/TLS certificate, meaning credentials sent to it are unencrypted.")
        elif not ssl.certificate_valid:
            reasons.append(f"The site uses a broken or invalid SSL certificate ({ssl.ssl_error_message or 'validation error'}).")
        elif ssl.days_until_expiry is not None and ssl.days_until_expiry < 15:
            reasons.append(f"The SSL certificate is nearing expiration (expires in {ssl.days_until_expiry} days), which is typical of throwaway certificates.")

        # 4. Integrate Machine Learning Intelligence
        if ml_prediction in ["Phishing", "Suspicious"]:
            reasons.append(f"Our Machine Learning classification models flagged this URL as {ml_prediction.upper()} with a confidence level of {ml_confidence:.1f}%.")

        # Compile Heuristics Summary
        if not reasons:
            summary = "PhishScope AI did not detect any notable indicators of phishing or malicious activity. The structural elements of the URL, SSL state, domain metadata, and Machine Learning models classify this URL as clean."
            recommendation = "Safe to visit. However, always exercise caution when entering credential data on external websites."
        else:
            summary_bullets = "\n".join([f" - {reason}" for reason in reasons])
            summary = f"The URL exhibits several high-risk characteristics:\n\n{summary_bullets}"
            
            # Determine overall risk category and supply suitable recommendation
            if domain.is_blacklisted or ml_prediction == "Phishing" or not ssl.certificate_valid:
                recommendation = "CRITICAL ACTION: Do NOT visit this website. It contains severe security indicators. Close any open tabs and block the domain on your network filters."
            else:
                recommendation = "SUSPICIOUS WARNING: Exercise extreme caution. We recommend avoiding this site. Do not input credentials, personal information, or download any attachments."

        return summary, recommendation
