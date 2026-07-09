"""
PhishScope AI - Data Models
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module defines structures for scanned data using standard Python Dataclasses, 
supporting validation, extraction, and reporting pipelines.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from datetime import datetime

@dataclass
class URLExtractedFeatures:
    """Dataclass holding structural features of a URL."""
    url: str
    url_length: int
    hostname: str
    hostname_length: int
    path: str
    path_length: int
    query: str
    query_length: int
    dot_count: int
    digit_count: int
    letter_count: int
    hyphen_count: int
    underscore_count: int
    slash_count: int
    question_mark_count: int
    equal_count: int
    percent_count: int
    ampersand_count: int
    special_char_count: int
    entropy_score: float

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class SSLCertificateDetails:
    """Dataclass representing SSL Certificate analysis."""
    certificate_exists: bool = False
    certificate_valid: bool = False
    certificate_expiry: Optional[str] = None
    days_until_expiry: Optional[int] = None
    issuer: Optional[str] = None
    hostname_match: bool = False
    ssl_error_message: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class DomainAnalysisDetails:
    """Dataclass representing Domain Threat intel analysis."""
    domain_name: str
    is_ip_address: bool = False
    ip_version: Optional[str] = None
    is_url_shortener: bool = False
    recently_registered: bool = False
    registration_date: Optional[str] = None
    age_in_days: Optional[int] = None
    is_suspicious_tld: bool = False
    tld: str = ""
    is_typosquatting: bool = False
    impersonated_brand: Optional[str] = None
    is_homograph_attack: bool = False
    subdomain_count: int = 0
    suspicious_keywords_found: List[str] = field(default_factory=list)
    is_blacklisted: bool = False
    blacklist_match_type: Optional[str] = None  # domain, ip, url, or none

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class RiskAnalysisDetails:
    """Dataclass representing Risk Engine assessment."""
    base_score: int
    final_score: int
    risk_level: str  # Critical, High, Medium, Low, Safe
    deductions: Dict[str, int] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ScanResult:
    """The master wrapper for all scanning results."""
    url: str
    timestamp: str
    is_valid_url: bool
    features: Optional[URLExtractedFeatures] = None
    ssl_details: Optional[SSLCertificateDetails] = None
    domain_details: Optional[DomainAnalysisDetails] = None
    ml_prediction: str = "Safe"  # Safe, Suspicious, Phishing
    ml_confidence: float = 0.0
    risk_details: Optional[RiskAnalysisDetails] = None
    ai_explanation: str = ""
    ai_recommendation: str = ""

    def to_dict(self) -> Dict:
        """Converts the full object to a clean nested dictionary."""
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "is_valid_url": self.is_valid_url,
            "features": self.features.to_dict() if self.features else None,
            "ssl_details": self.ssl_details.to_dict() if self.ssl_details else None,
            "domain_details": self.domain_details.to_dict() if self.domain_details else None,
            "ml_prediction": self.ml_prediction,
            "ml_confidence": round(self.ml_confidence * 100, 2),
            "risk_details": self.risk_details.to_dict() if self.risk_details else None,
            "ai_explanation": self.ai_explanation,
            "ai_recommendation": self.ai_recommendation
        }
