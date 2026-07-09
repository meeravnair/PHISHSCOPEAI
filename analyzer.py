"""
PhishScope AI - Domain Threat Analyzer Module
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module performs deep domain analysis, checking for homograph attacks, 
typosquatting, suspicious TLDs, IP usage, shorteners, local blacklists, 
and WHOIS age metrics.
"""

import socket
import re
import urllib.parse
import whois
import tldextract
from datetime import datetime
from typing import List, Optional, Tuple

# Offline TLDExtract instance to prevent SSL errors during internet fetches
tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)

from config import (
    SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, URL_SHORTENERS, 
    LOCAL_BLACKLIST, RECENT_REGISTRATION_DAYS_THRESHOLD, EXCESSIVE_SUBDOMAINS_THRESHOLD
)
from models import DomainAnalysisDetails
from utils import check_brand_impersonation, is_homograph
from logger import get_logger

logger = get_logger("analyzer")

class DomainAnalyzer:
    """Class to inspect domains, gather Threat Intel, and extract structural indicators."""

    @staticmethod
    def is_valid_ip(hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Determines whether the given hostname is an IP address.
        
        Args:
            hostname (str): The hostname.
            
        Returns:
            Tuple[bool, Optional[str]]: (Is IP, IP Version e.g. "IPv4", "IPv6", or None)
        """
        # Test IPv4
        try:
            socket.inet_pton(socket.AF_INET, hostname)
            return True, "IPv4"
        except socket.error:
            pass
            
        # Test IPv6
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True, "IPv6"
        except socket.error:
            pass
            
        return False, None

    @staticmethod
    def check_blacklist(url: str, domain: str, ip: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Matches components against the local blacklist database.
        
        Args:
            url (str): The full URL.
            domain (str): The domain.
            ip (str): The IP address of the domain.
            
        Returns:
            Tuple[bool, Optional[str]]: (Is blacklisted, match category)
        """
        # Normalize and clean for matching
        url_clean = url.lower().strip()
        domain_clean = domain.lower().strip()
        
        # 1. URL exact/substring check
        for blacklisted_url in LOCAL_BLACKLIST["urls"]:
            if blacklisted_url.lower() in url_clean:
                return True, "URL"

        # 2. Domain check
        if domain_clean in LOCAL_BLACKLIST["domains"]:
            return True, "Domain"
            
        # 3. IP check
        if ip and ip in LOCAL_BLACKLIST["ips"]:
            return True, "IP Address"
            
        return False, None

    @staticmethod
    def get_whois_age(domain: str) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Performs a WHOIS query to determine registration date and age of the domain.
        
        Args:
            domain (str): The domain name.
            
        Returns:
            Tuple[bool, Optional[str], Optional[int]]: (Is recent, Reg date string, Age in days)
        """
        try:
            # whois.whois might throw exceptions or block. Set a fallback logic
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if not creation_date:
                return False, None, None
                
            # If creation_date is a list (some registries return multiples)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if not isinstance(creation_date, datetime):
                # sometimes whois returns a string or non-datetime object
                return False, None, None
                
            age_delta = datetime.utcnow() - creation_date
            age_days = age_delta.days
            
            is_recent = age_days <= RECENT_REGISTRATION_DAYS_THRESHOLD
            return is_recent, creation_date.strftime("%Y-%m-%d"), age_days

        except Exception as e:
            # Log failure but do not disrupt execution
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return False, None, None

    @classmethod
    def analyze_domain(cls, url: str) -> DomainAnalysisDetails:
        """
        Analyzes the domain structure and gathers intelligence.
        
        Args:
            url (str): The URL under analysis.
            
        Returns:
            DomainAnalysisDetails: Populated result object.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.split(":")[0]  # Remove port if present
        
        details = DomainAnalysisDetails(domain_name=hostname)

        # 1. IP Address Detection
        is_ip, ip_ver = cls.is_valid_ip(hostname)
        details.is_ip_address = is_ip
        details.ip_version = ip_ver

        # 2. Resolve domain IP for blacklisting (if not already an IP)
        domain_ip = hostname if is_ip else None
        if not is_ip:
            try:
                domain_ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                logger.info(f"Could not resolve IP for host: {hostname}")

        # 3. Blacklist Match
        is_black, match_type = cls.check_blacklist(url, hostname, domain_ip)
        details.is_blacklisted = is_black
        details.blacklist_match_type = match_type

        # If it is an IP address, we bypass typical domain checks like TLD, WHOIS, brand impersonation
        if is_ip:
            return details

        # 4. URL Shorteners check
        details.is_url_shortener = hostname.lower() in URL_SHORTENERS

        # 5. Extract Domain details (SLD, TLD, Subdomains)
        ext = tld_extractor(url)
        details.tld = ext.suffix
        details.is_suspicious_tld = ext.suffix.lower() in SUSPICIOUS_TLDS

        # 6. Typosquatting / Brand Impersonation
        is_impersonated, brand_name = check_brand_impersonation(hostname)
        details.is_typosquatting = is_impersonated
        details.impersonated_brand = brand_name

        # 7. Homograph Check
        details.is_homograph_attack = is_homograph(hostname)

        # 8. Subdomains Count
        # If subdomain is e.g. "my.secure.portal", splitting by "." gives 3 subdomains
        if ext.subdomain:
            details.subdomain_count = len(ext.subdomain.split("."))
        else:
            details.subdomain_count = 0

        # 9. Suspicious Keywords In Hostname
        # Match keywords in the registrable domain (SLD)
        sld = ext.domain.lower()
        for word in SUSPICIOUS_KEYWORDS:
            # Word match or pattern match
            if word in sld:
                details.suspicious_keywords_found.append(word)

        # 10. WHOIS Age metric
        # Check domain registration age
        is_recent, reg_date, age_days = cls.get_whois_age(hostname)
        details.recently_registered = is_recent
        details.registration_date = reg_date
        details.age_in_days = age_days

        return details
