"""
PhishScope AI - Utility Functions
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module contains supporting helper tools such as Shannon Entropy calculations,
string similarity measurements (Levenshtein), homograph detection, and TLD cleaners.
"""

import math
import re
from typing import Optional, Tuple
from config import TARGET_BRANDS

def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string to detect randomized/obfuscated paths.
    
    Args:
        text (str): The input string to check.
        
    Returns:
        float: Entropy score (0.0 to 8.0, higher means more random).
    """
    if not text:
        return 0.0
        
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum(p * math.log(p, 2) for p in probabilities)
    return round(entropy, 4)

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes the standard Levenshtein Edit Distance between two strings.
    
    Args:
        s1 (str): First string.
        s2 (str): Second string.
        
    Returns:
        int: Minimum number of edits (insertions, deletions, substitutions).
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
        
    if len(s2) == 0:
        return len(s1)
        
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def check_brand_impersonation(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a domain name is highly similar to any target brand name.
    Useful for detecting typosquatting (e.g. paypa1.com, amaz0n.com).
    
    Args:
        domain (str): The domain string to verify.
        
    Returns:
        Tuple[bool, Optional[str]]: True and the brand name if impersonation is suspected.
    """
    # Normalize domain: strip www. and TLD
    parts = domain.lower().split('.')
    if not parts:
        return False, None
        
    # Get the main domain label
    if len(parts) > 1:
        # Assuming second level domain, e.g. "paypal" from "paypal.com"
        label = parts[-2]
    else:
        label = parts[0]
        
    # Ignore short names or direct matches
    if len(label) < 4:
        return False, None

    for brand in TARGET_BRANDS:
        if label == brand:
            return False, None  # Exact match (presumably the real domain, or verified)

        # Check edit distance
        dist = levenshtein_distance(label, brand)
        
        # Heuristics: if distance is small (1 or 2 edits) or brand is contained with noise
        if dist > 0 and dist <= 2:
            return True, brand
            
        if brand in label and len(label) > len(brand):
            return True, brand
            
    return False, None

def is_homograph(domain: str) -> bool:
    """
    Checks if the domain uses Internationalized Domain Name (IDN) punycode 
    or contains suspicious mixture of scripts (homograph attacks).
    
    Args:
        domain (str): The domain name.
        
    Returns:
        bool: True if an IDN homograph attack is suspected.
    """
    domain = domain.lower()
    
    # Punycode check
    if domain.startswith("xn--"):
        return True
        
    # Non-ASCII characters check
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return True
        
    return False

def clean_filename(url: str) -> str:
    """
    Converts a URL into a safe, clean file name for storing reports.
    
    Args:
        url (str): The input URL.
        
    Returns:
        str: Safe file name string.
    """
    # Remove protocol
    clean = re.sub(r'^https?://', '', url)
    # Replace non-alphanumeric with underscores
    clean = re.sub(r'[^a-zA-Z0-9]', '_', clean)
    # Truncate if too long
    return clean[:50].strip("_")
