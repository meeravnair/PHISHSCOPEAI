"""
PhishScope AI - URL Feature Extraction Module
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module extracts structural, syntactic, and complexity features from URLs
to be used as inputs for heuristic analysis and ML models.
"""

import urllib.parse
from models import URLExtractedFeatures
from utils import calculate_entropy

class URLFeatureExtractor:
    """Class to extract comprehensive lexical features from a URL string."""

    @staticmethod
    def extract_features(url: str) -> URLExtractedFeatures:
        """
        Parses a URL and extracts its structural and complexity metrics.
        
        Args:
            url (str): The URL to extract features from.
            
        Returns:
            URLExtractedFeatures: Struct representing all metrics.
        """
        parsed = urllib.parse.urlparse(url)
        
        # 1. Structural Lengths
        url_length = len(url)
        hostname = parsed.netloc or ""
        hostname_length = len(hostname)
        path = parsed.path or ""
        path_length = len(path)
        query = parsed.query or ""
        query_length = len(query)

        # 2. Basic Character Counts
        dot_count = url.count(".")
        digit_count = sum(c.isdigit() for c in url)
        letter_count = sum(c.isalpha() for c in url)
        hyphen_count = url.count("-")
        underscore_count = url.count("_")
        slash_count = url.count("/")
        question_mark_count = url.count("?")
        equal_count = url.count("=")
        percent_count = url.count("%")
        ampersand_count = url.count("&")

        # 3. Special Characters
        # Characters that are not alphanumeric and not standard delimiters like . or /
        special_chars_pattern = r"[^a-zA-Z0-9\.\/]"
        import re
        special_char_count = len(re.findall(special_chars_pattern, url))

        # 4. Entropy
        entropy_score = calculate_entropy(url)

        return URLExtractedFeatures(
            url=url,
            url_length=url_length,
            hostname=hostname,
            hostname_length=hostname_length,
            path=path,
            path_length=path_length,
            query=query,
            query_length=query_length,
            dot_count=dot_count,
            digit_count=digit_count,
            letter_count=letter_count,
            hyphen_count=hyphen_count,
            underscore_count=underscore_count,
            slash_count=slash_count,
            question_mark_count=question_mark_count,
            equal_count=equal_count,
            percent_count=percent_count,
            ampersand_count=ampersand_count,
            special_char_count=special_char_count,
            entropy_score=entropy_score
        )
