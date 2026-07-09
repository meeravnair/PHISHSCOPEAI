"""
PhishScope AI - URL Validator
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module verifies whether a given string is a properly formatted and valid URL.
"""

import re
import urllib.parse
import validators
from logger import get_logger

logger = get_logger("validator")

class URLValidator:
    """Class to handle URL structure validation."""

    @staticmethod
    def is_valid(url: str) -> bool:
        """
        Validates the structure of a URL.
        
        Args:
            url (str): The URL to validate.
            
        Returns:
            bool: True if URL is valid and structured correctly, False otherwise.
        """
        if not url:
            logger.warning("Empty URL provided for validation.")
            return False

        url = url.strip()

        # Check basic schema prefix
        if not re.match(r'^https?://', url, re.IGNORECASE):
            logger.info(f"URL validation failed: Protocol missing or invalid in '{url}'")
            return False

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                logger.info(f"URL validation failed: No domain hostname in '{url}'")
                return False
        except Exception as e:
            logger.error(f"URL parsing failed: {e}")
            return False

        # Validate with validators library
        # Some custom internal domains or unusual formatting might fail, so we combine regex and validators
        try:
            if not validators.url(url):
                # Fallback check for standard IP/domain regex
                # regex source matching domains or IP addresses
                regex = re.compile(
                    r'^https?://'  # http:// or https://
                    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
                    r'localhost|'  # localhost...
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ipv4
                    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ipv6
                    r'(?::\d+)?'  # optional port
                    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
                
                if not re.match(regex, url):
                    logger.info(f"Validators.url and regex both failed validation for '{url}'")
                    return False
        except Exception as e:
            logger.warning(f"Validation library error: {e}. Falling back to internal checks.")
            # If library fails/errors, we rely on basic parse check
            return bool(parsed.netloc)

        return True
