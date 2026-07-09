"""
PhishScope AI - SSL Certificate Checker Module
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module verifies HTTPS implementation, retrieves SSL certificate details,
inspects the issuer, validity timeframe, and matches the hostname.
"""

import socket
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, Optional
from models import SSLCertificateDetails
from logger import get_logger

logger = get_logger("ssl_checker")

class SSLCertificateChecker:
    """Class to inspect SSL certificates and HTTPS configurations."""

    @staticmethod
    def check_ssl(url: str, timeout: float = 3.0) -> SSLCertificateDetails:
        """
        Retrieves SSL certificate parameters from the host.
        
        Args:
            url (str): The target URL to test.
            timeout (float): Connection timeout in seconds.
            
        Returns:
            SSLCertificateDetails: Instantiated SSL details dataclass.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc.split(":")[0]  # Remove port if present
        
        details = SSLCertificateDetails()
        
        # 1. Scheme Check
        if parsed.scheme.lower() != "https":
            details.ssl_error_message = "URL uses unencrypted HTTP protocol"
            return details

        # 2. SSL/TLS Connection Attempt
        context = ssl.create_default_context()
        
        try:
            # Connect socket and wrap with ssl context
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        details.ssl_error_message = "SSL handshake succeeded but no peer certificate was sent"
                        return details
                    
                    details.certificate_exists = True
                    details.certificate_valid = True
                    details.hostname_match = True  # Verified by wrap_socket (raises CertificateError if mismatch)

                    # Extract Issuer
                    issuer_info = cert.get('issuer', ())
                    issuer_dict = {}
                    for item in issuer_info:
                        for key, value in item:
                            issuer_dict[key] = value
                    
                    details.issuer = issuer_dict.get('commonName') or issuer_dict.get('organizationName') or "Unknown Issuer"

                    # Extract Expiry Dates
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        # e.g., 'Oct 11 08:34:00 2026 GMT'
                        try:
                            # Parse dates (usually in GMT/UTC format from getpeercert)
                            expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            details.certificate_expiry = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
                            
                            delta = expiry_date - datetime.utcnow()
                            details.days_until_expiry = delta.days
                            
                            if delta.days <= 0:
                                details.certificate_valid = False
                                details.ssl_error_message = "SSL Certificate has expired"
                        except ValueError as ve:
                            logger.warning(f"Failed to parse certificate expiry date '{not_after_str}': {ve}")
                            details.certificate_expiry = not_after_str

        except socket.timeout:
            details.ssl_error_message = "SSL connection attempt timed out"
            logger.info(f"SSL timeout checking {hostname}")
        except (ssl.SSLCertVerificationError, ssl.CertificateError) as sce:
            details.certificate_exists = True
            details.certificate_valid = False
            details.ssl_error_message = f"Hostname mismatch or certificate validation error: {sce}"
            logger.info(f"SSL mismatch on {hostname}: {sce}")
        except ssl.SSLError as se:
            details.certificate_exists = True
            details.certificate_valid = False
            details.ssl_error_message = f"SSL Handshake failed: {se}"
            logger.info(f"SSL Handshake failure on {hostname}: {se}")
        except Exception as e:
            details.ssl_error_message = f"Failed to retrieve SSL details: {str(e)}"
            logger.info(f"SSL check exception on {hostname}: {e}")

        return details
