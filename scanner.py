"""
PhishScope AI - Security Scanner & CLI Interface
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module functions as the main scan orchestrator, linking validation, 
feature extraction, SSL checks, domain analysis, ML prediction, and risk scoring.
It also hosts the rich, colored interactive Command Line Interface.
"""

import sys
import argparse
import time
from datetime import datetime
import json
from typing import Optional
from colorama import Fore, Back, Style, init

from validator import URLValidator
from url_features import URLFeatureExtractor
from ssl_checker import SSLCertificateChecker
from analyzer import DomainAnalyzer
from ml_model import PhishingMLClassifier
from risk_engine import RiskEngine
from ai_summary import AISummaryGenerator
from models import ScanResult
from logger import get_logger

# Initialize Colorama
init(autoreset=True)

logger = get_logger("scanner")

class PhishScopeScanner:
    """Orchestrates standard threat scans on target URL addresses."""

    def __init__(self):
        self.ml_classifier = PhishingMLClassifier()

    def scan_url(self, url: str) -> ScanResult:
        """
        Runs a comprehensive phishing analysis on a given URL.
        
        Args:
            url (str): The URL target.
            
        Returns:
            ScanResult: Fully populated threat audit report object.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # 1. Validation
        is_valid = URLValidator.is_valid(url)
        if not is_valid:
            logger.warning(f"Aborting scan: invalid URL syntax '{url}'")
            return ScanResult(url=url, timestamp=timestamp, is_valid_url=False)

        logger.info(f"Initiating comprehensive scan for: {url}")
        
        # 2. Extract Structural Features
        logger.debug("Extracting lexical features...")
        features = URLFeatureExtractor.extract_features(url)
        
        # 3. SSL Checking
        logger.debug("Analyzing SSL certificate and cipher details...")
        ssl_details = SSLCertificateChecker.check_ssl(url)
        
        # 4. Domain Reputation Analysis
        logger.debug("Performing WHOIS and domain authority checks...")
        domain_details = DomainAnalyzer.analyze_domain(url)
        
        # 5. Machine Learning Inference
        logger.debug("Running ML classifier inference models...")
        ml_prediction, ml_confidence = self.ml_classifier.predict(url)
        
        # 6. Risk Aggregator Score
        logger.debug("Synthesizing metrics via Risk Engine...")
        risk_details = RiskEngine.calculate_risk(
            features=features,
            ssl=ssl_details,
            domain=domain_details,
            ml_prediction=ml_prediction
        )

        # 7. AI Executive Summary Synthesis
        logger.debug("Generating local AI-style dynamic description...")
        ai_summary, ai_recommendation = AISummaryGenerator.generate_summary(
            features=features,
            ssl=ssl_details,
            domain=domain_details,
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence
        )

        return ScanResult(
            url=url,
            timestamp=timestamp,
            is_valid_url=True,
            features=features,
            ssl_details=ssl_details,
            domain_details=domain_details,
            ml_prediction=ml_prediction,
            ml_confidence=ml_confidence,
            risk_details=risk_details,
            ai_explanation=ai_summary,
            ai_recommendation=ai_recommendation
        )


def show_banner():
    """Prints the PhishScope AI Ascii graphics banner and credits."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}========================================================================
{Fore.RED}{Style.BRIGHT}  ______   __    __  ______   ______   __    __   ______   ______   ______  
{Fore.RED}{Style.BRIGHT} /      \\ /  |  /  |/      | /      \\ /  |  /  | /      \\ /      \\ /      \\ 
{Fore.YELLOW}{Style.BRIGHT}/$$$$$$  |$$ |  $$ |$$$$$$/ /$$$$$$  |$$ |  $$ |/$$$$$$  |$$$$$$  |$$$$$$  |
{Fore.YELLOW}{Style.BRIGHT}$$ |  $$ |$$ |__$$ |  $$ |  $$ \\__$$/ $$ |__$$ |$$ \\__$$/ $$ |  $$/ $$    $$ |
{Fore.GREEN}{Style.BRIGHT}$$ |__$$ |$$    $$ |  $$ |  $$      \\ $$    $$ |$$      \\ $$ |      $$$$$$$$/ 
{Fore.GREEN}{Style.BRIGHT}$$    $$/ $$$$$$$$ |  $$ |   $$$$$$  |$$$$$$$$ | $$$$$$  |$$ |   __ $$       |
{Fore.BLUE}{Style.BRIGHT}$$$$$$$/  $$ |  $$ | _$$ |_ /  \\__$$ |$$ |  $$ |/  \\__$$ |$$ \\__/  |$$$$$$$/ 
{Fore.BLUE}{Style.BRIGHT}$$ |       $$ |  $$ |/ $$   |$$    $$/ $$ |  $$ |$$    $$/ $$    $$/ $$       |
{Fore.MAGENTA}{Style.BRIGHT}$$/        $$/   $$/ $$$$$$/  $$$$$$/  $$/   $$/  $$$$$$/   $$$$$$/   $$$$$$$/ 
                                                                        
                  {Fore.WHITE}{Style.BRIGHT}PhishScope AI Security URL Analysis Core Engine
========================================================================
{Fore.WHITE}Developed By      : {Fore.GREEN}Meera V Nair
{Fore.WHITE}GitHub Portfolio  : {Fore.BLUE}https://github.com/meeravnair
{Fore.WHITE}Current System Time: {Fore.YELLOW}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{Fore.CYAN}========================================================================
"""
    print(banner)

def render_cli_progress_bar(duration: float = 1.0):
    """Renders a simple console progress bar for user visual feedback."""
    sys.stdout.write(f"{Fore.CYAN}[*] Initializing threat intelligence analysis modules...\n")
    sys.stdout.flush()
    steps = 40
    for i in range(steps + 1):
        percent = (i / steps) * 100
        bar = "#" * i + "-" * (steps - i)
        sys.stdout.write(f"\r\t[{Fore.YELLOW}{bar}{Fore.WHITE}] {percent:3.0f}% Completed")
        sys.stdout.flush()
        time.sleep(duration / steps)
    sys.stdout.write("\n\n")
    sys.stdout.flush()

def display_scan_report(result: ScanResult):
    """Formats and prints the scan results to the console."""
    if not result.is_valid_url:
        print(f"{Fore.RED}[-] URL format check failed. Please supply a valid formatted URL (e.g. https://google.com)")
        return

    # Set risk color
    r_details = result.risk_details
    risk_level = r_details.risk_level
    score = r_details.final_score

    if risk_level == "Critical":
        risk_color = Fore.RED + Back.BLACK + Style.BRIGHT
    elif risk_level == "High":
        risk_color = Fore.RED + Style.BRIGHT
    elif risk_level == "Medium":
        risk_color = Fore.YELLOW + Style.BRIGHT
    elif risk_level == "Low":
        risk_color = Fore.GREEN + Style.BRIGHT
    else:
        risk_color = Fore.GREEN + Back.BLACK + Style.BRIGHT

    print(f"{Fore.CYAN}======================= SCAN METRICS & DIAGNOSTIC REPORT =======================")
    print(f"{Fore.WHITE}{Style.BRIGHT}Target URL      : {Fore.YELLOW}{result.url}")
    print(f"{Fore.WHITE}Scan Timestamp  : {result.timestamp}")
    print(f"{Fore.WHITE}Risk Security   : {risk_color}{score}/100 ({risk_level} Risk Level)")
    print(f"{Fore.WHITE}ML Prediction   : {Fore.YELLOW if result.ml_prediction == 'Suspicious' else (Fore.RED if result.ml_prediction == 'Phishing' else Fore.GREEN)}{result.ml_prediction} ({result.ml_confidence * 100:.1f}% Confidence)")
    print(f"{Fore.CYAN}--------------------------------------------------------------------------------")
    
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] AI EXECUTIVE ANALYSIS SUMMARY:")
    print(f"{Fore.WHITE}{result.ai_explanation}")
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] CORE MITIGATION RECOMMENDATION:")
    print(f"{Fore.GREEN if score >= 60 else Fore.RED}{Style.BRIGHT}{result.ai_recommendation}")
    print(f"{Fore.CYAN}--------------------------------------------------------------------------------")
    
    print(f"{Fore.CYAN}{Style.BRIGHT}[+] CORE LEXICAL FEATURES EXTRACTED:")
    feats = result.features
    print(f" - URL Length      : {feats.url_length:<6} | dots  : {feats.dot_count:<6} | hyphens : {feats.hyphen_count}")
    print(f" - Host Length     : {feats.hostname_length:<6} | slashes: {feats.slash_count:<6} | digits  : {feats.digit_count}")
    print(f" - Path Length     : {feats.path_length:<6} | query: {feats.query_length:<6} | entropy : {feats.entropy_score}")
    print(f" - Special Chars   : {feats.special_char_count}")
    print(f"{Fore.CYAN}--------------------------------------------------------------------------------")

    print(f"{Fore.CYAN}{Style.BRIGHT}[+] SSL/TLS INTEGRITY VERIFICATION:")
    ssl_c = result.ssl_details
    print(f" - Certificate Exists  : {'Yes' if ssl_c.certificate_exists else 'No'}")
    print(f" - Certificate Valid   : {'Yes' if ssl_c.certificate_valid else 'No'}")
    print(f" - Issuer Name         : {ssl_c.issuer or 'None'}")
    print(f" - Days to Expiry      : {ssl_c.days_until_expiry if ssl_c.days_until_expiry is not None else 'N/A'}")
    if ssl_c.ssl_error_message:
        print(f" - SSL Error Detail    : {Fore.RED}{ssl_c.ssl_error_message}")
    print(f"{Fore.CYAN}--------------------------------------------------------------------------------")

    print(f"{Fore.CYAN}{Style.BRIGHT}[+] DOMAIN REPUTATION & DNS THREAT INTEL:")
    dom = result.domain_details
    print(f" - Direct IP Address  : {'Yes ('+dom.ip_version+')' if dom.is_ip_address else 'No'}")
    print(f" - Redirection service: {'Yes' if dom.is_url_shortener else 'No'}")
    print(f" - Suspicious TLD     : {'Yes (.'+dom.tld+')' if dom.is_suspicious_tld else 'No'}")
    print(f" - Typosquatting Match: {'Yes' if dom.is_typosquatting else 'No'}")
    if dom.is_typosquatting:
        print(f"   - Impersonated Brand: {Fore.RED}{dom.impersonated_brand.upper()}")
    print(f" - Homograph Attack   : {'Yes' if dom.is_homograph_attack else 'No'}")
    print(f" - Subdomain nesting  : {dom.subdomain_count} layer(s)")
    print(f" - Domain Reg Date    : {dom.registration_date or 'Unknown'} (Age: {dom.age_in_days if dom.age_in_days is not None else 'N/A'} days)")
    if dom.suspicious_keywords_found:
        print(f" - Suspicious Keywords: {Fore.YELLOW}{', '.join(dom.suspicious_keywords_found)}")
    print(f" - Reputation Blacklist: {'Yes (Matched '+dom.blacklist_match_type+')' if dom.is_blacklisted else 'No'}")
    print(f"{Fore.CYAN}================================================================================")


def main():
    """Main CLI runner logic."""
    show_banner()
    
    parser = argparse.ArgumentParser(
        description="PhishScope AI URL security auditor engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-u", "--url", type=str, help="The target URL address to analyze.")
    parser.add_argument("-t", "--train", action="store_true", help="Force train/compare the ML model classifiers.")
    parser.add_argument("-o", "--output", type=str, help="File path to save result json details.")
    
    args = parser.parse_args()

    scanner = PhishScopeScanner()

    # Handle force training
    if args.train:
        print(f"{Fore.CYAN}[*] Starting Machine Learning Classifier Training Pipeline...")
        try:
            results = scanner.ml_classifier.train_models()
            print(f"{Fore.GREEN}[+] Model training completed successfully!")
            print(f"{Fore.CYAN}--------------------------------------------------")
            for model_name, acc in results.items():
                print(f" - {model_name:<20} : {acc*100:.2f}% validation accuracy")
            print(f"{Fore.CYAN}--------------------------------------------------")
        except Exception as e:
            print(f"{Fore.RED}[-] Model training pipeline failed: {e}")
        return

    # Handle single URL scanning
    if args.url:
        render_cli_progress_bar(1.2)
        try:
            result = scanner.scan_url(args.url)
            display_scan_report(result)
            
            # Export if output arg specified
            if args.output and result.is_valid_url:
                try:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        json.dump(result.to_dict(), f, indent=4)
                    print(f"{Fore.GREEN}[+] Scan results exported to: {args.output}")
                except Exception as ex:
                    print(f"{Fore.RED}[-] Failed to export scan results to JSON: {ex}")
            
            # Auto-save HTML, JSON, CSV reports in reports/ folder using the reporting module
            from report import ReportGenerator
            report_paths = ReportGenerator.generate_all_reports(result)
            print(f"{Fore.GREEN}[+] Professional reports generated successfully in local folder:")
            for r_type, path in report_paths.items():
                print(f" - {r_type.upper()}: [report](file:///{path.replace('\\', '/')})")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Scan encountered an error: {e}")
            import traceback
            traceback.print_exc()
    else:
        # If no arguments provided, print usage help
        parser.print_help()

if __name__ == "__main__":
    main()
