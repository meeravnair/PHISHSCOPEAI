"""
PhishScope AI - Logging Utility
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module sets up centralized logging for console output and persistent file logging.
"""

import logging
import os
import sys
from config import LOG_FILE_PATH

def get_logger(name: str) -> logging.Logger:
    """
    Configures and returns a Logger instance.
    
    Args:
        name (str): The name of the module invoking the logger.
        
    Returns:
        logging.Logger: The configured Logger instance.
    """
    logger = logging.getLogger(name)
    
    # If logger is already configured, return it to avoid duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    try:
        # Ensure log directory exists
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        # Fallback console log error
        print(f"[-] Failed to set up file logging: {e}", file=sys.stderr)

    return logger
