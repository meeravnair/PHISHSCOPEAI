"""
PhishScope AI - Flask Web Application Dashboard
Developed By: Meera V Nair
GitHub: https://github.com/meeravnair

This module runs the interactive Flask server, providing a modern dark-themed
dashboard for real-time URL scanning, visual metrics, history logs, and report retrieval.
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for

from scanner import PhishScopeScanner
from report import ReportGenerator
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, DEVELOPER_NAME, DEVELOPER_GITHUB, REPORTS_DIR
from logger import get_logger

logger = get_logger("web_app")

app = Flask(__name__, template_folder="templates", static_folder="static")
scanner = PhishScopeScanner()

# Persistent scan history JSON file path
HISTORY_FILE_PATH = os.path.join(REPORTS_DIR, "scan_history.json")

def load_scan_history() -> list:
    """Loads scan history from the local JSON database."""
    if os.path.exists(HISTORY_FILE_PATH):
        try:
            with open(HISTORY_FILE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read scan history file: {e}")
    return []

def save_to_scan_history(result_dict: dict):
    """Appends a scan result summary to the history database."""
    history = load_scan_history()
    
    # Check if URL already scanned; if so, we can move it to top or update
    history = [item for item in history if item["url"] != result_dict["url"]]
    
    summary = {
        "url": result_dict["url"],
        "timestamp": result_dict["timestamp"],
        "final_score": result_dict["risk_details"]["final_score"],
        "risk_level": result_dict["risk_details"]["risk_level"],
        "ml_prediction": result_dict["ml_prediction"],
        "ml_confidence": result_dict["ml_confidence"]
    }
    
    history.insert(0, summary)  # Prepend new scans
    history = history[:15]       # Retain last 15 scans
    
    try:
        os.makedirs(os.path.dirname(HISTORY_FILE_PATH), exist_ok=True)
        with open(HISTORY_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to save scan history file: {e}")

@app.route("/", methods=["GET"])
def index():
    """Renders the dashboard homepage showing input form and history logs."""
    history = load_scan_history()
    return render_template(
        "index.html",
        developer_name=DEVELOPER_NAME,
        developer_github=DEVELOPER_GITHUB,
        history=history
    )

@app.route("/scan", methods=["POST"])
def scan():
    """Handles scan requests, saves history, and returns JSON or redirects."""
    url = request.form.get("url")
    if not url:
        return render_template("index.html", error="Please provide a valid URL to analyze.")

    try:
        # Run scan orchestrator
        result = scanner.scan_url(url)
        
        if not result.is_valid_url:
            return render_template("index.html", error=f"Invalid URL formatting: '{url}'. Please include the schema protocol (e.g. http:// or https://).")

        result_dict = result.to_dict()
        
        # Save to database file
        save_to_scan_history(result_dict)
        
        # Generate reports (HTML, CSV, JSON, MD) in reports directory
        report_paths = ReportGenerator.generate_all_reports(result)
        result_dict["report_paths"] = {k: os.path.basename(v) for k, v in report_paths.items()}

        return render_template(
            "result.html",
            result=result_dict,
            developer_name=DEVELOPER_NAME,
            developer_github=DEVELOPER_GITHUB
        )
    except Exception as e:
        logger.error(f"Web scan route error: {e}")
        return render_template("index.html", error=f"Scan error occurred: {str(e)}")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """REST API endpoint for scanning URLs."""
    data = request.get_json() or {}
    url = data.get("url")
    if not url:
        return jsonify({"success": False, "error": "Missing 'url' parameter"}), 400

    try:
        result = scanner.scan_url(url)
        if not result.is_valid_url:
            return jsonify({"success": False, "error": "Invalid URL formatting"}), 400
            
        result_dict = result.to_dict()
        save_to_scan_history(result_dict)
        
        return jsonify({"success": True, "data": result_dict})
    except Exception as e:
        logger.error(f"API Scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/reports/download/<filename>", methods=["GET"])
def download_report(filename):
    """Serves report files directly from the reports folder."""
    # Prevent Directory Traversal vulnerability
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(REPORTS_DIR, safe_filename)
    
    if os.path.exists(file_path):
        try:
            return send_file(file_path, as_attachment=True)
        except Exception as e:
            logger.error(f"Download failed for {safe_filename}: {e}")
            return f"Error downloading report: {e}", 500
    else:
        return "Report file not found.", 404

@app.route("/history/clear", methods=["POST"])
def clear_history():
    """Clears the scan logs."""
    if os.path.exists(HISTORY_FILE_PATH):
        try:
            os.remove(HISTORY_FILE_PATH)
        except Exception as e:
            logger.error(f"Failed to clear history log file: {e}")
    return redirect(url_for("index"))

if __name__ == "__main__":
    logger.info(f"Starting PhishScope AI Web Dashboard Server on http://{FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
