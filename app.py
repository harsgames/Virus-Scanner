from flask import Flask, render_template, request, jsonify
import requests
import time
import re
import os

app = Flask(__name__)

VT_API_KEY = "ef9e902fff78178e965b1a558da319a26f845967c7f24a252ce8cb5e27c1091b"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HIBP_API_KEY = "f698b0efaeca4167a5e98e7786870eb8"  # Replace with your paid key!
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"

def vt_submit_url(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    res = requests.post(f"{VT_BASE_URL}/urls", headers=headers, data=data)
    res.raise_for_status()
    return res.json()["data"]["id"]

def vt_get_report(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    res = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
    res.raise_for_status()
    return res.json()

def vt_verdict(stats):
    if stats.get("malicious", 0) > 0:
        return "malicious"
    if stats.get("suspicious", 0) > 0:
        return "suspicious"
    if stats.get("harmless", 0) > 0:
        return "harmless"
    return "unknown"

def hibp_check_email(email):
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "VirusScanner/1.0"
    }
    params = {"truncateResponse": "false"}
    url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
    res = requests.get(url, headers=headers, params=params)

    if res.status_code == 404:
        return []
    if res.status_code == 401:
        raise Exception("Unauthorized: Invalid or missing HIBP API key.")
    if res.status_code == 429:
        raise Exception("Too many requests: Rate limited by HIBP API.")
    res.raise_for_status()

    breaches = res.json()
    results = []
    for breach in breaches:
        results.append({
            "Name": breach.get("Name"),
            "Title": breach.get("Title"),
            "Domain": breach.get("Domain"),
            "BreachDate": breach.get("BreachDate"),
            "AddedDate": breach.get("AddedDate"),
            "ModifiedDate": breach.get("ModifiedDate"),
            "PwnCount": breach.get("PwnCount"),
            "DataClasses": breach.get("DataClasses", []),
            "IsVerified": breach.get("IsVerified"),
            "IsFabricated": breach.get("IsFabricated"),
            "IsSensitive": breach.get("IsSensitive"),
            "IsRetired": breach.get("IsRetired"),
            "IsSpamList": breach.get("IsSpamList"),
            "LogoPath": breach.get("LogoPath")
        })
    return results

# EXISTING DESKTOP ROUTES
@app.route("/")
def index():
    """Default to URL scanner page"""
    return render_template("url-scanner.html")

@app.route("/url-scanner")
def url_scanner():
    """Dedicated URL scanner page"""
    return render_template("url-scanner.html")

@app.route("/email-scanner")
def email_scanner():
    """Dedicated email scanner page"""
    return render_template("email-scanner.html")

# NEW MOBILE ROUTES
@app.route("/mobile")
def mobile_index():
    """Mobile URL scanner page (default)"""
    return render_template("mobile-url-scanner.html")

@app.route("/mobile/url-scanner")
def mobile_url_scanner():
    """Mobile URL scanner page"""
    return render_template("mobile-url-scanner.html")

@app.route("/mobile/email-scanner")
def mobile_email_scanner():
    """Mobile email scanner page"""
    return render_template("mobile-email-scanner.html")

# REDIRECT ROUTES FOR MOBILE NAVIGATION
@app.route("/url-scanner-mobile")
def url_scanner_mobile_redirect():
    """Redirect for mobile navigation compatibility"""
    return render_template("mobile-url-scanner.html")

@app.route("/email-scanner-mobile")
def email_scanner_mobile_redirect():
    """Redirect for mobile navigation compatibility"""
    return render_template("mobile-email-scanner.html")

# API endpoint for all scan types (UNCHANGED)
@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        scan_type = data.get("type")
        value = data.get("value")
        scan_mode = data.get("mode", "quick")  # Support for scan modes
        
        if not scan_type or not value:
            return jsonify({"error": "Missing type or value parameter"}), 400

        if scan_type == "url":
            return handle_url_scan(value, scan_mode)
        elif scan_type == "email":
            return handle_email_scan(value, scan_mode)
        else:
            return jsonify({"error": "Invalid scan type. Use 'url' or 'email'"}), 400
            
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

def handle_url_scan(url, mode="quick"):
    """Handle URL scanning with VirusTotal"""
    try:
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Submit URL for scanning
        print(f"Submitting URL for analysis: {url}")
        analysis_id = vt_submit_url(url)
        print(f"Analysis ID: {analysis_id}")
        
        # Wait for analysis completion
        max_retries = 15 if mode == "deep" else 12
        for attempt in range(max_retries):
            print(f"Checking analysis status (attempt {attempt + 1}/{max_retries})")
            report = vt_get_report(analysis_id)
            status = report["data"]["attributes"]["status"]
            print(f"Status: {status}")
            
            if status == "completed":
                break
            elif status == "queued":
                time.sleep(5)
            else:
                time.sleep(3)
        else:
            return jsonify({
                "error": "Analysis timeout. The scan is taking longer than expected.",
                "suggestion": "Try again in a few minutes or use quick scan mode."
            }), 504

        # Extract results
        stats = report["data"]["attributes"]["stats"]
        engines = report["data"]["attributes"].get("results", {})
        print(f"Scan completed. Stats: {stats}")
        
        # Add additional analysis for deep mode
        additional_info = {}
        if mode == "deep":
            attributes = report["data"]["attributes"]
            additional_info = {
                "scan_date": attributes.get("date"),
                "total_votes": attributes.get("stats", {}).get("harmless", 0) + 
                             attributes.get("stats", {}).get("malicious", 0) + 
                             attributes.get("stats", {}).get("suspicious", 0),
                "reputation": calculate_reputation_score(stats)
            }
        
        return jsonify({
            "verdict": vt_verdict(stats),
            "stats": stats,
            "engines": engines,
            "additional_info": additional_info,
            "scan_mode": mode,
            "url_analyzed": url
        })

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
        if e.response.status_code == 401:
            return jsonify({"error": "Invalid VirusTotal API key"}), 401
        elif e.response.status_code == 429:
            return jsonify({"error": "API rate limit exceeded. Please try again later."}), 429
        else:
            return jsonify({"error": f"VirusTotal API error: {str(e)}"}), 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": f"URL scan failed: {str(e)}"}), 400

def handle_email_scan(email, mode="basic"):
    """Handle email breach checking with HIBP"""
    try:
        # Validate email format
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Check for breaches
        print(f"Checking email: {email}")
        breaches = hibp_check_email(email)
        print(f"Found {len(breaches)} breaches")
        
        # Process results based on scan mode
        if mode == "comprehensive":
            # For comprehensive mode, add more detailed analysis
            breach_analysis = analyze_breaches(breaches)
            return jsonify({
                "breaches": len(breaches),
                "details": breaches,
                "analysis": breach_analysis,
                "scan_mode": mode,
                "email_checked": email
            })
        else:
            # Basic mode - standard response
            return jsonify({
                "breaches": len(breaches),
                "details": breaches,
                "scan_mode": mode,
                "email_checked": email
            })

    except requests.exceptions.HTTPError as e:
        print(f"HIBP HTTP Error: {e}")
        if e.response.status_code == 401:
            return jsonify({"error": "Invalid HIBP API key or unauthorized access"}), 401
        elif e.response.status_code == 429:
            return jsonify({"error": "HIBP API rate limit exceeded. Please try again later."}), 429
        elif e.response.status_code == 404:
            # No breaches found
            return jsonify({
                "breaches": 0,
                "details": [],
                "scan_mode": mode,
                "email_checked": email
            })
        else:
            return jsonify({"error": f"HIBP API error: {str(e)}"}), 400
    except Exception as e:
        print(f"Email scan error: {e}")
        return jsonify({"error": f"Email scan failed: {str(e)}"}), 400

def calculate_reputation_score(stats):
    """Calculate a reputation score based on scan statistics"""
    total_engines = sum(stats.values())
    if total_engines == 0:
        return 50  # Neutral score
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    
    # Calculate score (0-100, where 100 is best)
    score = ((harmless * 100) + (suspicious * 30) + (malicious * 0)) / total_engines
    return round(score, 1)

def analyze_breaches(breaches):
    """Analyze breach data for comprehensive reporting"""
    if not breaches:
        return {
            "risk_level": "low",
            "most_recent_breach": None,
            "data_types_exposed": [],
            "total_accounts_affected": 0
        }
    
    # Sort by date to find most recent
    sorted_breaches = sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True)
    most_recent = sorted_breaches[0] if sorted_breaches else None
    
    # Collect all exposed data types
    all_data_types = set()
    total_affected = 0
    
    for breach in breaches:
        data_classes = breach.get("DataClasses", [])
        all_data_types.update(data_classes)
        total_affected += breach.get("PwnCount", 0)
    
    # Determine risk level
    breach_count = len(breaches)
    if breach_count >= 10:
        risk_level = "high"
    elif breach_count >= 5:
        risk_level = "medium"
    elif breach_count >= 1:
        risk_level = "low"
    else:
        risk_level = "none"
    
    return {
        "risk_level": risk_level,
        "most_recent_breach": most_recent,
        "data_types_exposed": list(all_data_types),
        "total_accounts_affected": total_affected,
        "breach_count": breach_count
    }

# Health check endpoint
@app.route("/api/health")
def health_check():
    """API health check endpoint"""
    return jsonify({
        "status": "healthy",
        "version": "2.0",
        "endpoints": {
            "url_scanner": "/",
            "url_scanner_alt": "/url-scanner", 
            "email_scanner": "/email-scanner",
            "mobile_url_scanner": "/mobile/url-scanner",
            "mobile_email_scanner": "/mobile/email-scanner",
            "api_scan": "/api/scan"
        }
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    
    print("🚀 Starting Enhanced Virus Scanner Backend...")
    print(f"📡 Server will run on port {port}")
    print("🌐 Available endpoints:")
    print(f"   • URL Scanner (Desktop): http://localhost:{port}/")
    print(f"   • Email Scanner (Desktop): http://localhost:{port}/email-scanner")
    print(f"   • URL Scanner (Mobile): http://localhost:{port}/mobile/url-scanner")
    print(f"   • Email Scanner (Mobile): http://localhost:{port}/mobile/email-scanner")
    print(f"   • API Health: http://localhost:{port}/api/health")
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
