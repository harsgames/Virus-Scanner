from flask import Flask, render_template, request, jsonify
import requests
import time

app = Flask(__name__)

VT_API_KEY = "ef9e902fff78178e965b1a558da319a26f845967c7f24a252ce8cb5e27c1091b"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HIBP_API_KEY = "f698b0efaeca4167a5e98e7786870eb8"  # Paid key required
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
        raise Exception("Invalid or missing HIBP API key.")
    if res.status_code == 429:
        raise Exception("Rate limited by HIBP API.")
    res.raise_for_status()

    return res.json()

@app.route("/")
def index():
    return render_template("frontend.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    scan_type = data.get("type")
    value = data.get("value")

    try:
        if scan_type == "url":
            analysis_id = vt_submit_url(value)
            for _ in range(12):
                report = vt_get_report(analysis_id)
                if report["data"]["attributes"]["status"] == "completed":
                    break
                time.sleep(5)
            else:
                return jsonify({"error": "VirusTotal scan timeout."}), 504

            stats = report["data"]["attributes"]["stats"]
            return jsonify({
                "verdict": vt_verdict(stats),
                "stats": stats
            })

        elif scan_type == "email":
            breaches = hibp_check_email(value)
            return jsonify(breaches)

        else:
            return jsonify({"error": "Invalid scan type."}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
