from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import pandas as pd
import requests
import whois
import ssl
import csv
import socket
import base64
from datetime import datetime
from urllib.parse import urlparse
from utils import extract_features_dict
from concurrent.futures import ThreadPoolExecutor
from Utils.whois_lookup import get_whois_details
from Utils.shodan_lookup import search_shodan
import tempfile
import magic
from PIL import Image
from PIL.ExifTags import TAGS
import hashlib



# Constants
MODEL_PATH = os.path.join('models', 'final_model.pkl')
VIRUSTOTAL_API_KEY = "44ca818a7925714131cbd49429118a812f3fd6c92c6832d02236eb7f0ae0b8c0"
GOOGLE_API_KEY = "AIzaSyAecmHb85bCr3Ywfkvi3ZnJNvN3Faeej9U"

# Initialize app
app = Flask(__name__)
CORS(app)

# Helper Functions
def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def load_tranco_list():
    domains = set()
    try:
        with open('tranco_LJL44.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            for row in reader:
                domains.add(row[1].lower())  # row[1] is domain
    except Exception as e:
        print(f"Failed to load Tranco list: {e}")
    return domains

TRANCOLIST_DOMAINS = load_tranco_list()

def check_tranco_rank(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        domain = domain.lstrip('www.')
        return domain in TRANCOLIST_DOMAINS
    except Exception as e:
        print(f"Tranco rank check failed: {e}")
        return False

def check_google_safe_browsing(api_key, url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE",
                "THREAT_TYPE_UNSPECIFIED"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=body)
        print(f"Safe Browsing Raw Response: {response.text}")  # print raw response here
        if response.status_code == 200:
            result = response.json()
            return result.get('matches') is not None
        else:
            print(f"Safe Browsing API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"Safe Browsing Exception: {e}")
        return False

openphish_cache = None
last_openphish_fetch_time = None

def check_openphish(url):
    global openphish_cache, last_openphish_fetch_time
    try:
        now = datetime.now()
        if openphish_cache is None or (now - last_openphish_fetch_time).seconds > 3600:  # refresh every 1 hour
            feed_url = "https://openphish.com/feed.txt"
            response = requests.get(feed_url, timeout=10)
            if response.status_code == 200:
                openphish_cache = response.text.splitlines()
                last_openphish_fetch_time = now
            else:
                print(f"OpenPhish feed fetch failed: {response.status_code}")
                return False

        normalized_url = url.rstrip('/').lower()
        return any(normalized_url in line.lower() for line in openphish_cache)
    except Exception as e:
        print(f"OpenPhish check failed: {e}")
        return False



def check_virustotal(api_key, url):
    headers = {
        "x-apikey": api_key
    }
    url_id = url_to_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(api_url, headers=headers)
        # print("VirusTotal Raw Response:", response.json())

        if response.status_code == 200:
            result = response.json()
            malicious_votes = result['data']['attributes']['last_analysis_stats']['malicious']
            return malicious_votes > 0
        else:
            print(f"VirusTotal API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"VirusTotal Exception: {e}")
        return False

def domain_age_in_days(url):
    try:
        parsed_url = urlparse(url)
        domain_info = whois.whois(parsed_url.netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now() - creation_date).days
            return age
        else:
            return -1
    except Exception as e:
        print(f"WHOIS failed: {e}")
        return -1

def check_ssl_expiry(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                remaining_days = (expiry_date - datetime.utcnow()).days
                return remaining_days
    except Exception as e:
        print(f"SSL check failed: {e}")
        return -1

def unwrap_shortlink(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.url
    except:
        return url

# Load ML Model
try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print("✅ Model loaded successfully.")
except Exception as e:
    model = None
    print(f"❌ Failed to load model: {e}")

# Routes
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Phishing Detection API is running.'})

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not loaded.'}), 500

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" in request.'}), 400

    url = data['url']

    try:
        features = extract_features_dict(url)
        features_df = pd.DataFrame([features])

        with ThreadPoolExecutor(max_workers=5) as executor:
            safe_browsing_future = executor.submit(check_google_safe_browsing, GOOGLE_API_KEY, url)
            virustotal_future = executor.submit(check_virustotal, VIRUSTOTAL_API_KEY, url)
            domain_age_future = executor.submit(domain_age_in_days, url)
            openphish_future = executor.submit(check_openphish, url)
            tranco_rank_future = executor.submit(check_tranco_rank, url)
            whois_future = executor.submit(get_whois_details, url)
            shodan_future = executor.submit(search_shodan, url)

            safe_browsing_flag = safe_browsing_future.result()
            virustotal_flag = virustotal_future.result()
            domain_age = domain_age_future.result()
            openphish_flag = openphish_future.result()
            tranco_flag = tranco_rank_future.result()
            whois_data = whois_future.result()
            shodan_flag = shodan_future.result()

        # Extract detailed WHOIS information
        whois_details = []
        if whois_data:
            whois_details = [
                f"Domain Name: {whois_data.get('domain_name')}",
                f"Registrar: {whois_data.get('registrar')}",
                f"Creation Date: {whois_data.get('creation_date')}",
                f"Expiration Date: {whois_data.get('expiration_date')}",
                f"Updated Date: {whois_data.get('updated_date')}",
                f"Name Servers: {', '.join(whois_data.get('name_servers', [])) if whois_data.get('name_servers') else 'N/A'}"
            ]

        # External checks
        external_checks = [
            {
                "name": "Google Safe Browsing",
                "description": "Checks if the URL is flagged by Google Safe Browsing.",
                "score": 100 if not safe_browsing_flag else 0,
                "findings": "No issues detected." if not safe_browsing_flag else "URL flagged as malicious.",
                "details": ["Google Safe Browsing API returned no threats." if not safe_browsing_flag else "Threat detected by Google Safe Browsing."],
            },
            {
                "name": "VirusTotal",
                "description": "Checks if the URL is flagged by VirusTotal.",
                "score": 100 if not virustotal_flag else 0,
                "findings": "No issues detected." if not virustotal_flag else "URL flagged as malicious.",
                "details": ["VirusTotal analysis shows no malicious activity." if not virustotal_flag else "Malicious activity detected by VirusTotal."],
            },
            {
                "name": "OpenPhish",
                "description": "Checks if the URL is listed in the OpenPhish feed.",
                "score": 100 if not openphish_flag else 0,
                "findings": "No issues detected." if not openphish_flag else "URL listed in OpenPhish feed.",
                "details": ["URL not found in OpenPhish feed." if not openphish_flag else "URL found in OpenPhish feed."],
            },
        ]

        # Internal checks
        internal_checks = [
            {
                "name": "Domain Age",
                "description": "Checks the age of the domain in days.",
                "score": 100 if domain_age > 30 else 50 if domain_age > 0 else 0,
                "findings": f"Domain age is {domain_age} days." if domain_age > 0 else "Domain age could not be determined.",
                "details": [f"Domain registered {domain_age} days ago." if domain_age > 0 else "WHOIS data does not provide domain age."],
            },
            {
                "name": "Tranco Rank",
                "description": "Checks if the domain is in the top 1M Tranco list.",
                "score": 100 if tranco_flag else 50,
                "findings": "Domain is in the top 1M Tranco list." if tranco_flag else "Domain is not in the top 1M Tranco list.",
                "details": ["Domain is ranked in the Tranco list." if tranco_flag else "Domain is not ranked in the Tranco list."],
            },
            {
                "name": "WHOIS Details",
                "description": "Provides WHOIS details for the domain, including registrar, creation date, expiration date, and name servers.",
                "score": 100 if whois_data else 50,
                "findings": "WHOIS details retrieved successfully." if whois_data else "WHOIS details could not be retrieved.",
                "details": whois_details if whois_details else ["WHOIS data is unavailable."],
            },
            {
                "name": "Shodan Analysis",
                "description": "Checks the server's reputation using Shodan.",
                "score": 100 if shodan_flag else 50,
                "findings": "No suspicious activity detected on the server." if shodan_flag else "Server has suspicious activity.",
                "details": ["Shodan analysis shows no suspicious activity." if shodan_flag else "Shodan analysis detected suspicious activity."],
            },
        ]

        # Combine all checks
        all_checks = external_checks + internal_checks

        # Calculate overall score
        overall_score = sum(check["score"] for check in all_checks) // len(all_checks)

        # Determine risk level
        if overall_score >= 80:
            risk_level = "Low Risk"
            summary = "This website appears to be legitimate."
            recommendation = "You can proceed with caution, but always be vigilant when sharing personal information online."
        elif overall_score >= 60:
            risk_level = "Medium Risk"
            summary = "This website has some suspicious characteristics."
            recommendation = "Proceed with caution. Verify the website's legitimacy before entering sensitive information."
        else:
            risk_level = "High Risk"
            summary = "This website shows strong signs of being a phishing attempt."
            recommendation = "Do not proceed. Avoid entering any personal information or credentials on this website."

        # Response
        response = {
            "url": url,
            "summary": summary,
            "detailedSummary": summary, 
            "recommendation": recommendation,
            "riskLevel": risk_level,
            "overallScore": overall_score,
            "checks": all_checks,
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/report_mistake', methods=['POST'])
def report_mistake():
    data = request.get_json()
    url = data.get('url')
    true_label = data.get('true_label')  # 0 (legit) or 1 (phishing)
    if not url or true_label is None:
        return jsonify({'error': 'Missing url or true_label.'}), 400

    try:
        features = extract_features_dict(url)
        features['true_label'] = true_label

        df = pd.DataFrame([features])

        if not os.path.exists('reported_mistakes.csv'):
            df.to_csv('reported_mistakes.csv', index=False)
        else:
            df.to_csv('reported_mistakes.csv', mode='a', header=False, index=False)

        return jsonify({'message': 'Reported mistake successfully recorded.'}), 200

    except Exception as e:
        return jsonify({'error': f'Reporting mistake failed: {str(e)}'}), 500
    

@app.route("/scan-image", methods=["POST"])
def scan_image():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = file.filename

    # Create a secure temporary file
    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, filename)
    file.save(filepath)

    results = {}

    try:
        # 1. Basic file type check
        mime = magic.from_file(filepath, mime=True)
        results["mime_type"] = mime

        # 2. Metadata extraction using Pillow
        metadata = {}
        with Image.open(filepath) as img:
            info = img._getexif()
            if info:
                for tag, value in info.items():
                    tag_name = TAGS.get(tag, tag)
                    metadata[tag_name] = value
        results["metadata"] = metadata or "No metadata found."

        # 3. VirusTotal scan (file hash scan)
        with open(filepath, "rb") as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(vt_url, headers)

        if vt_response.status_code == 200:
            results["virustotal"] = vt_response.json()
        else:
            results["virustotal"] = "File not found in VT database."
    
    finally:
        os.remove(filepath)  # Clean up temp file

    return jsonify(results)

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
