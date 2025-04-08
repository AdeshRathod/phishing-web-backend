
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
            get_whois_moredetails = executor.submit(get_whois_details, url)
            shodan_future = executor.submit(search_shodan, url)

            safe_browsing_flag = safe_browsing_future.result()
            virustotal_flag = virustotal_future.result()
            domain_age = domain_age_future.result()
            openphish_flag = openphish_future.result()
            tranco_flag = tranco_rank_future.result()
            moredetails_flag = get_whois_moredetails.result()
            shodan_flag = shodan_future.result()

        reasoning = []
        external_flags = [safe_browsing_flag, virustotal_flag, openphish_flag]
        final_label = ""
        probability = None

        # External checks first
        if any(external_flags):
            final_label = "Phishing (External Verification)"
            probability = 0.99
            if safe_browsing_flag:
                reasoning.append("Detected by Google Safe Browsing.")
            if virustotal_flag:
                reasoning.append("Detected as malicious by VirusTotal.")
            if openphish_flag:
                reasoning.append("Listed in OpenPhish feed.")
        else:
            # No external flags -> rely on model prediction
            prediction = model.predict(features_df)[0]
            proba = model.predict_proba(features_df)[0]
            base_probability = float(proba[1])  # Model phishing probability

            # Adjust probability based on domain age and tranco rank
            adjustment = 0
            if domain_age != -1 and domain_age < 30:
                adjustment += 0.10  # Increase probability by 10%
                reasoning.append(f"Domain is very new ({domain_age} days old).")
            if not tranco_flag:
                adjustment += 0.05  # Increase probability by 5%
                reasoning.append("Domain not found in Top 1M Tranco List.")

            adjusted_probability = min(base_probability + adjustment, 1.0)

            probability = adjusted_probability

            if adjusted_probability >= 0.5:
                final_label = "Phishing (Model Prediction)"
                reasoning.append(f"Model predicted phishing with adjusted probability {adjusted_probability:.2f}.")
            else:
                final_label = "Legitimate (Model Prediction)"
                reasoning.append(f"Model predicted legitimate with adjusted probability {1 - adjusted_probability:.2f}.")

        # Response
        response = {
            'prediction': final_label,
            'reasoning': reasoning,
            'model_probability_phishing': probability,
            'extracted_features': features,
            'external_checks': {
                'safe_browsing_detected': safe_browsing_flag,
                'virustotal_detected': virustotal_flag,
                'domain_age_days': domain_age,
                'openphish_detected': openphish_flag,
                'tranco_rank_found': tranco_flag,
                'shodan' : shodan_flag,
                'whois_moredetails' : moredetails_flag,
            }
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
    

@app.route("/api/scan-image", methods=["POST"])
def scan_image():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = file.filename
    filepath = os.path.join("/tmp", filename)
    file.save(filepath)

    results = {}

    # 1. Basic file type check
    mime = magic.from_file(filepath, mime=True)
    results["mime_type"] = mime

    # 2. Metadata extraction
    with exiftool.ExifTool() as et:
        metadata = et.get_metadata(filepath)
    results["metadata"] = metadata

    # 3. VirusTotal scan (file hash scan)
    with open(filepath, "rb") as f:
        file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(vt_url, headers=headers)

        if vt_response.status_code == 200:
            results["virustotal"] = vt_response.json()
        else:
            results["virustotal"] = "File not found in VT database."

    # 4. (Optional) YARA scanning or steganalysis can be added here

    os.remove(filepath)  # Clean up temp file
    return jsonify(results)


# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
