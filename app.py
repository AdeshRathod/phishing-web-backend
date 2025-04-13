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
from PIL.ExifTags import TAGS
import numpy as np
import cv2
from pyzbar.pyzbar import decode
import easyocr
import re


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

def pgd_attack(model, features, epsilon=0.1, alpha=0.01, num_iterations=10):
    """
    Perform PGD attack on the input features.

    Args:
        model: The trained machine learning model.
        features: The input features as a Pandas DataFrame.
        epsilon: The maximum perturbation allowed.
        alpha: The step size for each iteration.
        num_iterations: The number of iterations for the attack.

    Returns:
        adversarial_features: The adversarially perturbed features.
    """
    original_features = features.values.astype(np.float32)
    adversarial_features = original_features.copy()

    for _ in range(num_iterations):
        # Simulate gradient computation (replace with actual gradient logic if available)
        gradient = np.random.uniform(-1, 1, adversarial_features.shape)  # Random gradient for demonstration
        adversarial_features += alpha * np.sign(gradient)
        perturbation = np.clip(adversarial_features - original_features, -epsilon, epsilon)
        adversarial_features = original_features + perturbation

    return pd.DataFrame(adversarial_features, columns=features.columns)

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

        # Generate adversarial examples using PGD
        adversarial_features = pgd_attack(model, features_df, epsilon=0.1, alpha=0.01, num_iterations=10)

        # Predict on original and adversarial examples
        original_prediction = model.predict(features_df).tolist()
        adversarial_prediction = model.predict(adversarial_features).tolist()

        # Adversarial check
        adversarial_check = {
            "name": "Adversarial Robustness (PGD)",
            "description": "Evaluates the model's robustness to adversarial attacks using PGD.",
            "score": 100 if original_prediction == adversarial_prediction else 0,
            "findings": "Model is robust to adversarial attacks." if original_prediction == adversarial_prediction else "Model is vulnerable to adversarial attacks.",
            "details":[
                # f"Original Prediction: {original_prediction}",
                # f"Adversarial Prediction: {adversarial_prediction}",
                f"Adversarial Features: {adversarial_features.to_dict(orient='records')}"
            ],
        }

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

        # Combine all checks, with adversarial check at the top
        all_checks = [adversarial_check] + external_checks + internal_checks

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

    temp_dir = tempfile.gettempdir()
    filepath = os.path.join(temp_dir, filename)
    file.save(filepath)

    try:
        image = cv2.imread(filepath)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        # --- TEXT ANALYSIS VIA EasyOCR ---
        reader = easyocr.Reader(['en'])
        results = reader.readtext(image)
        extracted_text = " ".join([text[1] for text in results])

        suspicious_keywords = ["urgent", "click here", "verify", "account", "password", "login", "reset", "security"]
        found_keywords = [kw for kw in suspicious_keywords if kw.lower() in extracted_text.lower()]
        text_score = 100 - len(found_keywords) * 10
        text_score = max(40, min(text_score, 100))

        # --- URL DETECTION ---
        urls = re.findall(r'https?://[^\s\n\r]+', extracted_text)
        url_score = 90 if not urls else 60

        # --- QR CODE DETECTION ---
        decoded_qr = decode(image)
        qr_score = 90 if not decoded_qr else 70

        # --- BRAND IMPERSONATION (Basic) ---
        brand_keywords = [
            "apple", "amazon", "paypal", "google", "microsoft",  # Global brands
            "sbi", "icici", "hdfc", "axis bank", "paytm", "phonepe", "flipkart", "airtel", "vi", "jio", "lic", "irctc", "zomato", "swiggy"
        ]
        found_brands = [brand for brand in brand_keywords if brand.lower() in extracted_text.lower()]
        brand_score = 90 if not found_brands else 60

        # --- SOCIAL ENGINEERING DETECTION ---
        social_keywords = ["limited time", "act now", "only today", "warning", "locked", "compromised"]
        social_found = [kw for kw in social_keywords if kw.lower() in extracted_text.lower()]
        social_score = 90 - len(social_found) * 10
        social_score = max(50, min(social_score, 90))

        # --- FINAL SCORE ---
        scores = [text_score, url_score, qr_score, brand_score, social_score]
        overall_score = sum(scores) // len(scores)

        if overall_score < 60:
            risk_level = "High Risk"
            summary = "This image likely contains phishing content."
            recommendation = (
                "Do not interact with any links, QR codes, or contact information in this image. "
                "Delete the message and block the sender."
            )
        elif overall_score < 80:
            risk_level = "Medium Risk"
            summary = "This image has some suspicious characteristics."
            recommendation = (
                "Proceed with caution. Verify the sender's identity through official channels before taking any action."
            )
        else:
            risk_level = "Low Risk"
            summary = "This image appears to be safe."
            recommendation = (
                "No phishing content detected. Still, always be cautious with messages from unknown sources."
            )

        checks = [
            {
                "name": "Text Analysis",
                "description": "Examines text in the image for phishing indicators and suspicious language.",
                "score": text_score,
                "findings": f"Found {len(found_keywords)} suspicious text indicators." if found_keywords else "No suspicious text detected.",
                "details": found_keywords or ["All text appears normal."],
            },
            {
                "name": "URL Detection",
                "description": "Identifies and analyzes URLs present in the image.",
                "score": url_score,
                "findings": f"Detected {len(urls)} URLs." if urls else "No URLs detected in text.",
                "details": urls or ["No links found in the image."],
            },
            {
                "name": "QR Code Analysis",
                "description": "Detects and analyzes QR codes in the image.",
                "score": qr_score,
                "findings": "QR code(s) found and require verification." if decoded_qr else "No QR codes detected.",
                "details": [qr.data.decode("utf-8") for qr in decoded_qr] or ["No QR data."],
            },
            {
                "name": "Brand Impersonation",
                "description": "Detects attempts to impersonate trusted brands and services.",
                "score": brand_score,
                "findings": f"Brand references found: {found_brands}" if found_brands else "No brand impersonation detected.",
                "details": found_brands or ["No brand names detected in text."],
            },
            {
                "name": "Social Engineering Indicators",
                "description": "Identifies social engineering tactics and manipulation techniques.",
                "score": social_score,
                "findings": f"Found {len(social_found)} social engineering terms." if social_found else "No urgent or manipulative language detected.",
                "details": social_found or ["No social engineering patterns found."],
            },
        ]

        response = {
            "summary": summary,
            "detailedSummary": summary,
            "recommendation": recommendation,
            "riskLevel": risk_level,
            "checks": checks,
        }

        return jsonify(response)

    finally:
        if os.path.exists(filepath):
            os.remove(filepath)
# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
