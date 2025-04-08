# # app.py
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import pickle
# import os

# from utils import extract_features

# # Initialize Flask app
# app = Flask(__name__)
# CORS(app)  # Enable CORS for all domains (be stricter in production)

# # Load model
# model_path = os.path.join(os.getcwd(), 'model', 'final_model.pkl')
# try:
#     with open(model_path, 'rb') as f:
#         model = pickle.load(f)
# except Exception as e:
#     model = None
#     print(f"Failed to load model: {e}")

# @app.route('/', methods=['GET'])
# def home():
#     return jsonify({'message': 'Phishing Detection API is running!'})

# @app.route('/predict', methods=['POST'])
# def predict():
#     if model is None:
#         return jsonify({'error': 'Model not loaded properly'}), 500

#     data = request.get_json()

#     if not data or 'url' not in data:
#         return jsonify({'error': 'Missing URL parameter'}), 400

#     url = data['url']

#     try:
#         features = extract_features(url)
#         prediction = model.predict([features])[0]
#         result = "Legitimate" if prediction == 1 else "Phishing"
#         return jsonify({'prediction': result})
#     except Exception as e:
#         return jsonify({'error': f'Prediction failed: {e}'}), 500

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)  # Set debug=False for production


## multiple dataset# app.py

# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import os
# import pickle
# import pandas as pd
# import requests
# import whois
# import base64
# from datetime import datetime
# from urllib.parse import urlparse
# from utils import extract_features_dict
# from concurrent.futures import ThreadPoolExecutor
# from urllib.parse import urlparse

# # Constants
# MODEL_PATH = os.path.join('models', 'final_model.pkl')
# VIRUSTOTAL_API_KEY = "44ca818a7925714131cbd49429118a812f3fd6c92c6832d02236eb7f0ae0b8c0"
# GOOGLE_API_KEY = "AIzaSyAecmHb85bCr3Ywfkvi3ZnJNvN3Faeej9U"

# # Initialize app
# app = Flask(__name__)
# CORS(app)

# # Helper Functions

# def url_to_id(url):
#     """
#     Converts URL into VirusTotal's URL ID format (base64-encoded).
#     """
#     return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# def check_google_safe_browsing(api_key, url):
#     """
#     Checks URL against Google Safe Browsing API.
#     """
#     api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
#     body = {
#         "client": {
#             "clientId": "phishing-detector",
#             "clientVersion": "1.0"
#         },
#         "threatInfo": {
#             "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
#             "platformTypes": ["ANY_PLATFORM"],
#             "threatEntryTypes": ["URL"],
#             "threatEntries": [{"url": url}]
#         }
#     }
#     try:
#         response = requests.post(api_url, json=body)
#         if response.status_code == 200:
#             result = response.json()
#             return result != {}
#         else:
#             print(f"Safe Browsing API error: {response.status_code}")
#             return False
#     except Exception as e:
#         print(f"Safe Browsing Exception: {e}")
#         return False

# def check_virustotal(api_key, url):
#     """
#     Checks URL using VirusTotal API.
#     """
#     headers = {
#         "x-apikey": api_key
#     }
#     url_id = url_to_id(url)
#     api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
#     try:
#         response = requests.get(api_url, headers=headers)
#         if response.status_code == 200:
#             result = response.json()
#             malicious_votes = result['data']['attributes']['last_analysis_stats']['malicious']
#             return malicious_votes > 0
#         else:
#             print(f"VirusTotal API error: {response.status_code}")
#             return False
#     except Exception as e:
#         print(f"VirusTotal Exception: {e}")
#         return False

# def domain_age_in_days(url):
#     """
#     Returns the age of the domain in days.
#     """
#     try:
#         parsed_url = urlparse(url)
#         domain_info = whois.whois(parsed_url.netloc)
#         creation_date = domain_info.creation_date
#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]
#         if creation_date:
#             age = (datetime.now() - creation_date).days
#             return age
#         else:
#             return -1
#     except Exception as e:
#         print(f"WHOIS failed: {e}")
#         return -1


# def check_ssl_expiry(hostname):
#     try:
#         context = ssl.create_default_context()
#         with socket.create_connection((hostname, 443)) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 cert = ssock.getpeercert()
#                 expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
#                 remaining_days = (expiry_date - datetime.utcnow()).days
#                 return remaining_days
#     except Exception as e:
#         print(f"SSL check failed: {e}")
#         return -1

# def unwrap_shortlink(url):
#     try:
#         response = requests.head(url, allow_redirects=True)
#         return response.url
#     except:
#         return url


# # Load ML Model
# try:
#     with open(MODEL_PATH, 'rb') as f:
#         model = pickle.load(f)
#     print("✅ Model loaded successfully.")
# except Exception as e:
#     model = None
#     print(f"❌ Failed to load model: {e}")

# # Routes

# @app.route('/', methods=['GET'])
# def home():
#     return jsonify({'message': 'Phishing Detection API is running.'})

# @app.route('/predict', methods=['POST'])
# def predict():
#     if model is None:
#         return jsonify({'error': 'Model not loaded.'}), 500

#     data = request.get_json()
#     if not data or 'url' not in data:
#         return jsonify({'error': 'Missing "url" in request.'}), 400

#     url = data['url']

#     try:
#         features = extract_features_dict(url)
#         features_df = pd.DataFrame([features])

#         with ThreadPoolExecutor(max_workers=3) as executor:
#             safe_browsing_future = executor.submit(check_google_safe_browsing, GOOGLE_API_KEY, url)
#             virustotal_future = executor.submit(check_virustotal, VIRUSTOTAL_API_KEY, url)
#             domain_age_future = executor.submit(domain_age_in_days, url)

#             safe_browsing_flag = safe_browsing_future.result()
#             virustotal_flag = virustotal_future.result()
#             domain_age = domain_age_future.result()

#         # Final decision
#         if safe_browsing_flag or virustotal_flag or (domain_age != -1 and domain_age < 30):
#             final_prediction = "Phishing (External Verification)"
#         else:
#             prediction = model.predict(features_df)[0]
#             final_prediction = "Phishing" if prediction == 1 else "Legitimate"

#         # 🆕 Include external API results in the response
#         response = {
#             'prediction': final_prediction,
#             'external_checks': {
#                 'safe_browsing_detected': safe_browsing_flag,
#                 'virustotal_detected': virustotal_flag,
#                 'domain_age_days': domain_age,
#                 'domain_age_check_success': domain_age
#             }
#         }

#         return jsonify(response)

#     except Exception as e:
#         return jsonify({'error': f'Prediction failed: {str(e)}'}), 500
    

# @app.route('/report_mistake', methods=['POST'])
# def report_mistake():
#     data = request.get_json()
#     url = data.get('url')
#     true_label = data.get('true_label')  # 0 or 1
#     if not url or true_label is None:
#         return jsonify({'error': 'Missing url or true_label.'}), 400

#     features = extract_features_dict(url)
#     features['true_label'] = true_label

#     df = pd.DataFrame([features])
#     if not os.path.exists('reported_mistakes.csv'):
#         df.to_csv('reported_mistakes.csv', index=False)
#     else:
#         df.to_csv('reported_mistakes.csv', mode='a', header=False, index=False)

#     return jsonify({'message': 'Reported successfully.'})


# # Run the app
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)


from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import pandas as pd
import requests
import whois
import base64
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from utils import extract_features_dict
from concurrent.futures import ThreadPoolExecutor

# Constants
MODEL_PATH = os.path.join('models', 'final_model.pkl')
VIRUSTOTAL_API_KEY = "44ca818a7925714131cbd49429118a812f3fd6c92c6832d02236eb7f0ae0b8c0"
GOOGLE_API_KEY = "AIzaSyAecmHb85bCr3Ywfkvi3ZnJNvN3Faeej9U"

# Initialize app
app = Flask(__name__)
CORS(app)

# Helper Functions

def url_to_id(url):
    """
    Converts URL into VirusTotal's URL ID format (base64-encoded).
    """
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_google_safe_browsing(api_key, url):
    """
    Checks URL against Google Safe Browsing API.
    """
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=body)
        if response.status_code == 200:
            result = response.json()
            return bool(result)
        else:
            print(f"Safe Browsing API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"Safe Browsing Exception: {e}")
        return False

def check_virustotal(api_key, url):
    """
    Checks URL using VirusTotal API.
    """
    headers = {
        "x-apikey": api_key
    }
    url_id = url_to_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        response = requests.get(api_url, headers=headers)
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
    """
    Returns the age of the domain in days.
    """
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
    """
    Checks SSL certificate expiry.
    """
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
    """
    Unwraps shortened URLs by following redirects.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
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

        with ThreadPoolExecutor(max_workers=3) as executor:
            safe_browsing_future = executor.submit(check_google_safe_browsing, GOOGLE_API_KEY, url)
            virustotal_future = executor.submit(check_virustotal, VIRUSTOTAL_API_KEY, url)
            domain_age_future = executor.submit(domain_age_in_days, url)

            safe_browsing_flag = safe_browsing_future.result()
            virustotal_flag = virustotal_future.result()
            domain_age = domain_age_future.result()

        # Final decision
        if safe_browsing_flag or virustotal_flag or (domain_age != -1 and domain_age < 30):
            final_prediction = "Phishing (External Verification)"
        else:
            prediction = model.predict(features_df)[0]
            final_prediction = "Phishing" if prediction == 1 else "Legitimate"

        response = {
            'prediction': final_prediction,
            'external_checks': {
                'safe_browsing_detected': safe_browsing_flag,
                'virustotal_detected': virustotal_flag,
                'domain_age_days': domain_age,
                'domain_age_check_success': domain_age != -1
            }
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/report_mistake', methods=['POST'])
def report_mistake():
    data = request.get_json()
    url = data.get('url')
    true_label = data.get('true_label')  # 0 or 1
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

        return jsonify({'message': 'Reported successfully.'})
    except Exception as e:
        return jsonify({'error': f'Failed to report: {str(e)}'}), 500

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
