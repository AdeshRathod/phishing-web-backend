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


## multiple dataset
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import pandas as pd
from utils import extract_features_dict

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join('models', 'final_model.pkl')

# Load model
try:
    with open(MODEL_PATH, 'rb') as file:
        model = pickle.load(file)
    print("✅ Model loaded successfully.")
except Exception as e:
    model = None
    print(f"❌ Failed to load model: {e}")

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
        prediction = model.predict(features_df)[0]
        result = "Phishing" if prediction == 1 else "Legitimate"
        return jsonify({'prediction': result})
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
