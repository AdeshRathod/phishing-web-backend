# import pandas as pd
# from sklearn.model_selection import train_test_split
# from xgboost import XGBClassifier
# import joblib

# # Load dataset
# df = pd.read_csv('../dataset/phishing_dataset.csv')

# print(df.columns)

# # Drop the 'Index' column if it exists
# if 'Index' in df.columns:
#     df = df.drop(columns=['Index'])

# # Features and target
# X = df.drop(columns=['class'])  # all columns except the label
# y = df['class']  # label

# # 🛠 Fix labels: Replace -1 with 0
# y = y.replace(-1, 0)

# # Split into train/test
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Train model
# model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
# model.fit(X_train, y_train)

# # Save model
# joblib.dump(model, 'phishing_model.pkl')
# print("✅ Model trained and saved!")

##version 2 for training final model.pkl
# train_model.py
# import pandas as pd
# import pickle
# import os

# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import classification_report, accuracy_score

# # Define paths
# DATA_PATH = os.path.join(os.path.dirname(os.getcwd()), 'dataset', 'phishing_site_urls.csv')
# MODEL_DIR = os.path.join(os.getcwd(), 'models')
# MODEL_PATH = os.path.join(MODEL_DIR, 'final_model.pkl')

# def extract_features(url):
#     features = {}
#     features['url_length'] = len(url)
#     features['num_digits'] = sum(c.isdigit() for c in url)
#     features['num_special_chars'] = sum(c in ['-', '_', '.', '/'] for c in url)
#     features['has_https'] = int('https' in url)
#     features['count_www'] = url.count('www')
#     features['count_com'] = url.count('.com')
#     features['count_at'] = url.count('@')
#     return features

# def load_data(path):
#     try:
#         df = pd.read_csv(path)
#         print(f"Data loaded successfully: {df.shape[0]} samples")
#         return df
#     except Exception as e:
#         print(f"Error loading data: {e}")
#         raise

# def train_and_save_model():
#     # Load dataset
#     df = load_data(DATA_PATH)

#     print(df.columns)


#     features = df['URL'].apply(extract_features)
#     X = pd.DataFrame(features.tolist())
#     y = df['Label']
#     # Split dataset
#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y, test_size=0.2, random_state=42
#     )

#     # Initialize model
#     model = RandomForestClassifier(n_estimators=100, random_state=42)

#     # Train model
#     model.fit(X_train, y_train)
#     print("Model training completed.")

#     # Evaluate model
#     y_pred = model.predict(X_test)
#     acc = accuracy_score(y_test, y_pred)
#     print(f"Test Accuracy: {acc:.4f}")
#     print(classification_report(y_test, y_pred))

#     # Ensure model directory exists
#     os.makedirs(MODEL_DIR, exist_ok=True)

#     # Save model
#     with open(MODEL_PATH, 'wb') as f:
#         pickle.dump(model, f)
#     print(f"Model saved at: {MODEL_PATH}")

# if __name__ == '__main__':
#     train_and_save_model()


## multiple dataset training
import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from utils import extract_features  # Make sure this function works well for your URLs

# Paths
DATASET_PATH = os.path.join(os.getcwd(), 'dataset', 'Phishing_dataset_04.csv')
MODEL_DIR = os.path.join(os.getcwd(), 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'final_model.pkl')

def load_dataset():
    df = pd.read_csv(DATASET_PATH)
    print(f"✅ Loaded dataset with {df.shape[0]} rows")

    # Normalize column names and values
    df = df.rename(columns=lambda x: x.strip().lower())
    if 'url' not in df.columns or 'target' not in df.columns:
        raise ValueError("Dataset must contain 'URL' and 'Target' columns")

    df = df[['url', 'target']].dropna()
    df['target'] = df['target'].apply(lambda x: 1 if str(x).strip() == '1' else 0)
    return df

def train_and_save_model():
    df = load_dataset()

    # Feature extraction
    print("🔍 Extracting features...")
    X = pd.DataFrame(df['url'].apply(lambda x: extract_features(str(x))).tolist())
    y = df['target']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    print("🧠 Training model...")
    model = RandomForestClassifier(n_estimators=200, max_depth=15, class_weight='balanced', random_state=42)
    model.fit(X_train, y_train)

    # Evaluation
    y_pred = model.predict(X_test)
    print(f"\n🎯 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))

    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"✅ Model saved at {MODEL_PATH}")

if __name__ == '__main__':
    train_and_save_model()
