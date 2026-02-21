from flask import Flask, request, jsonify
import joblib
import re
import numpy as np

app = Flask(__name__)

import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

import joblib

email_model = joblib.load("models/email_model.pkl")
tfidf = joblib.load("models/tfidf.pkl")
url_model = joblib.load("models/url_model.pkl")

# Check if models exist
if os.path.exists("models/email_model.pkl"):
    email_model = joblib.load("models/email_model.pkl")
    tfidf = joblib.load("models/tfidf.pkl")
    url_model = joblib.load("models/url_model.pkl")

else:
    print("Models not found. Training models...")

    os.makedirs("models", exist_ok=True)

    # Train Email Model
    email_df = pd.read_csv("https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_DATA_REPO/main/emails.csv")

    X_email = email_df["text_combined"]
    y_email = email_df["label"]

    tfidf = TfidfVectorizer(max_features=5000)
    X_email_vec = tfidf.fit_transform(X_email)

    email_model = LogisticRegression()
    email_model.fit(X_email_vec, y_email)

    joblib.dump(email_model, "models/email_model.pkl")
    joblib.dump(tfidf, "models/tfidf.pkl")

    # Train URL Model
    url_df = pd.read_csv("https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_DATA_REPO/main/urls.csv")

    url_df["Label"] = url_df["Label"].map({"good": 0, "bad": 1})

    def extract_features(url):
        url = str(url)
        return [
            len(url),
            url.count("."),
            url.count("-"),
            url.count("/"),
            sum(c.isdigit() for c in url),
            1 if "@" in url else 0,
            1 if "https" in url else 0,
            1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
            1 if any(word in url.lower() for word in ["login","verify","update","bank","secure"]) else 0
        ]

    X_url = url_df["URL"].apply(extract_features).tolist()
    y_url = url_df["Label"]

    url_model = RandomForestClassifier(n_estimators=200)
    url_model.fit(X_url, y_url)

    joblib.dump(url_model, "models/url_model.pkl")

    print("Models trained successfully.")

# URL feature extractor
def extract_features(url):
    url = str(url)
    features = {}

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["has_at"] = 1 if "@" in url else 0
    features["has_https"] = 1 if "https" in url else 0
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0
    features["suspicious_words"] = 1 if any(word in url.lower() for word in ["login", "verify", "update", "bank", "secure"]) else 0

    return np.array(list(features.values())).reshape(1, -1)

@app.route("/")
def home():
    return "PhishGuard AI Backend is Running Successfully 🚀"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json

    email_text = data.get("email_text", "")
    url = data.get("url", "")

    # Email prediction
    email_vector = tfidf.transform([email_text])
    email_prob = email_model.predict_proba(email_vector)[0][1]

    # URL prediction
    url_features = extract_features(url)
    url_prob = url_model.predict_proba(url_features)[0][1]

    # Hybrid risk score
    risk_score = int((email_prob * 50) + (url_prob * 50))

    if risk_score < 30:
        classification = "Safe"
    elif risk_score < 70:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    return jsonify({
        "email_probability": round(float(email_prob), 2),
        "url_probability": round(float(url_prob), 2),
        "risk_score": risk_score,
        "classification": classification
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)