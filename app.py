from flask import Flask, request, jsonify, render_template
import joblib
import re
import numpy as np
import os

app = Flask(__name__)

# Load trained models safely
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

email_model = joblib.load(os.path.join(BASE_DIR, "models", "email_model.pkl"))
tfidf = joblib.load(os.path.join(BASE_DIR, "models", "tfidf.pkl"))
url_model = joblib.load(os.path.join(BASE_DIR, "models", "url_model.pkl"))


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
    features["suspicious_words"] = 1 if any(
        word in url.lower() for word in ["login", "verify", "update", "bank", "secure"]
    ) else 0

    return np.array(list(features.values())).reshape(1, -1)


@app.route("/")
def home():
    return render_template("index.html")


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

    
    # Dynamic weighting logic
    if url_prob > 0.7:
        risk_score = int((email_prob * 30) + (url_prob * 70))
    else:
        risk_score = int((email_prob * 60) + (url_prob * 40))

    # Rule-based override system
    strong_phishing_patterns = [
    "verify-login",
    "account-update",
    "secure-bank",
    "password-reset"
    ]

    if any(pattern in url.lower() for pattern in strong_phishing_patterns):
        risk_score = max(risk_score, 85)

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        risk_score = max(risk_score, 90)

    if risk_score < 35:
        classification = "Safe"
    elif risk_score < 65:
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
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)