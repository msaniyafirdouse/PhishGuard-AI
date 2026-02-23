from flask import Flask, request, jsonify, render_template
import joblib
import re
import numpy as np
import os
import whois
from urllib.parse import urlparse
from datetime import datetime

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

def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days
        else:
            return None
    except:
        return None

@app.route("/")
def home():
    return render_template("index.html")


# @app.route("/analyze", methods=["POST"])
# def analyze():
#     data = request.json

#     email_text = data.get("email_text", "")
#     url = data.get("url", "")

#     # Email prediction
#     email_vector = tfidf.transform([email_text])
#     email_prob = email_model.predict_proba(email_vector)[0][1]

#     # URL prediction
#     url_features = extract_features(url)
#     url_prob = url_model.predict_proba(url_features)[0][1]

    
#     # # Dynamic weighting logic
#     # if url_prob > 0.7:
#     #     risk_score = int((email_prob * 30) + (url_prob * 70))
#     # else:
#     #     risk_score = int((email_prob * 60) + (url_prob * 40))

#     # Independent scoring logic

#     if email_text.strip() and url.strip():
#      # Both provided
#         risk_score = int((email_prob * 50) + (url_prob * 50))

#     elif email_text.strip() and not url.strip():
#         # Only text provided
#         risk_score = int(email_prob * 100)

#     elif url.strip() and not email_text.strip():
#         # Only URL provided
#         risk_score = int(url_prob * 100)

#     else:
#         risk_score = 0


#     # Rule-based override system
#     strong_phishing_patterns = [
#     "verify-login",
#     "account-update",
#     "secure-bank",
#     "password-reset"
#     ]

#     if any(pattern in url.lower() for pattern in strong_phishing_patterns):
#         risk_score = max(risk_score, 85)

#     if re.search(r"\d+\.\d+\.\d+\.\d+", url):
#         risk_score = max(risk_score, 90)

#     # Domain age check
#     domain_age = get_domain_age(url)

#     if domain_age is not None:
#         if domain_age < 30:
#             risk_score += 20
#             reasons.append("Domain is very newly registered (less than 30 days).")
#         elif domain_age < 90:
#             risk_score += 10
#             reasons.append("Domain is recently registered (less than 90 days).")

#     if risk_score < 35:
#         classification = "Safe"
#     elif risk_score < 65:
#         classification = "Suspicious"
#     else:
#         classification = "Phishing"

#     return jsonify({
#         "email_probability": round(float(email_prob), 2),
#         "url_probability": round(float(url_prob), 2),
#         "risk_score": risk_score,
#         "classification": classification
#     })

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json

    email_text = data.get("email_text", "")
    url = data.get("url", "")

    reasons = []

    # ----------------------------
    # Email prediction (only if provided)
    # ----------------------------
    if email_text.strip():
        email_vector = tfidf.transform([email_text])
        email_prob = email_model.predict_proba(email_vector)[0][1]

        if email_prob > 0.75:
            reasons.append("Email content shows strong phishing indicators based on linguistic patterns.")
        elif email_prob > 0.45:
            reasons.append("Email content contains moderately suspicious language patterns.")
        else:
            reasons.append("No significant phishing language detected in the message content.")
    else:
        email_prob = 0

    # ----------------------------
    # URL prediction (only if provided)
    # ----------------------------
    if url.strip():
        url_features = extract_features(url)
        url_prob = url_model.predict_proba(url_features)[0][1]

        if url_prob > 0.75:
             reasons.append("URL structure strongly matches known phishing patterns.")
        elif url_prob > 0.45:
            reasons.append("URL contains moderately suspicious structural characteristics.")
        else:
            reasons.append("URL structure appears legitimate with no major phishing indicators.")
    else:
        url_prob = 0

    # ----------------------------
    # Independent scoring logic
    # ----------------------------
    if email_text.strip() and url.strip():
        risk_score = int((email_prob * 50) + (url_prob * 50))
    elif email_text.strip():
        risk_score = int(email_prob * 100)
    elif url.strip():
        risk_score = int(url_prob * 100)
    else:
        risk_score = 0

    # ----------------------------
    # Rule-based override system
    # ----------------------------
    strong_phishing_patterns = [
        "verify-login",
        "account-update",
        "secure-bank",
        "password-reset"
    ]

    if any(pattern in url.lower() for pattern in strong_phishing_patterns):
        risk_score = max(risk_score, 85)
        reasons.append("URL contains terms frequently observed in phishing campaigns; this increases risk but is not independently conclusive.")
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        risk_score = max(risk_score, 90)
        reasons.append("Use of a raw IP address instead of a domain name is often correlated with malicious activity.") 
    # ----------------------------
    # Domain Age Intelligence
    # ----------------------------
    if url.strip():
        domain_age = get_domain_age(url)

        if domain_age is not None:
            if domain_age < 30:
                risk_score += 20
                reasons.append("Domain is very newly registered (<30 days).")
            elif domain_age < 90:
                risk_score += 10
                reasons.append("Domain is recently registered (<90 days).")
            else:
                reasons.append("Domain has been registered for a significant period, reducing phishing likelihood.")
    # Cap risk score at 100
    risk_score = min(risk_score, 100)

    # ----------------------------
    # Classification
    # ----------------------------
    if risk_score < 40:
        classification = "Safe"
    elif risk_score < 70:
        classification = "Suspicious"
    else:
        classification = "Phishing"

    # Final AI reasoning summary
    if classification == "Safe":
        reasons.insert(0, "Overall analysis indicates low phishing probability based on combined ML and rule-based evaluation.")
    elif classification == "Suspicious":
        reasons.insert(0, "Combined machine learning signals and heuristic checks indicate moderate phishing risk.")
    else:
        reasons.insert(0, "High confidence phishing indicators detected from multiple intelligence layers.")
    
    
    return jsonify({
        "email_probability": str(int(email_prob * 100)) + "%",
        "url_probability": str(int(url_prob * 100)) + "%",
        "risk_score": risk_score,
        "classification": classification,
        "reasons": reasons
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)