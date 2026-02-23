🛡️ PhishGuard AI
Hybrid AI-Based Phishing Email & URL Detection System
__________________________________________________________________________________________________________________________________
🚀 Overview
PhishGuard AI is a hybrid cybersecurity intelligence system designed to detect phishing emails, malicious URLs, and social engineering attacks using a combination of:
•	🤖 Machine Learning models
•	🧠 Rule-based heuristic analysis
•	🌐 Domain intelligence signals
•	📊 Explainable AI threat reporting
Unlike traditional keyword-based spam filters, PhishGuard AI uses a multi-layered detection framework that assigns a dynamic risk score (0–100) based on combined intelligence signals.
__________________________________________________________________________________________________________________________________
🎯 Problem Statement
Phishing attacks are becoming:
•	More personalized
•	Harder to detect
•	Capable of bypassing traditional spam filters
•	Responsible for credential theft and financial fraud
Most existing systems either:
•	Rely purely on blacklists, or
•	Use opaque ML models without explanation
PhishGuard AI solves this by combining detection + transparency.
__________________________________________________________________________________________________________________________________
🧠 How It Works
PhishGuard AI uses a Hybrid Risk Scoring Engine:
1️⃣ Email Intelligence Layer
•	TF-IDF vectorization
•	Logistic Regression classification
•	Linguistic pattern detection
•	Suspicious phrase analysis
2️⃣ URL Intelligence Layer
•	Structural feature extraction:
o	URL length
o	Number of dots
o	Digits count
o	Presence of IP address
o	Suspicious keywords
•	Random Forest classifier
3️⃣ Domain Intelligence Layer
•	WHOIS domain age lookup
•	Newly registered domain detection
•	Age-based risk correlation
4️⃣ Rule-Based Heuristic Signals
•	High-risk keyword patterns
•	Suspicious URL structures
•	IP address usage detection
__________________________________________________________________________________________________________________________________
📊 Risk Scoring Logic
Final risk score is computed using:
Hybrid Risk Score =
ML Email Probability
•	ML URL Probability
•	Heuristic Adjustments
•	Domain Intelligence Signals
Classification:
•	0–39 → ✅ Safe
•	40–69 → ⚠ Suspicious
•	70–100 → 🚨 Phishing
This ensures decisions are not based on a single keyword or signal.
__________________________________________________________________________________________________________________________________
🔍 Explainable AI (XAI)
When users click Documentation, the system provides:
•	Why the content was classified
•	Which intelligence layers contributed
•	Whether ML or heuristics influenced the decision
•	Domain age insights
•	Structural URL analysis reasoning
This improves transparency and user trust.
__________________________________________________________________________________________________________________________________
🛠 Tech Stack
Backend:
•	Python
•	Flask
•	Scikit-learn
•	Joblib
•	WHOIS
•	NumPy
Machine Learning:
•	TF-IDF Vectorizer
•	Logistic Regression (Email model)
•	Random Forest (URL model)
Frontend:
•	HTML5
•	Advanced CSS (Cyber UI theme)
•	JavaScript
•	Real-time Risk Visualization
Deployment:
•	Render (Cloud Deployment)
