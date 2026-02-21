import pandas as pd
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

df = pd.read_csv("data/urls.csv")

# Convert good/bad to 0/1
df["Label"] = df["Label"].map({"good": 0, "bad": 1})
df = df.dropna()

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

    return pd.Series(features)

X = df["URL"].apply(extract_features)
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=50,
    max_depth=10,
    random_state=42
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
print("URL Model Accuracy:", accuracy_score(y_test, pred))

joblib.dump(model, "models/url_model.pkl")

print("Improved URL model saved successfully.")