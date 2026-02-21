import pandas as pd
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Load dataset
df = pd.read_csv("data/emails.csv")

# Basic cleaning function
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    return text

df["text_combined"] = df["text_combined"].apply(clean_text)

# Features and labels
X = df["text_combined"]
y = df["label"]

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# TF-IDF
vectorizer = TfidfVectorizer(max_features=5000)
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Model
model = LogisticRegression()
model.fit(X_train_tfidf, y_train)

# Evaluate
pred = model.predict(X_test_tfidf)
print("Accuracy:", accuracy_score(y_test, pred))

# Save
joblib.dump(model, "models/email_model.pkl")
joblib.dump(vectorizer, "models/tfidf.pkl")

print("Email model saved successfully.")