import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import os

data = pd.read_csv("phishing_dataset.csv")

X = data["text"]
y = data["label"]

vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
X_vec = vectorizer.fit_transform(X)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_vec, y)

os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/phishing_model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print("✅ Model trained successfully")
