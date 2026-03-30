import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ---------------- CONFIG ----------------
DATASET_PATH = "email_dataset_clean.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------- LOAD DATA ----------------
df = pd.read_csv(DATASET_PATH)

df["text"] = df["text"].astype(str)
df["label"] = df["label"].astype(int)

X = df["text"]
y = df["label"]

# ---------------- VECTORIZATION ----------------
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    stop_words="english"
)

X_vec = vectorizer.fit_transform(X)

# ---------------- SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42, stratify=y
)

# ---------------- MODEL ----------------
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# ---------------- EVALUATION ----------------
y_pred = model.predict(X_test)
print("TEXT MODEL RESULTS")
print(classification_report(y_test, y_pred))

# ---------------- SAVE ----------------
joblib.dump(model, os.path.join(MODEL_DIR, "phishing_text_model.pkl"))
joblib.dump(vectorizer, os.path.join(MODEL_DIR, "text_vectorizer.pkl"))

print("✅ Text phishing model saved")
