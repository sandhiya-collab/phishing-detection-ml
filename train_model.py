import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

# ---------------- CONFIG ----------------
DATASET_PATH = "phishing_url.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------- LOAD DATA ----------------
df = pd.read_csv(DATASET_PATH)

# Target column must be named 'target'
y = df["target"].astype(int)
X = df.drop(columns=["target"])

# ---------------- SCALE FEATURES ----------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---------------- SPLIT ----------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ---------------- MODEL ----------------
model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)

# ---------------- EVALUATION ----------------
y_pred = model.predict(X_test)
print("URL FEATURE MODEL RESULTS")
print(classification_report(y_test, y_pred))

# ---------------- SAVE ----------------
joblib.dump(model, os.path.join(MODEL_DIR, "phishing_url_model.pkl"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "url_scaler.pkl"))

print("✅ URL feature phishing model saved")
