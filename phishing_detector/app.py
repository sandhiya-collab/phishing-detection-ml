from flask import Flask, request, jsonify, render_template
import joblib
import os
from difflib import SequenceMatcher
from urllib.parse import urlparse
import re

from google_safe import check_google_safe
from virustotal import check_virustotal
from domain_ai import domain_age_check

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "vectorizer.pkl")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# ---------------- BRAND SIMILARITY ----------------
KNOWN_BRANDS = [
    "paypal.com", "amazon.com", "google.com",
    "facebook.com", "instagram.com",
    "microsoft.com", "apple.com",
    "flipkart.com", "linkedin.com", "sbi.in", "icici.com", "hdfcbank.com"
]

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def brand_similarity_check(domain):
    domain = domain.lower()
    best_score = 0
    best_brand = None
    for brand in KNOWN_BRANDS:
        score = similarity(domain, brand)
        if score > best_score:
            best_score = score
            best_brand = brand
    if best_score > 0.75 and domain != best_brand:
        return 0.9, f"URL appears similar to the well-known brand '{best_brand}', potential typosquatting detected"
    else:
        return 0.0, "No obvious typosquatting or brand impersonation detected, URL appears normal"

# ---------------- DOMAIN EXTRACTION ----------------
def extract_domains(text):
    urls = re.findall(r'https?://[^\s]+', text)
    emails = re.findall(r'[\w\.-]+@([\w\.-]+)', text)

    domains = []

    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc)

    for email_domain in emails:
        domains.append(email_domain)

    return domains

# ---------------- FLASK ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    text = data.get("input", "").strip()

    if not text:
        return jsonify({"error": "Empty input"}), 400

    # ---------------- Extract domains from text ----------------
    domains = extract_domains(text)
    if not domains:
        domains = extract_domains("http://" + text)# fallback for direct URL input

    # ---------------- Initialize scores ----------------
    g_score, g_exp = 0, ""
    vt_score, vt_exp = 0, ""
    d_score, d_exp = 0, ""
    b_score, b_exp = 0, ""

    # ---------------- Run AI modules for each domain ----------------
    for d in domains:
        # Google Safe Browsing
        gs, ge = check_google_safe(d)
        if gs > g_score:
            g_score = gs
            g_exp = ge

        # VirusTotal
        vt, ve = check_virustotal(d)
        if vt > vt_score:
            vt_score = vt
            vt_exp = ve

        # Domain Age
        da, de = domain_age_check(d)
        if da > d_score:
            d_score = da
            d_exp = de

        # Brand Similarity
        bs, be = brand_similarity_check(d)
        if bs > b_score:
            b_score = bs
            b_exp = be

    # ---------------- Collect explanations ----------------
    explanations = [g_exp, vt_exp, d_exp, b_exp]

    # ---------------- ML Model ----------------
    try:
        X = vectorizer.transform([text])
        prob = model.predict_proba(X)[0]
        ml_score = prob[1]
    except:
        ml_score = 0.0

    # ---------------- Final score ----------------
    final_score = max(ai_score:=max(g_score, vt_score, d_score, b_score), 0.6 * ai_score + 0.4 * ml_score)
    confidence = round(final_score * 100, 2)

    # ---------------- Determine result ----------------
    if final_score >= 0.6:
        result = "Phishing"
    elif final_score >= 0.35:
        result = "Suspicious"
    else:
        result = "Safe"

    explanation_text = " | ".join(explanations)

    return jsonify({
        "result": result,
        "confidence": confidence,
        "explanation": explanation_text
    })

if __name__ == "__main__":
    app.run()
