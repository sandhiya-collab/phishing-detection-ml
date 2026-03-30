from urllib.parse import urlparse
import re

SUSPICIOUS_TLDS = {".xyz", ".top", ".gq", ".ml", ".cf", ".tk"}

def run(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    score = 0.0
    reasons = []

    # ---------- IP address instead of domain ----------
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 0.5
        reasons.append("IP address used instead of domain")

    # ---------- Digits in domain ----------
    if any(char.isdigit() for char in domain):
        score += 0.3
        reasons.append("Digits present in domain")

    # ---------- Hyphenated domain ----------
    if "-" in domain:
        score += 0.2
        reasons.append("Hyphenated domain")

    # ---------- Suspicious TLD ----------
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 0.4
            reasons.append(f"Suspicious TLD ({tld})")
            break

    # ---------- No HTTPS ----------
    if parsed.scheme != "https":
        score += 0.2
        reasons.append("No HTTPS")

    # ---------- Excessive subdomains ----------
    if domain.count(".") > 3:
        score += 0.3
        reasons.append("Too many subdomains")

    # ---------- URL length ----------
    if len(url) > 75:
        score += 0.2
        reasons.append("Unusually long URL")

    return {
        "name": "url_structure",
        "score": min(score, 1.0),
        "explanation": ", ".join(reasons) if reasons else "URL structure appears normal"
    }
