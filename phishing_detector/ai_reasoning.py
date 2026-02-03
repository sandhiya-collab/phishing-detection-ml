def ai_url_analysis(text):
    t = text.lower()
    reasons = []
    score = 0

    if "login" in t or "verify" in t:
        reasons.append("Requests sensitive information")
        score += 0.3

    if "urgent" in t:
        reasons.append("Creates urgency")
        score += 0.2

    if t.startswith("http://"):
        reasons.append("Uses insecure HTTP")
        score += 0.2

    if "-" in t and "." in t:
        reasons.append("Suspicious domain pattern")
        score += 0.2

    if not reasons:
        reasons.append("No suspicious intent")

    return min(score, 1.0), reasons
