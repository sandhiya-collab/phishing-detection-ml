import requests, os

API_KEY = os.getenv("AQ.Ab8RN6Jifxi_CsW7vwOx5vVrFCr_dl2UYa7IV3sWXhii57hMPw")

def check_google_safe(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {"clientId": "ai-phishing", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    r = requests.post(endpoint, json=payload).json()
    return (1.0, "Flagged by Google Safe Browsing") if "matches" in r else (0.0, "Not flagged by Google Safe Browsing")
