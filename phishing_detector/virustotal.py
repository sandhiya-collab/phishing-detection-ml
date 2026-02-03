import requests, base64

API_KEY = "dcdcdd30de35f39e110850ca8a829fccf63dd351d7420cbfee944a12a2a25848"
BASE_URL = "https://www.virustotal.com/api/v3/urls"

def check_virustotal(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}

    r = requests.get(f"{BASE_URL}/{url_id}", headers=headers)
    data = r.json()

    if "data" in data:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        m = stats.get("malicious",0)
        s = stats.get("suspicious",0)
        if m+s > 0:
            return min(1,(m+s)/10), f"VirusTotal flagged {m} malicious and {s} suspicious engines"

    return 0.0, "VirusTotal reports no malicious activity"
