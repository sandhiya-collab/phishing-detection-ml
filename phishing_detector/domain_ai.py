import whois
from datetime import datetime

def domain_age_check(url):
    try:
        w = whois.whois(url)
        age = w.creation_date
        if isinstance(age, list):
            age = age[0]
        days = (datetime.now() - age).days
        if days < 180:
            return 1.0, f"Domain age: {days} days (new)"
        return 0.0, f"Domain age: {days} days"
    except:
        return 0.0, "Unable to determine domain age"
