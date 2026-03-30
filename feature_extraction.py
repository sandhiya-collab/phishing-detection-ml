# feature_extraction.py
import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Extract features from URL for phishing detection
    Returns a list of 15 features
    """
    features = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Feature 1: URL Length
        features.append(len(url))
        
        # Feature 2: Number of dots
        features.append(url.count('.'))
        
        # Feature 3: Number of hyphens
        features.append(url.count('-'))
        
        # Feature 4: Number of @ symbols
        features.append(url.count('@'))
        
        # Feature 5: Has https
        features.append(1 if url.startswith('https') else 0)
        
        # Feature 6: Number of subdomains
        features.append(domain.count('.') - 1 if domain.count('.') > 1 else 0)
        
        # Feature 7: Domain length
        features.append(len(domain))
        
        # Feature 8: Has IP address
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        features.append(1 if re.search(ip_pattern, url) else 0)
        
        # Feature 9: Number of digits
        features.append(sum(c.isdigit() for c in url))
        
        # Feature 10: Has port
        features.append(1 if ':' in domain and domain.split(':')[-1].isdigit() else 0)
        
        # Feature 11: Has suspicious words
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'paypal']
        features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
        
        # Feature 12: Number of query parameters
        features.append(len(parsed.query.split('&')) if parsed.query else 0)
        
        # Feature 13: Path length
        features.append(len(parsed.path))
        
        # Feature 14: Number of double slashes
        features.append(url.count('//') - 1 if url.count('//') > 1 else 0)
        
        # Feature 15: Has hex characters
        features.append(1 if '%' in url else 0)
        
    except Exception:
        # Return default features if extraction fails
        features = [0] * 15
    
    # Ensure we have exactly 15 features
    while len(features) < 15:
        features.append(0)
    features = features[:15]
    
    return features