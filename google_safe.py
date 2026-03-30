# google_safe.py
import os
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import pysafebrowsing
try:
    from pysafebrowsing import SafeBrowsing
    PYSAFE_AVAILABLE = True
    logger.info("✅ pysafebrowsing loaded successfully")
except ImportError:
    PYSAFE_AVAILABLE = False
    logger.warning("⚠️ pysafebrowsing not installed. Run: pip install pysafebrowsing")

# Load environment variables
load_dotenv()

def check_url_safe_browsing(url):
    """
    Check a URL against Google Safe Browsing
    
    Args:
        url: The URL to check
    
    Returns:
        dict or bool: Returns dict with threat info or False if safe/error
    """
    # Get API key (check both possible variable names)
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY') or os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    
    if not api_key:
        logger.debug("No Google Safe Browsing API key configured")
        return False
    
    if not PYSAFE_AVAILABLE:
        logger.debug("pysafebrowsing not available")
        return False
    
    try:
        # Initialize Safe Browsing client
        s = SafeBrowsing(api_key)
        
        # Lookup the URL
        result = s.lookup_urls([url])
        
        if url in result and result[url].get('malicious', False):
            threats = result[url].get('threats', [])
            logger.info(f"🚨 Google Safe Browsing detected threats: {threats}")
            return {
                'malicious': True,
                'threats': threats,
                'source': 'google_safe_browsing',
                'details': f"Blocked by Google: {', '.join(threats)}"
            }
        
        logger.debug(f"✅ URL is safe according to Google: {url}")
        return False  # URL is safe
        
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing: {str(e)}")
        return False

def check_google_safe(url):
    """
    Compatibility function for app.py
    Returns (score, message) tuple as expected by the main app
    
    Args:
        url: The URL to check
    
    Returns:
        tuple: (score, message) where score is 0.0-1.0
    """
    result = check_url_safe_browsing(url)
    
    if result and isinstance(result, dict) and result.get('malicious'):
        # If malicious, return high score (0.7-0.9 depending on threats)
        threats = result.get('threats', [])
        if 'MALWARE' in threats:
            score = 0.9
        elif 'SOCIAL_ENGINEERING' in threats:
            score = 0.85
        elif 'UNWANTED_SOFTWARE' in threats:
            score = 0.8
        else:
            score = 0.75
            
        return score, result.get('details', 'Blocked by Google Safe Browsing')
    else:
        # If safe or error, return low score
        return 0.0, 'URL is safe according to Google Safe Browsing'

def check_google_safe_simple(url):
    """
    Even simpler compatibility function that just returns a score
    Some apps might expect just a float score
    """
    result = check_url_safe_browsing(url)
    if result and isinstance(result, dict) and result.get('malicious'):
        return 0.8  # High score for malicious
    return 0.0  # Low score for safe

# For testing
if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://paypal-verification.com",
        "https://malware-test-site.com"
    ]
    
    print("\n🔍 Testing Google Safe Browsing:")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\n📌 Testing URL: {url}")
        
        # Test the original function
        result = check_url_safe_browsing(url)
        print(f"  check_url_safe_browsing: {result}")
        
        # Test the compatibility function
        score, message = check_google_safe(url)
        print(f"  check_google_safe: score={score}, message='{message}'")
        
        # Test the simple version
        simple_score = check_google_safe_simple(url)
        print(f"  check_google_safe_simple: score={simple_score}")