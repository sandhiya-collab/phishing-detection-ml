# domain_ai.py
import whois
from datetime import datetime
import asyncio
import socket
import re
from urllib.parse import urlparse

async def domain_age_check_async(url):
    """Async check domain age via WHOIS with multiple fallbacks"""
    try:
        # Extract domain
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.replace('www.', '').split('/')[0].split(':')[0]
        
        if not domain:
            return 0.0, "⚠️ Could not extract domain"
        
        # METHOD 1: WHOIS lookup (primary)
        try:
            import functools
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(
                None, 
                functools.partial(whois.whois, domain)
            )
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                    
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 7:
                    return 0.95, f"🚨 BRAND NEW: {age_days} days old"
                elif age_days < 30:
                    return 0.75, f"⚠️ Very new: {age_days} days old"
                elif age_days < 90:
                    return 0.50, f"⚠️ New domain: {age_days} days old"
                elif age_days < 365:
                    return 0.25, f"ℹ️ Less than 1 year: {age_days} days old"
                else:
                    return 0.0, f"✅ Established: {age_days/365:.1f} years old"
        except:
            pass  # Fall through to next method
        
        # METHOD 2: DNS lookup (fallback)
        try:
            import dns.resolver
            answers = await loop.run_in_executor(
                None,
                functools.partial(dns.resolver.resolve, domain, 'A')
            )
            if answers:
                return 0.30, "⚠️ Domain exists but age unknown (WHOIS blocked)"
        except:
            pass
        
        # METHOD 3: Known domains cache
        known_domains = {
            'google.com': (27.5, '1997-09-15'),
            'microsoft.com': (37.5, '1988-11-02'),
            'amazon.com': (28.5, '1994-11-01'),
            'apple.com': (37.0, '1987-02-19'),
            'paypal.com': (26.0, '1998-12-01'),
            'github.com': (17.0, '2007-10-29'),
            'netflix.com': (27.0, '1997-08-11'),
            'facebook.com': (21.0, '1997-03-29'),
            'twitter.com': (19.0, '2000-01-21'),
            'linkedin.com': (22.0, '2002-05-05'),
        }
        
        for known_domain, (years, date) in known_domains.items():
            if known_domain in domain:
                return 0.0, f"✅ Established: {years} years old (since {date})"
        
        # METHOD 4: Check for suspicious patterns
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.work', '.date']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return 0.70, f"⚠️ Suspicious TLD: {tld} - often used for phishing"
        
        # METHOD 5: Check domain length (random domains are often suspicious)
        if len(domain.split('.')[0]) > 15:
            return 0.50, "⚠️ Long random subdomain - potentially suspicious"
        
        return 0.30, "ℹ️ Domain age unknown - Unable to verify"
            
    except Exception as e:
        return 0.0, f"⚠️ Domain age check failed: {str(e)[:50]}"

def domain_age_check(url):
    """Sync wrapper for Flask"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(domain_age_check_async(url))
    except:
        return 0.30, "⚠️ Domain age service unavailable"
    finally:
        loop.close()