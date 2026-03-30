# virustotal.py
import os
import httpx
import asyncio
import base64
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
API_URL = 'https://www.virustotal.com/api/v3/urls'

async def check_virustotal_async(url):
    """Async check VirusTotal"""
    if not API_KEY:
        return 0.0, "API key not configured - Get free key at virustotal.com"
    
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Encode URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            # Try to get existing report
            response = await client.get(
                f"{API_URL}/{url_id}",
                headers={"x-apikey": API_KEY}
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Get detection stats
                stats = attributes.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                if total > 0:
                    score = (malicious + (suspicious * 0.5)) / total
                    if malicious > 0:
                        return score, f"⚠️ {malicious}/{total} vendors flagged as malicious"
                    elif suspicious > 0:
                        return score, f"⚠️ {suspicious}/{total} vendors flagged as suspicious"
                    else:
                        return 0.0, f"✅ Clean - {harmless}/{total} vendors detected no threats"
                else:
                    return 0.0, "✅ No detection data available"
                    
            elif response.status_code == 404:
                # Submit URL for analysis
                submit_response = await client.post(
                    API_URL,
                    headers={"x-apikey": API_KEY},
                    data={"url": url}
                )
                if submit_response.status_code == 200:
                    return 0.0, "⏳ URL submitted for analysis - Check back later"
                else:
                    return 0.0, "⚠️ Submission failed"
            else:
                return 0.0, f"⚠️ API error: {response.status_code}"
                
    except Exception as e:
        return 0.0, f"⚠️ Check failed: {str(e)}"

def check_virustotal(url):
    """Sync wrapper for Flask"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(check_virustotal_async(url))
    except:
        return 0.0, "⚠️ Service temporarily unavailable"
    finally:
        loop.close()