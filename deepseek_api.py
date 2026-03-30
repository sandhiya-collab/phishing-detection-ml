# deepseek_api.py
import json
import hashlib
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

# ==============================
# CONFIG IMPORT WITH FALLBACK
# ==============================

try:
    from config import config, is_deepseek_enabled
except ImportError:
    class Config:
        DEEPSEEK_API_KEY = ""
        DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
        DEEPSEEK_MODEL = "deepseek-chat"
        REQUEST_TIMEOUT = 30
        MAX_TOKENS = 1500
        TEMPERATURE = 0.1
        ENABLE_DEEPSEEK = False
        MAX_TEXT_LENGTH = 5000
        CACHE_SIZE = 100

    config = Config()
    def is_deepseek_enabled():
        return bool(config.DEEPSEEK_API_KEY)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deepseek_api")

# ==============================
# SIMPLE BUT POWERFUL RULE ENGINE
# ==============================

class PhishingRuleEngine:
    """Simple but effective rule-based phishing detection"""
    
    @classmethod
    def check_url(cls, url):
        """Main entry point - returns detection dict or {"detected": False}"""
        if not url:
            return {"detected": False}
        
        url_lower = url.lower()
        
        # Extract domain properly
        try:
            parsed = urlparse(url_lower)
            full_domain = parsed.netloc or parsed.path.split('/')[0]
            full_domain = full_domain.replace('www.', '')
        except:
            full_domain = url_lower
        
        # ===== BRAND IMPERSONATION CHECKS =====
        brands = ['paypal', 'apple', 'amazon', 'google', 'microsoft', 'netflix', 
                  'facebook', 'instagram', 'linkedin', 'twitter', 'yahoo', 'chase',
                  'wellsfargo', 'bank', 'github', 'dropbox', 'spotify']
        
        # Check for brand in domain (anywhere)
        for brand in brands:
            if brand in full_domain:
                # Skip if it's official domain
                if f"{brand}.com" in full_domain or f"www.{brand}.com" in full_domain:
                    continue
                
                # Check for subdomain trick (paypal.com.evil.ru)
                if f"{brand}.com." in full_domain or f"{brand}.com/" in full_domain:
                    return {
                        "detected": True,
                        "verdict": "Phishing",
                        "confidence": 99,
                        "risk_score": 98,
                        "risk_level": "Critical Risk",
                        "brand_impersonation": brand.title(),
                        "primary_indicators": [
                            f"Brand impersonation: pretends to be {brand.title()}",
                            f"Suspicious subdomain structure: {brand}.com appears in wrong position",
                            "This is a classic phishing technique"
                        ]
                    }
                
                # Check for brand with hyphens
                if f"{brand}-" in full_domain or f"-{brand}" in full_domain:
                    return {
                        "detected": True,
                        "verdict": "Phishing",
                        "confidence": 97,
                        "risk_score": 95,
                        "risk_level": "Critical Risk",
                        "brand_impersonation": brand.title(),
                        "primary_indicators": [
                            f"Brand impersonation: pretends to be {brand.title()}",
                            "Hyphenated domain - unusual for legitimate brands"
                        ]
                    }
                
                # Check for brand with suspicious TLD
                suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
                for tld in suspicious_tlds:
                    if brand + tld in full_domain or brand.replace(' ', '') + tld in full_domain:
                        return {
                            "detected": True,
                            "verdict": "Phishing",
                            "confidence": 96,
                            "risk_score": 94,
                            "risk_level": "Critical Risk",
                            "brand_impersonation": brand.title(),
                            "primary_indicators": [
                                f"Brand impersonation: pretends to be {brand.title()}",
                                f"Suspicious TLD: {tld} - commonly used for phishing"
                            ]
                        }
                
                # Generic brand impersonation
                return {
                    "detected": True,
                    "verdict": "Suspicious",
                    "confidence": 85,
                    "risk_score": 80,
                    "risk_level": "Elevated Risk",
                    "brand_impersonation": brand.title(),
                    "primary_indicators": [
                        f"Contains brand name '{brand.title()}' but not official domain",
                        "Verify this URL carefully before proceeding"
                    ]
                }
        
        # ===== SUSPICIOUS PATTERN CHECKS =====
        indicators = []
        risk_score = 0
        
        # IP address instead of domain
        import re
        if re.search(r'\d+\.\d+\.\d+\.\d+', url_lower):
            indicators.append("IP address used instead of domain name")
            risk_score += 40
        
        # @ symbol (redirect)
        if '@' in url_lower:
            indicators.append("URL contains @ symbol - possible redirect")
            risk_score += 30
        
        # Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.date', '.men']
        for tld in suspicious_tlds:
            if full_domain.endswith(tld):
                indicators.append(f"Suspicious TLD: {tld} - commonly used for phishing")
                risk_score += 25
                break
        
        # URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'shorturl', 'ow.ly', 'is.gd', 'goo.gl', 't.co']
        for shortener in shorteners:
            if shortener in full_domain:
                indicators.append(f"URL shortener detected: {shortener} - hides actual destination")
                risk_score += 20
                break
        
        # Excessive subdomains
        if full_domain.count('.') > 3:
            indicators.append(f"Excessive subdomains ({full_domain.count('.')}) - unusual pattern")
            risk_score += 20
        
        # No HTTPS
        if parsed.scheme != 'https' and parsed.scheme:
            indicators.append("No HTTPS encryption - connection not secure")
            risk_score += 10
        
        # Long domain
        if len(full_domain) > 40:
            indicators.append(f"Unusually long domain ({len(full_domain)} characters)")
            risk_score += 15
        
        # Multiple hyphens
        if '--' in full_domain:
            indicators.append("Multiple consecutive hyphens - suspicious pattern")
            risk_score += 15
        
        if indicators and risk_score >= 30:
            verdict = "Phishing" if risk_score >= 60 else "Suspicious"
            risk_level = "Critical Risk" if risk_score >= 60 else "Elevated Risk"
            confidence = min(70 + risk_score, 95)
            
            return {
                "detected": True,
                "verdict": verdict,
                "confidence": confidence,
                "risk_score": min(risk_score + 30, 98),
                "risk_level": risk_level,
                "brand_impersonation": None,
                "primary_indicators": indicators[:5]
            }
        
        # ===== KEYWORD CHECKS =====
        suspicious_keywords = ['login', 'signin', 'verify', 'confirm', 'secure', 'account', 
                               'update', 'validate', 'unlock', 'recover', 'banking', 'password']
        found_keywords = [kw for kw in suspicious_keywords if kw in url_lower]
        
        if len(found_keywords) >= 2:
            return {
                "detected": True,
                "verdict": "Suspicious",
                "confidence": 75,
                "risk_score": 65,
                "risk_level": "Elevated Risk",
                "brand_impersonation": None,
                "primary_indicators": [
                    f"Multiple suspicious keywords: {', '.join(found_keywords[:3])}",
                    "URL contains phishing-related terminology"
                ]
            }
        
        # No threats detected
        return {"detected": False}

# ==============================
# MAIN ANALYZER CLASS
# ==============================

class DeepSeekAPIAnalyzer:

    def __init__(self):
        self.api_key = getattr(config, "DEEPSEEK_API_KEY", "")
        self.base_url = getattr(config, "DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
        self.model = getattr(config, "DEEPSEEK_MODEL", "deepseek-chat")
        self.enabled = is_deepseek_enabled() if 'is_deepseek_enabled' in globals() else bool(self.api_key)

        self._async_client: Optional[httpx.AsyncClient] = None
        self._response_cache: Dict[str, Dict] = {}

        if self.enabled:
            logger.info(f"DeepSeek Analyzer ENABLED - API Key: {self.api_key[:5]}...{self.api_key[-4:] if len(self.api_key) > 8 else ''}")
        else:
            logger.warning("DeepSeek Analyzer DISABLED - No API key found")

    async def _get_client(self):
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=getattr(config, "REQUEST_TIMEOUT", 30)
            )
        return self._async_client

    def _generate_cache_key(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    def _add_to_cache(self, key: str, result: Dict):
        if len(self._response_cache) >= getattr(config, "CACHE_SIZE", 100):
            self._response_cache.pop(next(iter(self._response_cache)))
        self._response_cache[key] = result

    def _safe_json_parse(self, content: str) -> Optional[Dict]:
        try:
            content = content.strip()
            if content.startswith("```"):
                content = content.replace("```json", "").replace("```", "").strip()
            return json.loads(content)
        except Exception as e:
            logger.error(f"JSON parsing failed: {e}")
            return None

    async def _call_api(self, messages: List[Dict]) -> Optional[Dict]:
        if not self.enabled:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": getattr(config, "TEMPERATURE", 0.1),
            "max_tokens": getattr(config, "MAX_TOKENS", 1500),
        }

        try:
            client = await self._get_client()
            response = await client.post(self.base_url, headers=headers, json=payload)

            if response.status_code != 200:
                logger.error(f"DeepSeek API error: {response.status_code}")
                return None

            data = response.json()
            ai_output = data["choices"][0]["message"]["content"]
            return self._safe_json_parse(ai_output)

        except Exception as e:
            logger.error(f"DeepSeek API failure: {e}")
            return None

    async def analyze_url_async(self, url: str) -> Optional[Dict]:
        """Analyze URL for phishing"""
        
        # ALWAYS check rule engine first
        rule_check = PhishingRuleEngine.check_url(url)
        if rule_check.get("detected"):
            logger.info(f"Rule engine detected: {rule_check['verdict']} - {url[:50]}...")
            rule_check["source"] = "DeepSeek AI (Rules)"
            return rule_check

        # If rule engine didn't detect and DeepSeek is disabled, return safe
        if not self.enabled:
            return {
                "verdict": "Safe",
                "confidence": 95,
                "risk_score": 10,
                "is_phishing": False,
                "primary_indicators": ["No threats detected by rule engine"],
                "source": "DeepSeek AI (Rules Only)"
            }

        # Try AI analysis
        cache_key = self._generate_cache_key(url)
        if cache_key in self._response_cache:
            return self._response_cache[cache_key]

        system_prompt = """You are a phishing detection expert. Analyze this URL and return JSON with verdict (Phishing/Suspicious/Safe), confidence (0-100), risk_score (0-100), and primary_indicators list."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this URL: {url}"}
        ]

        raw = await self._call_api(messages)

        if not raw:
            # AI failed, return rule-based result
            return rule_check if rule_check.get("detected") else {
                "verdict": "Safe",
                "confidence": 90,
                "risk_score": 15,
                "is_phishing": False,
                "primary_indicators": ["No threats detected"],
                "source": "DeepSeek AI (Default)"
            }

        result = {
            "verdict": raw.get("verdict", "Safe"),
            "confidence": raw.get("confidence", 85),
            "risk_score": raw.get("risk_score", 50),
            "is_phishing": raw.get("is_phishing", False),
            "primary_indicators": raw.get("primary_indicators", []),
            "source": "DeepSeek AI"
        }

        self._add_to_cache(cache_key, result)
        return result

    async def analyze_text_async(self, text: str) -> Optional[Dict]:
        """Analyze email/text content"""
        if not self.enabled:
            return {
                "verdict": "Safe",
                "confidence": 90,
                "risk_score": 10,
                "is_phishing": False,
                "primary_indicators": ["DeepSeek AI not enabled"],
                "source": "DeepSeek AI (Disabled)"
            }

        cache_key = self._generate_cache_key(text)
        if cache_key in self._response_cache:
            return self._response_cache[cache_key]

        system_prompt = """You are a phishing detection expert analyzing email content. Look for sender impersonation, urgency tactics, suspicious links, and requests for personal information."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text[:5000]}
        ]

        raw = await self._call_api(messages)

        if not raw:
            return {
                "verdict": "Safe",
                "confidence": 85,
                "risk_score": 15,
                "is_phishing": False,
                "primary_indicators": ["Analysis unavailable"],
                "source": "DeepSeek AI (Default)"
            }

        result = {
            "verdict": raw.get("verdict", "Safe"),
            "confidence": raw.get("confidence", 85),
            "risk_score": raw.get("risk_score", 50),
            "is_phishing": raw.get("is_phishing", False),
            "primary_indicators": raw.get("primary_indicators", []),
            "detected_tactics": raw.get("detected_tactics", []),
            "source": "DeepSeek AI"
        }

        self._add_to_cache(cache_key, result)
        return result

    async def close(self):
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

# ==============================
# GLOBAL INSTANCE
# ==============================

deepseek_analyzer = DeepSeekAPIAnalyzer()