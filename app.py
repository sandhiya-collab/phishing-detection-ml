from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import joblib
import os
import re
import asyncio
from urllib.parse import urlparse
import pandas as pd
from email import policy
from email.parser import BytesParser
import tldextract
import whois
from datetime import datetime, timedelta
import socket
import ssl
import certifi
import urllib.request
import json
from collections import defaultdict, Counter
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle
import hashlib
import logging
from dotenv import load_dotenv

# Import MySQL URI from config
from config import SQLALCHEMY_DATABASE_URI

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from google_safe import check_google_safe
except ImportError:
    logger.warning("google_safe import failed, using fallback")
    def check_google_safe(url): return 0.0, "Google Safe Browsing not configured"

try:
    from virustotal import check_virustotal
except ImportError:
    logger.warning("virustotal import failed, using fallback")
    def check_virustotal(url): return 0.0, "VirusTotal not configured"

try:
    from domain_ai import domain_age_check
except ImportError:
    logger.warning("domain_ai import failed, using fallback")
    def domain_age_check(url): return 0.3, "Domain age check not available"

try:
    from feature_extraction import extract_features
except ImportError:
    logger.warning("feature_extraction import failed, using fallback")
    def extract_features(url): return [0] * 15

try:
    from deepseek_api import deepseek_analyzer
except ImportError as e:
    logger.warning(f"DeepSeek API import failed: {e}")
    deepseek_analyzer = None

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
# Use MySQL instead of SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['WTF_CSRF_TIME_LIMIT'] = None

# MySQL pool settings for better performance
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

# Comment out SQLite instance directory creation
# os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'), exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
csrf = CSRFProtect(app)

csrf.exempt('/predict')
csrf.exempt('/threat-intel')
csrf.exempt('/feedback')
csrf.exempt('/api/keys')
csrf.exempt('/api/history')
csrf.exempt('/api/user-history')
csrf.exempt('/api/stats')

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    scans = db.relationship('ScanHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade='all, delete-orphan')
    feedback = db.relationship('UserFeedback', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        self.last_login = datetime.utcnow()
        db.session.commit()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    __table_args__ = (
        db.Index('idx_user_created', 'user_id', 'created_at'),
        {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    )
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    scan_type = db.Column(db.String(20), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    verdict = db.Column(db.String(20), nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    analysis_source = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    full_result = db.Column(db.JSON)

class APIKey(db.Model):
    __tablename__ = 'api_keys'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    key_name = db.Column(db.String(50), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, index=True)
    requests_count = db.Column(db.Integer, default=0)

class UserFeedback(db.Model):
    __tablename__ = 'user_feedback'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_history.id'))
    url = db.Column(db.String(500))
    domain = db.Column(db.String(255))
    verdict_given = db.Column(db.String(20))
    is_correct = db.Column(db.Boolean)
    correct_verdict = db.Column(db.String(20))
    feedback_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class SystemStats(db.Model):
    __tablename__ = 'system_stats'
    __table_args__ = {'mysql_engine': 'InnoDB', 'mysql_charset': 'utf8mb4'}
    
    id = db.Column(db.Integer, primary_key=True)
    total_scans = db.Column(db.Integer, default=0)
    total_users = db.Column(db.Integer, default=0)
    phishing_detected = db.Column(db.Integer, default=0)
    suspicious_detected = db.Column(db.Integer, default=0)
    safe_detected = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_api_key():
    return hashlib.sha256(os.urandom(32)).hexdigest()

try:
    URL_MODEL = joblib.load(os.path.join(BASE_DIR, "models/phishing_url_model.pkl"))
    URL_SCALER = joblib.load(os.path.join(BASE_DIR, "models/url_scaler.pkl"))
    TEXT_MODEL = joblib.load(os.path.join(BASE_DIR, "models/phishing_text_model.pkl"))
    VECTORIZER = joblib.load(os.path.join(BASE_DIR, "models/text_vectorizer.pkl"))
    logger.info("Models loaded successfully")
except Exception as e:
    logger.warning(f"Model loading failed: {e}. Using dynamic learning system.")
    URL_MODEL = None
    URL_SCALER = None
    TEXT_MODEL = None
    VECTORIZER = None

logger.info(f"\n{'='*50}")
logger.info(f"DEEPSEEK ANALYZER STATUS:")
logger.info(f"  Analyzer exists: {deepseek_analyzer is not None}")
if deepseek_analyzer:
    logger.info(f"  Enabled: {deepseek_analyzer.enabled}")
    logger.info(f"  API Key exists: {bool(deepseek_analyzer.api_key)}")
    if deepseek_analyzer.api_key:
        logger.info(f"  API Key: {deepseek_analyzer.api_key[:5]}...{deepseek_analyzer.api_key[-4:]}")
else:
    logger.info("  DeepSeek Analyzer NOT AVAILABLE")
logger.info(f"{'='*50}\n")

class DynamicLearner:
    
    def __init__(self):
        self.tld_stats = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
        self.domain_patterns = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
        self.subdomain_stats = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
        self.length_stats = {'safe': [], 'suspicious': [], 'phishing': []}
        self.hyphen_stats = {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total_hyphen': 0}
        self.number_stats = {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total_with_numbers': 0}
        
        self.vectorizer = TfidfVectorizer(max_features=100, analyzer='char', ngram_range=(2, 4))
        self.classifier = MultinomialNB()
        self.is_trained = False
        self.training_data = []
        self.training_labels = []
        
        self.load_knowledge()
    
    def load_knowledge(self):
        try:
            knowledge_file = os.path.join(BASE_DIR, 'dynamic_knowledge.json')
            if os.path.exists(knowledge_file):
                with open(knowledge_file, 'r') as f:
                    data = json.load(f)
                    
                    self.tld_stats = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
                    for k, v in data.get('tld_stats', {}).items():
                        self.tld_stats[k] = v
                    
                    self.domain_patterns = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
                    for k, v in data.get('domain_patterns', {}).items():
                        self.domain_patterns[k] = v
                    
                    self.subdomain_stats = defaultdict(lambda: {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total': 0})
                    for k, v in data.get('subdomain_stats', {}).items():
                        self.subdomain_stats[int(k) if k.isdigit() else k] = v
                    
                    self.length_stats = data.get('length_stats', {'safe': [], 'suspicious': [], 'phishing': []})
                    self.hyphen_stats = data.get('hyphen_stats', {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total_hyphen': 0})
                    self.number_stats = data.get('number_stats', {'safe': 0, 'suspicious': 0, 'phishing': 0, 'total_with_numbers': 0})
                    
                    model_file = os.path.join(BASE_DIR, 'dynamic_model.pkl')
                    vectorizer_file = os.path.join(BASE_DIR, 'dynamic_vectorizer.pkl')
                    if os.path.exists(model_file) and os.path.exists(vectorizer_file):
                        with open(model_file, 'rb') as f:
                            self.classifier = pickle.load(f)
                        with open(vectorizer_file, 'rb') as f:
                            self.vectorizer = pickle.load(f)
                        self.is_trained = True
                        
                logger.info(f"Loaded dynamic knowledge from {len(data.get('tld_stats', {}))} TLDs")
        except Exception as e:
            logger.info(f"No existing knowledge found, starting fresh ({e})")
    
    def save_knowledge(self):
        try:
            data = {
                'tld_stats': dict(self.tld_stats),
                'domain_patterns': dict(self.domain_patterns),
                'subdomain_stats': {str(k): v for k, v in self.subdomain_stats.items()},
                'length_stats': self.length_stats,
                'hyphen_stats': self.hyphen_stats,
                'number_stats': self.number_stats
            }
            knowledge_file = os.path.join(BASE_DIR, 'dynamic_knowledge.json')
            with open(knowledge_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            if len(self.training_data) >= 10:
                model_file = os.path.join(BASE_DIR, 'dynamic_model.pkl')
                vectorizer_file = os.path.join(BASE_DIR, 'dynamic_vectorizer.pkl')
                with open(model_file, 'wb') as f:
                    pickle.dump(self.classifier, f)
                with open(vectorizer_file, 'wb') as f:
                    pickle.dump(self.vectorizer, f)
        except Exception as e:
            logger.warning(f"Failed to save knowledge: {e}")
    
    def extract_features(self, url, domain):
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else 'unknown'
        domain_name = parts[-2] if len(parts) > 1 else parts[0]
        subdomains = parts[:-2] if len(parts) > 2 else []
        
        return {
            'full_domain': domain,
            'tld': tld,
            'domain_pattern': f"{domain_name}.{tld}",
            'subdomain_count': len(subdomains),
            'domain_length': len(domain),
            'has_hyphen': 1 if '-' in domain else 0,
            'has_numbers': 1 if any(c.isdigit() for c in domain) else 0,
            'url_string': url
        }
    
    def learn_from_result(self, url, domain, verdict, is_correct=True, feedback_score=None):
        features = self.extract_features(url, domain)
        
        actual_verdict = verdict.lower()
        if feedback_score is not None:
            pass
        
        tld = features['tld']
        self.tld_stats[tld][actual_verdict] += 1
        self.tld_stats[tld]['total'] += 1
        
        pattern = features['domain_pattern']
        self.domain_patterns[pattern][actual_verdict] += 1
        self.domain_patterns[pattern]['total'] += 1
        
        sub_count = features['subdomain_count']
        self.subdomain_stats[sub_count][actual_verdict] += 1
        self.subdomain_stats[sub_count]['total'] += 1
        
        self.length_stats[actual_verdict].append(features['domain_length'])
        
        if features['has_hyphen']:
            self.hyphen_stats[actual_verdict] += 1
            self.hyphen_stats['total_hyphen'] += 1
        
        if features['has_numbers']:
            self.number_stats[actual_verdict] += 1
            self.number_stats['total_with_numbers'] += 1
        
        self.training_data.append(url)
        self.training_labels.append(actual_verdict)
        
        if len(self.training_data) % 10 == 0 and len(self.training_data) >= 10:
            self.retrain_ml_model()
        
        self.save_knowledge()
        logger.info(f"Learned from: {domain} -> {actual_verdict}")
    
    def retrain_ml_model(self):
        try:
            if len(self.training_data) >= 10:
                X = self.vectorizer.fit_transform(self.training_data)
                self.classifier.fit(X, self.training_labels)
                self.is_trained = True
                logger.info(f"Retrained ML model with {len(self.training_data)} samples")
        except Exception as e:
            logger.warning(f"ML training failed: {e}")
    
    def get_statistical_confidence(self, url, domain):
        features = self.extract_features(url, domain)
        
        confidence_factors = []
        weights = []
        
        tld = features['tld']
        if tld in self.tld_stats and self.tld_stats[tld]['total'] > 5:
            tld_data = self.tld_stats[tld]
            safe_ratio = tld_data['safe'] / tld_data['total'] if tld_data['total'] > 0 else 0
            suspicious_ratio = tld_data['suspicious'] / tld_data['total'] if tld_data['total'] > 0 else 0
            phishing_ratio = tld_data['phishing'] / tld_data['total'] if tld_data['total'] > 0 else 0
            
            tld_score = (safe_ratio * 0) + (suspicious_ratio * 0.5) + (phishing_ratio * 1.0)
            confidence_factors.append(tld_score)
            weights.append(0.25)
        
        pattern = features['domain_pattern']
        if pattern in self.domain_patterns and self.domain_patterns[pattern]['total'] > 2:
            pattern_data = self.domain_patterns[pattern]
            safe_ratio = pattern_data['safe'] / pattern_data['total'] if pattern_data['total'] > 0 else 0
            suspicious_ratio = pattern_data['suspicious'] / pattern_data['total'] if pattern_data['total'] > 0 else 0
            phishing_ratio = pattern_data['phishing'] / pattern_data['total'] if pattern_data['total'] > 0 else 0
            
            pattern_score = (safe_ratio * 0) + (suspicious_ratio * 0.5) + (phishing_ratio * 1.0)
            confidence_factors.append(pattern_score)
            weights.append(0.3)
        
        sub_count = features['subdomain_count']
        if sub_count in self.subdomain_stats and self.subdomain_stats[sub_count]['total'] > 3:
            sub_data = self.subdomain_stats[sub_count]
            safe_ratio = sub_data['safe'] / sub_data['total'] if sub_data['total'] > 0 else 0
            suspicious_ratio = sub_data['suspicious'] / sub_data['total'] if sub_data['total'] > 0 else 0
            phishing_ratio = sub_data['phishing'] / sub_data['total'] if sub_data['total'] > 0 else 0
            
            sub_score = (safe_ratio * 0) + (suspicious_ratio * 0.5) + (phishing_ratio * 1.0)
            confidence_factors.append(sub_score)
            weights.append(0.2)
        
        if self.length_stats['safe'] and self.length_stats['phishing']:
            safe_avg = np.mean(self.length_stats['safe'])
            phishing_avg = np.mean(self.length_stats['phishing'])
            current_len = features['domain_length']
            
            len_score = 1.0 - min(abs(current_len - safe_avg) / max(safe_avg, 1), 
                                  abs(current_len - phishing_avg) / max(phishing_avg, 1))
            confidence_factors.append(len_score)
            weights.append(0.1)
        
        if self.hyphen_stats['total_hyphen'] > 5:
            hyphen_ratio = self.hyphen_stats['phishing'] / max(self.hyphen_stats['total_hyphen'], 1)
            if features['has_hyphen']:
                confidence_factors.append(hyphen_ratio)
                weights.append(0.1)
        
        if self.number_stats['total_with_numbers'] > 5:
            numbers_ratio = self.number_stats['phishing'] / max(self.number_stats['total_with_numbers'], 1)
            if features['has_numbers']:
                confidence_factors.append(numbers_ratio)
                weights.append(0.05)
        
        if confidence_factors and weights:
            total_weight = sum(weights)
            normalized_weights = [w / total_weight for w in weights]
            final_score = sum(f * w for f, w in zip(confidence_factors, normalized_weights))
            return min(final_score, 1.0)
        
        return 0.5
    
    def get_ml_prediction(self, url):
        if self.is_trained and len(self.training_data) >= 10:
            try:
                X = self.vectorizer.transform([url])
                pred = self.classifier.predict(X)[0]
                proba = self.classifier.predict_proba(X)[0]
                confidence = max(proba)
                
                if pred == 'phishing':
                    return confidence, f"ML predicts phishing ({confidence:.0%} confidence)"
                elif pred == 'suspicious':
                    return confidence * 0.7, f"ML predicts suspicious ({confidence:.0%} confidence)"
                else:
                    return 1 - confidence, f"ML predicts safe ({confidence:.0%} confidence)"
            except Exception as e:
                logger.warning(f"ML prediction failed: {e}")
        return None, None
    
    def get_insights(self, url, domain):
        insights = []
        
        similar_domains = []
        for pattern in self.domain_patterns:
            if pattern in domain or domain in pattern:
                similar_domains.append(pattern)
        
        if similar_domains:
            insights.append(f"Found {len(similar_domains)} similar domains in history")
        
        tld = domain.split('.')[-1] if '.' in domain else 'unknown'
        if tld in self.tld_stats and self.tld_stats[tld]['total'] > 10:
            safe_pct = (self.tld_stats[tld]['safe'] / self.tld_stats[tld]['total']) * 100
            insights.append(f"TLD .{tld} is safe in {safe_pct:.0f}% of historical cases")
        
        return insights

dynamic_learner = DynamicLearner()

def normalize_url(url):
    return url if url.startswith("http") else "http://" + url

def extract_urls(text):
    return list(set(re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text.lower())))

def parse_email(raw):
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw.encode())
        body = msg.get_body(preferencelist=("plain"))
        return msg["from"], msg["subject"] or "", body.get_content() if body else ""
    except Exception:
        return None, None, raw

def run_async(coro):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def verify_ssl_certificate(domain):
    """Verify SSL certificate with better error handling and timeout"""
    try:
        # Skip SSL check for domains without HTTPS
        if not domain or '.' not in domain:
            return False, "Invalid domain"
        
        # Add timeout to prevent hanging
        context = ssl.create_default_context(cafile=certifi.where())
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Check expiration
                    from datetime import datetime
                    exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if exp_date < datetime.now():
                        return False, "SSL Certificate Expired"
                    return True, "Valid SSL"
    except socket.timeout:
        return False, "SSL Check Timeout"
    except ssl.SSLCertVerificationError:
        return False, "Invalid SSL Certificate"
    except ConnectionRefusedError:
        return False, "Connection Refused"
    except Exception as e:
        pass
    return False, "SSL Check Failed"

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                return 0.7, f"Very new domain ({age_days} days)"
            elif age_days < 365:
                return 0.3, f"New domain ({age_days} days)"
            else:
                return 0.0, f"Established domain ({age_days} days)"
    except Exception as e:
        pass
    return 0.3, "Unable to verify age"

def parse_threat_intel_message(message, source):
    msg_lower = message.lower()
    if any(term in msg_lower for term in ['malicious', 'phishing']):
        return 0.9, f"{source}: Malicious"
    if any(term in msg_lower for term in ['suspicious', 'warning']):
        return 0.5, f"{source}: Suspicious"
    if any(term in msg_lower for term in ['clean', 'safe']):
        return 0.0, f"{source}: Clean"
    return 0.3, f"{source}: {message}"

def save_scan_to_db(user_id, scan_type, content, verdict, risk_level, confidence, analysis_source, full_result):
    try:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        scan = ScanHistory(
            user_id=user_id,
            scan_type=scan_type,
            content=content[:500],
            content_hash=content_hash,
            verdict=verdict,
            risk_level=risk_level,
            confidence=confidence,
            analysis_source=analysis_source,
            full_result=full_result,
            created_at=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()
        return scan.id
    except Exception as e:
        logger.error(f"Error saving scan: {e}")
        db.session.rollback()
        return None

def update_system_stats(verdict):
    try:
        stats = SystemStats.query.first()
        if not stats:
            stats = SystemStats()
            db.session.add(stats)
        
        stats.total_scans += 1
        if verdict and verdict.lower() == 'phishing':
            stats.phishing_detected += 1
        elif verdict and verdict.lower() == 'suspicious':
            stats.suspicious_detected += 1
        elif verdict:
            stats.safe_detected += 1
        
        stats.total_users = User.query.count()
        stats.last_updated = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating stats: {e}")
        db.session.rollback()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not username or not email or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'All fields are required'}), 400
            else:
                flash('All fields are required', 'error')
                return render_template('register.html')
        
        if len(username) < 3 or len(username) > 80:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Username must be 3-80 characters'}), 400
            else:
                flash('Username must be 3-80 characters', 'error')
                return render_template('register.html')
        
        # Stricter email validation
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
           if request.is_json:
              return jsonify({'success': False, 'error': 'Invalid email format'}), 400
           else:
             flash('Invalid email format (use name@domain.com)', 'error')
             return render_template('register.html')
        
        if len(password) < 8:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
            else:
                flash('Password must be at least 8 characters', 'error')
                return render_template('register.html')
        
        if password != confirm_password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Passwords do not match'}), 400
            else:
                flash('Passwords do not match', 'error')
                return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            if request.is_json:
                return jsonify({'success': False, 'error': 'Username already exists'}), 400
            else:
                flash('Username already exists', 'error')
                return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            if request.is_json:
                return jsonify({'success': False, 'error': 'Email already registered'}), 400
            else:
                flash('Email already registered', 'error')
                return render_template('register.html')
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        update_system_stats(None)
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})
        else:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not username or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Username and password required'}), 400
            else:
                flash('Username and password required', 'error')
                return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.update_last_login()
            
            if not APIKey.query.filter_by(user_id=user.id).first():
                api_key = APIKey(
                    user_id=user.id,
                    key_name='Default API Key',
                    api_key=generate_api_key(),
                    expires_at=datetime.utcnow() + timedelta(days=365)
                )
                db.session.add(api_key)
                db.session.commit()
            
            if request.is_json:
                return jsonify({
                    'success': True, 
                    'message': 'Login successful!',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                })
            else:
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
        else:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
            else:
                flash('Invalid username or password', 'error')
                return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        })
    
    return redirect(url_for('home'))

@app.route("/")
def home():
    return render_template("index.html", user=current_user if current_user.is_authenticated else None)

@app.route("/results")
def results_page():
    return render_template("results.html", user=current_user if current_user.is_authenticated else None)

@app.route("/dashboard")
@login_required
def dashboard():
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    phishing_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Phishing').count()
    suspicious_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Suspicious').count()
    safe_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Safe').count()
    
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).limit(10).all()
    
    stats = {
        'total_scans': total_scans,
        'phishing': phishing_scans,
        'suspicious': suspicious_scans,
        'safe': safe_scans
    }
    
    return render_template("dashboard.html", user=current_user, scans=recent_scans, stats=stats)

@app.route("/profile")
@login_required
def profile():
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).limit(10).all()
    api_keys = APIKey.query.filter_by(user_id=current_user.id).all()
    
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    phishing_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Phishing').count()
    suspicious_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Suspicious').count()
    safe_scans = ScanHistory.query.filter_by(user_id=current_user.id, verdict='Safe').count()
    
    stats = {
        'total_scans': total_scans,
        'phishing': phishing_scans,
        'suspicious': suspicious_scans,
        'safe': safe_scans
    }
    
    return render_template("profile.html", user=current_user, scans=recent_scans, api_keys=api_keys, stats=stats)

@app.route("/history")
@login_required
def history_page():
    return render_template("history.html", user=current_user)

@app.route("/api-keys")
@login_required
def api_keys_page():
    api_keys = APIKey.query.filter_by(user_id=current_user.id).all()
    return render_template("api_keys.html", user=current_user, api_keys=api_keys)

@app.route("/terms")
def terms():
    return render_template("terms.html", user=current_user if current_user.is_authenticated else None)

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", user=current_user if current_user.is_authenticated else None)

@app.route('/api/keys', methods=['POST'])
@login_required
@limiter.limit("10 per day")
def create_api_key():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid JSON'}), 400
    
    key_name = data.get('key_name', '').strip()
    if not key_name:
        return jsonify({'success': False, 'error': 'Key name is required'}), 400
    
    if len(key_name) > 50:
        return jsonify({'success': False, 'error': 'Key name too long (max 50 characters)'}), 400
    
    existing_keys = APIKey.query.filter_by(user_id=current_user.id, is_active=True).count()
    if existing_keys >= 10:
        return jsonify({'success': False, 'error': 'Maximum 10 active API keys allowed'}), 400
    
    existing_name = APIKey.query.filter_by(user_id=current_user.id, key_name=key_name).first()
    if existing_name:
        return jsonify({'success': False, 'error': 'A key with this name already exists'}), 400
    
    api_key = APIKey(
        user_id=current_user.id,
        key_name=key_name,
        api_key=generate_api_key(),
        expires_at=datetime.utcnow() + timedelta(days=365)
    )
    
    db.session.add(api_key)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'api_key': api_key.api_key,
        'message': 'API key created successfully'
    })

@app.route('/api/keys/<int:key_id>/revoke', methods=['POST'])
@login_required
@limiter.limit("20 per day")
def revoke_api_key(key_id):
    api_key = APIKey.query.get_or_404(key_id)
    
    if api_key.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    if not api_key.is_active:
        return jsonify({'success': False, 'error': 'API key is already revoked'}), 400
    
    api_key.is_active = False
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'API key revoked successfully'})

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@login_required
@limiter.limit("20 per day")
def delete_api_key(key_id):
    api_key = APIKey.query.get_or_404(key_id)
    
    if api_key.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    db.session.delete(api_key)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'API key deleted permanently'})

@app.route("/api/history", methods=["GET"])
@login_required
@limiter.limit("60 per minute")
def get_user_history():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        scan_type = request.args.get('type')
        search = request.args.get('search', '')
        risk = request.args.get('risk', '')
        
        if page < 1:
            page = 1
        if per_page < 1:
            per_page = 20
        
        query = ScanHistory.query.filter_by(user_id=current_user.id)
        
        if scan_type and scan_type != 'all':
            query = query.filter_by(scan_type=scan_type)
        
        if risk and risk != 'all':
            risk_capitalized = risk.capitalize()
            query = query.filter_by(verdict=risk_capitalized)
        
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(ScanHistory.content.ilike(search_pattern))
        
        paginated = query.order_by(ScanHistory.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            "success": True,
            "scans": [{
                "id": s.id,
                "type": s.scan_type,
                "content": s.content[:200] + "..." if len(s.content) > 200 else s.content,
                "verdict": s.verdict,
                "risk_level": s.risk_level,
                "confidence": s.confidence,
                "analysis_source": s.analysis_source,
                "created_at": s.created_at.isoformat()
            } for s in paginated.items],
            "total": paginated.total,
            "pages": paginated.pages,
            "current_page": paginated.page,
            "per_page": paginated.per_page
        })
    except Exception as e:
        logger.error(f"Error in get_user_history: {e}")
        return jsonify({"success": False, "error": "Failed to fetch history"}), 500

@app.route("/api/history/<int:scan_id>", methods=["GET"])
@login_required
def get_scan_details(scan_id):
    try:
        scan = ScanHistory.query.get_or_404(scan_id)
        
        if scan.user_id != current_user.id:
            return jsonify({"success": False, "error": "Unauthorized"}), 403
        
        return jsonify({
            "success": True,
            "scan": {
                "id": scan.id,
                "type": scan.scan_type,
                "content": scan.content,
                "verdict": scan.verdict,
                "risk_level": scan.risk_level,
                "confidence": scan.confidence,
                "analysis_source": scan.analysis_source,
                "full_result": scan.full_result,
                "created_at": scan.created_at.isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error in get_scan_details: {e}")
        return jsonify({"success": False, "error": "Failed to fetch scan details"}), 500

@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
@login_required
def delete_scan(scan_id):
    try:
        scan = ScanHistory.query.get_or_404(scan_id)
        
        if scan.user_id != current_user.id:
            return jsonify({"success": False, "error": "Unauthorized"}), 403
        
        db.session.delete(scan)
        db.session.commit()
        
        return jsonify({"success": True, "message": "Scan deleted"})
    except Exception as e:
        logger.error(f"Error in delete_scan: {e}")
        db.session.rollback()
        return jsonify({"success": False, "error": "Failed to delete scan"}), 500

@app.route("/api/user-history", methods=["GET"])
@login_required
def get_user_history_from_db():
    try:
        scans = ScanHistory.query.filter_by(user_id=current_user.id)\
                .order_by(ScanHistory.created_at.desc())\
                .limit(100)\
                .all()
        
        history = []
        for scan in scans:
            history.append({
                'id': scan.id,
                'timestamp': scan.created_at.isoformat(),
                'type': scan.scan_type,
                'content': scan.content[:100] + '...' if len(scan.content) > 100 else scan.content,
                'verdict': scan.verdict,
                'riskLevel': scan.risk_level,
                'confidence': f"{scan.confidence}%",
                'accuracy': scan.analysis_source,
                'status': scan.verdict.lower()
            })
        
        return jsonify({
            'success': True,
            'history': history
        })
    except Exception as e:
        logger.error(f"Error fetching user history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        stats = SystemStats.query.first()
        
        if not stats:
            stats = SystemStats()
            db.session.add(stats)
            db.session.commit()
        
        recent_scans = ScanHistory.query.order_by(ScanHistory.created_at.desc()).limit(10).all()
        
        return jsonify({
            "success": True,
            "stats": {
                "total_scans": stats.total_scans,
                "total_users": stats.total_users,
                "phishing_detected": stats.phishing_detected,
                "suspicious_detected": stats.suspicious_detected,
                "safe_detected": stats.safe_detected
            },
            "recent_activity": [{
                "type": s.scan_type,
                "verdict": s.verdict,
                "created_at": s.created_at.isoformat()
            } for s in recent_scans]
        })
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        return jsonify({"success": False, "error": "Failed to fetch stats"}), 500

@app.route("/predict", methods=["POST"])
@limiter.limit("30 per minute")
def predict():
    try:
        data = request.get_json(force=True)
        text = data.get("input", "").strip()
        input_type = data.get("type", "url")
        api_key = request.headers.get('X-API-Key')

        if not text:
            return jsonify({"error": "Input cannot be empty"}), 400
        
        if len(text) > 10000:
            return jsonify({"error": "Input too long (max 10000 characters)"}), 400

        user = None
        if api_key:
            key_record = APIKey.query.filter_by(api_key=api_key, is_active=True).first()
            if key_record and (not key_record.expires_at or key_record.expires_at > datetime.utcnow()):
                user = key_record.user
                key_record.last_used = datetime.utcnow()
                key_record.requests_count += 1
                db.session.commit()
        elif current_user.is_authenticated:
            user = current_user

        sender, subject, body = (None, "", text)

        if input_type == "email":
            sender, subject, body = parse_email(text)

        urls = extract_urls(body)
        all_reasons = []
        threat_intel_messages = {}
        ai_result = None
        domain = None
        current_url = ""
        
        # STEP 1: First check with rule engine (heuristic detection)
        rule_engine_result = None
        if urls and input_type == "url":
            try:
                from deepseek_api import PhishingRuleEngine
                current_url = urls[0]
                rule_engine_result = PhishingRuleEngine.check_url(current_url)
                if rule_engine_result and rule_engine_result.get("detected"):
                    logger.info(f"Rule engine pre-check: {rule_engine_result['verdict']}")
                    all_reasons.extend(rule_engine_result.get("primary_indicators", []))
            except Exception as e:
                logger.error(f"Rule engine error: {e}")
        
        # STEP 2: DeepSeek AI analysis (if enabled)
        if deepseek_analyzer and deepseek_analyzer.enabled:
            try:
                logger.info("Attempting DeepSeek AI analysis...")
                
                if urls:
                    ai_raw_result = run_async(
                        deepseek_analyzer.analyze_url_async(urls[0])
                    )
                    current_url = urls[0]
                else:
                    ai_raw_result = run_async(
                        deepseek_analyzer.analyze_text_async(body[:500])
                    )

                if ai_raw_result:
                    ai_result = {
                        "success": True,
                        "verdict": ai_raw_result.get("verdict", "Safe"),
                        "confidence": float(ai_raw_result.get("confidence", 85)),
                        "risk_score": ai_raw_result.get("risk_score", 50),
                        "primary_indicators": ai_raw_result.get("primary_indicators", []),
                        "brand_impersonation": ai_raw_result.get("brand_impersonation"),
                        "source": ai_raw_result.get("source", "DeepSeek AI")
                    }
                    ai_indicators = ai_raw_result.get("primary_indicators", [])
                    all_reasons.extend(ai_indicators)
                    logger.info(f"DeepSeek AI: {ai_result['verdict']} ({ai_result['confidence']}%)")
                    
            except Exception as e:
                logger.error(f"DeepSeek AI Failed: {str(e)}")
                ai_result = {"success": False, "error": str(e)}
        else:
            ai_result = {"success": False, "error": "DeepSeek AI unavailable"}

        # STEP 3: Threat intelligence checks
        if urls and input_type == "url":
            try:
                url = normalize_url(urls[0])
                parsed = urlparse(url)
                domain = parsed.netloc
                
                gs_score, gs_message = check_google_safe(url)
                vt_score, vt_message = check_virustotal(url)
                da_score, da_message = check_domain_age(domain)
                
                gs_conf, gs_disp = parse_threat_intel_message(gs_message, "Google Safe Browsing")
                vt_conf, vt_disp = parse_threat_intel_message(vt_message, "VirusTotal")
                
                threat_intel_messages = {
                    "Google Safe Browsing": gs_disp,
                    "VirusTotal": vt_disp,
                    "Domain Age": da_message
                }
                
                if gs_conf >= 0.5:
                    all_reasons.append(gs_disp)
                if vt_conf >= 0.5:
                    all_reasons.append(vt_disp)
                    
            except Exception as e:
                logger.error(f"Threat Intel failed: {e}")

        # STEP 4: Statistical learning
        statistical_score = 0.5
        ml_prediction = None
        ml_confidence = None
        
        if domain:
            statistical_score = dynamic_learner.get_statistical_confidence(current_url, domain)
            ml_prediction, ml_confidence = dynamic_learner.get_ml_prediction(current_url)
            
            if ml_prediction is not None:
                all_reasons.append(ml_confidence)
            
            insights = dynamic_learner.get_insights(current_url, domain)
            all_reasons.extend(insights)

        # STEP 5: Threat intelligence consensus
        gs_malicious = "Malicious" in threat_intel_messages.get("Google Safe Browsing", "")
        vt_malicious = "Malicious" in threat_intel_messages.get("VirusTotal", "")
        gs_warning = "Suspicious" in threat_intel_messages.get("Google Safe Browsing", "")
        vt_warning = "Suspicious" in threat_intel_messages.get("VirusTotal", "")

        malicious_count = sum([gs_malicious, vt_malicious])
        warning_count = sum([gs_warning, vt_warning])

        threat_intel_consensus = "clean"
        if malicious_count >= 2:
            threat_intel_consensus = "malicious"
            all_reasons.append("Multiple threat intelligence sources confirm malicious content.")
        elif malicious_count == 1:
            threat_intel_consensus = "suspicious"
            all_reasons.append("One threat intelligence source reports malicious, but others disagree. Proceeding with caution.")
        elif warning_count >= 2:
            threat_intel_consensus = "suspicious"
            all_reasons.append("Multiple threat intelligence sources report suspicious activity.")
        elif warning_count == 1:
            threat_intel_consensus = "clean_with_note"
            all_reasons.append("One source reported suspicious activity, but consensus is clean.")

        # STEP 6: FINAL VERDICT DETERMINATION
        final_verdict = "Safe"
        final_risk = "Minimal Risk"
        final_status = "safe"
        final_confidence = 85
        analysis_source = "DeepSeek AI"
        
        # Priority 1: Rule engine detected phishing (highest confidence)
        if rule_engine_result and rule_engine_result.get("detected"):
            if rule_engine_result["verdict"] == "Phishing":
                final_verdict = "Phishing"
                final_risk = "Critical Risk"
                final_status = "phishing"
                final_confidence = rule_engine_result["confidence"]
                analysis_source = "DeepSeek AI (Rules)"
                all_reasons = rule_engine_result.get("primary_indicators", []) + all_reasons
            elif rule_engine_result["verdict"] == "Suspicious" and final_verdict == "Safe":
                final_verdict = "Suspicious"
                final_risk = "Elevated Risk"
                final_status = "suspicious"
                final_confidence = rule_engine_result["confidence"]
                analysis_source = "DeepSeek AI (Rules)"
                all_reasons = rule_engine_result.get("primary_indicators", []) + all_reasons
        
        # Priority 2: Threat intelligence consensus
        elif threat_intel_consensus == "malicious":
            final_verdict = "Phishing"
            final_risk = "Critical Risk"
            final_status = "phishing"
            final_confidence = 95
            analysis_source = "Threat Intelligence (Consensus)"
        
        # Priority 3: AI result with rule engine override already applied in deepseek_api
        elif ai_result and ai_result.get("success"):
            final_verdict = ai_result.get("verdict", "Safe")
            final_confidence = ai_result.get("confidence", 85)
            analysis_source = ai_result.get("source", "DeepSeek AI")
            
            if threat_intel_consensus == "suspicious":
                if final_verdict == "Safe":
                    final_verdict = "Suspicious"
                    final_risk = "Elevated Risk"
                    final_status = "suspicious"
                    analysis_source = "DeepSeek AI + Threat Intel"
                else:
                    analysis_source = "DeepSeek AI + Threat Intel"
            elif threat_intel_consensus == "clean_with_note":
                analysis_source = "DeepSeek AI + Threat Intel"
        
        # Priority 4: Statistical learning fallback
        else:
            if threat_intel_consensus == "suspicious":
                final_verdict = "Suspicious"
                final_risk = "Elevated Risk"
                final_status = "suspicious"
                final_confidence = 85
                analysis_source = "Threat Intelligence (Consensus)"
            else:
                if statistical_score > 0.7:
                    final_verdict = "Suspicious"
                    final_risk = "Elevated Risk"
                    final_status = "suspicious"
                    final_confidence = statistical_score * 100
                    analysis_source = "Statistical Learning"
                elif statistical_score > 0.4:
                    final_verdict = "Suspicious"
                    final_risk = "Elevated Risk"
                    final_status = "suspicious"
                    final_confidence = statistical_score * 100
                    analysis_source = "Statistical Learning"
                else:
                    final_verdict = "Safe"
                    final_risk = "Minimal Risk"
                    final_status = "safe"
                    final_confidence = 85
                    analysis_source = "Statistical Learning"

        # Set risk level based on verdict
        if final_verdict == "Phishing":
            final_risk = "Critical Risk"
        elif final_verdict == "Suspicious":
            final_risk = "Elevated Risk"
        else:
            final_risk = "Minimal Risk"

        # Learn from result (if domain available)
        if domain:
            dynamic_learner.learn_from_result(current_url, domain, final_verdict.lower())

        # Save to database if user authenticated
        if user:
            scan_id = save_scan_to_db(
                user_id=user.id,
                scan_type=input_type,
                content=text,
                verdict=final_verdict,
                risk_level=final_risk,
                confidence=final_confidence,
                analysis_source=analysis_source,
                full_result={
                    'verdict': final_verdict,
                    'risk_level': final_risk,
                    'confidence': final_confidence,
                    'reasons': all_reasons[:5],
                    'threat_intel': threat_intel_messages,
                    'brand_impersonation': rule_engine_result.get('brand_impersonation') if rule_engine_result else None
                }
            )
        
        update_system_stats(final_verdict)

        # Deduplicate reasons
        unique_reasons = []
        for reason in all_reasons:
            if reason not in unique_reasons and len(reason) < 100:
                unique_reasons.append(reason)

        # Prepare response
        response = {
            "success": True,
            "verdict": final_verdict,
            "status": final_status,
            "risk_level": final_risk,
            "confidence": round(final_confidence, 1),
            "summary": f"Analysis complete. {unique_reasons[0] if unique_reasons else 'No issues detected'}",
            "analysis_source": analysis_source,
            "primary_indicators": unique_reasons[:5],
            "threat_intelligence": threat_intel_messages,
            "model_metrics": {
                "detection_method": "Rule Engine + ML + Statistical Learning",
                "samples_learned": len(dynamic_learner.training_data),
                "ml_trained": dynamic_learner.is_trained,
                "rule_engine": "Active"
            }
        }

        # Add brand impersonation if detected
        if rule_engine_result and rule_engine_result.get('brand_impersonation'):
            response["brand_impersonation"] = rule_engine_result['brand_impersonation']
        elif ai_result and ai_result.get('brand_impersonation'):
            response["brand_impersonation"] = ai_result['brand_impersonation']

        if user:
            response["user"] = {
                "id": user.id,
                "username": user.username
            }

        return jsonify(response)

    except Exception as e:
        logger.error(f"ERROR in predict: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": "An internal error occurred"}), 500

@app.route("/feedback", methods=["POST"])
@limiter.limit("20 per minute")
def feedback():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"success": False, "error": "Invalid JSON"}), 400
        
        url = data.get("url", "")
        domain = data.get("domain", "")
        verdict = data.get("verdict", "")
        is_correct = data.get("is_correct", True)
        correct_verdict = data.get("correct_verdict")
        scan_id = data.get("scan_id")
        
        if not domain or not verdict:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        user = None
        if current_user.is_authenticated:
            user = current_user
        
        actual = correct_verdict.lower() if correct_verdict else verdict.lower()
        dynamic_learner.learn_from_result(url, domain, actual, is_correct)
        
        if user:
            feedback_entry = UserFeedback(
                user_id=user.id,
                scan_id=scan_id,
                url=url,
                domain=domain,
                verdict_given=verdict,
                is_correct=is_correct,
                correct_verdict=correct_verdict,
                feedback_text=data.get("feedback_text", "")
            )
            db.session.add(feedback_entry)
            db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Thank you! The system will improve from your feedback."
        })
        
    except Exception as e:
        logger.error(f"Error in feedback: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/threat-intel", methods=["POST"])
@limiter.limit("30 per minute")
def threat_intel():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "").strip()
        input_type = data.get("type", "url")
        
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400
        
        # For non-URL inputs, return empty data
        if input_type != "url":
            return jsonify({
                "success": True,
                "threat_intelligence": {
                    "Google Safe Browsing": "—",
                    "VirusTotal": "—",
                    "Domain Age": "—",
                    "SSL Certificate": "—"
                }
            })
        
        url = normalize_url(url)
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Initialize default values
        threat_data = {
            "Google Safe Browsing": "Checking...",
            "VirusTotal": "Checking...",
            "Domain Age": "Checking...",
            "SSL Certificate": "—"  # SSL disabled
        }
        
        # Run checks with individual error handling
        try:
            gs_score, gs_message = check_google_safe(url)
            _, gs_disp = parse_threat_intel_message(gs_message, "Google")
            threat_data["Google Safe Browsing"] = gs_disp
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            threat_data["Google Safe Browsing"] = "Service unavailable"
        
        try:
            vt_score, vt_message = check_virustotal(url)
            _, vt_disp = parse_threat_intel_message(vt_message, "VirusTotal")
            threat_data["VirusTotal"] = vt_disp
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            threat_data["VirusTotal"] = "Service unavailable"
        
        try:
            da_score, da_message = check_domain_age(domain)
            threat_data["Domain Age"] = da_message
        except Exception as e:
            logger.error(f"Domain age error: {e}")
            threat_data["Domain Age"] = "Unable to verify"
        
        return jsonify({
            "success": True,
            "threat_intelligence": threat_data
        })
        
    except Exception as e:
        logger.error(f"Error in threat-intel: {e}")
        return jsonify({
            "success": True,
            "threat_intelligence": {
                "Google Safe Browsing": "Service unavailable",
                "VirusTotal": "Service unavailable",
                "Domain Age": "Unable to verify",
                "SSL Certificate": "—"
            }
        })

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html', user=current_user if current_user.is_authenticated else None), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html', user=current_user if current_user.is_authenticated else None), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return jsonify({"success": False, "error": "Rate limit exceeded. Please try again later."}), 429

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "deepseek_enabled": deepseek_analyzer.enabled if deepseek_analyzer else False,
        "samples_learned": len(dynamic_learner.training_data),
        "ml_trained": dynamic_learner.is_trained,
        "database_connected": True,
        "users_count": User.query.count()
    })

import click
from flask.cli import with_appcontext

@click.command('init-db')
@with_appcontext
def init_db_command():
    db.create_all()
    click.echo('Database initialized!')

@click.command('create-admin')
@with_appcontext
def create_admin_command():
    username = click.prompt('Username', default='admin')
    email = click.prompt('Email', default='admin@phishguard.com')
    password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
    
    admin = User.query.filter_by(username=username).first()
    if not admin:
        admin = User(
            username=username,
            email=email
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        click.echo(f'Admin user "{username}" created!')
    else:
        click.echo(f'User "{username}" already exists')

@click.command('list-users')
@with_appcontext
def list_users_command():
    users = User.query.all()
    if users:
        click.echo("\nRegistered Users:")
        click.echo("-" * 50)
        for user in users:
            click.echo(f"ID: {user.id} | Username: {user.username} | Email: {user.email} | Created: {user.created_at.strftime('%Y-%m-%d %H:%M')}")
        click.echo("-" * 50)
        click.echo(f"Total: {len(users)} users")
    else:
        click.echo("No users found")

@click.command('reset-db')
@with_appcontext
def reset_db_command():
    if click.confirm('This will delete ALL data. Are you sure?'):
        db.drop_all()
        db.create_all()
        click.echo('Database reset complete!')

app.cli.add_command(init_db_command)
app.cli.add_command(create_admin_command)
app.cli.add_command(list_users_command)
app.cli.add_command(reset_db_command)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)