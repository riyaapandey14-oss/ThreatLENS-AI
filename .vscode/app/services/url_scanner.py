import re
import urllib.parse
from urllib.parse import urlparse
import math

class URLScanner:
    BADWORDS = {
        'phishing': ['login', 'verify', 'secure', 'update', 'account', 'bank', 'paypal', 'password'],
        'malware': ['download', 'free', 'crack', 'keygen', 'torrent'],
        'suspicious': ['bit.ly', 'tinyurl', 'ow.ly', 'go0gle.com']
    }
    
    DOMAINS = {
        'legit': ['google.com', 'microsoft.com', 'github.com'],
        'risky': ['ru', 'tk', 'ml', 'ga', 'cf'],
        'suspicious': ['bit.ly', 'tinyurl', 'ow.ly']
    }
    
    @staticmethod
    def scan(url):
        if not url:
            return {'risk_score': 100, 'risk_level': 'Invalid', 'details': ['Empty URL']}
        
        parsed = urlparse(url)
        risk_score = 0
        details = []
        
        if parsed.scheme != 'https':
            risk_score += 20
            details.append('No HTTPS')
        
        domain = parsed.netloc.lower()
        if any(tld in domain for tld in URLScanner.DOMAINS['risky']):
            risk_score += 15
            details.append('Risky TLD')
        if any(short in domain for short in URLScanner.DOMAINS['suspicious']):
            risk_score += 25
            details.append('URL shortener')
        
        path = (parsed.path + parsed.query).lower()
        for category, words in URLScanner.BADWORDS.items():
            for word in words:
                if word in path:
                    risk_score += 10
                    details.append(f'{category.capitalize()}: {word}')
                    break
        
        if path:
            path_counts = [path.count(c) for c in set(path)]
            path_probs = [count / len(path) for count in path_counts]
            path_entropy = -sum(p * math.log2(p) for p in path_probs if p > 0)
            if path_entropy < 2.5:
                risk_score += 10
                details.append('Low entropy (obfuscated)')
        
        risk_score = min(100, risk_score)
        
        if risk_score <= 20:
            risk_level = 'Safe ✅'
        elif risk_score <= 50:
            risk_level = 'Low Risk ℹ️'
        elif risk_score <= 80:
            risk_level = 'High Risk ⚠️'
        else:
            risk_level = 'Phishing! 🚨'
        
        explanation = {
            'Safe ✅': 'Legitimate.',
            'Low Risk ℹ️': 'Minor concerns.',
            'High Risk ⚠️': 'Avoid clicking.',
            'Phishing! 🚨': 'Do NOT click!'
        }[risk_level]
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'details': details,
            'explanation': explanation
        }
