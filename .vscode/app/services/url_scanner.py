import re
from urllib.parse import urlparse

class URLScanner:
    @staticmethod
    def scan(url):
        if not url:
            return {
                'result': 'DANGEROUS',
                'risk_score': 100,
                'reason': 'Empty URL',
                'advice': 'Enter a valid URL'
            }
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        full_lower = url.lower()
        
        risk = 0
        reasons = []
        advice_list = []
        
        # HTTPS
        if parsed.scheme != 'https':
            risk += 20
            reasons.append('Uses HTTP (no encryption)')
            advice_list.append('Only use HTTPS sites')
        
        # Suspicious keywords
        keywords = ['login', 'verify', 'free', 'bank', 'reward', 'urgent', 'update', 'account suspended']
        if any(kw in full_lower for kw in keywords):
            risk += 25
            reasons.append('Suspicious keywords')
            advice_list.append('Double-check sender/legitimacy')
        
        # Fake domains
        fake_indicators = ['g00gle', 'paypa1', 'pay-pal', 'rnicrosoft', 'arnazon', 'supp0rt']
        if any(ind in domain for ind in fake_indicators) or len(domain.replace('.', '')) != len(domain):
            risk += 40
            reasons.append('Fake domain/homoglyph')
            advice_list.append('Hover to see real domain')
        
        # Shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl']
        if any(s in full_lower for s in shorteners):
            risk += 20
            reasons.append('URL shortener')
            advice_list.append('Expand or avoid short links')
        
        # Unusual structure
        symbols_count = len(re.findall(r'[^a-zA-Z0-9./?=&-]', full_lower))
        param_count = len(parsed.query.split('&')) if parsed.query else 0
        if symbols_count > 15 or param_count > 8:
            risk += 15
            reasons.append('Unusual structure/parameters')
            advice_list.append('Avoid complex/obfuscated URLs')
        
        risk = min(100, risk)
        
        if risk <= 30:
            result = 'SAFE'
        elif risk <= 70:
            result = 'SUSPICIOUS'
        else:
            result = 'DANGEROUS'
        
        reason_str = '; '.join(reasons) or 'No major issues'
        advice_str = '\n- '.join(advice_list) or 'Proceed, but verify'
        
        return {
            'result': result,
            'risk_score': round(risk),
            'reason': reason_str,
            'advice': advice_str,
            'details': reasons,  # Template compat
            'risk_level': result  # Template compat
        }
