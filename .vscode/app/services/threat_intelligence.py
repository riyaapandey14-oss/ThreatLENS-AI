class SOCAnalystAI:
    """User-friendly cybersecurity expert - plain English responses"""
    
    KNOWLEDGE_BASE = {
        'general': {
            'keywords': ['help', 'hi', 'hello', 'start', 'what'], 
            'response': 'Hi! I can help with cybersecurity questions. Try asking about passwords, phishing emails, two-factor authentication, malware, VPNs, or security incidents. What would you like to know?'
        },
        'phishing': {
            'keywords': ['phish', 'email suspicious', 'fake email', 'click link'],
            'response': 'Don\'t click suspicious links! Always hover over links to see the real URL before clicking. Check if the website uses HTTPS (lock icon). If an email asks for urgent action or personal info, it\'s probably fake. Forward suspicious emails to your IT team.'
        },
        'password': {
            'keywords': ['pass', 'password', 'weak password', 'forgot password'],
            'response': 'Use long passphrases like "BlueSky$2024Coffee!" (16+ characters) instead of short passwords. Never reuse passwords across websites. Use a password manager like LastPass or Bitwarden. Change passwords every 90 days.'
        },
        'mfa': {
            'keywords': ['2fa', 'mfa', 'two factor', 'authentication'],
            'response': 'Turn on two-factor authentication everywhere! Use an authenticator app (Google Authenticator, Authy) or hardware key (YubiKey). SMS is okay but not the best. It adds a second verification step even if someone has your password.'
        },
        'malware': {
            'keywords': ['malware', 'virus', 'ransomware'],
            'response': 'If you think your computer has malware: 1) Disconnect from internet 2) Run antivirus scan 3) Change all passwords from clean device 4) Restore from backup if needed. Prevention: Keep software updated and avoid suspicious downloads.'
        },
        'vpn': {
            'keywords': ['vpn', 'remote work', 'public wifi'],
            'response': 'Use a VPN on public WiFi! It encrypts your internet traffic so hackers can\'t steal your data. Good free options: ProtonVPN. Paid: NordVPN, ExpressVPN. Always verify the VPN is connected before browsing.'
        },
        'firewall': {
            'keywords': ['firewall', 'block hackers'],
            'response': 'Windows Firewall is usually good enough for home use. It blocks unauthorized access. For businesses, use next-gen firewalls with web filtering. Check your firewall is enabled in Windows Security settings.'
        },
        'backup': {
            'keywords': ['backup', 'ransom', 'lost files'],
            'response': 'Backup strategy: 3-2-1 rule. 3 copies, 2 different media, 1 offsite. Use external drive + cloud (Google Drive, OneDrive). Test restores monthly. Ransomware can\'t encrypt backups that are offline.'
        },
        'update': {
            'keywords': ['update', 'patch', 'security update'],
            'response': 'Enable automatic updates for Windows, browser, and apps. Most cyberattacks exploit old software vulnerabilities. Restart weekly to install patches. Check Settings > Update & Security.'
        },
        'social': {
            'keywords': ['social engineer', 'someone called'],
            'response': 'Never give info to unsolicited callers. Verify identity by calling back official number. Social engineering tricks you into giving access. "Bank called about fraud" is usually fake.'
        }
    }
    
    @staticmethod
    def analyze(query, scan_type='general', base_risk=30):
        """Simple, friendly cybersecurity answers for everyone"""
        q = query.lower()
        
        best_match = 'general'
        best_score = 0
        
        for topic, info in SOCAnalystAI.KNOWLEDGE_BASE.items():
            score = sum(1 for word in info['keywords'] if word in q)
            if score > best_score:
                best_score = score
                best_match = topic
        
        response = SOCAnalystAI.KNOWLEDGE_BASE[best_match]['response']
        risk = min(90, base_risk + best_score * 10)
        
        return {
            'analyst_response': response,
            'risk_score': risk,
            'topic': best_match
        }
