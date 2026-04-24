"""
ThreatLens AI - Rule-Based Analysis Engine
Complete cybersecurity logic without any external APIs.
"""

import re
import math
import random
from collections import Counter
from urllib.parse import urlparse

class PasswordAnalyzer:
    COMMON_WEAK = {
        'password', '123456', '123456789', 'qwerty', 'abc123', 'password1',
        'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'hello',
        'freedom', 'whatever', 'qazwsx', 'trustno1', '111111', '000000',
        'iloveyou', 'football', 'baseball', 'sunshine', 'princess', 'starwars',
        'harley', 'michael', 'mustang', 'access', 'love', 'pussy', '696969',
        'qwertyuiop', '12345678', 'adobe123', 'admin123', 'letmein1', 'photoshop',
        'shadow', 'ashley', 'mattew', 'bailey', 'superman', 'batman'
    }

    @staticmethod
    def analyze(password):
        if not password or len(password) == 0:
            return {
                'score': 0,
                'strength': 'EMPTY',
                'suggestions': ['Enter a password to analyze.'],
                'crack_time': 'Instant',
                'checks': [],
                'length': 0
            }

        score = 0
        suggestions = []
        checks = []

        # Length scoring
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5
            suggestions.append('Use at least 12 characters (16+ recommended).')
        checks.append(f'Length {length}: {"✓" if length >= 8 else "✗"}')

        # Character classes
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

        if has_upper:
            score += 10
        else:
            suggestions.append('Add uppercase letters (A-Z).')
        if has_lower:
            score += 10
        else:
            suggestions.append('Add lowercase letters (a-z).')
        if has_digit:
            score += 10
        else:
            suggestions.append('Add numbers (0-9).')
        if has_special:
            score += 15
        else:
            suggestions.append('Add special characters (!@#$%^&*).')

        checks.extend([
            f'Uppercase: {"✓" if has_upper else "✗"}',
            f'Lowercase: {"✓" if has_lower else "✗"}',
            f'Digits: {"✓" if has_digit else "✗"}',
            f'Special: {"✓" if has_special else "✗"}'
        ])

        # Repetition penalty
        char_counts = Counter(password)
        max_repeat = max(char_counts.values()) if char_counts else 0
        if max_repeat > 3:
            score -= 15
            suggestions.append('Avoid repeating the same character 3+ times.')

        # Common password check
        pwd_clean = password.lower().strip()
        if pwd_clean in PasswordAnalyzer.COMMON_WEAK:
            score -= 25
            suggestions.append('Avoid common passwords like "password" or "123456".')

        # Sequential patterns
        sequences = ['123', 'abc', 'qwe', 'asd', 'zxc', 'qaz', 'wsx', '789', '098']
        found_seq = [s for s in sequences if s in pwd_clean]
        if found_seq:
            score -= 10
            suggestions.append('Avoid keyboard sequences like "qwerty" or "123".')

        score = max(0, min(100, score))

        # Strength classification
        if score >= 80:
            strength = 'STRONG'
            crack_time = 'Centuries'
        elif score >= 60:
            strength = 'GOOD'
            crack_time = 'Years'
        elif score >= 40:
            strength = 'MEDIUM'
            crack_time = 'Months'
        else:
            strength = 'WEAK'
            crack_time = 'Hours'

        return {
            'score': score,
            'strength': strength,
            'suggestions': suggestions[:5],
            'checks': checks,
            'crack_time': crack_time,
            'length': length
        }


class URLScanner:
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'bank', 'free', 'win', 'gift', 'secure-update',
        'account-suspended', 'billing', 'payment', 'update', 'confirm',
        'urgent', 'claim', 'prize', 'congrats', 'reward', 'bonus', 'offer',
        'deal', 'act-now', 'limited-time', 'verify-account', 'signin',
        'wallet', 'crypto', 'bitcoin', 'investment', 'guaranteed'
    ]
    SHORTENERS = ['bit.ly', 'tinyurl', 't.co', 'ow.ly', 'goo.gl', 'short.link',
                  'is.gd', 'buff.ly', 'rb.gy', 'clck.ru', 'qrco.de']

    @staticmethod
    def scan(url):
        if not url or not url.strip():
            return {
                'risk_score': 100,
                'risk_level': 'DANGEROUS',
                'reasons': ['No URL provided'],
                'tips': ['Enter a valid URL to scan.']
            }

        original_url = url.strip()
        if not original_url.startswith(('http://', 'https://')):
            url = 'https://' + original_url
        else:
            url = original_url

        risk = 0
        reasons = []
        tips = []

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        full_lower = url.lower()

        # HTTPS check
        if parsed.scheme != 'https':
            risk += 20
            reasons.append('Uses HTTP instead of HTTPS (no encryption).')
            tips.append('Only enter sensitive data on HTTPS sites.')

        # Suspicious keywords
        hits = [kw for kw in URLScanner.SUSPICIOUS_KEYWORDS if kw in full_lower]
        if hits:
            risk += min(25, len(hits) * 5)
            reasons.append(f'Suspicious keywords detected: {", ".join(hits[:4])}.')
            tips.append('Double-check legitimacy before entering credentials.')

        # IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            risk += 30
            reasons.append('URL uses an IP address instead of a domain name.')
            tips.append('Legitimate sites use domain names, not raw IP addresses.')

        # Very long URL
        if len(url) > 100:
            risk += 10
            reasons.append('Unusually long URL (possible obfuscation).')
            tips.append('Long URLs with many parameters may hide malicious redirects.')

        # Excessive hyphens
        if domain.count('-') >= 3:
            risk += 15
            reasons.append('Domain contains excessive hyphens (common in phishing).')
            tips.append('Phishing sites often use hyphenated domains to mimic brands.')

        # Many subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 2:
            risk += 10
            reasons.append('Multiple subdomains detected.')
            tips.append('Be wary of deep subdomain structures.')

        # Random-looking domain
        first_part = domain.split('.')[0] if domain else ''
        if len(first_part) >= 10:
            unique_ratio = len(set(first_part)) / len(first_part)
            if unique_ratio > 0.75:
                risk += 20
                reasons.append('Domain appears random or auto-generated.')
                tips.append('Random character domains are frequently used for malware.')

        # URL shorteners
        if any(s in full_lower for s in URLScanner.SHORTENERS):
            risk += 15
            reasons.append('URL shortener detected — destination is hidden.')
            tips.append('Use a URL expander to reveal the real destination.')

        # Fake brand indicators
        fake_brands = ['paypa1', 'g00gle', 'arnazon', 'rnicrosoft', 'faceb00k',
                       'app1e', 'netf1ix', 'lnstagram', 'twltter', 'l1nked1n']
        if any(fake in domain for fake in fake_brands):
            risk += 35
            reasons.append('Possible fake brand domain (homoglyph attack).')
            tips.append('Carefully check spelling of well-known brand domains.')

        # Too many parameters
        if parsed.query:
            param_count = len(parsed.query.split('&'))
            if param_count > 5:
                risk += 10
                reasons.append('Excessive query parameters detected.')
                tips.append('Too many URL parameters may be used to track or exploit.')

        risk = min(100, max(0, risk))

        if risk <= 30:
            level = 'SAFE'
        elif risk <= 60:
            level = 'SUSPICIOUS'
        else:
            level = 'DANGEROUS'

        if not reasons:
            reasons.append('No major red flags detected.')
            tips.append('Always verify site legitimacy before entering data.')

        return {
            'risk_score': risk,
            'risk_level': level,
            'reasons': reasons,
            'tips': tips,
            'original_url': original_url
        }


class EmailAnalyzer:
    URGENCY = [
        'act now', 'urgent', 'immediate action required', 'verify now',
        'expires today', 'limited time', 'account will be suspended',
        'confirm immediately', 'respond now', 'last chance', 'final warning',
        'action needed', 'your account has been compromised', 'unusual activity'
    ]
    CREDENTIALS = [
        'verify your password', 'confirm your login', 'update your credentials',
        'enter your ssn', 'provide your credit card', 'validate your account',
        're-enter your information', 'update payment details', 'confirm identity'
    ]
    THREATS = [
        'suspend your account', 'close your account', 'legal action',
        'penalty', 'fine', 'lawsuit', 'arrest warrant', 'debt collection',
        'blacklist', 'report to authorities', 'permanently disabled'
    ]
    REWARDS = [
        'you won', 'congratulations', 'claim your prize', 'free gift',
        'exclusive reward', 'bonus', 'cash prize', 'lottery winner',
        'inheritance', 'unexpected money', 'refund pending', 'winner selected'
    ]

    @staticmethod
    def analyze(email_text):
        if not email_text or len(email_text.strip()) < 5:
            return {
                'risk_level': 'UNKNOWN',
                'risk_label': 'Insufficient text',
                'risk_score': 0,
                'red_flags': ['Email text is too short to analyze.'],
                'recommendations': ['Paste the full email content for better analysis.']
            }

        text_lower = email_text.lower()
        score = 0
        flags = []
        recs = []

        # Urgency
        urg_found = [p for p in EmailAnalyzer.URGENCY if p in text_lower]
        if urg_found:
            score += min(30, len(urg_found) * 10)
            flags.append(f'Urgency language: {", ".join(urg_found[:3])}')
            recs.append('Legitimate companies rarely demand immediate action via email.')

        # Credentials
        cred_found = [p for p in EmailAnalyzer.CREDENTIALS if p in text_lower]
        if cred_found:
            score += 25
            flags.append(f'Request for sensitive info: {", ".join(cred_found[:2])}')
            recs.append('Never provide passwords or payment details via email links.')

        # Threats
        threat_found = [p for p in EmailAnalyzer.THREATS if p in text_lower]
        if threat_found:
            score += min(25, len(threat_found) * 10)
            flags.append(f'Threat language: {", ".join(threat_found[:3])}')
            recs.append('Threats of account closure or legal action are common phishing tactics.')

        # Rewards
        reward_found = [p for p in EmailAnalyzer.REWARDS if p in text_lower]
        if reward_found:
            score += 20
            flags.append(f'Unsolicited rewards: {", ".join(reward_found[:2])}')
            recs.append('If it sounds too good to be true, it probably is.')

        # Suspicious links
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', email_text)
        suspicious_links = 0
        for u in urls:
            u_low = u.lower()
            if any(kw in u_low for kw in ['verify', 'login', 'update', 'confirm', 'secure']):
                suspicious_links += 1
        if suspicious_links > 0:
            score += 15
            flags.append(f'Suspicious links found: {suspicious_links}')
            recs.append('Hover over links to preview the real destination before clicking.')

        # Grammar heuristics
        common_issues = ['dear customer', 'dear user', 'valued costumer', 'acount',
                         'verfy', 'immediatly', 'sensetive', 'informtion', 'log-in',
                         'securty', 'confidentialy', 'immedite']
        issue_count = sum(1 for issue in common_issues if issue in text_lower)
        if issue_count >= 2:
            score += 10
            flags.append('Poor grammar and spelling detected.')
            recs.append('Professional organizations proofread communications.')

        score = min(100, score)

        if score >= 70:
            level = 'HIGH'
            label = 'High phishing risk — do not interact'
        elif score >= 40:
            level = 'MEDIUM'
            label = 'Medium phishing risk — be cautious'
        else:
            level = 'LOW'
            label = 'Low phishing risk — likely legitimate'

        if not flags:
            flags.append('No significant phishing indicators found.')
            recs.append('Always remain vigilant, even with low-risk emails.')

        return {
            'risk_level': level,
            'risk_label': label,
            'risk_score': score,
            'red_flags': flags,
            'recommendations': recs
        }


class KnowledgeBase:
    TOPICS = [
        {
            'id': 'phishing',
            'keywords': ['phishing', 'phish', 'fake email', 'suspicious email',
                         'email scam', 'spoof email', 'clickbait'],
            'title': 'Phishing Signs',
            'response': (
                'Phishing is a cyberattack where attackers impersonate trusted entities '
                'to steal credentials or data.\n\n'
                'Common Signs:\n'
                '1. Urgent language ("Act now!", "Account suspended!")\n'
                '2. Suspicious sender addresses (e.g., support@paypa1.com)\n'
                '3. Generic greetings ("Dear Customer" instead of your name)\n'
                '4. Unexpected attachments or links\n'
                '5. Requests for passwords, PINs, or payment info\n'
                '6. Poor spelling and grammar\n\n'
                'What to Do:\n'
                '- Do NOT click links or download attachments\n'
                '- Verify via a known official website or phone number\n'
                '- Report to your IT/security team\n'
                '- Use email filtering and anti-phishing browser extensions'
            )
        },
        {
            'id': 'mfa',
            'keywords': ['mfa', '2fa', 'multi factor', 'two factor', 'authenticator',
                         'totp', 'sms code', 'verification code', 'second factor'],
            'title': 'Multi-Factor Authentication (MFA)',
            'response': (
                'MFA adds an extra layer of security by requiring two or more verification factors.\n\n'
                'Benefits:\n'
                '- Blocks 99.9% of automated credential-stuffing attacks\n'
                '- Protects even if your password is leaked\n'
                '- Required by most compliance frameworks (NIST, SOC2)\n\n'
                'Best Practices:\n'
                '1. Use hardware security keys (YubiKey) when possible\n'
                '2. Prefer authenticator apps over SMS\n'
                '3. Store backup codes securely offline\n'
                '4. Enable MFA on email, banking, and work accounts first'
            )
        },
        {
            'id': 'ransomware',
            'keywords': ['ransomware', 'ransom', 'encrypt files', 'locked files',
                         'pay bitcoin', 'decrypt', 'wannacry', 'crypto locker'],
            'title': 'Ransomware',
            'response': (
                'Ransomware is malware that encrypts your files and demands payment.\n\n'
                'Prevention:\n'
                '1. Regular offline backups (3-2-1 rule)\n'
                '2. Keep OS and software patched\n'
                '3. Use endpoint detection and response (EDR)\n'
                '4. Disable macros in Office documents by default\n'
                '5. Network segmentation\n\n'
                'If Infected:\n'
                '- Isolate the machine immediately\n'
                '- Do NOT pay the ransom\n'
                '- Report to law enforcement\n'
                '- Restore from clean backups'
            )
        },
        {
            'id': 'malware',
            'keywords': ['malware', 'virus', 'trojan', 'worm', 'spyware',
                         'keylogger', 'rootkit', 'botnet', 'backdoor'],
            'title': 'Malware',
            'response': (
                'Malware is any software designed to harm, exploit, or gain unauthorized access.\n\n'
                'Types:\n'
                '- Virus: attaches to legitimate files and spreads\n'
                '- Trojan: disguises itself as legitimate software\n'
                '- Worm: self-replicates across networks\n'
                '- Spyware: secretly monitors activity\n'
                '- Ransomware: encrypts files for ransom\n\n'
                'Protection:\n'
                '1. Install reputable anti-malware and keep it updated\n'
                '2. Avoid downloading software from untrusted sources\n'
                '3. Keep operating systems and applications patched\n'
                '4. Regular scans and behavioral monitoring'
            )
        },
        {
            'id': 'password_hygiene',
            'keywords': ['password', 'passphrase', 'password manager',
                         'strong password', 'password security', 'password tip'],
            'title': 'Password Hygiene',
            'response': (
                'Strong passwords are your first line of defense.\n\n'
                'Best Practices:\n'
                '1. Use passphrases: 4+ random words (e.g., "CorrectHorseBatteryStaple!47")\n'
                '2. Length beats complexity: aim for 16+ characters\n'
                '3. Unique password for every account\n'
                '4. Use a password manager (Bitwarden, 1Password, KeePass)\n'
                '5. Enable MFA everywhere possible\n'
                '6. Check HaveIBeenPwned.com for breaches\n\n'
                'Avoid:\n'
                '- Dictionary words, names, birthdays\n'
                '- Keyboard walks (qwerty, asdf)\n'
                '- Reusing passwords across sites'
            )
        },
        {
            'id': 'wifi',
            'keywords': ['wifi', 'wi-fi', 'public wifi', 'hotspot', 'open network',
                         'wireless security', 'free internet', 'cafe wifi'],
            'title': 'Public Wi-Fi Safety',
            'response': (
                'Public Wi-Fi networks are convenient but risky.\n\n'
                'Risks:\n'
                '- Man-in-the-middle attacks\n'
                '- Rogue access points\n'
                '- Unencrypted traffic sniffing\n'
                '- Session hijacking\n\n'
                'Safety Tips:\n'
                '1. Use a reputable VPN on all public networks\n'
                '2. Avoid accessing banking or sensitive accounts\n'
                '3. Disable auto-connect to open Wi-Fi\n'
                '4. Verify the network name with staff\n'
                '5. Use your phone\'s mobile hotspot when possible\n'
                '6. Ensure sites use HTTPS'
            )
        },
        {
            'id': 'social_engineering',
            'keywords': ['social engineering', 'pretexting', 'baiting', 'quid pro quo',
                         'tailgating', 'manipulation', 'psychological hack'],
            'title': 'Social Engineering',
            'response': (
                'Social engineering manipulates people into breaking security procedures.\n\n'
                'Common Tactics:\n'
                '- Phishing: deceptive emails/messages\n'
                '- Pretexting: creating a false scenario to gain trust\n'
                '- Baiting: offering something enticing (free USB)\n'
                '- Quid pro quo: promising a service in exchange for info\n'
                '- Tailgating: following someone into a secure area\n\n'
                'Defense:\n'
                '1. Verify identity before sharing information\n'
                '2. Be skeptical of unsolicited requests\n'
                '3. Follow the principle of least privilege\n'
                '4. Regular security awareness training\n'
                '5. Report suspicious interactions'
            )
        },
        {
            'id': 'ddos',
            'keywords': ['ddos', 'dos', 'denial of service', 'flood attack',
                         'syn flood', 'botnet attack', 'traffic flood'],
            'title': 'DDoS Basics',
            'response': (
                'A DDoS attack overwhelms a target with traffic.\n\n'
                'Types:\n'
                '- Volumetric: floods bandwidth\n'
                '- Protocol: exploits protocol weaknesses\n'
                '- Application: targets web server resources\n\n'
                'Mitigation:\n'
                '1. Use a CDN with DDoS protection (Cloudflare)\n'
                '2. Rate limiting and traffic filtering\n'
                '3. Scalable cloud infrastructure\n'
                '4. Blackhole routing for extreme floods\n'
                '5. Have a DDoS response plan ready'
            )
        },
        {
            'id': 'data_breach',
            'keywords': ['data breach', 'breach', 'leak', 'exposed data',
                         'compromised', 'stolen data', 'have i been pwned'],
            'title': 'Data Breach Response',
            'response': (
                'A data breach is unauthorized access to sensitive information.\n\n'
                'Immediate Steps:\n'
                '1. Contain: isolate affected systems\n'
                '2. Assess: determine scope and data types involved\n'
                '3. Notify: inform affected users and regulators\n'
                '4. Investigate: preserve logs and evidence\n'
                '5. Remediate: patch vulnerabilities, reset credentials\n\n'
                'If Your Data Was Breached:\n'
                '- Change passwords immediately\n'
                '- Enable MFA on all accounts\n'
                '- Monitor bank statements\n'
                '- Watch for phishing emails exploiting the breach'
            )
        },
        {
            'id': 'safe_browsing',
            'keywords': ['safe browsing', 'browser security', 'https', 'padlock',
                         'certificate', 'tls', 'ssl', 'secure site'],
            'title': 'Safe Browsing',
            'response': (
                'Safe browsing habits protect you from malicious websites.\n\n'
                'Best Practices:\n'
                '1. Look for HTTPS and a valid certificate padlock\n'
                '2. Keep your browser updated\n'
                '3. Use ad-blockers and anti-tracking extensions\n'
                '4. Enable safe browsing features (Google Safe Browsing)\n'
                '5. Avoid downloading files from untrusted sites\n'
                '6. Check URL spelling carefully\n'
                '7. Use a password manager with autofill\n'
                '8. Disable unused browser extensions\n'
                '9. Run downloads through VirusTotal'
            )
        },
        {
            'id': 'vpn',
            'keywords': ['vpn', 'virtual private network', 'proxy', 'encryption',
                         'hide ip', 'privacy', 'secure connection'],
            'title': 'VPN & Privacy',
            'response': (
                'A VPN encrypts your internet connection and masks your IP address.\n\n'
                'Benefits:\n'
                '- Encrypts traffic on public Wi-Fi\n'
                '- Hides browsing from ISP\n'
                '- Bypasses geo-restrictions\n'
                '- Prevents tracking by IP\n\n'
                'Cautions:\n'
                '- Not all VPNs are trustworthy\n'
                '- VPN does not make you anonymous by itself\n'
                '- Does not protect against malware or phishing\n'
                '- Free VPNs may sell your data\n\n'
                'Recommendations: Mullvad, ProtonVPN, IVPN'
            )
        },
        {
            'id': 'incident_response',
            'keywords': ['incident response', 'ir', 'security incident', 'compromise',
                         'intrusion', 'soc', 'siem', 'security event'],
            'title': 'Incident Response',
            'response': (
                'Incident Response is the organized approach to addressing security breaches.\n\n'
                'NIST 4-Phase Lifecycle:\n'
                '1. Preparation: tools, plans, training\n'
                '2. Detection & Analysis: SIEM alerts, threat hunting\n'
                '3. Containment, Eradication & Recovery\n'
                '4. Post-Incident Activity: lessons learned\n\n'
                'Key Tips:\n'
                '- Document everything with timestamps\n'
                '- Preserve evidence before remediation\n'
                '- Communicate clearly with stakeholders\n'
                '- Run tabletop exercises regularly'
            )
        }
    ]

    FALLBACK_RESPONSE = (
        "I don't have a direct module for that topic yet, but here are general cybersecurity best practices:\n\n"
        "1. Use strong, unique passwords for every account\n"
        "2. Enable multi-factor authentication (MFA) everywhere\n"
        "3. Keep all software and operating systems updated\n"
        "4. Be skeptical of unsolicited emails, messages, and phone calls\n"
        "5. Use a reputable VPN on public Wi-Fi\n"
        "6. Regularly back up important data offline\n"
        "7. Use anti-malware and keep it updated\n"
        "8. Verify URLs before clicking links\n"
        "9. Monitor accounts for unusual activity\n"
        "10. Stay informed about emerging threats\n\n"
        "Try asking about: phishing, MFA, ransomware, malware, passwords, Wi-Fi safety, "
        "social engineering, DDoS, data breaches, safe browsing, VPNs, or incident response."
    )

    @staticmethod
    def ask(query):
        if not query or len(query.strip()) < 2:
            return {'matched': False, 'title': 'Ask a Question', 'response': 'Please enter a cybersecurity question.'}

        q_lower = query.lower().strip()
        q_words = set(re.findall(r'\b\w+\b', q_lower))

        best_topic = None
        best_score = 0

        for topic in KnowledgeBase.TOPICS:
            # Match keywords
            kw_score = sum(3 for kw in topic['keywords'] if kw in q_lower)
            # Word overlap
            topic_words = set(re.findall(r'\b\w+\b', ' '.join(topic['keywords']).lower()))
            overlap = len(topic_words & q_words)
            score = kw_score + overlap

            if score > best_score:
                best_score = score
                best_topic = topic

        if best_topic and best_score >= 2:
            return {
                'matched': True,
                'title': best_topic['title'],
                'response': best_topic['response'],
                'topic_id': best_topic['id']
            }

        return {
            'matched': False,
            'title': 'General Cybersecurity Guidance',
            'response': KnowledgeBase.FALLBACK_RESPONSE
        }


class QuizManager:
    QUESTIONS = [
        {
            'question': 'What does HTTPS stand for?',
            'options': ['Hyper Text Transfer Protocol Secure', 'Hyper Transfer Text Protocol Secure',
                        'High Text Transfer Protocol Secure', 'Hyper Text Transmission Protocol Secure'],
            'correct': 0
        },
        {
            'question': 'Which is the strongest form of MFA?',
            'options': ['SMS text message', 'Hardware security key (YubiKey)', 'Email verification code', 'Security questions'],
            'correct': 1
        },
        {
            'question': 'What is phishing?',
            'options': ['A type of malware', 'A social engineering attack via deceptive messages',
                        'A network scanning tool', 'A type of firewall'],
            'correct': 1
        },
        {
            'question': 'What should you do if you suspect a phishing email?',
            'options': ['Click the link to verify', 'Reply to the sender', 'Delete and report it', 'Forward it to friends'],
            'correct': 2
        },
        {
            'question': 'How long should a strong password ideally be?',
            'options': ['6 characters', '8 characters', '12 characters', '16+ characters'],
            'correct': 3
        },
        {
            'question': 'What is a VPN primarily used for?',
            'options': ['Speeding up internet', 'Encrypting internet traffic', 'Blocking ads', 'Storing passwords'],
            'correct': 1
        },
        {
            'question': 'What does ransomware do?',
            'options': ['Steals credit card numbers', 'Encrypts files and demands payment', 'Spams your contacts', 'Deletes system files'],
            'correct': 1
        },
        {
            'question': 'Which of these is NOT a good password practice?',
            'options': ['Using a password manager', 'Reusing passwords across sites', 'Enabling MFA', 'Using passphrases'],
            'correct': 1
        },
        {
            'question': 'What is the 3-2-1 backup rule?',
            'options': ['3 copies, 2 media types, 1 offsite', '3 backups daily, 2 weekly, 1 monthly',
                        '3TB storage, 2 drives, 1 cloud', '3 passwords, 2 devices, 1 account'],
            'correct': 0
        },
        {
            'question': 'What should you check before entering passwords on a website?',
            'options': ['The website color scheme', 'HTTPS and valid certificate', 'Number of ads', 'Website loading speed'],
            'correct': 1
        },
        {
            'question': 'What is a DDoS attack?',
            'options': ['Stealing data from a database', 'Overwhelming a service with traffic',
                        'Installing malware on devices', 'Intercepting network packets'],
            'correct': 1
        },
        {
            'question': 'What is social engineering?',
            'options': ['Building secure networks', 'Manipulating people to break security', 'Encrypting data', 'Writing secure code'],
            'correct': 1
        }
    ]

    @staticmethod
    def get_quiz(num_questions=10):
        selected = random.sample(QuizManager.QUESTIONS, min(num_questions, len(QuizManager.QUESTIONS)))
        return [{'id': i, **q} for i, q in enumerate(selected)]

    @staticmethod
    def grade(quiz_questions, answers):
        """
        quiz_questions: list of question dicts (the same ones shown to user)
        answers: dict mapping question id -> selected option index
        Returns: score (int), total (int), results list
        """
        score = 0
        results = []

        for q in quiz_questions:
            q_id = q['id']
            user_answer = answers.get(str(q_id), -1)
            correct = q['correct']
            is_correct = (user_answer == correct)
            if is_correct:
                score += 1
            results.append({
                'question': q['question'],
                'user_answer': q['options'][user_answer] if 0 <= user_answer < len(q['options']) else 'No answer',
                'correct_answer': q['options'][correct],
                'is_correct': is_correct
            })

        total = len(quiz_questions)
        return {
            'score': score,
            'total': total,
            'percentage': round((score / total) * 100) if total else 0,
            'results': results
        }
