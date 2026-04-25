"""ThreatLens AI - Rule-Based Detection Engine. No paid APIs."""
import re
import random
from urllib.parse import urlparse


class PasswordAnalyzer:
    COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "letmein", "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
        "princess", "admin", "welcome", "shadow", "football", "password1", "123456789",
        "hello", "freedom", "whatever", "qazwsx", "654321", "harley", "hunter"}

    @staticmethod
    def analyze(password):
        if not password:
            return {"score": 0, "strength": "WEAK", "crack_time": "Instant",
                    "checks": ["No password provided"], "suggestions": ["Enter a password"]}
        score, checks, suggestions = 0, [], []
        length = len(password)
        if length >= 16:
            score += 40
            checks.append("Length 16+ characters")
        elif length >= 12:
            score += 30
            checks.append("Length 12+ characters")
        elif length >= 8:
            score += 20
            checks.append("Length 8+ characters")
        else:
            score += length * 2
            checks.append("Length only " + str(length))
            suggestions.append("Use at least 12 characters")
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^A-Za-z0-9]", password))
        if has_upper:
            score += 10
            checks.append("Uppercase letters (A-Z)")
        else:
            checks.append("No uppercase letters")
            suggestions.append("Add uppercase letters")
        if has_lower:
            score += 10
            checks.append("Lowercase letters (a-z)")
        else:
            checks.append("No lowercase letters")
            suggestions.append("Add lowercase letters")
        if has_digit:
            score += 10
            checks.append("Numbers (0-9)")
        else:
            checks.append("No numbers")
            suggestions.append("Add numbers")
        if has_special:
            score += 10
            checks.append("Special characters")
        else:
            checks.append("No special characters")
            suggestions.append("Add special characters (!@#$%)")
        repeats = len(re.findall(r"(.)\1{2,}", password))
        if repeats:
            score -= min(10, repeats * 5)
            checks.append(str(repeats) + " repeated sequences")
            suggestions.append("Avoid repeating characters")
        else:
            checks.append("No repeated sequences")
        pwd_lower = password.lower()
        if pwd_lower in PasswordAnalyzer.COMMON_PASSWORDS:
            score -= 20
            checks.append("Common weak password")
            suggestions.append("Avoid common passwords")
        else:
            checks.append("Not in common password list")
        common_words = ["password", "qwerty", "admin", "login", "welcome", "master"]
        if any(w in pwd_lower for w in common_words):
            score -= 10
            checks.append("Contains dictionary word")
            suggestions.append("Avoid dictionary words")
        else:
            checks.append("No common dictionary words")
        score = max(0, min(100, score))
        strength = "STRONG" if score >= 80 else "GOOD" if score >= 60 else "MEDIUM" if score >= 40 else "WEAK"
        crack = "Centuries" if score >= 80 else "Months to years" if score >= 60 else "Days to weeks" if score >= 40 else "Minutes to hours" if score >= 20 else "Instant"
        return {"score": score, "strength": strength, "crack_time": "Estimated crack time: " + crack,
                "checks": checks, "suggestions": suggestions if suggestions else ["Great password!"]}


class URLScanner:
    SUSPICIOUS_KEYWORDS = ["login", "signin", "verify", "verification", "confirm", "update",
        "secure", "account", "banking", "payment", "invoice", "free", "win", "winner",
        "prize", "gift", "bonus", "urgent", "alert", "suspend", "limited", "expire",
        "unlock", "validate", "authenticate", "credential", "password", "ssn", "refund"]

    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "short.link",
        "is.gd", "buff.ly", "adf.ly", "bitly.com", "shorturl.at"]

    @staticmethod
    def scan(url):
        if not url or not url.strip():
            return {"risk_level": "DANGEROUS", "risk_score": 100,
                    "reasons": ["No URL provided"], "tips": ["Enter a valid URL"]}
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full = url.lower()
        except Exception:
            return {"risk_level": "DANGEROUS", "risk_score": 100,
                    "reasons": ["Invalid URL format"], "tips": ["Check the URL and try again"]}
        risk, reasons, tips = 0, [], []
        if parsed.scheme != "https":
            risk += 20
            reasons.append("Uses HTTP instead of HTTPS (no encryption)")
            tips.append("Always prefer HTTPS websites")
        found_keywords = [kw for kw in URLScanner.SUSPICIOUS_KEYWORDS if kw in full]
        if found_keywords:
            risk += min(30, len(found_keywords) * 10)
            reasons.append("Suspicious keywords found: " + ", ".join(found_keywords[:3]))
            tips.append("Be cautious of URLs with urgency or financial terms")
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain.replace("www.", "")):
            risk += 25
            reasons.append("IP address used instead of domain name")
            tips.append("Legitimate sites use domain names, not raw IPs")
        if len(url) > 100:
            risk += 10
            reasons.append("Unusually long URL (" + str(len(url)) + " characters)")
            tips.append("Long URLs may hide malicious parameters")
        hyphen_count = domain.count("-")
        if hyphen_count >= 3:
            risk += 15
            reasons.append("Many hyphens in domain (" + str(hyphen_count) + ")")
            tips.append("Multiple hyphens are common in phishing domains")
        subdomain_count = domain.count(".") - 1
        if subdomain_count > 2:
            risk += 15
            reasons.append("Multiple subdomains (" + str(subdomain_count) + ")")
            tips.append("Excessive subdomains can be suspicious")
        core_domain = domain.replace("www.", "").split(".")[0]
        if len(core_domain) > 15 and len(set(core_domain)) / len(core_domain) > 0.7:
            risk += 20
            reasons.append("Random-looking domain name")
            tips.append("Random characters in domains are often temporary/phishing")
        if any(short in domain for short in URLScanner.SHORTENERS):
            risk += 20
            reasons.append("URL shortener detected")
            tips.append("Shortened URLs can hide malicious destinations")
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".click", ".link"]
        if any(full.endswith(tld) for tld in suspicious_tlds):
            risk += 10
            reasons.append("Suspicious top-level domain")
            tips.append("Some TLDs are frequently used for malicious sites")
        query = parsed.query.lower()
        param_count = len(query.split("&")) if query else 0
        if param_count > 5:
            risk += 10
            reasons.append("Many URL parameters (" + str(param_count) + ")")
            tips.append("Excessive parameters may be used for tracking or attacks")
        risk = min(100, risk)
        level = "SAFE" if risk <= 25 else "SUSPICIOUS" if risk <= 60 else "DANGEROUS"
        if not reasons:
            reasons.append("No significant risk indicators found")
            tips.append("Always verify the sender before clicking any link")
        return {"risk_level": level, "risk_score": risk, "reasons": reasons, "tips": tips}


class EmailAnalyzer:
    URGENCY_PATTERNS = ["act now", "urgent", "immediate", "hurry", "limited time",
        "expires soon", "verify now", "confirm now", "update now", "respond immediately",
        "action required", "time sensitive", "deadline", "final notice",
        "account will be suspended", "last chance", "do not ignore"]

    THREAT_PATTERNS = ["suspended", "terminated", "closed", "locked", "blocked",
        "unauthorized", "suspicious activity", "security alert",
        "breach detected", "compromised", "frozen", "penalty"]

    CREDENTIAL_PATTERNS = ["verify your password", "confirm your credentials",
        "update payment", "enter your ssn", "social security", "credit card",
        "bank account", "login to", "sign in to", "reset your password", "validate account"]

    REWARD_PATTERNS = ["you won", "congratulations", "selected as winner",
        "claim your prize", "free gift", "bonus", "cash reward", "lottery",
        "inheritance", "million dollars", "unexpected money", "click to claim"]

    @staticmethod
    def analyze(email_text):
        if not email_text or not email_text.strip():
            return {"risk_level": "LOW", "risk_score": 0, "risk_label": "No content provided",
                    "red_flags": [], "action": "Enter email content to analyze", "recommendations": []}
        text_lower = email_text.lower()
        risk, flags = 0, []
        urgency_hits = [p for p in EmailAnalyzer.URGENCY_PATTERNS if p in text_lower]
        if urgency_hits:
            risk += min(25, len(urgency_hits) * 8)
            flags.append("Urgency language: " + ", ".join(urgency_hits[:3]))
        threat_hits = [p for p in EmailAnalyzer.THREAT_PATTERNS if p in text_lower]
        if threat_hits:
            risk += min(25, len(threat_hits) * 8)
            flags.append("Threat language: " + ", ".join(threat_hits[:3]))
        cred_hits = [p for p in EmailAnalyzer.CREDENTIAL_PATTERNS if p in text_lower]
        if cred_hits:
            risk += 30
            flags.append("Requests sensitive credentials or personal data")
        reward_hits = [p for p in EmailAnalyzer.REWARD_PATTERNS if p in text_lower]
        if reward_hits:
            risk += 20
            flags.append("Too-good-to-be-true offers or fake rewards")
        link_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        links = re.findall(link_pattern, email_text, re.IGNORECASE)
        suspicious_links = []
        for link in links:
            link_lower = link.lower()
            if any(x in link_lower for x in ["bit.ly", "tinyurl", "click", "verify", "login", "update"]):
                suspicious_links.append(link[:50])
        if suspicious_links:
            risk += 15
            flags.append("Suspicious links detected")
        grammar_issues = 0
        grammar_patterns = [r'\b(dear\s+customer|dear\s+user|dear\s+valued)\b',
                            r'\b(kindly|urgently|immediately)\b']
        for pattern in grammar_patterns:
            if re.search(pattern, text_lower):
                grammar_issues += 1
        if grammar_issues >= 2:
            risk += 10
            flags.append("Unusual formatting or generic greetings")
        risk = min(100, risk)
        if risk >= 60:
            level, label = "HIGH", "High phishing risk detected"
            action = "Do not click any links. Delete the email and report it to your security team."
        elif risk >= 30:
            level, label = "MEDIUM", "Medium phishing risk - exercise caution"
            action = "Be cautious. Verify sender independently before taking any action."
        else:
            level, label = "LOW", "Low phishing risk"
            action = "Low risk detected, but always remain vigilant."
        recommendations = ["Never click links in unexpected emails",
            "Verify sender address carefully", "Hover over links to see true destination",
            "When in doubt, contact the organization directly"]
        if not flags:
            flags.append("No major phishing indicators found")
        return {"risk_level": level, "risk_score": risk, "risk_label": label,
                "red_flags": flags, "action": action, "recommendations": recommendations}


class KnowledgeBase:
    TOPICS = {
        "phishing": {
            "keywords": ["phishing", "phish", "fake email", "spoof email", "suspicious email"],
            "title": "Phishing Detection Guide",
            "response": """Phishing is a cyberattack where attackers impersonate trusted entities to steal credentials or data.

COMMON SIGNS:
- Urgent language ("Act now!", "Account suspended!")
- Generic greetings ("Dear Customer")
- Suspicious links that don't match the real domain
- Requests for passwords, SSN, or payment info
- Spelling errors and poor grammar
- Attachments you didn't expect

HOW TO PROTECT:
1. Verify sender email addresses carefully
2. Hover over links before clicking
3. Never enter credentials from email links
4. Use MFA on all accounts
5. Report phishing to your IT/security team

REMEMBER: Legitimate organizations never ask for passwords via email."""
        },
        "mfa": {
            "keywords": ["mfa", "2fa", "two factor", "multi factor", "authenticator", "otp"],
            "title": "Multi-Factor Authentication (MFA)",
            "response": """MFA adds an extra layer of security beyond passwords.

BENEFITS:
- Blocks 99.9% of automated attacks
- Protects even if your password is stolen
- Required for compliance in many industries

TYPES (best to least secure):
1. Hardware keys (YubiKey, Titan) — most secure
2. Authenticator apps (Authy, Google Authenticator)
3. SMS codes — better than nothing, but vulnerable to SIM swapping
4. Email codes — least secure

BEST PRACTICES:
- Enable MFA on email, banking, and work accounts
- Prefer app-based or hardware keys over SMS
- Keep backup codes in a secure location
- Use different MFA methods for critical accounts

FACT: Microsoft reports MFA blocks 99.9% of account compromise attacks."""
        },
        "ransomware": {
            "keywords": ["ransomware", "ransom", "encrypt", "locked files", "bitcoin payment"],
            "title": "Ransomware Explained",
            "response": """Ransomware is malware that encrypts your files and demands payment for decryption.

HOW IT SPREADS:
- Phishing emails with malicious attachments
- Exploiting unpatched software vulnerabilities
- Remote desktop protocol (RDP) attacks
- Malicious downloads and cracked software

PREVENTION:
1. Regular offline backups (3-2-1 rule)
2. Keep all software updated
3. Use reputable antivirus/EDR
4. Disable macros in Office documents
5. Network segmentation

IF INFECTED:
- Isolate the machine immediately
- Do NOT pay the ransom (no guarantee of recovery)
- Contact law enforcement and incident response
- Restore from clean backups
- Report to CISA at report@cisa.gov

NEVER PAY: Paying funds criminal organizations and marks you as a future target."""
        },
        "malware": {
            "keywords": ["malware", "virus", "trojan", "worm", "spyware", "adware"],
            "title": "Malware Overview",
            "response": """Malware is any software designed to harm or exploit systems.

COMMON TYPES:
- Virus: Self-replicates by attaching to files
- Worm: Spreads across networks automatically
- Trojan: Disguises itself as legitimate software
- Spyware: Steals data without your knowledge
- Ransomware: Encrypts files for ransom
- Adware: Displays unwanted advertisements

WARNING SIGNS:
- Slow computer performance
- Unexpected pop-ups
- Programs starting automatically
- Changed browser homepage
- Missing files or disk space
- Antivirus disabled

PROTECTION:
1. Keep OS and software updated
2. Use reputable antivirus (Windows Defender, Malwarebytes)
3. Don't download from untrusted sources
4. Avoid pirated software
5. Regular scans and monitoring

If you suspect infection: Disconnect from internet, boot into safe mode, run full scan."""
        },
        "password_hygiene": {
            "keywords": ["password", "passphrase", "password manager", "strong password"],
            "title": "Password Hygiene",
            "response": """Strong passwords are your first line of defense.

BEST PRACTICES:
- Use 16+ character passphrases (4+ random words)
- Mix uppercase, lowercase, numbers, symbols
- Unique password for every account
- Never reuse passwords across sites
- Change immediately after a breach

PASSWORD MANAGERS:
Recommended: Bitwarden (free), 1Password, KeePass
- Generates strong random passwords
- Stores them encrypted
- Auto-fills login forms
- Syncs across devices

AVOID:
- Dictionary words, names, dates
- Keyboard patterns (qwerty, 123456)
- Passwords under 12 characters
- Writing passwords on paper
- Sharing passwords via email/chat

EXAMPLE STRONG PASSPHRASE:
"Correct-Horse-Battery-Staple!47"
(Memorable, long, mixed characters)"""
        },
        "wifi": {
            "keywords": ["wifi", "wi-fi", "public wifi", "hotspot", "wireless", "open network"],
            "title": "Public Wi-Fi Safety",
            "response": """Public Wi-Fi networks are convenient but dangerous.

RISKS:
- Man-in-the-middle attacks
- Network sniffing and packet capture
- Fake hotspots (evil twin attacks)
- Unencrypted data transmission
- Session hijacking

STAY SAFE:
1. Use a VPN on all public networks
2. Avoid banking and shopping on public Wi-Fi
3. Verify network name with staff
4. Disable auto-connect to open networks
5. Use your phone's hotspot instead when possible
6. Ensure HTTPS on all sites
7. Turn off file sharing

VPN RECOMMENDATIONS:
ProtonVPN (free tier), Mullvad, Windscribe

RED FLAG: Networks named "Free_WiFi", "Starbucks_Guest", or similar generic names may be fake."""
        },
        "social_engineering": {
            "keywords": ["social engineering", "pretexting", "baiting", "tailgating"],
            "title": "Social Engineering",
            "response": """Social engineering manipulates people into breaking security procedures.

COMMON TACTICS:
- Phishing: Deceptive emails/messages
- Pretexting: Creating a false scenario
- Baiting: Leaving infected USB drives
- Quid pro quo: Offering help to get access
- Tailgating: Following someone into secure areas
- Vishing: Voice phishing over phone

RED FLAGS:
- Unsolicited contact claiming urgency
- Requests for confidential information
- Too-good-to-be-true offers
- Pressure to bypass procedures
- Unfamiliar contacts referencing internal info

DEFENSE:
1. Verify identity independently
2. Follow verification procedures
3. Never share credentials
4. Report suspicious contacts
5. Security awareness training

REMEMBER: Technology can't fix human trust. Awareness is your best defense."""
        },
        "ddos": {
            "keywords": ["ddos", "dos", "flood", "denial of service", "traffic flood"],
            "title": "DDoS Attacks",
            "response": """DDoS (Distributed Denial of Service) floods a target with traffic to make it unavailable.

TYPES:
- Volumetric: Overwhelms bandwidth (UDP floods)
- Protocol: Exploits server resources (SYN floods)
- Application: Targets web apps (HTTP floods)

IMPACT:
- Website/service downtime
- Revenue loss
- Reputation damage
- Distraction for other attacks

PROTECTION:
1. DDoS mitigation services (Cloudflare, AWS Shield)
2. Rate limiting on servers
3. CDN for traffic distribution
4. Network monitoring and alerting
5. Incident response plan
6. Auto-scaling infrastructure

FOR HOME USERS:
- Restart your router if targeted
- Contact your ISP
- Use gaming VPNs with DDoS protection
- Don't share your IP address publicly

NOTE: Launching DDoS attacks is illegal under the Computer Fraud and Abuse Act."""
        },
        "data_breach": {
            "keywords": ["data breach", "breach", "leaked data", "compromised"],
            "title": "Data Breach Response",
            "response": """A data breach is when sensitive information is accessed without authorization.

IMMEDIATE STEPS:
1. Confirm the breach (check haveibeenpwned.com)
2. Change passwords on affected accounts
3. Enable MFA everywhere
4. Check for unauthorized activity
5. Monitor bank/credit statements
6. Place fraud alert if financial data exposed

IF YOUR DATA IS BREACHED:
- Assume the data is permanent on the dark web
- Never reuse the compromised password
- Watch for phishing using breached data
- Consider credit monitoring
- Report identity theft if applicable

PREVENTION:
- Use unique passwords (password manager)
- Enable MFA on all accounts
- Monitor breach notifications
- Regular security audits
- Minimal data sharing

LEGAL: In many jurisdictions, companies must notify you of breaches within 72 hours."""
        },
        "safe_browsing": {
            "keywords": ["safe browsing", "browser security", "https", "privacy", "cookies"],
            "title": "Safe Browsing Tips",
            "response": """Safe browsing habits protect you from online threats.

ESSENTIAL PRACTICES:
1. Look for HTTPS and padlock icon
2. Keep browser updated
3. Use privacy-focused browsers (Firefox, Brave)
4. Install uBlock Origin for ad blocking
5. Disable unnecessary browser extensions
6. Clear cookies and cache regularly
7. Use private/incognito mode for sensitive searches

PRIVACY TOOLS:
- Privacy Badger (blocks trackers)
- HTTPS Everywhere (forces encryption)
- DuckDuckGo (private search)
- ProtonMail (encrypted email)

DANGEROUS HABITS:
- Downloading pirated software
- Clicking "Allow" on notifications
- Ignoring security warnings
- Using outdated browsers
- Saving passwords in browser (use manager instead)

RED FLAGS:
- Browser warnings about unsafe sites
- Pop-ups saying you have a virus
- Requests to install unknown extensions
- Sites with excessive ads or redirects

Remember: If something feels wrong, trust your instincts and leave the site."""
        },
        "encryption": {
            "keywords": ["encryption", "encrypt", "tls", "ssl", "cipher", "end to end"],
            "title": "Encryption Basics",
            "response": """Encryption scrambles data so only authorized parties can read it.

TYPES:
- At rest: Data stored on disk (BitLocker, FileVault)
- In transit: Data moving over network (TLS/HTTPS)
- End-to-end: Only sender and receiver can read (Signal, WhatsApp)

HOW IT WORKS:
- Plain text + Encryption algorithm + key = Ciphertext
- Ciphertext + Decryption key = Plain text
- Without the key, data is unreadable

EVERYDAY ENCRYPTION:
- HTTPS websites (TLS)
- Messaging apps (Signal protocol)
- Password managers (AES-256)
- VPN tunnels (WireGuard, OpenVPN)
- Full disk encryption

WHY IT MATTERS:
- Protects data from interception
- Required for compliance (GDPR, HIPAA)
- Prevents unauthorized access
- Secures backups and archives

BACKDOOR WARNING: Governments sometimes request encryption backdoors, but these weaken security for everyone."""
        },
        "firewall": {
            "keywords": ["firewall", "network security", "ports", "iptables", "ufw"],
            "title": "Firewall Guide",
            "response": """A firewall monitors and controls network traffic based on security rules.

TYPES:
- Hardware: Physical devices (Cisco ASA, pfSense)
- Software: Programs on computers (Windows Defender Firewall)
- Cloud: AWS Security Groups, Azure NSGs
- Host-based: Runs on individual servers

HOW IT WORKS:
- Inspects packets entering/leaving network
- Allows or blocks based on rules
- Can filter by IP, port, protocol, application
- Stateful: Tracks connection state

BEST PRACTICES:
1. Default deny: Block everything, allow only needed
2. Minimize open ports
3. Keep rules simple and documented
4. Regular audits and logging
5. Layer with IDS/IPS

COMMON PORTS:
- 22: SSH (secure remote access)
- 80: HTTP (insecure web)
- 443: HTTPS (secure web)
- 3389: RDP (remote desktop)

WARNING: Don't disable your firewall. Even home routers have basic protection."""
        },
        "incident_response": {
            "keywords": ["incident response", "security incident", "breach response", "soc"],
            "title": "Incident Response",
            "response": """Incident response is the organized approach to addressing security breaches.

NIST PHASES:
1. PREPARATION: Plan, train, tools ready
2. DETECTION & ANALYSIS: Identify and assess
3. CONTAINMENT: Stop the spread
4. ERADICATION: Remove threat
5. RECOVERY: Restore systems
6. POST-INCIDENT: Lessons learned

FIRST 24 HOURS:
- Isolate affected systems
- Preserve evidence
- Notify stakeholders
- Engage incident response team
- Document everything
- Assess scope and impact

KEY ROLES:
- Incident Commander: Overall coordination
- Technical Lead: Forensics and analysis
- Communications: External messaging
- Legal: Compliance and liability

CONTACTS TO HAVE READY:
- Legal counsel
- Cyber insurance provider
- Law enforcement (FBI IC3)
- Forensics firm
- Public relations

PREPARATION IS KEY: The best incident response starts before the incident."""
        }
    }

    FALLBACK_RESPONSE = {
        "title": "Cybersecurity Assistant",
        "response": """I do not have a direct module for that yet, but here are general cybersecurity best practices:

FUNDAMENTALS:
- Use strong, unique passwords for every account
- Enable multi-factor authentication everywhere
- Keep software and operating systems updated
- Use a password manager
- Back up important data regularly

PHISHING DEFENSE:
- Don't click links in unexpected emails
- Verify sender addresses
- Hover to see true link destinations
- Report suspicious emails

BROWSING SAFETY:
- Look for HTTPS on all sites
- Use ad blockers and privacy tools
- Avoid public Wi-Fi without VPN
- Don't download from untrusted sources

DEVICE SECURITY:
- Use screen locks and encryption
- Install updates promptly
- Use reputable antivirus
- Be cautious with app permissions

Want specific information? Try asking about:
phishing, MFA, ransomware, malware, passwords,
Wi-Fi safety, social engineering, DDoS, data breaches, or safe browsing."""
    }

    @staticmethod
    def ask(query):
        if not query:
            return KnowledgeBase.FALLBACK_RESPONSE
        query_lower = query.lower()
        words = set(query_lower.split())
        best_topic, best_score = None, 0
        for topic_id, topic_data in KnowledgeBase.TOPICS.items():
            score = 0
            for keyword in topic_data["keywords"]:
                if keyword in query_lower:
                    score += len(keyword)
            topic_words = set(" ".join(topic_data["keywords"]).split())
            score += len(words & topic_words) * 5
            if score > best_score:
                best_score = score
                best_topic = topic_id
        if best_topic and best_score >= 5:
            return {"title": KnowledgeBase.TOPICS[best_topic]["title"],
                    "response": KnowledgeBase.TOPICS[best_topic]["response"]}
        return KnowledgeBase.FALLBACK_RESPONSE


class QuizManager:
    QUESTION_BANK = [
        {"id": 1, "question": "What does MFA stand for?",
         "options": ["Multi-Factor Authentication", "Main Frame Access", "Managed File Access", "Multi-Function Application"],
         "correct": 0},
        {"id": 2, "question": "Which is the strongest password?",
         "options": ["Password123", "P@ssw0rd", "Tr0ub4dor&3", "correct-horse-battery-staple!47"],
         "correct": 3},
        {"id": 3, "question": "What is phishing?",
         "options": ["A type of firewall", "A social engineering attack via email", "A network protocol", "An encryption method"],
         "correct": 1},
        {"id": 4, "question": "Which protocol encrypts data in transit on websites?",
         "options": ["HTTP", "FTP", "HTTPS", "SMTP"],
         "correct": 2},
        {"id": 5, "question": "What should you do if you suspect a ransomware infection?",
         "options": ["Pay the ransom immediately", "Isolate the machine and do not pay", "Ignore it and continue working", "Reboot the computer"],
         "correct": 1},
        {"id": 6, "question": "What is the purpose of a firewall?",
         "options": ["Speed up internet", "Monitor and control network traffic", "Store passwords", "Create backups"],
         "correct": 1},
        {"id": 7, "question": "Which of these is a sign of a phishing email?",
         "options": ["Proper spelling and grammar", "Known sender address", "Urgent action required", "HTTPS links only"],
         "correct": 2},
        {"id": 8, "question": "What does DDoS stand for?",
         "options": ["Data Delivery over Secure Socket", "Distributed Denial of Service", "Digital Defense on Systems", "Direct Download of Software"],
         "correct": 1},
        {"id": 9, "question": "Why should you avoid public Wi-Fi for banking?",
         "options": ["It is too slow", "It may be unencrypted and insecure", "Banks block public Wi-Fi", "It uses too much battery"],
         "correct": 1},
        {"id": 10, "question": "What is social engineering?",
         "options": ["Building secure networks", "Manipulating people to break security", "Encrypting social media", "Hacking with software tools"],
         "correct": 1},
        {"id": 11, "question": "Which is the most secure MFA method?",
         "options": ["SMS text message", "Email code", "Authenticator app", "Hardware security key"],
         "correct": 3},
        {"id": 12, "question": "What should you do after a data breach?",
         "options": ["Nothing, breaches are harmless", "Change passwords and enable MFA", "Delete your accounts", "Tell friends to do the same"],
         "correct": 1},
        {"id": 13, "question": "What is a VPN used for?",
         "options": ["Speed up downloads", "Encrypt internet traffic", "Store files", "Create passwords"],
         "correct": 1},
        {"id": 14, "question": "Which is NOT a type of malware?",
         "options": ["Virus", "Firewall", "Trojan", "Ransomware"],
         "correct": 1},
        {"id": 15, "question": "What does HTTPS protect against?",
         "options": ["Slow loading", "Man-in-the-middle attacks", "Pop-up ads", "Cookies"],
         "correct": 1}
    ]

    @staticmethod
    def get_quiz(num_questions=10):
        questions = QuizManager.QUESTION_BANK.copy()
        random.shuffle(questions)
        selected = questions[:num_questions]
        for i, q in enumerate(selected):
            q = q.copy()
            q["id"] = i
            selected[i] = q
        return selected

    @staticmethod
    def grade(questions, answers):
        correct = 0
        results = []
        for q in questions:
            q_id = str(q["id"])
            user_ans_idx = answers.get(q_id, -1)
            correct_ans_idx = q["correct"]
            user_answer = q["options"][user_ans_idx] if 0 <= user_ans_idx < len(q["options"]) else "No answer"
            correct_answer = q["options"][correct_ans_idx]
            is_correct = (user_ans_idx == correct_ans_idx)
            if is_correct:
                correct += 1
            results.append({
                "question": q["question"],
                "user_answer": user_answer,
                "correct_answer": correct_answer,
                "is_correct": is_correct
            })
        total = len(questions)
        percentage = round((correct / total) * 100) if total > 0 else 0
        return {
            "score": correct,
            "total": total,
            "percentage": percentage,
            "results": results
        }
