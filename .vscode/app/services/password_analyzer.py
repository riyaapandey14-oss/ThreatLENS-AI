import re

class PasswordAnalyzer:
    @staticmethod
    def analyze(password):
        if not password:
            return {
                'strength': 'WEAK',
                'score': 0,
                'reason': 'No password provided',
                'suggestion': 'Enter a password to analyze'
            }
        
        checks = {
            'Length': len(password) >= 8,
            'Uppercase': bool(re.search(r'[A-Z]', password)),
            'Lowercase': bool(re.search(r'[a-z]', password)),
            'Numbers': bool(re.search(r'\\d', password)),
            'Symbols': bool(re.search(r'[^a-zA-Z0-9\\s]', password))
        }
        
        score = sum(checks.values())
        
        if score <= 2:
            strength = 'WEAK'
        elif score <= 4:
            strength = 'MEDIUM'
        else:
            strength = 'STRONG'
        
        reasons = [f"{name}: {'PASS' if passed else 'FAIL'}" for name, passed in checks.items()]
        
        suggestions = []
        if not checks['Length']:
            suggestions.append('Use 8+ characters')
        if not checks['Uppercase']:
            suggestions.append('Add uppercase letters (A-Z)')
        if not checks['Lowercase']:
            suggestions.append('Add lowercase letters (a-z)')
        if not checks['Numbers']:
            suggestions.append('Add numbers (0-9)')
        if not checks['Symbols']:
            suggestions.append('Add special chars (!@#$%)')
        
        suggestion = '; '.join(suggestions) or 'Perfect password!'
        
        # Template compatibility
        return {
            'strength': strength,
            'score': score,
            'reason': '; '.join(reasons),
            'suggestion': suggestion,
            'details': reasons  # For template
            # Drop zxcvbn for simple logic
        }
