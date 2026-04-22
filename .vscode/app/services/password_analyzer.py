import re
import math
import time

class PasswordAnalyzer:
    @staticmethod
    def analyze(password):
        if not password:
            return {'score': 0, 'strength': 'empty', 'crack_time': 'instant', 'details': []}
        
        length_score = min(len(password) // 4, 25)
        upper_score = 10 if re.search(r'[A-Z]', password) else 0
        lower_score = 10 if re.search(r'[a-z]', password) else 0
        digit_score = 10 if re.search(r'\\d', password) else 0
        symbol_score = 20 if re.search(r'[^a-zA-Z0-9]', password) else 0
        unique_chars = len(set(password))
        repeat_penalty = max(0, 40 - unique_chars * 2)
        
        total_score = length_score + upper_score + lower_score + digit_score + symbol_score - repeat_penalty
        total_score = max(0, min(100, total_score))
        
        # Crack time estimation (simplified)
        entropy = unique_chars * math.log2(len(set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*')))
        crack_time = math.exp(entropy / 32) / 10**9  # Simplified
        
        strength_map = {
            (0, 39): 'Very Weak', (40, 59): 'Weak', (60, 79): 'Fair', 
            (80, 94): 'Good', (95, 100): 'Excellent'
        }
        
        strength = next(label for (low, high), label in strength_map.items() if low <= total_score <= high)
        crack_str = f'{int(crack_time/3600/24/365):,} years' if crack_time > 1 else f'{int(crack_time*3600):,} seconds'
        
        details = [
            f'Length: {len(password)} ({length_score}pts)',
            f'Uppercase: {"Yes" if upper_score else "No"}',
            f'Lowercase: {"Yes" if lower_score else "No"}',
            f'Digits: {"Yes" if digit_score else "No"}',
            f'Symbols: {"Yes" if symbol_score else "No"}',
            f'Repeated chars: {len(password) - unique_chars}'
        ]
        
        return {
            'score': total_score,
            'strength': strength,
            'crack_time': crack_str,
            'details': details
        }
