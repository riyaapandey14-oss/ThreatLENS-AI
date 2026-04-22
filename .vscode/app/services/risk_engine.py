class RiskEngine:
    @staticmethod
    def calculate_overall_risk(password_data, url_data, ai_data):
        # Weighted scoring: Password 40%, URL 40%, AI 20%
        password_risk = 100 - password_data.get('score', 0)  # Invert strength to risk
        url_risk = url_data.get('risk_score', 50)
        ai_risk = ai_data.get('risk_score', 50) if ai_data.get('risk_score') else 0
        
        overall_risk = (
            password_risk * 0.4 +
            url_risk * 0.4 +
            ai_risk * 0.2
        )
        
        threat_level = {
            (0, 30): 'Low Risk 🟢',
            (31, 60): 'Medium Risk 🟡', 
            (61, 85): 'High Risk 🟠',
            (86, 100): 'Critical Risk 🔴'
        }
        
        level = next(level for (low, high), level in threat_level.items() if low <= overall_risk <= high)
        
        return {
            'overall_risk': round(overall_risk, 1),
            'threat_level': level,
            'breakdown': {
                'password': round(password_risk, 1),
                'url': round(url_risk, 1),
                'ai': round(ai_risk, 1)
            }
        }
