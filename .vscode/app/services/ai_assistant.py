import os
import re
from .threat_intelligence import SOCAnalystAI
import logging

logger = logging.getLogger(__name__)

class GrokAIAnalyst:
    def __init__(self):
        self.grok_key = os.environ.get('GROK_API_KEY')
        self.grok_available = bool(self.grok_key and len(self.grok_key) > 10)
        self.client = None
        if self.grok_available:
            try:
                # Note: xAI requires credits to use Grok API
                # For now, we'll use rule-based fallback
                print('[Grok AI] Credits required - using rule-based analysis')
                self.grok_available = False
            except Exception as e:
                logger.warning(f'Grok init failed: {e}')
                self.grok_available = False
        self.rule_fallback = SOCAnalystAI()

    def analyze(self, query, context=None):
        # For now, always use rule-based analysis until credits are purchased
        rule_resp = self.rule_fallback.analyze(query)
        rule_resp['analyst_response'] += '\n\nGrok AI integration ready (purchase credits at https://console.x.ai)'
        rule_resp['source'] = 'RULES'
        return rule_resp
        return rule_resp

AIAnalyst = GrokAIAnalyst()