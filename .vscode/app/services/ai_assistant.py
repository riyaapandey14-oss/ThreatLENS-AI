from huggingface_hub import InferenceClient
from .threat_intelligence import SOCAnalystAI
import logging

logger = logging.getLogger(__name__)

class FreeAIAnalyst:
    def __init__(self):
        try:
            self.hf_client = InferenceClient(
                model="mistralai/Mistral-7B-Instruct-v0.1",
            )
            self.hf_available = True
            print("[FREE AI] Hugging Face client ready!")
        except:
            self.hf_available = False
            print("[FREE AI] HF not available, rules only")
        self.rule_fallback = SOCAnalystAI()

    def analyze(self, query, context=None):
        if self.hf_available:
            try:
                system_prompt = """You are ThreatLens AI cybersecurity expert.

Provide concise analysis + risk + actions.

Examples:
- Phishing: Indicators + prevention
- Password: Entropy + best practices
- URL: Risk level + verification steps"""
                
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": query}
                ]
                
                if context:
                    messages.append({"role": "user", "content": f"Context: {context}"})
                
                response = self.hf_client.chat_completion(
                    messages=messages,
                    max_tokens=300,
                    temperature=0.1,
                    stream=False
                )
                
                content = response.choices[0].message.content.strip()
                return {
                    'analyst_response': content,
                    'risk_score': 50,
                    'source': 'HF_FREE'
                }
            except Exception as e:
                logger.warning(f"HF failed: {e}")
        
        # Always available rule fallback
        rule_resp = self.rule_fallback.analyze(query)
        rule_resp['analyst_response'] += "\n\n🔧 Free AI active (HF rate limit fallback)"
        rule_resp['source'] = 'RULE_BASED_FREE'
        return rule_resp

AIAnalyst = FreeAIAnalyst()
