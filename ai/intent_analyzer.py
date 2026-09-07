import re
import json
import time
import requests
from typing import Dict, Any, List, Optional


class DeceptionIntentAnalyzer:
    """Analyzes email text for psychological coercion, urgency, and wire fraud tactics."""

    URGENCY_PATTERNS = [
        r'\b(?:immediately|urgent|within\s+\d+\s+(?:hours?|minutes?|days?)|act\s+now|action\s+required|asap|time-sensitive)\b',
        r'\b(?:account\s+suspended|suspended\s+temporarily|permanent\s+deactivation|access\s+revoked)\b',
        r'\b(?:final\s+notice|last\s+warning|termination|legal\s+action|lawsuit|penalty|comparecencia|notificación\s+judicial)\b'
    ]

    BEC_PATTERNS = [
        r'\b(?:wire\s+transfer|fund\s+transfer|swift|direct\s+deposit|payroll\s+update|bank\s+details)\b',
        r'\b(?:confidential\s+matter|strictly\s+confidential|do\s+not\s+call|keep\s+this\s+private)\b',
        r'\b(?:ceo|cfo|chief\s+executive|managing\s+director|board\s+of\s+directors)\b',
        r'\b(?:vendor\s+payment|updated\s+invoice|remittance\s+advice|routing\s+number)\b'
    ]

    CREDENTIAL_PATTERNS = [
        r'\b(?:verify\s+your\s+account|confirm\s+password|reset\s+password|login\s+credentials)\b',
        r'\b(?:mfa\s+verification|2fa\s+code|security\s+update|validate\s+identity)\b',
        r'\b(?:office\s*365|microsoft\s*365|google\s*workspace|webmail\s*portal)\b'
    ]

    def __init__(self, lm_studio_url: str = "http://localhost:1234/v1"):
        self.lm_studio_url = lm_studio_url
        self._lm_studio_available = None
        self._last_check_time = 0

    def _check_lm_studio_alive(self) -> bool:
        now = time.time()
        if self._lm_studio_available is not None and (now - self._last_check_time) < 30:
            return self._lm_studio_available

        self._last_check_time = now
        try:
            resp = requests.get(f"{self.lm_studio_url}/models", timeout=0.4)
            self._lm_studio_available = (resp.status_code == 200)
        except Exception:
            self._lm_studio_available = False
        return self._lm_studio_available

    def analyze(self, subject: str, body_text: str) -> Dict[str, Any]:
        combined_text = f"{subject}\n{body_text}".strip()
        if not combined_text:
            return {
                "intent_score": 0,
                "threat_category": "BENIGN",
                "tactics_detected": [],
                "ai_summary": "Empty content evaluated as clean."
            }

        tactics = []
        score = 0

        # 1. Urgency & Coercion
        urgency_matches = []
        for pat in self.URGENCY_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            urgency_matches.extend(found)
        if urgency_matches:
            score += 40
            tactics.append({
                "tactic": "Psychological Urgency & Fear Coercion",
                "severity": "HIGH",
                "description": "Uses artificial time pressure to force hasty recipient action.",
                "evidence": list(set(urgency_matches))[:4]
            })

        # 2. BEC Wire Fraud
        bec_matches = []
        for pat in self.BEC_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            bec_matches.extend(found)
        if bec_matches:
            score += 45
            tactics.append({
                "tactic": "Executive Impersonation & Wire Transfer Fraud (BEC)",
                "severity": "CRITICAL",
                "description": "Requests urgent fund transfers under executive authority or secrecy.",
                "evidence": list(set(bec_matches))[:4]
            })

        # 3. Credential Harvesting
        cred_matches = []
        for pat in self.CREDENTIAL_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            cred_matches.extend(found)
        if cred_matches:
            score += 35
            tactics.append({
                "tactic": "Credential Harvesting Phishing",
                "severity": "HIGH",
                "description": "Directs recipient to re-authenticate or input account passwords.",
                "evidence": list(set(cred_matches))[:4]
            })

        final_score = min(score, 100)
        if final_score >= 70:
            category = "MALICIOUS SOCIAL ENGINEERING"
        elif final_score >= 35:
            category = "SUSPICIOUS DECEPTION"
        else:
            category = "BENIGN"

        summary = f"Detected {len(tactics)} psychological manipulation patterns indicating {category}."
        if not tactics:
            summary = "No coercion, credential harvesting, or wire fraud tactics detected."

        return {
            "intent_score": final_score,
            "threat_category": category,
            "tactics_detected": tactics,
            "ai_summary": summary
        }
