import re
import json
import time
import requests
from typing import Dict, Any, List, Optional


class DeceptionIntentAnalyzer:
    """Analyzes email text for psychological coercion, urgency, and wire fraud tactics."""

    URGENCY_PATTERNS = [
        r'\b(?:immediately|act\s+now|urgent\s+action\s+required|within\s+\d+\s+(?:hours?|minutes?))\b',
        r'\b(?:account\s+will\s+be\s+(?:suspended|terminated|deactivated)|access\s+will\s+be\s+revoked)\b',
        r'\b(?:final\s+notice|last\s+warning|legal\s+proceedings|pending\s+lawsuit|immediate\s+penalty)\b'
    ]

    BEC_PATTERNS = [
        r'\b(?:wire\s+transfer|send\s+funds|swift\s+transfer|direct\s+wire|update\s+direct\s+deposit|new\s+banking\s+details)\b',
        r'\b(?:keep\s+this\s+strictly\s+confidential|do\s+not\s+discuss\s+with\s+anyone|confidential\s+acquisition)\b',
        r'\b(?:process\s+payment\s+asap|urgent\s+remittance|vendor\s+bank\s+account\s+change)\b'
    ]

    CREDENTIAL_PATTERNS = [
        r'\b(?:verify\s+your\s+password|confirm\s+your\s+credentials|login\s+to\s+verify\s+identity|re-enter\s+your\s+password)\b',
        r'\b(?:submit\s+mfa\s+code|enter\s+2fa\s+pin|unauthorized\s+login\s+detected\s+click\s+here)\b',
        r'\b(?:validate\s+account\s+security|unlock\s+your\s+suspended\s+account\s+now)\b'
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
            score += 35
            tactics.append({
                "tactic": "Psychological Urgency & Pressure",
                "severity": "MEDIUM",
                "description": "Uses artificial time pressure to prompt quick action.",
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
                "tactic": "Executive Impersonation & Wire Fraud (BEC)",
                "severity": "CRITICAL",
                "description": "Requests unauthorized funds transfer or secrecy.",
                "evidence": list(set(bec_matches))[:4]
            })

        # 3. Credential Harvesting
        cred_matches = []
        for pat in self.CREDENTIAL_PATTERNS:
            found = re.findall(pat, combined_text, re.IGNORECASE)
            cred_matches.extend(found)
        if cred_matches:
            score += 45
            tactics.append({
                "tactic": "Credential Harvesting Phishing",
                "severity": "HIGH",
                "description": "Directs recipient to input passwords or MFA codes.",
                "evidence": list(set(cred_matches))[:4]
            })

        # Cap score at 100
        score = min(score, 100)

        # Classification
        if score >= 70:
            category = "MALICIOUS"
        elif score >= 45:
            category = "SUSPICIOUS"
        else:
            category = "BENIGN"

        summary = f"Detected {len(tactics)} psychological deception cues." if tactics else "No social engineering or wire fraud tactics detected."

        return {
            "intent_score": score,
            "threat_category": category,
            "tactics_detected": tactics,
            "ai_summary": summary
        }
