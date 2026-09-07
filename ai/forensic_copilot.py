import re
import json
import requests
from typing import Dict, Any, List, Optional


class AIForensicCopilot:
    """Conversational AI Assistant. Explains scan findings and guides response."""

    def __init__(self, lm_studio_url: str = "http://localhost:1234/v1"):
        self.lm_studio_url = lm_studio_url

    def _check_lm_studio_alive(self) -> bool:
        try:
            resp = requests.get(f"{self.lm_studio_url}/models", timeout=0.4)
            return resp.status_code == 200
        except Exception:
            return False

    def generate_initial_greeting(self, case_data: Dict[str, Any]) -> str:
        headers = case_data.get("headers", {})
        threat = case_data.get("threat_summary", {})
        diag = threat.get("diagnostics", {})
        flagged = threat.get("flagged_engines_count", 0)
        total = threat.get("total_engines_count", 7)
        origin_geo = case_data.get("origin_geo", {})

        subject = headers.get("subject", "(No Subject)")
        from_raw = headers.get("from_raw", "Unknown")
        verdict = threat.get("threat_verdict", "UNKNOWN")
        root_cause = diag.get("root_cause", "Analysis completed.")

        return (
            f"👋 **Hello! I am your TRACEON Cyber Copilot.**\n\n"
            f"📊 **Scan Verdict:** `{verdict}` ({flagged}/{total} engines triggered)\n"
            f"🔍 **Subject:** *\"{subject}\"*\n"
            f"👤 **Claimed Sender:** `{from_raw}`\n"
            f"🌐 **Origin Server:** `{origin_geo.get('country', 'N/A')} ({origin_geo.get('city', 'N/A')})` via `{origin_geo.get('isp', 'N/A')}`\n\n"
            f"💡 **Executive Summary:** {root_cause}\n\n"
            f"Ask me anything about this email! For example:\n"
            f"• *\"Why was this flagged?\"*\n"
            f"• *\"Is it safe to open the attachment?\"*\n"
            f"• *\"Does the sender match Amazon/PayPal?\"*\n"
            f"• *\"Draft a warning email for my team.\"*"
        )

    def answer_query(
        self,
        case_data: Dict[str, Any],
        user_query: str,
        chat_history: Optional[List[Dict[str, str]]] = None
    ) -> str:
        if not user_query.strip():
            return "Please enter a question regarding the forensic scan."

        headers = case_data.get("headers", {})
        threat = case_data.get("threat_summary", {})
        diag = threat.get("diagnostics", {})
        auth = case_data.get("authentication", {})
        homoglyph = case_data.get("homoglyph", {})
        attachments = case_data.get("attachments", [])
        origin_geo = case_data.get("origin_geo", {})
        flagged = threat.get("flagged_engines_count", 0)

        # 1. Try Live Local LLM
        if self._check_lm_studio_alive():
            try:
                system_prompt = (
                    "You are TRACEON Cyber Copilot, an elite SOC Analyst and Digital Email Forensics Expert. "
                    "Explain email security threats clearly and concisely using markdown.\n\n"
                    f"CONTEXT:\n"
                    f"- Subject: {headers.get('subject')}\n"
                    f"- From: {headers.get('from_raw')}\n"
                    f"- Verdict: {threat.get('threat_verdict')} ({flagged}/7 engines)\n"
                    f"- Root Cause: {diag.get('root_cause')}\n"
                    f"- Findings: {json.dumps(diag.get('what_is_wrong', []))}\n"
                    f"- Origin: {origin_geo.get('country')} ({origin_geo.get('city')}), ISP: {origin_geo.get('isp')}\n"
                    f"- Auth: SPF={auth.get('spf', {}).get('status')}, DKIM={auth.get('dkim', {}).get('status')}, DMARC={auth.get('dmarc', {}).get('status')}\n"
                )

                messages = [{"role": "system", "content": system_prompt}]
                if chat_history:
                    for ch in chat_history[-3:]:
                        messages.append({"role": ch.get("role", "user"), "content": ch.get("content", "")})
                messages.append({"role": "user", "content": user_query})

                resp = requests.post(
                    f"{self.lm_studio_url}/chat/completions",
                    json={"messages": messages, "temperature": 0.3, "max_tokens": 400},
                    timeout=8
                )
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"].strip()
            except Exception:
                pass

        # 2. Smart Contextual Heuristics (Offline Mode)
        q_lower = user_query.lower()

        if any(w in q_lower for w in ["why", "flagged", "reason", "wrong", "dangerous", "threat"]):
            findings = diag.get("what_is_wrong", [])
            resp = f"**Here is why this email was flagged ({flagged}/7 engines):**\n\n"
            resp += f"🔍 **Primary Diagnosis:** {diag.get('root_cause')}\n\n"
            if findings:
                resp += "**Key Forensic Indicators:**\n"
                for f in findings:
                    resp += f"• {re.sub(r'<[^>]+>', '', f)}\n"
            return resp

        if any(w in q_lower for w in ["safe", "click", "open", "attachment", "download", "link"]):
            if flagged > 0:
                return (
                    "🛑 **NO, it is NOT safe.**\n\n"
                    "• Do **not** click any links or scan QR codes.\n"
                    "• Do **not** download or preview attached files.\n"
                    f"• Email originates from unverified infrastructure (`{origin_geo.get('isp', 'Unknown ISP')}`)."
                )
            else:
                return "✅ **Yes.** All 7 engines verified this email as authentic with valid cryptographic signatures."

        if any(w in q_lower for w in ["amazon", "paypal", "microsoft", "apple", "google", "brand", "real", "fake", "sender"]):
            from_domain = headers.get("from_domain", "")
            if homoglyph.get("is_spoof"):
                brand = homoglyph.get("targeted_brand", "target brand")
                return (
                    f"⚠️ **Brand Impersonation (Homoglyph Attack).**\n\n"
                    f"Sender domain `\"{from_domain}\"` looks like **{brand}**, but uses non-Latin Unicode.\n"
                    f"• Real registered domain is: `{homoglyph.get('punycode')}`.\n"
                    f"• Email was NOT sent by {brand}."
                )
            elif any(s in from_domain for s in ["libero.it", "gmail.com", "yahoo.com"]):
                return (
                    f"⚠️ **Sender Mismatch Detected.**\n\n"
                    f"The email claims an official role, but was sent from a consumer webmail (`{headers.get('from_raw')}`). "
                    f"Legitimate organizations send from their own verified domains."
                )
            else:
                return (
                    f"🔍 **Sender Verification:** Sent from `{headers.get('from_address')}` via `{origin_geo.get('isp', 'ISP')}`. "
                    f"SPF: `{auth.get('spf', {}).get('status', 'NONE')}`, DKIM: `{auth.get('dkim', {}).get('status', 'NONE')}`."
                )

        if any(w in q_lower for w in ["draft", "warning", "email", "report", "team"]):
            return (
                f"📝 **Draft Security Notice for Team:**\n\n"
                f"---\n"
                f"**Subject:** [SECURITY WARNING] Suspicious Email - \"{headers.get('subject')}\"\n\n"
                f"**Team Notice:**\n"
                f"A suspicious email with subject *\"{headers.get('subject')}\"* sent from `{headers.get('from_raw')}` was flagged by TRACEON.\n\n"
                f"**Details:** {diag.get('root_cause')}\n\n"
                f"**Actions:**\n"
                f"1. Do NOT click any links, scan QR codes, or open attachments.\n"
                f"2. Delete the email immediately.\n"
                f"---\n"
            )

        return (
            f"**Forensic Assessment for Case:**\n\n"
            f"• **Risk Verdict:** `{threat.get('threat_verdict')}`\n"
            f"• **Origin Server:** `{origin_geo.get('country', 'N/A')}` ({origin_geo.get('isp', 'N/A')})\n"
            f"• **Action Required:** {diag.get('user_actions', ['Exercise caution.'])[0]}\n\n"
            f"Ask me to explain specific headers, check if links are safe, or draft a warning report!"
        )
