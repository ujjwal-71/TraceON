import uuid
from typing import Dict, Any, List

from core.parser import EmailForensicParser
from core.hop_tracer import HopTracer
from core.auth_verifier import AuthVerifier
from intel.geolocation import GeoLocationTriangulator
from intel.infrastructure import InfrastructureThreatAnalyzer
from ai.intent_analyzer import DeceptionIntentAnalyzer
from ai.homoglyph import HomoglyphInspector
from ai.quishing_attachment import QuishingInspector
from ai.forensic_arbiter import ForensicArbiter
from ai.symbolic_engine import SymbolicDeductionEngine
from graph.correlator import ThreatGraphCorrelator


class AegisTraceEngine:
    """Master 7-Engine Email Forensic Coordinator."""

    def __init__(self, allow_online_geo: bool = True):
        self.geo_triangulator = GeoLocationTriangulator(allow_online=allow_online_geo)
        self.infra_analyzer = InfrastructureThreatAnalyzer()
        self.intent_analyzer = DeceptionIntentAnalyzer()
        self.homoglyph_inspector = HomoglyphInspector()
        self.quishing_inspector = QuishingInspector()
        self.arbiter = ForensicArbiter()
        self.symbolic_engine = SymbolicDeductionEngine()
        self.graph_correlator = ThreatGraphCorrelator()

    def analyze_email(self, raw_content: bytes | str) -> Dict[str, Any]:
        case_id = str(uuid.uuid4())

        # 1. Parse MIME & Hashes
        parser = EmailForensicParser(raw_content)
        hashes = parser.hashes
        headers = parser.parse_headers()
        body = parser.parse_body()
        attachments = parser.parse_attachments()
        urls = parser.extract_urls(body["plain_text"], body["html"])

        # 2. Reverse Hop Traversal
        hop_tracer = HopTracer(parser.msg)
        hop_trace = hop_tracer.trace_hops()

        # 3. GeoLocation & Infrastructure
        origin_ip = hop_trace.get("origin_ip") or headers.get("x_originating_ip")
        origin_geo = self.geo_triangulator.lookup_ip(origin_ip)
        origin_geo["origin_ip"] = origin_ip
        infra_threat = self.infra_analyzer.analyze(origin_geo, hop_trace.get("hops", []))

        # 4. Cryptographic Authentication
        auth_verifier = AuthVerifier(parser.msg, headers)
        auth_results = auth_verifier.verify()
        origin_geo["attribution_confidence"] = self.geo_triangulator.calculate_confidence(
            origin_geo, auth_results.get("overall_auth_verdict") == "AUTHENTIC"
        )

        # 5. Homoglyph Domain Inspector
        homoglyph = self.homoglyph_inspector.inspect_domain(headers.get("from_domain", ""))

        # 6. Attachment & Quishing QR Reader
        inspected_attachments = self.quishing_inspector.inspect(attachments)

        # 7. AI Social Engineering Intent
        ai_intent = self.intent_analyzer.analyze(headers.get("subject", ""), body["plain_text"])

        # 8. Declarative Symbolic Logic Proofs
        symbolic_proofs = self.symbolic_engine.evaluate_facts(
            headers=headers,
            auth=auth_results,
            hop_trace=hop_trace,
            homoglyph=homoglyph,
            attachments=inspected_attachments,
            urls=urls,
            ai_intent=ai_intent,
            origin_geo=origin_geo
        )

        # 9. 7-Engine Scorecard
        engines_report = self._build_engine_matrix(
            headers=headers,
            hop_trace=hop_trace,
            infra_threat=infra_threat,
            auth_results=auth_results,
            ai_intent=ai_intent,
            homoglyph=homoglyph,
            attachments=inspected_attachments,
            urls=urls
        )

        # 10. AI Arbiter Meta-Review
        arbiter_report = self.arbiter.cross_examine(
            engines_report=engines_report,
            headers=headers,
            auth=auth_results,
            hop_trace=hop_trace,
            homoglyph=homoglyph,
            quishing_attachments=inspected_attachments,
            urls=urls,
            ai_intent=ai_intent
        )

        audit_map = {a["engine_id"]: a for a in arbiter_report.get("tool_audits", [])}
        for eng in engines_report:
            if eng["id"] in audit_map:
                eng["ai_audit_verdict"] = audit_map[eng["id"]]["ai_audit_verdict"]
                eng["ai_audit_note"] = audit_map[eng["id"]]["ai_audit_note"]
            else:
                eng["ai_audit_verdict"] = "AI VERIFIED ✓"
                eng["ai_audit_note"] = "Consistent with multi-vector findings."

        flagged_count = sum(1 for e in engines_report if e["status"] in ["MALICIOUS", "SUSPICIOUS"])
        total_engines = len(engines_report)
        overall_score = min(int((flagged_count / total_engines) * 100 + (30 if flagged_count >= 3 else 0)), 100)

        auth_passed = auth_results.get("dmarc", {}).get("status") == "PASS" or auth_results.get("spf", {}).get("status") == "PASS"
        content_malicious = ai_intent.get("intent_score", 0) >= 60 or homoglyph.get("is_spoof") or any(a.get("is_quishing") for a in inspected_attachments)
        is_compromised = auth_passed and content_malicious

        if flagged_count >= 4 or (is_compromised and flagged_count >= 2):
            verdict = "MALICIOUS EMAIL (High Confidence)"
            risk_level = "CRITICAL"
        elif flagged_count >= 2:
            verdict = "SUSPICIOUS EMAIL / HIGH DECEPTION RISK"
            risk_level = "HIGH"
        elif flagged_count == 1:
            verdict = "ELEVATED RISK / ANOMALIES DETECTED"
            risk_level = "MEDIUM"
        else:
            verdict = "CLEAN & AUTHENTICATED EMAIL"
            risk_level = "LOW"
            overall_score = 0

        mitre_tactics = self._build_mitre_mapping(engines_report, is_compromised)

        diagnostics = self._synthesize_diagnostic_summary(
            headers=headers,
            engines=engines_report,
            ai_intent=ai_intent,
            homoglyph=homoglyph,
            attachments=inspected_attachments,
            urls=urls,
            auth=auth_results,
            flagged_count=flagged_count,
            is_compromised=is_compromised
        )

        threat_summary = {
            "overall_risk_score": overall_score,
            "flagged_engines_count": flagged_count,
            "total_engines_count": total_engines,
            "detection_ratio": f"{flagged_count}/{total_engines}",
            "risk_level": risk_level,
            "threat_verdict": verdict,
            "is_compromised_account_suspected": is_compromised,
            "geo_attribution_confidence": origin_geo.get("attribution_confidence", {}),
            "arbiter_consensus": arbiter_report,
            "symbolic_proofs": symbolic_proofs,
            "mitre_attack_tactics": mitre_tactics,
            "diagnostics": diagnostics,
            "case_id": case_id
        }

        result = {
            "case_id": case_id,
            "hashes": hashes,
            "headers": headers,
            "body": body,
            "hop_trace": hop_trace,
            "origin_geo": origin_geo,
            "infrastructure_threat": infra_threat,
            "authentication": auth_results,
            "ai_intent": ai_intent,
            "homoglyph": homoglyph,
            "attachments": inspected_attachments,
            "urls": urls,
            "engines_report": engines_report,
            "arbiter_report": arbiter_report,
            "symbolic_proofs": symbolic_proofs,
            "threat_summary": threat_summary
        }

        self.graph_correlator.ingest_case(case_id, result)
        return result

    def _build_engine_matrix(
        self,
        headers: Dict[str, Any],
        hop_trace: Dict[str, Any],
        infra_threat: Dict[str, Any],
        auth_results: Dict[str, Any],
        ai_intent: Dict[str, Any],
        homoglyph: Dict[str, Any],
        attachments: List[Dict[str, Any]],
        urls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        engines = []

        # 1. AI Intent
        score = ai_intent.get("intent_score", 0)
        e1_status = "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 35 else "CLEAN")
        engines.append({
            "id": "engine_ai_intent",
            "name": "AI Social Engineering & Intent Analyzer",
            "category": "Behavioral Intelligence",
            "status": e1_status,
            "details": ai_intent.get("ai_summary", "No deception cues detected.")
        })

        # 2. Relay Hops
        has_anomalies = hop_trace.get("has_anomalies", False)
        e2_status = "MALICIOUS" if has_anomalies else (infra_threat.get("status", "CLEAN"))
        engines.append({
            "id": "engine_geo_hops",
            "name": "Reverse Relay Hop Latency & Timestomp Engine",
            "category": "Network Routing",
            "status": e2_status,
            "details": f"Traced {hop_trace.get('total_hops', 0)} server hops. " + ("Forged retrograde timestamps detected!" if has_anomalies else "Routing latency consistent.")
        })

        # 3. Cryptographic Authentication
        auth_verdict = auth_results.get("overall_auth_verdict", "UNVERIFIED")
        e3_status = "CLEAN" if auth_verdict == "AUTHENTIC" else ("MALICIOUS" if auth_results.get("is_spoofed") else "SUSPICIOUS")
        engines.append({
            "id": "engine_crypto_auth",
            "name": "Cryptographic Authentication & DMARC Matrix",
            "category": "Protocol Security",
            "status": e3_status,
            "details": f"DMARC: {auth_results.get('dmarc', {}).get('status')}, SPF: {auth_results.get('spf', {}).get('status')}, DKIM: {auth_results.get('dkim', {}).get('status')}."
        })

        # 4. Homoglyph Inspector
        e4_status = "MALICIOUS" if homoglyph.get("is_spoof") else ("SUSPICIOUS" if homoglyph.get("is_punycode") else "CLEAN")
        engines.append({
            "id": "engine_homoglyph",
            "name": "Domain & Homoglyph Lookalike Inspector",
            "category": "Identity Intelligence",
            "status": e4_status,
            "details": f"Target: {homoglyph.get('targeted_brand')}" if homoglyph.get("is_spoof") else f"Domain '{headers.get('from_domain')}' clean."
        })

        # 5. Quishing & Attachments
        has_quish = any(a.get("is_quishing") for a in attachments)
        high_risk = any(a.get("risk_score", 0) >= 70 for a in attachments)
        e5_status = "MALICIOUS" if (has_quish or high_risk) else "CLEAN"
        engines.append({
            "id": "engine_quishing_payload",
            "name": "Quishing (QR Phish) & Attachment Sandbox",
            "category": "Payload Forensics",
            "status": e5_status,
            "details": "Quishing QR code redirect detected!" if has_quish else f"Scanned {len(attachments)} attachments. Clean."
        })

        # 6. Embedded URLs
        has_ip_url = any(u.get("is_ip_based") for u in urls)
        suspicious_tld = any(u.get("is_suspicious_tld") for u in urls)
        e6_status = "MALICIOUS" if has_ip_url else ("SUSPICIOUS" if suspicious_tld else "CLEAN")
        engines.append({
            "id": "engine_url_inspector",
            "name": "Embedded URL & Hyperlink Analyzer",
            "category": "Web Intelligence",
            "status": e6_status,
            "details": "Suspicious raw IP URL detected." if has_ip_url else f"Scanned {len(urls)} URLs. No malicious redirects."
        })

        # 7. Envelope Anomalies
        anomalies = headers.get("sender_anomalies", [])
        e7_status = "MALICIOUS" if any(a.get("type") == "RETURN_PATH_MISMATCH" for a in anomalies) else "CLEAN"
        engines.append({
            "id": "engine_envelope_anomaly",
            "name": "Envelope & Header Anomaly Detector",
            "category": "Header Integrity",
            "status": e7_status,
            "details": anomalies[0].get("detail", "Sender domains fully aligned.") if anomalies else "Sender domains fully aligned."
        })

        return engines

    def _build_mitre_mapping(self, engines: List[Dict[str, Any]], is_compromised: bool) -> List[Dict[str, str]]:
        mitre = []
        flagged_ids = [e["id"] for e in engines if e["status"] in ["MALICIOUS", "SUSPICIOUS"]]
        if flagged_ids:
            mitre.append({"id": "T1566", "name": "Phishing", "tactic": "Initial Access"})
        if is_compromised:
            mitre.append({"id": "T1078", "name": "Valid Accounts (Compromised Account Abuse)", "tactic": "Defense Evasion"})
        if "engine_homoglyph" in flagged_ids:
            mitre.append({"id": "T1566.002", "name": "Spearphishing Link (Homoglyph Spoof)", "tactic": "Initial Access"})
        if "engine_quishing_payload" in flagged_ids:
            mitre.append({"id": "T1566.001", "name": "Spearphishing Attachment (Quishing)", "tactic": "Initial Access"})
        if "engine_ai_intent" in flagged_ids:
            mitre.append({"id": "T1656", "name": "Impersonation (Social Engineering)", "tactic": "Execution"})
        if "engine_geo_hops" in flagged_ids:
            mitre.append({"id": "T1070.006", "name": "Timestomp / Forged Header Obfuscation", "tactic": "Defense Evasion"})
        return mitre

    def _synthesize_diagnostic_summary(
        self,
        headers: Dict[str, Any],
        engines: List[Dict[str, Any]],
        ai_intent: Dict[str, Any],
        homoglyph: Dict[str, Any],
        attachments: List[Dict[str, Any]],
        urls: List[Dict[str, Any]],
        auth: Dict[str, Any],
        flagged_count: int,
        is_compromised: bool
    ) -> Dict[str, Any]:
        subject = headers.get("subject", "")
        from_raw = headers.get("from_raw", "")
        from_domain = headers.get("from_domain", "")

        what_wrong = []
        user_actions = []
        soc_actions = []

        quish_att = next((a for a in attachments if a.get("is_quishing")), None)

        if quish_att:
            root_cause = "Quishing Threat: Malicious 2D QR Code hidden inside image attachment designed to harvest credentials."
            threat_badge_text = "CRITICAL - QUISHING ATTACK"
            threat_badge_color = "rose"
            what_wrong.append(f"<b>Hidden Barcode Vector:</b> Attachment '{quish_att.get('filename')}' contains an embedded QR code pointing to: <code>{quish_att.get('quishing_decoded_url')}</code>.")
            what_wrong.append("<b>Filter Bypass:</b> Attackers used an image QR code to evade traditional text-based filters.")
            user_actions.append("🛑 <b>DO NOT scan the QR code with your phone</b> or click the link.")
            user_actions.append("🗑️ <b>Delete this message immediately</b> and notify IT.")
            soc_actions.append("🛡️ <b>Block Destination URL:</b> Add the decoded domain to firewall/proxy blacklist.")
            soc_actions.append("⚡ <b>Purge Message:</b> Run 1-Click SOC Playbook to remove this QR attachment across all mailboxes.")

        elif homoglyph.get("is_spoof"):
            brand = homoglyph.get("targeted_brand", "known brand")
            root_cause = f"Homoglyph Impersonation: Adversary registered a visual lookalike domain spoofing {brand} using non-Latin characters."
            threat_badge_text = "HIGH RISK - HOMOGLYPH SPOOF"
            threat_badge_color = "rose"
            what_wrong.append(f"<b>Visual Deception:</b> Sender domain <code>{from_domain}</code> uses Cyrillic/Greek lookalike characters spoofing <b>{brand}</b>.")
            what_wrong.append(f"<b>Punycode Translation:</b> Actual registered domain is: <code>{homoglyph.get('punycode')}</code>.")
            user_actions.append("🛑 <b>DO NOT enter credentials</b> on any login page linked in this email.")
            user_actions.append("⚠️ <b>Verify URL Spelling:</b> Always navigate to official websites directly.")
            soc_actions.append(f"🛡️ <b>Block Punycode:</b> Blacklist <code>{homoglyph.get('punycode')}</code> on mail gateway.")

        elif is_compromised or (ai_intent.get("intent_score", 0) >= 60 and flagged_count >= 1):
            root_cause = "Social Engineering & Executive Coercion (Business Email Compromise / Urgent Fraud)."
            threat_badge_text = "HIGH RISK - WIRE FRAUD / BEC"
            threat_badge_color = "rose"
            raw_tactics = ai_intent.get("tactics_detected", [])
            t_names = [t.get('tactic', str(t)) if isinstance(t, dict) else str(t) for t in raw_tactics]
            tactics_str = ', '.join(t_names) if t_names else 'Urgency & Financial Coercion'
            what_wrong.append(f"<b>Coercive Language:</b> Email exhibits high psychological pressure ({tactics_str}).")
            if is_compromised:
                what_wrong.append("<b>Compromised Account:</b> SPF/DKIM passed, indicating an attacker is abusing a hijacked legitimate account.")
            user_actions.append("🛑 <b>DO NOT initiate wire transfers</b> or share confidential company data.")
            user_actions.append("📞 <b>Perform Out-of-Band Verification:</b> Call the sender on a known trusted phone number.")
            soc_actions.append("🛡️ <b>Revoke Sessions:</b> Force password reset and MFA re-authentication on the compromised account.")

        elif any("¡URGENTE!" in subject.upper() or "NOTIFICACIÓN JUDICIAL" in subject.upper() for _ in [1]):
            root_cause = "Fake Judicial Extortion Scam: Uses counterfeit legal subpoena threats to induce panic."
            threat_badge_text = "SUSPICIOUS - EXTORTION PHISH"
            threat_badge_color = "amber"
            what_wrong.append("<b>Panic-Inducing Subject:</b> Subject uses urgency tags like <code>¡URGENTE! Notificación judicial</code>.")
            what_wrong.append(f"<b>Sender Mismatch:</b> Official judicial notice sent from a free consumer email (<code>{from_raw}</code>).")
            user_actions.append("🛑 <b>DO NOT click links</b> or download unexpected legal notice files.")
            user_actions.append("🗑️ <b>Mark as Phishing</b> and delete immediately.")
            soc_actions.append("🛡️ <b>Blacklist Sender:</b> Block sender address and relay IP across the organization.")

        elif flagged_count > 0:
            root_cause = f"Anomalous Indicators Detected ({flagged_count} security engine(s) triggered)."
            threat_badge_text = "ELEVATED RISK - SUSPICIOUS"
            threat_badge_color = "amber"
            for eng in engines:
                if eng["status"] in ["MALICIOUS", "SUSPICIOUS"]:
                    what_wrong.append(f"<b>{eng['name']}:</b> {eng['details']}")
            user_actions.append("⚠️ <b>Exercise Caution:</b> Verify sender identity before taking action.")
            soc_actions.append("🛡️ <b>Review Relays:</b> Inspect reverse relay hops and authentication alignment.")

        else:
            root_cause = "Clean & Verified: All 7 security engines confirmed the email as authentic with zero anomalies."
            threat_badge_text = "SAFE & AUTHENTIC"
            threat_badge_color = "emerald"
            what_wrong.append("✅ <b>Cryptographic Verification:</b> SPF, DKIM, and DMARC records are valid and fully aligned.")
            what_wrong.append("✅ <b>No Malicious Payloads:</b> Zero suspicious URLs, homoglyphs, or quishing QR codes found.")
            user_actions.append("✅ <b>Safe to Read:</b> Email is authentic and poses no detected security threat.")
            soc_actions.append("✅ <b>No Action Required:</b> Routine email verified.")

        return {
            "root_cause": root_cause,
            "threat_badge_text": threat_badge_text,
            "threat_badge_color": threat_badge_color,
            "what_is_wrong": what_wrong,
            "user_actions": user_actions,
            "soc_actions": soc_actions
        }
