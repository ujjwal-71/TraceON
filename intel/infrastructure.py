from typing import Dict, Any, List


class InfrastructureThreatAnalyzer:
    """Evaluates hosting reputation and AS risk profiles."""

    HIGH_RISK_ASNS = ["AS60729", "AS200651", "AS9009"]

    def analyze(self, origin_geo: Dict[str, Any], hops: List[Dict[str, Any]]) -> Dict[str, Any]:
        asn = origin_geo.get("asn", "")
        isp = origin_geo.get("isp", "")
        country = origin_geo.get("country", "")

        risk_score = 0
        indicators = []

        if any(h in asn for h in self.HIGH_RISK_ASNS):
            risk_score += 60
            indicators.append(f"Origin IP resides in known bulletproof/anonymizer ASN ({asn}).")

        if "tor" in isp.lower() or "bulletproof" in isp.lower():
            risk_score += 40
            indicators.append("ISP identified as Tor Exit Node or Bulletproof Hosting.")

        status = "MALICIOUS" if risk_score >= 60 else ("SUSPICIOUS" if risk_score >= 30 else "CLEAN")
        return {
            "risk_score": min(risk_score, 100),
            "status": status,
            "indicators": indicators,
            "summary": f"Infrastructure assessed as {status} (Risk: {risk_score}/100)."
        }
