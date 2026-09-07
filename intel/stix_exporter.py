import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List


class STIX21Exporter:
    """Exports forensic telemetry as standard OASIS STIX 2.1 JSON bundle."""

    @staticmethod
    def generate_bundle(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        case_id = analysis_data.get("case_id", "UNKNOWN")
        headers = analysis_data.get("headers", {})
        hashes = analysis_data.get("hashes", {})
        origin_geo = analysis_data.get("origin_geo", {})
        threat = analysis_data.get("threat_summary", {})
        diag = threat.get("diagnostics", {})

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        bundle_id = f"bundle--{uuid.uuid4()}"

        objects = []

        # 1. Identity (TRACEON SOC)
        identity_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "TRACEON Automated Digital Forensics",
            "identity_class": "system"
        })

        # 2. Attack Pattern / Indicator
        indicator_id = f"indicator--{uuid.uuid4()}"
        sha256 = hashes.get("sha256", "")
        sender = headers.get("from_address", "")
        pattern = f"[email-message:from_ref.value = '{sender}']"
        if sha256:
            pattern = f"[file:hashes.'SHA-256' = '{sha256}']"

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"TRACEON Phishing IOC: {headers.get('subject', 'Suspicious Email')[:50]}",
            "description": diag.get("root_cause", "Malicious email indicator detected by TRACEON."),
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now_iso
        })

        # 3. Report Object
        report_id = f"report--{uuid.uuid4()}"
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Forensic Investigation Dossier - Case {case_id[:8].upper()}",
            "description": f"Verdict: {threat.get('threat_verdict')} ({threat.get('detection_ratio')} flagged). Origin: {origin_geo.get('country')}.",
            "published": now_iso,
            "object_refs": [identity_id, indicator_id]
        })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }
