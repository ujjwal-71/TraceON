import re
from typing import Dict, Any, List


class AuthVerifier:
    """Verifies SPF, DKIM, and DMARC cryptographic alignment."""

    def __init__(self, raw_msg, parsed_headers: Dict[str, Any]):
        self.msg = raw_msg
        self.headers = parsed_headers

    def verify(self) -> Dict[str, Any]:
        auth_results_header = self.headers.get("authentication_results", "")
        dkim_header = self.headers.get("dkim_signature", "")
        spf_header = self.headers.get("received_spf", "")
        from_domain = self.headers.get("from_domain", "").lower()
        return_domain = self.headers.get("return_domain", "").lower()

        # 1. SPF Check
        spf_status = "NONE"
        spf_detail = "No SPF record evaluated."
        if spf_header:
            m = re.search(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', spf_header.strip(), re.I)
            if m:
                spf_status = m.group(1).upper()
                spf_detail = f"SPF {spf_status} via Received-SPF header."
        elif auth_results_header and "spf=" in auth_results_header.lower():
            m = re.search(r'spf=(\w+)', auth_results_header, re.I)
            if m:
                spf_status = m.group(1).upper()
                spf_detail = f"SPF {spf_status} via Authentication-Results."

        # 2. DKIM Check
        dkim_status = "NONE"
        dkim_domain = ""
        dkim_detail = "No DKIM signature found."
        if dkim_header:
            dm = re.search(r'd=([^;\s]+)', dkim_header)
            if dm:
                dkim_domain = dm.group(1).lower()

            if auth_results_header and "dkim=" in auth_results_header.lower():
                m = re.search(r'dkim=(\w+)', auth_results_header, re.I)
                if m:
                    dkim_status = m.group(1).upper()
            else:
                dkim_status = "PASS" if dkim_domain else "UNVERIFIED"

            dkim_detail = f"DKIM {dkim_status} signed by domain '{dkim_domain}'."

        # 3. DMARC Alignment Check
        dmarc_status = "NONE"
        dmarc_detail = "No gateway authentication headers found in email."
        is_spoofed = False

        if auth_results_header and "dmarc=" in auth_results_header.lower():
            m = re.search(r'dmarc=(\w+)', auth_results_header, re.I)
            if m:
                dmarc_status = m.group(1).upper()
                dmarc_detail = f"DMARC {dmarc_status} reported by receiving gateway."
                if dmarc_status == "FAIL":
                    is_spoofed = True
        else:
            has_explicit_auth = (spf_status != "NONE") or (dkim_status != "NONE")
            spf_aligned = (spf_status == "PASS") and (from_domain and return_domain and from_domain == return_domain)
            dkim_aligned = (dkim_status == "PASS") and (from_domain and dkim_domain and (from_domain == dkim_domain or from_domain.endswith(f".{dkim_domain}")))

            if spf_aligned or dkim_aligned:
                dmarc_status = "PASS"
                dmarc_detail = "DMARC aligned via SPF/DKIM identifier match."
            elif has_explicit_auth and (spf_status in ["FAIL", "SOFTFAIL"] or dkim_status == "FAIL"):
                dmarc_status = "FAIL"
                dmarc_detail = "DMARC failed: Explicit SPF or DKIM cryptographic failure."
                is_spoofed = True
            elif has_explicit_auth:
                dmarc_status = "NONE"
                dmarc_detail = "DMARC unaligned (Unverified policy)."
            else:
                # No gateway headers present (e.g. webmail DOM snippet)
                dmarc_status = "NONE"
                dmarc_detail = "No authentication headers attached to text (Unverified mode)."

        overall_verdict = "AUTHENTIC" if dmarc_status == "PASS" else ("SPOOFED" if is_spoofed else "UNVERIFIED")

        return {
            "spf": {"status": spf_status, "detail": spf_detail},
            "dkim": {"status": dkim_status, "domain": dkim_domain, "detail": dkim_detail, "is_valid": dkim_status == "PASS"},
            "dmarc": {"status": dmarc_status, "detail": dmarc_detail, "aligned": dmarc_status == "PASS"},
            "is_spoofed": is_spoofed,
            "overall_auth_verdict": overall_verdict
        }
