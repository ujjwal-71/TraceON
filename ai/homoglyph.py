import unicodedata
from typing import Dict, Any, List, Optional


class HomoglyphInspector:
    """Detects Cyrillic and Greek lookalike characters spoofing known brands."""

    CONFUSABLES = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
        'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'а': 'a', 'ո': 'n', 'օ': 'o', 'р': 'p', 'ԁ': 'd', 'ԛ': 'q'
    }

    TARGET_BRANDS = [
        "paypal.com", "microsoft.com", "google.com", "amazon.com", "apple.com",
        "netflix.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "github.com"
    ]

    def inspect_domain(self, domain_str: str) -> Dict[str, Any]:
        if not domain_str:
            return {
                "domain": "",
                "is_spoof": False,
                "is_punycode": False,
                "punycode": "",
                "normalized": "",
                "targeted_brand": None,
                "reasons": []
            }

        clean_dom = domain_str.lower().strip()
        reasons = []

        is_puny = clean_dom.startswith("xn--") or ".xn--" in clean_dom
        punycode = ""
        try:
            punycode = clean_dom.encode("idna").decode("ascii")
        except Exception:
            punycode = clean_dom

        # normalize homoglyphs to latin
        normalized_chars = []
        has_homoglyphs = False
        for char in clean_dom:
            if char in self.CONFUSABLES:
                normalized_chars.append(self.CONFUSABLES[char])
                has_homoglyphs = True
            else:
                normalized_chars.append(char)
        normalized_domain = "".join(normalized_chars)

        targeted_brand = None
        is_spoof = False

        for brand in self.TARGET_BRANDS:
            brand_name = brand.split(".")[0]
            if brand_name in normalized_domain and brand_name not in clean_dom and has_homoglyphs:
                is_spoof = True
                targeted_brand = brand
                reasons.append(f"Domain uses visual lookalike characters spoofing '{brand}'.")
                break
            elif normalized_domain == brand and clean_dom != brand:
                is_spoof = True
                targeted_brand = brand
                reasons.append(f"Domain visually clones '{brand}' using non-Latin Unicode.")
                break

        if is_puny and not reasons:
            reasons.append(f"Punycode encoded domain ({punycode}).")

        return {
            "domain": clean_dom,
            "is_spoof": is_spoof,
            "is_punycode": is_puny,
            "punycode": punycode,
            "normalized": normalized_domain,
            "has_homoglyphs": has_homoglyphs,
            "targeted_brand": targeted_brand,
            "reasons": reasons
        }
