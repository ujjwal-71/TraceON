import requests
from typing import Dict, Any, List


class GeoLocationTriangulator:
    """Resolves IP addresses to physical coordinates, ASN, and ISP."""

    MOCK_DB = {
        "209.85.216.41": {"country": "United States", "country_code": "US", "city": "Mountain View", "lat": 37.4223, "lon": -122.0848, "isp": "Google LLC", "asn": "AS15169"},
        "45.154.255.80": {"country": "Panama", "country_code": "PA", "city": "Panama City", "lat": 8.9824, "lon": -79.5199, "isp": "Bulletproof Offshore Relay", "asn": "AS60729"},
        "51.15.42.18": {"country": "France", "country_code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "isp": "Scaleway / OVH Cloud", "asn": "AS12876"},
        "185.120.10.5": {"country": "Italy", "country_code": "IT", "city": "Milan", "lat": 45.4642, "lon": 9.1900, "isp": "Italiaonline / Libero Mail", "asn": "AS12874"},
        "192.30.252.192": {"country": "United States", "country_code": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "GitHub Inc.", "asn": "AS36459"},
        "185.220.101.5": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Zwiebelfreunde Tor Node", "asn": "AS200651"}
    }

    def __init__(self, allow_online: bool = True):
        self.allow_online = allow_online
        self._cache = {}

    def lookup_ip(self, ip_str: str) -> Dict[str, Any]:
        if not ip_str:
            return self._empty_geo("Unknown Origin")

        if ip_str in self._cache:
            return self._cache[ip_str]

        if ip_str in self.MOCK_DB:
            res = self.MOCK_DB[ip_str]
            self._cache[ip_str] = res
            return res

        # fallback online lookup with quick timeout
        if self.allow_online:
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,city,lat,lon,isp,as", timeout=1.0)
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("status") == "success":
                        res = {
                            "country": d.get("country", "Unknown"),
                            "country_code": d.get("countryCode", "XX"),
                            "city": d.get("city", "Unknown"),
                            "lat": d.get("lat", 0.0),
                            "lon": d.get("lon", 0.0),
                            "isp": d.get("isp", "Unknown ISP"),
                            "asn": d.get("as", "AS0")
                        }
                        self._cache[ip_str] = res
                        return res
            except Exception:
                pass

        return self._empty_geo(ip_str)

    def calculate_confidence(self, origin_geo: Dict[str, Any], is_authenticated: bool) -> Dict[str, Any]:
        isp = origin_geo.get("isp", "").lower()
        if "google" in isp or "github" in isp or "microsoft" in isp or "amazon" in isp:
            score = 95
            rating = "HIGH_CONFIDENCE_CORPORATE"
        elif "tor" in isp or "bulletproof" in isp or "vpn" in isp:
            score = 35
            rating = "ANONYMIZED_PROXY"
        elif is_authenticated:
            score = 85
            rating = "AUTHENTICATED_RELAY"
        else:
            score = 75
            rating = "STANDARD_ROUTING"

        return {
            "score": score,
            "rating": rating,
            "explanation": f"Attribution confidence scored at {score}% based on infrastructure classification."
        }

    def _empty_geo(self, ip_str: str) -> Dict[str, Any]:
        return {
            "country": "Internal / Non-Routable",
            "country_code": "LAN",
            "city": "Private Subnet",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Local Relay",
            "asn": "AS-PRIVATE"
        }
