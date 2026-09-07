import re
import ipaddress
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any


class HopTracer:
    """Traces email routing hops backwards from recipient to sender. Detects fake headers."""

    IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def __init__(self, raw_msg):
        self.msg = raw_msg
        self.received_headers = self.msg.get_all("Received", []) or []

    def is_public_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        except ValueError:
            return False

    def parse_single_received(self, header_val: str, index: int) -> Dict[str, Any]:
        clean_val = " ".join(header_val.split())

        date_str = ""
        iso_date = ""
        timestamp = 0
        if ";" in clean_val:
            date_str = clean_val.split(";")[-1].strip()
            try:
                dt = parsedate_to_datetime(date_str)
                iso_date = dt.isoformat()
                timestamp = int(dt.timestamp())
            except Exception:
                iso_date = date_str

        from_match = re.search(r'\bfrom\s+([^\s\(\)]+)', clean_val, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else "unknown"

        by_match = re.search(r'\bby\s+([^\s\(\)]+)', clean_val, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else "unknown"

        with_match = re.search(r'\bwith\s+([^\s;]+)', clean_val, re.IGNORECASE)
        protocol = with_match.group(1) if with_match else "SMTP"

        ips = self.IP_REGEX.findall(clean_val)
        primary_ip = ""
        for ip in ips:
            if self.is_public_ip(ip):
                primary_ip = ip
                break
        if not primary_ip and ips:
            primary_ip = ips[0]

        return {
            "hop_index": index,
            "raw": clean_val,
            "from_host": from_host,
            "by_host": by_host,
            "protocol": protocol,
            "ip": primary_ip,
            "is_public_ip": self.is_public_ip(primary_ip) if primary_ip else False,
            "date_str": date_str,
            "iso_date": iso_date,
            "timestamp": timestamp,
            "delay_seconds": 0,
            "anomalies": []
        }

    def trace_hops(self) -> Dict[str, Any]:
        # reverse headers so Hop 1 is the sender and Hop N is recipient
        reversed_headers = list(reversed(self.received_headers))
        hops = []

        for idx, h in enumerate(reversed_headers, start=1):
            hops.append(self.parse_single_received(h, idx))

        # calculate hop latency and detect time traveling headers
        for i in range(len(hops)):
            if i > 0 and hops[i]["timestamp"] and hops[i - 1]["timestamp"]:
                delay = hops[i]["timestamp"] - hops[i - 1]["timestamp"]
                hops[i]["delay_seconds"] = delay

                if delay < -60:
                    hops[i]["anomalies"].append({
                        "type": "TIMESTAMP_RETROGRADE",
                        "severity": "CRITICAL",
                        "detail": f"Hop timestamp is {abs(delay)}s earlier than previous hop. Forged Received header detected."
                    })

        origin_ip = None
        for hop in hops:
            if hop["is_public_ip"]:
                origin_ip = hop["ip"]
                break

        return {
            "total_hops": len(hops),
            "origin_ip": origin_ip,
            "hops": hops,
            "has_anomalies": any(len(h["anomalies"]) > 0 for h in hops)
        }
