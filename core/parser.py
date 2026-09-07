import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
import re
from typing import Dict, List, Any
from urllib.parse import urlparse
import tldextract


class EmailForensicParser:
    """Parses raw email bytes, extracts headers, URLs, attachments, and evidence hashes."""

    def __init__(self, raw_content: bytes | str):
        if isinstance(raw_content, str):
            self.raw_bytes = raw_content.encode('utf-8', errors='replace')
        else:
            self.raw_bytes = raw_content

        self.msg = email.message_from_bytes(self.raw_bytes, policy=policy.default)
        self.hashes = self._calculate_evidence_hashes()

    def _calculate_evidence_hashes(self) -> Dict[str, Any]:
        """Evidence hashes for chain of custody."""
        return {
            "sha256": hashlib.sha256(self.raw_bytes).hexdigest(),
            "sha1": hashlib.sha1(self.raw_bytes).hexdigest(),
            "md5": hashlib.md5(self.raw_bytes).hexdigest(),
            "byte_size": len(self.raw_bytes)
        }

    def parse_headers(self) -> Dict[str, Any]:
        from_display, from_addr = parseaddr(self.msg.get("From", ""))
        reply_display, reply_addr = parseaddr(self.msg.get("Reply-To", ""))
        return_path = self.msg.get("Return-Path", "").strip("<> ")

        raw_date = self.msg.get("Date", "")
        iso_date = ""
        timestamp = 0
        if raw_date:
            try:
                dt = parsedate_to_datetime(raw_date)
                iso_date = dt.isoformat()
                timestamp = int(dt.timestamp())
            except Exception:
                iso_date = raw_date

        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        return_domain = return_path.split("@")[-1] if "@" in return_path else ""
        reply_domain = reply_addr.split("@")[-1] if "@" in reply_addr else ""

        # detect sender vs envelope mismatches
        sender_anomalies = []
        if return_path and from_addr and (from_domain.lower() != return_domain.lower()):
            sender_anomalies.append({
                "type": "RETURN_PATH_MISMATCH",
                "severity": "HIGH",
                "detail": f"From '{from_addr}' does not match Return-Path '{return_path}'"
            })

        if reply_addr and from_addr and (from_domain.lower() != reply_domain.lower()):
            sender_anomalies.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "MEDIUM",
                "detail": f"Reply-To '{reply_addr}' redirects replies away from '{from_addr}'"
            })

        def clean_str(s: Any) -> str:
            if not isinstance(s, str):
                s = str(s) if s is not None else ""
            try:
                return s.encode('utf-8', 'surrogateescape').decode('utf-8', 'replace')
            except Exception:
                return str(s)

        raw_headers = []
        for k, v in self.msg.raw_items():
            raw_headers.append({"name": clean_str(k), "value": clean_str(v)})

        return {
            "subject": clean_str(self.msg.get("Subject", "(No Subject)")),
            "from_raw": clean_str(self.msg.get("From", "")),
            "from_display": clean_str(from_display),
            "from_address": clean_str(from_addr),
            "from_domain": clean_str(from_domain),
            "to": clean_str(self.msg.get("To", "")),
            "cc": clean_str(self.msg.get("Cc", "")),
            "bcc": clean_str(self.msg.get("Bcc", "")),
            "date_raw": clean_str(raw_date),
            "date_iso": clean_str(iso_date),
            "timestamp": timestamp,
            "message_id": clean_str(self.msg.get("Message-ID", "").strip("<> ")),
            "return_path": clean_str(return_path),
            "return_domain": clean_str(return_domain),
            "reply_to": clean_str(reply_addr),
            "reply_domain": clean_str(reply_domain),
            "x_mailer": clean_str(self.msg.get("X-Mailer", self.msg.get("User-Agent", "Not Specified"))),
            "x_originating_ip": clean_str(self.msg.get("X-Originating-IP", "").strip("[] ")),
            "authentication_results": clean_str(self.msg.get("Authentication-Results", "")),
            "dkim_signature": clean_str(self.msg.get("DKIM-Signature", "")),
            "received_spf": clean_str(self.msg.get("Received-SPF", "")),
            "sender_anomalies": sender_anomalies,
            "raw_headers": raw_headers
        }

    def parse_body(self) -> Dict[str, Any]:
        plain_text = ""
        html_content = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in content_disposition:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded_text = payload.decode(charset, errors="replace")

                    if content_type == "text/plain" and not plain_text:
                        plain_text = decoded_text
                    elif content_type == "text/html" and not html_content:
                        html_content = decoded_text
                except Exception:
                    pass
        else:
            content_type = self.msg.get_content_type()
            try:
                payload = self.msg.get_payload(decode=True)
                charset = self.msg.get_content_charset() or "utf-8"
                if payload:
                    text = payload.decode(charset, errors="replace")
                    if content_type == "text/plain":
                        plain_text = text
                    elif content_type == "text/html":
                        html_content = text
            except Exception:
                pass

        return {
            "plain_text": plain_text.strip(),
            "html": html_content.strip(),
            "has_html": bool(html_content.strip())
        }

    def parse_attachments(self) -> List[Dict[str, Any]]:
        attachments = []
        if not self.msg.is_multipart():
            return attachments

        for idx, part in enumerate(self.msg.walk(), start=1):
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if "attachment" in content_disposition or filename:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                clean_filename = filename or f"attachment_{idx}"
                size = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
                content_type = part.get_content_type()

                ext = clean_filename.split(".")[-1].lower() if "." in clean_filename else ""
                risk_score = 0
                if ext in ["exe", "scr", "bat", "vbs", "js", "hta", "ps1", "dll"]:
                    risk_score = 100
                elif ext in ["zip", "iso", "7z", "rar", "tar", "gz"]:
                    risk_score = 45
                elif ext in ["docm", "xlsm", "pptm"]:
                    risk_score = 75

                attachments.append({
                    "id": idx,
                    "filename": clean_filename,
                    "extension": ext,
                    "content_type": content_type,
                    "size_bytes": size,
                    "sha256": sha256,
                    "risk_score": risk_score,
                    "raw_bytes": payload
                })

        return attachments

    def extract_urls(self, body_text: str, html_text: str) -> List[Dict[str, Any]]:
        combined = f"{body_text} {html_text}"
        url_regex = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        raw_urls = set(url_regex.findall(combined))
        urls = []

        suspicious_tlds = [".top", ".xyz", ".club", ".work", ".click", ".fit", ".gq", ".tk", ".ml", ".cf", ".ga"]

        for u in raw_urls:
            clean_url = u.rstrip(")>],.;'\"")
            try:
                parsed = urlparse(clean_url)
                ext = tldextract.extract(clean_url)
                registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

                is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc.split(":")[0]))
                has_suspicious_tld = any(clean_url.endswith(t) or f"{t}/" in clean_url for t in suspicious_tlds)

                risk = 0
                if is_ip:
                    risk = 90
                elif has_suspicious_tld:
                    risk = 60

                urls.append({
                    "url": clean_url,
                    "domain": registered_domain,
                    "scheme": parsed.scheme,
                    "is_ip_based": is_ip,
                    "is_suspicious_tld": has_suspicious_tld,
                    "risk_score": risk
                })
            except Exception:
                continue

        return urls
