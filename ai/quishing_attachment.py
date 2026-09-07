import io
import re
from typing import Dict, Any, List


class QuishingInspector:
    """Scans attachments for hidden QR codes (Quishing) and dangerous payloads."""

    def inspect(self, attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []

        for att in attachments:
            raw_bytes = att.get("raw_bytes", b"")
            filename = att.get("filename", "")
            ext = att.get("extension", "").lower()

            is_quishing = False
            qr_url = None

            # 1. Image OCR / QR scan
            if ext in ["png", "jpg", "jpeg", "webp", "gif", "bmp"]:
                try:
                    from PIL import Image
                    from pyzbar.pyzbar import decode
                    image = Image.open(io.BytesIO(raw_bytes))
                    decoded = decode(image)
                    if decoded:
                        qr_url = decoded[0].data.decode("utf-8", errors="replace")
                        is_quishing = True
                except Exception:
                    pass

            # fallback regex for simulated or encoded qr streams
            if not qr_url and raw_bytes:
                match = re.search(rb'https?://[^\s<>"]+', raw_bytes)
                if match and b"qr" in filename.lower():
                    try:
                        qr_url = match.group(0).decode("utf-8", errors="replace")
                        is_quishing = True
                    except Exception:
                        pass

            item = dict(att)
            item.pop("raw_bytes", None)
            item["is_quishing"] = is_quishing
            item["quishing_decoded_url"] = qr_url
            if is_quishing:
                item["risk_score"] = 95

            results.append(item)

        return results
