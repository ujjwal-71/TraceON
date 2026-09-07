import imaplib
import email
from email import policy
from typing import List, Dict, Any


class GmailInboxConnector:
    """Connects to live Gmail via IMAP SSL or provides demo enterprise messages."""

    DEMO_INBOX = [
        {
            "id": "DEMO-01",
            "subject": "CONFIDENTIAL & URGENT: Acquisition Escrow Wire Transfer",
            "from": "Robert Vance, CEO <ceo.office.vance@gmail.com>",
            "date": "Today, 09:15 AM",
            "snippet": "Emily, I am in an all-day confidential board meeting. Need an immediate wire transfer of $285,000..."
        },
        {
            "id": "DEMO-02",
            "subject": "[ACTION REQUIRED] Mandatory MFA Re-Authentication - Scan Attached QR Code",
            "from": "Microsoft 365 Security <security-update@microsoft-mfa-support.com>",
            "date": "Today, 10:30 AM",
            "snippet": "Your Microsoft 365 session has expired. Scan the QR code with your mobile device immediately..."
        },
        {
            "id": "DEMO-03",
            "subject": "Unauthorized Login Attempt Detected on Your PayPal Account",
            "from": "PayPal Security Alert <support@pаypal.com>",
            "date": "Today, 11:00 AM",
            "snippet": "We detected an unauthorized login attempt from Moscow, Russia. Verify credentials to secure account..."
        },
        {
            "id": "DEMO-04",
            "subject": "Notice of Immediate Audit Compliance & Discrepancy Review",
            "from": "Financial Audits <audits@bank-internal.com>",
            "date": "Today, 12:00 PM",
            "snippet": "Attention Accounting Team, please find attached the immediate discrepancy compliance checklist..."
        },
        {
            "id": "DEMO-05",
            "subject": "System Migration: Verify Webmail Password Before Midnight",
            "from": "IT Helpdesk Support <admin-support@libero.it>",
            "date": "Today, 01:00 PM",
            "snippet": "Our email servers are undergoing scheduled migration. Re-confirm credentials to preserve stored mail..."
        },
        {
            "id": "DEMO-06",
            "subject": "[GitHub] Security Advisory: New Vulnerability Resolved in dependencies",
            "from": "GitHub Notifications <notifications@github.com>",
            "date": "Today, 02:00 PM",
            "snippet": "A security advisory has been published for a repository you watch. No action is required if automated..."
        }
    ]

    @classmethod
    def get_demo_inbox(cls) -> List[Dict[str, Any]]:
        return cls.DEMO_INBOX

    @classmethod
    def get_demo_email_bytes(cls, demo_id: str) -> bytes:
        from AISCRIPTS.generate_sample_dataset import generate_dataset
        import os
        sample_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
        if not os.path.exists(sample_dir) or len(os.listdir(sample_dir)) == 0:
            generate_dataset(sample_dir)

        index_map = {
            "DEMO-01": "01_bec_executive_wire_fraud.eml",
            "DEMO-02": "02_quishing_mfa_invoice.eml",
            "DEMO-03": "03_homoglyph_paypal_spoof.eml",
            "DEMO-04": "04_forged_relay_hop_attack.eml",
            "DEMO-05": "05_credential_harvest_it_helpdesk.eml",
            "DEMO-06": "06_legitimate_multihop_enterprise.eml"
        }
        fname = index_map.get(demo_id, "01_bec_executive_wire_fraud.eml")
        fpath = os.path.join(sample_dir, fname)
        with open(fpath, "rb") as f:
            return f.read()

    @staticmethod
    def fetch_live_headers(email_addr: str, app_pass: str, max_emails: int = 15) -> List[Dict[str, Any]]:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_addr, app_pass)
        mail.select("inbox")

        _, data = mail.search(None, "ALL")
        mail_ids = data[0].split()
        recent_ids = mail_ids[-max_emails:]

        messages = []
        for mid in reversed(recent_ids):
            _, msg_data = mail.fetch(mid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1], policy=policy.default)
                    messages.append({
                        "id": mid.decode("utf-8"),
                        "subject": msg.get("Subject", "(No Subject)"),
                        "from": msg.get("From", "Unknown"),
                        "date": msg.get("Date", "")
                    })
        mail.logout()
        return messages

    @staticmethod
    def fetch_raw_email(email_addr: str, app_pass: str, mail_id: str) -> bytes:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_addr, app_pass)
        mail.select("inbox")
        _, msg_data = mail.fetch(mail_id, "(RFC822)")
        raw_bytes = b""
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                raw_bytes = response_part[1]
                break
        mail.logout()
        return raw_bytes
