import os


def generate_dataset(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    samples = {
        "01_bec_executive_wire_fraud.eml": """From: "Robert Vance, CEO" <ceo.office.vance@gmail.com>
To: "Emily Watson, CFO" <e.watson@enterprise-corp.com>
Subject: CONFIDENTIAL & URGENT: Acquisition Escrow Wire Transfer
Date: Sun, 30 Aug 2026 09:15:00 +0000
Message-ID: <bec-vance-001@gmail.com>
Return-Path: <ceo.office.vance@gmail.com>
Reply-To: <ceo.office.vance@gmail.com>
Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.216.41])
          by mx.enterprise-corp.com (Enterprise Inbound Gateway) with ESMTPS id vance778
          for <e.watson@enterprise-corp.com>; Sun, 30 Aug 2026 09:15:01 +0000
Authentication-Results: mx.enterprise-corp.com; dkim=pass (d=gmail.com); spf=pass (ip=209.85.216.41)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Emily,

I am currently in an all-day confidential board meeting regarding our Q3 acquisition.
We need an immediate wire transfer of $285,000 processed to the escrow account before 2:00 PM today.

Do not call my mobile as I cannot step out of the meeting room. 
Reply directly to this email with confirmation once the wire is initiated.

Best regards,
Robert Vance
Chief Executive Officer
Enterprise Corp.
""",

        "02_quishing_mfa_invoice.eml": """From: Microsoft 365 Security <security-update@microsoft-mfa-support.com>
To: victim@company.com
Subject: [ACTION REQUIRED] Mandatory MFA Re-Authentication - Scan Attached QR Code
Date: Sun, 30 Aug 2026 10:30:00 +0000
Message-ID: <quish-mfa-002@microsoft-mfa-support.com>
Return-Path: <bounce@microsoft-mfa-support.com>
Received: from relay.panama-bulletproof.net (relay.panama-bulletproof.net [45.154.255.80])
          by mx.company.com with ESMTPS id qsh991; Sun, 30 Aug 2026 10:30:02 +0000
Authentication-Results: mx.company.com; spf=fail (ip=45.154.255.80); dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Employee,

Your Microsoft 365 Authenticator session has expired due to our new zero-trust compliance policy.
To maintain access to your corporate inbox, please scan the QR code using your mobile device or visit http://185.220.101.5/mfa-login immediately.

Failure to verify within 4 hours will result in permanent account deactivation.

Microsoft 365 Identity Security Team
""",

        "03_homoglyph_paypal_spoof.eml": """From: "PayPal Security Alert" <support@pаypal.com>
To: user@target-domain.com
Subject: Unauthorized Login Attempt Detected on Your PayPal Account
Date: Sun, 30 Aug 2026 11:00:00 +0000
Message-ID: <paypal-spoof-003@pаypal.com>
Return-Path: <support@pаypal.com>
Received: from vps-ovh-eu.net (vps-ovh-eu.net [51.15.42.18])
          by mx.target-domain.com with ESMTPS id pay902; Sun, 30 Aug 2026 11:00:01 +0000
Authentication-Results: mx.target-domain.com; spf=softfail; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Customer,

We detected an unauthorized login attempt from an unknown device in Moscow, Russia.
Please verify your PayPal credentials at https://pаypal.com/security-checkpoint to secure your account and cancel any pending transactions.

Thank you,
PayPal Customer Trust & Safety
""",

        "04_forged_relay_hop_attack.eml": """From: Financial Audits <audits@bank-internal.com>
To: accounting@company.com
Subject: Notice of Immediate Audit Compliance & Discrepancy Review
Date: Sun, 30 Aug 2026 12:00:00 +0000
Message-ID: <forged-hop-004@bank-internal.com>
Return-Path: <audits@bank-internal.com>
Received: from mx.internal-gateway.com (mx.internal-gateway.com [10.0.0.1])
          by mx.company.com with ESMTPS id for100; Sun, 30 Aug 2026 12:00:00 +0000
Received: from forged-mail-server.com (forged-mail-server.com [185.220.101.5])
          by mx.internal-gateway.com with ESMTPS id for099; Sun, 30 Aug 2026 12:05:00 +0000
Authentication-Results: mx.company.com; spf=neutral
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Attention Accounting Team,

Please find attached the immediate discrepancy compliance checklist for review.
Immediate action is required to avoid financial regulatory penalties.
""",

        "05_credential_harvest_it_helpdesk.eml": """From: IT Helpdesk Support <admin-support@libero.it>
To: staff@university.edu
Subject: System Migration: Verify Webmail Password Before Midnight
Date: Sun, 30 Aug 2026 13:00:00 +0000
Message-ID: <it-help-005@libero.it>
Return-Path: <admin-support@libero.it>
Received: from mail.libero.it (mail.libero.it [185.120.10.5])
          by mx.university.edu with ESMTPS id it888; Sun, 30 Aug 2026 13:00:01 +0000
Authentication-Results: mx.university.edu; spf=none; dmarc=none
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Staff & Faculty,

Our email servers are undergoing scheduled migration to the new cloud cluster.
You must re-confirm your current webmail credentials at http://45.154.255.80/webmail-login to preserve your stored emails.

IT Support Center
""",

        "06_legitimate_multihop_enterprise.eml": """From: GitHub Notifications <notifications@github.com>
To: developer@techcompany.com
Subject: [GitHub] Security Advisory: New Vulnerability Resolved in dependencies
Date: Sun, 30 Aug 2026 14:00:00 +0000
Message-ID: <gh-clean-006@github.com>
Return-Path: <noreply@github.com>
Received: from out-1.smtp.github.com (out-1.smtp.github.com [192.30.252.192])
          by mx.google.com with ESMTPS id gh1122
          for <developer@techcompany.com>; Sun, 30 Aug 2026 14:00:01 +0000
Authentication-Results: mx.google.com; dkim=pass header.i=@github.com; spf=pass (google.com: domain of noreply@github.com designates 192.30.252.192 as permitted sender) smtp.mailfrom=noreply@github.com; dmarc=pass (p=REJECT)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hello,

A security advisory has been published for a repository you watch.
No action is required if your build pipelines are set to automated dependency updates.

Best,
The GitHub Team
"""
    }

    for fname, content in samples.items():
        with open(os.path.join(output_dir, fname), "w", encoding="utf-8") as f:
            f.write(content.strip())
