# TRACEON // AI-Powered Email Forensic & Threat Intelligence Platform

> **Problem Statement #26106**: Comprehensive Email Threat Detection, Hop-by-Hop GeoLocation Triangulation & Ephemeral Zero-Retention Forensic Sentinel.

---

## 🌟 Key Innovations

1. **Zero-Retention Ephemeral Privacy**:
   - Analyzes emails strictly in volatile computer memory (RAM).
   - **Zero Disk Writes**: No raw emails or attachments are stored in permanent databases.
   - **10-Minute Auto-Purge**: Volatile telemetry is automatically purged after 10 minutes (or immediately via 1-click manual wipe).

2. **Neuro-Symbolic Declarative Logic Engine (`ai/symbolic_engine.py`)**:
   - Pure-Python Declarative Logic Inference Engine (Prolog-style forward/backward chaining).
   - Generates transparent, verifiable **Formal Deductive Proof Chains** (`Fact ➔ Axiom ➔ Deduction`) with zero hallucinations.

3. **7-Engine Forensic Diagnostic Suite (`core/engine.py`)**:
   - **Engine 1**: AI Social Engineering & Intent Analyzer (Urgency, Coercion, BEC Wire Fraud).
   - **Engine 2**: Reverse Relay Hop Latency & Timestomp Engine ($\Delta t < 0$ forgery detection).
   - **Engine 3**: Cryptographic Authentication & DMARC Alignment Matrix (SPF, DKIM, DMARC).
   - **Engine 4**: Domain & Homoglyph Lookalike Inspector (Cyrillic/Greek Unicode & Punycode).
   - **Engine 5**: Quishing (QR Phish) & Attachment Sandbox (2D Barcode OCR decoder).
   - **Engine 6**: Embedded URL & Hyperlink Analyzer (Raw IP & disposable TLD detector).
   - **Engine 7**: Envelope & Header Anomaly Detector (Display vs Return-Path mismatch).

4. **1-Click Webmail Browser Extension (`extension/`)**:
   - **Popup**: Top-left auto-scan toggle, top-right "Go to full site" button, and central **Round Upload Button**.
   - **In-Webmail Shield**: Injects a glowing `[ 🛡️ TRACEON ]` button next to Gmail/Outlook's **Important marker / Star**.
   - **In-Page Mini-Scorecard**: Displays `Score: X/7 FLAGGED`, quick diagnosis, *"It isn't a final product yet!"* disclaimer, and `[ ⚡ See Full Results ]` deep-link.

5. **Legal & Courtroom Evidence Suite (`reporting/` & `web/templates/`)**:
   - Section 65B Indian Evidence Act / Section 63 BSA 2023 certified PDF evidence dossiers.
   - Dedicated `/privacy` and `/terms` legal compliance pages.
   - OASIS STIX 2.1 CTI Threat Intelligence JSON exporter.
   - 1-Click SOC automated incident response playbooks (iptables, Palo Alto, AWS WAF, M365 Exchange Online).

---

## 🚀 Quick Start Guide

### 1. Start the TRACEON SOC Server
```powershell
# From the project root:
python run.py
```
Open **`http://127.0.0.1:8000`** in your browser to view the Cyber HUD Studio.

---

### 2. Install the Chrome / Edge Browser Extension
1. Open Google Chrome, MS Edge, or Brave.
2. Navigate to `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the folder:
   ```
   D:\TraceON\extension
   ```
5. Open [Gmail](https://mail.google.com) or [Outlook](https://outlook.live.com) — you will see the glowing `[ 🛡️ TRACEON ]` button next to email rows!

---

## ⚖️ Legal & Privacy Compliance

- **Indian IT Act, 2000**: Compliant with electronic record integrity standards.
- **DPDPA 2023 & GDPR Art. 5(1)(e)**: Ephemeral RAM lifecycle with automatic 10-minute purge.
- **Zero Third-Party Cookies**: No advertising cookies or external tracking pixels.
- **License**: Open-Source MIT License with explicit defensive evaluation safe harbor.
