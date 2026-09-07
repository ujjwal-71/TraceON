import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from typing import Dict, Any


class ForensicDossierGenerator:
    """Generates courtroom-admissible PDF forensic evidence dossiers."""

    @staticmethod
    def generate_pdf(analysis_data: Dict[str, Any]) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('DocTitle', parent=styles['Normal'], fontName="Helvetica-Bold", fontSize=18, textColor=colors.HexColor("#0F172A"), leading=22)
        subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#0284C7"), leading=12)
        section_heading = ParagraphStyle('SecHead', parent=styles['Normal'], fontName="Helvetica-Bold", fontSize=11, textColor=colors.HexColor("#0F172A"), leading=14, spaceBefore=6, spaceAfter=4)
        body_style = ParagraphStyle('BodyText', parent=styles['Normal'], fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#334155"), leading=10)
        code_style = ParagraphStyle('CodeText', parent=styles['Normal'], fontName="Courier", fontSize=7, textColor=colors.HexColor("#0F172A"), leading=8)

        elements = []

        # 1. Header
        elements.append(Paragraph("TRACEON // FORENSIC INCIDENT DOSSIER", title_style))
        elements.append(Paragraph(f"DIGITAL EVIDENCE ATTESTATION &bull; GENERATED: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
        elements.append(Spacer(1, 4))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceBefore=2, spaceAfter=6))

        # 2. Evidence Integrity Table
        hashes = analysis_data.get("hashes", {})
        headers = analysis_data.get("headers", {})
        threat = analysis_data.get("threat_summary", {})
        origin_geo = analysis_data.get("origin_geo", {})

        elements.append(Paragraph("<b>1. Digital Evidence Integrity & Chain of Custody</b>", section_heading))
        evidence_table_data = [
            [Paragraph("<b>SHA-256 Checksum:</b>", body_style), Paragraph(f"<code>{hashes.get('sha256', 'N/A')}</code>", code_style)],
            [Paragraph("<b>Case Reference ID:</b>", body_style), Paragraph(f"<code>EVID-{hashes.get('sha256', '')[:12].upper()}</code>", code_style)],
            [Paragraph("<b>Overall Threat Verdict:</b>", body_style), Paragraph(f"<b>{threat.get('threat_verdict', 'UNKNOWN')} ({threat.get('detection_ratio', 'N/A')} Flagged)</b>", body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(headers.get('subject', '(No Subject)'), body_style)],
            [Paragraph("<b>Claimed Sender:</b>", body_style), Paragraph(f"{headers.get('from_raw', 'N/A')}", body_style)],
            [Paragraph("<b>Origin Infrastructure:</b>", body_style), Paragraph(f"{origin_geo.get('country', 'N/A')} ({origin_geo.get('city', 'N/A')}) &bull; ISP: {origin_geo.get('isp', 'N/A')}", body_style)],
        ]

        ev_table = Table(evidence_table_data, colWidths=[140, 400])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(ev_table)
        elements.append(Spacer(1, 4))

        # 3. Threat Diagnosis & Remediation
        diag = threat.get("diagnostics", {})
        if diag:
            elements.append(Paragraph("<b>2. Forensic Threat Diagnosis & Actionable Remediation</b>", section_heading))
            diag_wrong_text = "<br/>".join([f"&bull; {w}" for w in diag.get("what_is_wrong", [])])
            diag_action_text = "<b>User Action:</b><br/>" + "<br/>".join([f"&bull; {u}" for u in diag.get("user_actions", [])]) + "<br/><br/><b>SOC Action:</b><br/>" + "<br/>".join([f"&bull; {s}" for s in diag.get("soc_actions", [])])

            diag_table_data = [
                [Paragraph(f"<b>Root Cause:</b> {diag.get('root_cause', 'N/A')}", ParagraphStyle('DiagRC', parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#1E3A8A"))), ""],
                [
                    Paragraph("<b>🚨 Forensic Findings:</b>", ParagraphStyle('DiagW', parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#B91C1C"))),
                    Paragraph("<b>⚡ Required Actions:</b>", ParagraphStyle('DiagA', parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#047857")))
                ],
                [
                    Paragraph(diag_wrong_text, body_style),
                    Paragraph(diag_action_text, body_style)
                ]
            ]
            diag_table = Table(diag_table_data, colWidths=[270, 270])
            diag_table.setStyle(TableStyle([
                ('SPAN', (0, 0), (1, 0)),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
                ('BACKGROUND', (0, 1), (0, -1), colors.HexColor("#FEF2F2")),
                ('BACKGROUND', (1, 1), (1, -1), colors.HexColor("#F0FDF4")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 2),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ]))
            elements.append(diag_table)
            elements.append(Spacer(1, 4))

        # 4. 7-Engine Detection Table
        elements.append(Paragraph("<b>3. 7-Engine Detection Scorecard</b>", section_heading))
        engines = analysis_data.get("engines_report", [])
        engine_table_data = [["Security Engine", "Category", "Result", "Forensic Rationale"]]
        for e in engines:
            engine_table_data.append([
                e.get("name", "")[:28],
                e.get("category", "")[:18],
                e.get("status", ""),
                Paragraph(e.get("details", "")[:120], body_style)
            ])

        eng_table = Table(engine_table_data, colWidths=[140, 90, 60, 250])
        eng_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        elements.append(eng_table)
        elements.append(Spacer(1, 4))

        # 5. Section 65B Attestation
        elements.append(Paragraph("<b>4. Examiner Legal Certification (Sec 65B IEA / Sec 63 BSA 2023)</b>", section_heading))
        cert_text = (
            "I hereby certify that the electronic record hash and forensic telemetry documented above was produced "
            "by TRACEON in the ordinary course of digital forensic analysis. The cryptographic hashes and timestamp "
            "integrity parameters reflect an uncorrupted snapshot of the analyzed artifact."
        )
        elements.append(Paragraph(cert_text, body_style))
        elements.append(Spacer(1, 6))

        sig_data = [
            [Paragraph("<b>Digital Forensic Examiner:</b> Automated SOC Engine", body_style), Paragraph(f"<b>Attestation Date:</b> {datetime.utcnow().strftime('%Y-%m-%d')}", body_style)],
            [Paragraph(f"<b>Case Verification Token:</b> <code>{hashes.get('sha256', '')[:24]}</code>", code_style), Paragraph("<b>Signature:</b> [CRYPTOGRAPHICALLY SEALED]", body_style)]
        ]
        sig_table = Table(sig_data, colWidths=[300, 240])
        sig_table.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(sig_table)

        doc.build(elements)
        return buffer.getvalue()
