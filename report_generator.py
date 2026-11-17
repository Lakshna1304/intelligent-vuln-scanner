from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from config import Config

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#64748b"),
}


class PDFReportGenerator:
    def __init__(self):
        Config.ensure_directories()
        self.styles = getSampleStyleSheet()
        self._register_custom_styles()

    def _register_custom_styles(self):
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=20,
                leading=24,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=8,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=13,
                leading=16,
                textColor=colors.HexColor("#1e3a8a"),
                spaceBefore=14,
                spaceAfter=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BodySmall",
                parent=self.styles["Normal"],
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#1e293b"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="TableCell",
                parent=self.styles["Normal"],
                fontSize=8,
                leading=10,
                textColor=colors.HexColor("#0f172a"),
            )
        )

    def _build_severity_chart(self, dist: Dict[str, int]) -> Drawing:
        drawing = Drawing(460, 170)
        labels = ["Critical", "High", "Medium", "Low", "Informational"]
        data = [dist.get(lbl, 0) for lbl in labels]

        if sum(data) == 0:
            drawing.add(String(120, 80, "No vulnerabilities recorded in this assessment.", fontSize=11))
            return drawing

        pie = Pie()
        pie.x = 65
        pie.y = 20
        pie.width = 130
        pie.height = 130
        pie.data = data
        pie.labels = [f"{lbl} ({val})" if val > 0 else "" for lbl, val in zip(labels, data)]
        pie.slices.strokeWidth = 0.8
        pie.slices.strokeColor = colors.white

        for idx, lbl in enumerate(labels):
            pie.slices[idx].fillColor = SEVERITY_COLORS[lbl]

        legend = Legend()
        legend.x = 250
        legend.y = 125
        legend.dx = 10
        legend.dy = 10
        legend.fontSize = 9
        legend.alignment = "right"
        legend.colorNamePairs = [(SEVERITY_COLORS[lbl], f"{lbl}: {dist.get(lbl, 0)}") for lbl in labels]

        drawing.add(pie)
        drawing.add(legend)
        return drawing

    def generate_report(self, scan: Dict[str, Any]) -> Path:
        filename = f"AegisVuln_Assessment_Scan_{scan['id']}_{scan['target'].replace(':', '_').replace('/', '_')}.pdf"
        output_path = Config.REPORTS_DIR / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=LETTER,
            rightMargin=0.6 * inch,
            leftMargin=0.6 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.65 * inch,
            title=f"Vulnerability Assessment Report - {scan['target']}",
        )

        story = []
        summary = scan.get("attack_surface_summary", {})
        sev_dist = summary.get("severity_distribution", {})
        generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        story.append(Paragraph("INTELLIGENT VULNERABILITY ASSESSMENT & RISK ANALYSIS REPORT", self.styles["ReportTitle"]))
        story.append(
            Paragraph(
                f"<b>Target System:</b> {scan['target']} &nbsp;|&nbsp; "
                f"<b>Assessment ID:</b> #{scan['id']} &nbsp;|&nbsp; "
                f"<b>Generated:</b> {generated_ts}",
                self.styles["BodySmall"],
            )
        )
        story.append(Spacer(1, 10))

        story.append(Paragraph("1. Executive Summary & Target Metadata", self.styles["SectionHeader"]))
        meta_data = [
            ["Target IP / Host", scan["target"], "Overall Risk Score", f"{scan['overall_risk_score']} / 10.0 ({scan['risk_grade']})"],
            ["Scan Profile", scan["scan_mode"].upper(), "Asset Criticality", scan["asset_criticality"]],
            ["Detected OS", f"{scan['os_detected']} ({scan['os_accuracy']}%)", "Open Ports Discovered", str(summary.get("total_open_ports", len(scan["ports"])))],
            ["Confirmed CVEs", str(summary.get("confirmed_cves_count", 0)), "Potential Security Risks", str(summary.get("potential_risks_count", 0))],
        ]
        meta_table = Table(meta_data, colWidths=[1.45 * inch, 2.15 * inch, 1.55 * inch, 2.15 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                    ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f1f5f9")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 10))

        exec_text = (
            f"An authorized, non-destructive vulnerability assessment was conducted against <b>{scan['target']}</b> "
            f"utilizing service banner enumeration, NIST NVD CVE correlation, and contextual business risk scoring. "
            f"The target achieved an overall risk rating of <b>{scan['risk_grade']} ({scan['overall_risk_score']}/10.0)</b> "
            f"across <b>{len(scan['ports'])}</b> active network services, identifying "
            f"<b>{summary.get('confirmed_cves_count', 0)} confirmed CVEs</b> and "
            f"<b>{summary.get('potential_risks_count', 0)} configuration/exposure risks</b>."
        )
        story.append(Paragraph(exec_text, self.styles["BodySmall"]))

        story.append(Paragraph("2. Risk Severity Distribution", self.styles["SectionHeader"]))
        story.append(self._build_severity_chart(sev_dist))

        story.append(Paragraph("3. Assessment Methodology & Scope Controls", self.styles["SectionHeader"]))
        methodology_text = (
            "1. <b>Authorization Verification:</b> Target CIDR scope and explicit operator consent were validated prior to packet transmission.<br/>"
            "2. <b>Service & Version Discovery:</b> Non-destructive TCP connect and version detection probes enumerated active listeners without exploit payloads.<br/>"
            "3. <b>CVE Intelligence Correlation:</b> Discovered product/version fingerprints were cross-referenced against verified NIST NVD v2.0 records.<br/>"
            "4. <b>Contextual Risk Prioritization:</b> Findings were ranked using CVSS base scores weighted by service exposure sensitivity and asset criticality."
        )
        story.append(Paragraph(methodology_text, self.styles["BodySmall"]))

        story.append(Paragraph("4. Discovered Attack Surface (Open Ports & Services)", self.styles["SectionHeader"]))
        port_rows = [["Port/Proto", "State", "Service", "Software & Version", "Exposure"]]
        for p in scan["ports"]:
            sw = f"{p.get('product', '')} {p.get('version', '')}".strip() or "Unidentified"
            port_rows.append(
                [
                    f"{p['port_number']}/{p['protocol']}",
                    p["state"].upper(),
                    p.get("service_name", "unknown"),
                    Paragraph(sw, self.styles["TableCell"]),
                    p.get("exposure_level", "Moderate"),
                ]
            )
        if len(port_rows) == 1:
            port_rows.append(["None", "-", "-", "No open ports detected", "-"])

        port_table = Table(port_rows, colWidths=[0.95 * inch, 0.75 * inch, 1.25 * inch, 3.35 * inch, 1.0 * inch])
        port_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(port_table)
        story.append(PageBreak())

        story.append(Paragraph("5. Prioritized Vulnerability Findings & Remediation Plan", self.styles["SectionHeader"]))
        if not scan["vulnerabilities"]:
            story.append(Paragraph("No confirmed vulnerabilities or configuration risks were detected.", self.styles["BodySmall"]))
        else:
            for v in scan["vulnerabilities"]:
                header_line = (
                    f"<b>Rank #{v['priority_rank']} | [{v['severity'].upper()}] {v['title']}</b> "
                    f"(CVE: {v['cve_id']} | CVSS: {v['cvss_score']} | Priority: {v['priority_score']}/10.0)"
                )
                story.append(Paragraph(header_line, self.styles["BodySmall"]))
                detail_data = [
                    ["Classification", f"{v['finding_type']} ({v.get('source', 'NVD/Nmap')})", "Affected Service", f"Port {v.get('port_number') or 'N/A'} ({v.get('affected_software', 'N/A')})"],
                    ["Description", Paragraph(v["description"], self.styles["TableCell"]), "", ""],
                    ["Technical Evidence", Paragraph(v.get("evidence", "N/A"), self.styles["TableCell"]), "", ""],
                    ["Business Impact", Paragraph(v.get("business_impact", "N/A"), self.styles["TableCell"]), "", ""],
                    ["Remediation", Paragraph(v["remediation"], self.styles["TableCell"]), "", ""],
                ]
                v_table = Table(detail_data, colWidths=[1.25 * inch, 2.4 * inch, 1.25 * inch, 2.4 * inch])
                v_table.setStyle(
                    TableStyle(
                        [
                            ("SPAN", (1, 1), (3, 1)),
                            ("SPAN", (1, 2), (3, 2)),
                            ("SPAN", (1, 3), (3, 3)),
                            ("SPAN", (1, 4), (3, 4)),
                            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
                            ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#f1f5f9")),
                            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                            ("FONTNAME", (2, 0), (2, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("PADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.append(v_table)
                story.append(Spacer(1, 10))

        story.append(Paragraph("6. Overall Security Recommendations", self.styles["SectionHeader"]))
        rec_text = (
            "• <b>Immediate Patching (0–7 Days):</b> Remediate all Critical and High Confirmed CVEs starting with Rank #1.<br/>"
            "• <b>Network Segmentation:</b> Restrict administrative and datastore ports (SSH, SMB, MySQL, Redis) to management VLANs.<br/>"
            "• <b>Protocol Hardening:</b> Replace cleartext services (FTP/Telnet) with encrypted alternatives (SFTP/SSH) and enforce TLS 1.2+.<br/>"
            "• <b>Continuous Re-Assessment:</b> Re-run an assessment after remediation and use the Scan Comparison engine to verify closure."
        )
        story.append(Paragraph(rec_text, self.styles["BodySmall"]))

        doc.build(story)
        return output_path
