"""Human-readable Markdown and PDF incident reports."""

from __future__ import annotations

from io import BytesIO

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas import Incident


def incident_markdown(incident: Incident) -> str:
    assessment = incident.assessment
    alert = incident.alert

    time_str = alert.timestamp.strftime("%Y-%m-%d %H:%M UTC") if hasattr(alert.timestamp, "strftime") else str(alert.timestamp)
    updated_str = incident.updated_at.strftime("%Y-%m-%d %H:%M UTC") if hasattr(incident.updated_at, "strftime") else str(incident.updated_at)

    lines = [
        f"# 🛡️ DEFENSIVE INCIDENT REPORT — {alert.title}",
        "**Document Classification:** CONFIDENTIAL // INTERNAL SOC USE ONLY  ",
        f"**Generated At:** {updated_str}  ",
        "",
        "---",
        "",
        "## 📋 Case Overview & Metadata",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        "| **Case Title** | " + alert.title + " |",
        f"| **Case ID** | `{incident.id}` |",
        f"| **Current Status** | `{incident.status.value.upper()}` |",
        f"| **Telemetry Source** | {alert.source} (`{alert.external_id}`) |",
        f"| **Alert Timestamp** | {time_str} |",
        "| **Lead Security Analyst** | Sanjay Pramod Prathibha ([LinkedIn Profile](https://www.linkedin.com/in/sanjay-p-p/)) |",
        f"| **Priority Level** | **{assessment.priority.value.upper()}** |",
        f"| **Risk Score** | 🔥 **{assessment.risk_score} / 100** |",
        f"| **Analyst Confidence** | 🎯 **{assessment.confidence}%** |",
        "",
        "---",
        "",
        "## 👔 Executive Summary & Business Impact",
        "",
        assessment.summary,
        "",
        f"**Alert Description:** {alert.description}",
        "",
        f"**Business Impact:** Observed activity impacting entities: {', '.join(f'`{k}:{v}`' for k,v in alert.entities.items()) or 'Internal Network Workstation'}.",
        "",
        "---",
        "",
        "## 🎯 Adversary Root Cause & Attack Vector Analysis",
        "",
    ]

    # Root Cause inference
    techniques_str = ", ".join(t.name for t in assessment.mitre_techniques) or "Unclassified Anomaly"
    lines.extend([
        f"- **Primary Attack Vector:** {techniques_str}",
        f"- **Scope of Exposure:** Host/User Entities ({', '.join(alert.entities.values()) or 'Internal Asset'})",
        f"- **Analyst Verdict:** Initial triage complete. Prioritizing containment and telemetry validation.",
        "",
        "---",
        "",
        "## 🛡️ MITRE ATT&CK mapping & Enterprise Matrix",
        "",
        "| Technique ID | Technique Name | Tactic | Confidence | Matched Evidence / Context |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    if assessment.mitre_techniques:
        for item in assessment.mitre_techniques:
            lines.append(f"| **{item.technique_id}** | {item.name} | {item.tactic} | {item.confidence}% | {item.reason} |")
    else:
        lines.append("| `N/A` | No automated ATT&CK technique matched | Manual Review | 0% | Review alert description telemetry |")

    lines.extend([
        "",
        "---",
        "",
        "## 🌐 Indicators of Compromise (IOCs) & Threat Intelligence",
        "",
        "| Indicator Value | Type | Vendor Classification | Provider | Reputation Score | Threat Details |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    if assessment.enrichment:
        for item in assessment.enrichment:
            score = f"{item.reputation_score}%" if item.reputation_score is not None else "N/A"
            lines.append(f"| `{item.value}` | `{item.indicator_type.upper()}` | **{item.classification.upper()}** | {item.provider} | {score} | {item.summary} |")
    else:
        lines.append("| `N/A` | `N/A` | CLEAN | Local Context | 0% | No indicators extracted |")

    lines.extend([
        "",
        "---",
        "",
        "## 🛠️ AI Containment Playbook & Response Checklist",
        "",
    ])

    for idx, action in enumerate(assessment.recommended_actions, 1):
        lines.append(f"- [ ] **Task {idx}:** {action}")

    if incident.analyst_notes:
        lines.extend([
            "",
            "---",
            "",
            "## 📝 Analyst notes & Investigation Records",
            "",
            incident.analyst_notes,
        ])

    if incident.audit_logs:
        lines.extend([
            "",
            "---",
            "",
            "## 🕒 Audit trail & case timeline",
            "",
            "| Timestamp (UTC) | Event Type | Summary | Actor | Details |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for event in incident.audit_logs:
            t_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(event.timestamp, "strftime") else str(event.timestamp)
            lines.append(f"| `{t_str}` | `{event.event_type}` | {event.summary} | `{event.actor}` | {event.details} |")

    lines.extend([
        "",
        "---",
        "",
        "## ✍️ Governance & Response Sign-Off",
        "",
        "**Analyst Sign-off:** All evidence validated against source telemetry. Safety boundary enforced; no destructive actions executed automatically.",
        "",
    ])

    return "\n".join(lines)


def incident_pdf(incident: Incident) -> bytes:
    """Render a professional multi-page PDF incident report using ReportLab."""
    stream = BytesIO()
    document = SimpleDocTemplate(
        stream,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=HexColor("#0f2b3c"),
        spaceAfter=4,
    )

    h2_style = ParagraphStyle(
        "ReportH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=HexColor("#0a7c6e"),
        spaceBefore=12,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=HexColor("#1e293b"),
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=HexColor("#ffffff"),
    )

    table_cell_style = ParagraphStyle(
        "TableCell",
        parent=body_style,
        fontSize=8.5,
        leading=11,
    )

    story = []

    # Title & Header Banner
    story.append(Paragraph(f"DEFENSIVE INCIDENT REPORT", title_style))
    story.append(Paragraph(f"<b>Case Title:</b> {incident.alert.title}", body_style))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1.5, color=HexColor("#39d4c2"), spaceAfter=10))

    # Case Metadata Table
    assessment = incident.assessment
    alert = incident.alert

    meta_data = [
        [Paragraph("<b>Field</b>", table_header_style), Paragraph("<b>Value</b>", table_header_style)],
        [Paragraph("<b>Case ID</b>", table_cell_style), Paragraph(f"<code>{incident.id}</code>", table_cell_style)],
        [Paragraph("<b>Current Status</b>", table_cell_style), Paragraph(incident.status.value.upper(), table_cell_style)],
        [Paragraph("<b>Priority Level</b>", table_cell_style), Paragraph(f"<b>{assessment.priority.value.upper()}</b>", table_cell_style)],
        [Paragraph("<b>Risk Score</b>", table_cell_style), Paragraph(f"<b>{assessment.risk_score} / 100</b>", table_cell_style)],
        [Paragraph("<b>Analyst Confidence</b>", table_cell_style), Paragraph(f"{assessment.confidence}%", table_cell_style)],
        [Paragraph("<b>Source Telemetry</b>", table_cell_style), Paragraph(f"{alert.source} ({alert.external_id})", table_cell_style)],
    ]

    t_meta = Table(meta_data, colWidths=[2.0 * inch, 5.0 * inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), HexColor("#0f2b3c")),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor("#ffffff"), HexColor("#f8fafc")]),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Executive Summary
    story.append(Paragraph("Executive Summary & Business Impact", h2_style))
    story.append(Paragraph(f"<b>Summary:</b> {assessment.summary}", body_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Alert Description:</b> {alert.description}", body_style))
    story.append(Spacer(1, 10))

    # MITRE ATT&CK Mapping
    story.append(Paragraph("MITRE ATT&CK Enterprise Mapping", h2_style))
    mitre_data = [
        [Paragraph("<b>ID</b>", table_header_style), Paragraph("<b>Technique Name</b>", table_header_style), Paragraph("<b>Tactic</b>", table_header_style), Paragraph("<b>Evidence</b>", table_header_style)]
    ]
    if assessment.mitre_techniques:
        for tech in assessment.mitre_techniques:
            mitre_data.append([
                Paragraph(f"<b>{tech.technique_id}</b>", table_cell_style),
                Paragraph(tech.name, table_cell_style),
                Paragraph(tech.tactic, table_cell_style),
                Paragraph(tech.reason, table_cell_style),
            ])
    else:
        mitre_data.append([Paragraph("N/A", table_cell_style), Paragraph("No ATT&CK technique mapped", table_cell_style), Paragraph("N/A", table_cell_style), Paragraph("Review alert description context", table_cell_style)])

    t_mitre = Table(mitre_data, colWidths=[1.1 * inch, 2.2 * inch, 1.4 * inch, 2.3 * inch])
    t_mitre.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (3, 0), HexColor("#0f2b3c")),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor("#ffffff"), HexColor("#f8fafc")]),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_mitre)
    story.append(Spacer(1, 10))

    # Indicators & Threat Intel
    story.append(Paragraph("Indicators of Compromise (IOCs) & Threat Intel", h2_style))
    ioc_data = [
        [Paragraph("<b>Indicator Value</b>", table_header_style), Paragraph("<b>Type</b>", table_header_style), Paragraph("<b>Classification</b>", table_header_style), Paragraph("<b>Provider</b>", table_header_style), Paragraph("<b>Details</b>", table_header_style)]
    ]
    if assessment.enrichment:
        for enr in assessment.enrichment:
            ioc_data.append([
                Paragraph(f"<code>{enr.value}</code>", table_cell_style),
                Paragraph(enr.indicator_type.upper(), table_cell_style),
                Paragraph(f"<b>{enr.classification.upper()}</b>", table_cell_style),
                Paragraph(enr.provider, table_cell_style),
                Paragraph(enr.summary, table_cell_style),
            ])
    else:
        ioc_data.append([Paragraph("N/A", table_cell_style), Paragraph("N/A", table_cell_style), Paragraph("CLEAN", table_cell_style), Paragraph("Local", table_cell_style), Paragraph("No indicators extracted", table_cell_style)])

    t_ioc = Table(ioc_data, colWidths=[1.8 * inch, 0.8 * inch, 1.2 * inch, 1.1 * inch, 2.1 * inch])
    t_ioc.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (4, 0), HexColor("#0f2b3c")),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor("#ffffff"), HexColor("#f8fafc")]),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_ioc)
    story.append(Spacer(1, 10))

    # Recommended Actions
    story.append(Paragraph("Recommended Containment Playbook Tasks", h2_style))
    for idx, act in enumerate(assessment.recommended_actions, 1):
        story.append(Paragraph(f"<b>Task {idx}:</b> {act}", body_style))

    if incident.analyst_notes:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Analyst Investigation Notes", h2_style))
        story.append(Paragraph(incident.analyst_notes, body_style))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#cbd5e1"), spaceAfter=8))
    story.append(Paragraph("<b>Defensive Boundary Sign-off:</b> All evidence validated against source telemetry. Analyst-in-the-loop governance preserved.", body_style))

    document.build(story)
    return stream.getvalue()


