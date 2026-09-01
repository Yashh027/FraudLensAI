from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#07111f")
PANEL = colors.HexColor("#101a2a")
BORDER = colors.HexColor("#2a3950")
TEXT = colors.HexColor("#e8eef8")
MUTED = colors.HexColor("#9eabc0")
CYAN = colors.HexColor("#55d6ff")
GREEN = colors.HexColor("#48d597")
AMBER = colors.HexColor("#f2b84b")
RED = colors.HexColor("#ff637d")
WHITE = colors.white


def _safe(value: Any, fallback: str = "Not reported") -> str:
    if value is None or value == "":
        return fallback
    return str(value)


def _fmt_dt(value: Any) -> str:
    if not value:
        return "Not reported"
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _risk_color(level: str):
    return {"low": GREEN, "medium": AMBER, "high": RED, "critical": RED}.get(str(level).lower(), CYAN)


def _paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def build_security_report(data: dict[str, Any], scanned_at: Any = None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=17 * mm,
        bottomMargin=16 * mm,
        title="FraudLens Security Report",
        author="FraudLens AI",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=TEXT, spaceAfter=4)
    subtitle = ParagraphStyle("subtitle", parent=styles["Normal"], fontSize=9, leading=12, textColor=MUTED)
    section = ParagraphStyle("section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=CYAN, spaceBefore=9, spaceAfter=7)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=TEXT, spaceAfter=5)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=10, textColor=MUTED)
    label = ParagraphStyle("label", parent=body, fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=MUTED)
    value = ParagraphStyle("value", parent=body, fontName="Helvetica-Bold", fontSize=10, leading=12, textColor=TEXT)
    right = ParagraphStyle("right", parent=value, alignment=TA_RIGHT)

    target = _safe(data.get("target"))
    score = _safe(data.get("risk_score"), "0")
    level = _safe(data.get("risk_level"), "Unknown")
    assessment = data.get("risk_assessment") or {}
    confidence = _safe(assessment.get("confidence") or data.get("confidence"), "Unknown")
    verdict = _safe(assessment.get("verdict") or data.get("verdict"), "Assessment complete")
    explanation = _safe(assessment.get("explanation"), "No explanation was recorded.")
    recommendation = _safe(data.get("recommendation"), "No recommendation was recorded.")
    findings = data.get("findings") or []
    intelligence = data.get("intelligence") or []
    components = data.get("url_components") or []
    domain = data.get("domain_info") or {}
    registration = domain.get("registration") or {}
    infrastructure = domain.get("infrastructure") or {}
    dns = domain.get("dns") or {}

    story = []
    story.append(Table([[Paragraph("FRAUDLENS", title), Paragraph("SECURITY INTELLIGENCE REPORT", subtitle)]], colWidths=[95 * mm, 75 * mm], style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY), ("BOX", (0, 0), (-1, -1), 0.6, BORDER), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ])))
    story += [Spacer(1, 6), _paragraph("Professional URL threat assessment generated from the FraudLens analysis engine.", small), Spacer(1, 5)]

    meta = [[_paragraph("TARGET URL", label), _paragraph("SCAN TIMESTAMP", label)], [_paragraph(target, value), _paragraph(_fmt_dt(scanned_at or data.get("scan_timestamp") or datetime.now(timezone.utc)), value)]]
    story.append(Table(meta, colWidths=[95 * mm, 75 * mm], style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.5, BORDER), ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ])))

    story.append(_paragraph("FINAL ASSESSMENT", section))
    assessment_table = [[_paragraph("RISK SCORE", label), _paragraph("RISK LEVEL", label), _paragraph("CONFIDENCE", label), _paragraph("VERDICT", label)], [_paragraph(f"{score}/100", value), _paragraph(level.upper(), value), _paragraph(confidence, value), _paragraph(verdict, value)]]
    t = Table(assessment_table, colWidths=[42 * mm, 42 * mm, 42 * mm, 44 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.6, _risk_color(level)), ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(t)
    story += [_paragraph("ENGINE EXPLANATION", label), _paragraph(explanation, body)]

    story.append(_paragraph("LOCAL FINDINGS", section))
    if findings:
        rows = [[_paragraph("FINDING", label), _paragraph("SEVERITY", label), _paragraph("IMPACT", label), _paragraph("DESCRIPTION", label)]]
        for f in findings:
            rows.append([_paragraph(_safe(f.get("rule")), body), _paragraph(_safe(f.get("severity")), body), _paragraph(f"+{_safe(f.get('score'), '0')}", body), _paragraph(_safe(f.get("description")), body)])
        ft = Table(rows, colWidths=[43 * mm, 27 * mm, 18 * mm, 82 * mm], repeatRows=1)
        ft.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), CYAN), ("GRID", (0, 0), (-1, -1), 0.35, BORDER), ("BACKGROUND", (0, 1), (-1, -1), PANEL), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(ft)
    else:
        story.append(_paragraph("No local suspicious characteristics were recorded.", body))

    story.append(_paragraph("THREAT INTELLIGENCE", section))
    if intelligence:
        rows = [[_paragraph("PROVIDER", label), _paragraph("STATUS", label), _paragraph("SCORE", label), _paragraph("RESULT", label)]]
        for p in intelligence:
            status = "AVAILABLE" if p.get("available") else "UNAVAILABLE"
            if p.get("malicious") is True:
                result = "MALICIOUS"
            elif p.get("malicious") is False:
                result = "No malicious result"
            else:
                result = _safe(p.get("details"), "No result")
            rows.append([_paragraph(_safe(p.get("provider")), body), _paragraph(status, body), _paragraph(_safe(p.get("score"), "—"), body), _paragraph(result, body)])
        it = Table(rows, colWidths=[40 * mm, 28 * mm, 20 * mm, 82 * mm], repeatRows=1)
        it.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.35, BORDER), ("BACKGROUND", (0, 1), (-1, -1), PANEL), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(it)
    else:
        story.append(_paragraph("No threat-intelligence provider results were recorded.", body))

    story.append(PageBreak())
    story.append(_paragraph("URL STRUCTURE & DOMAIN INTELLIGENCE", section))
    if components:
        rows = [[_paragraph("COMPONENT", label), _paragraph("VALUE", label), _paragraph("STATUS", label)]]
        for c in components:
            status = "FLAGGED" if c.get("suspicious") else _safe(c.get("status"), "PARSED")
            if c.get("reason"):
                status += f" — {c['reason']}"
            rows.append([_paragraph(_safe(c.get("key")), body), _paragraph(_safe(c.get("value")), body), _paragraph(status, body)])
        ct = Table(rows, colWidths=[38 * mm, 78 * mm, 54 * mm], repeatRows=1)
        ct.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.35, BORDER), ("BACKGROUND", (0, 1), (-1, -1), PANEL), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(ct)
    else:
        story.append(_paragraph("URL component data was not recorded.", body))

    story.append(_paragraph("DOMAIN / INFRASTRUCTURE", section))
    infra_rows = [
        ["Hostname", _safe(domain.get("hostname") or domain.get("domain"))],
        ["Domain", _safe(domain.get("domain"))],
        ["Subdomain", _safe(domain.get("subdomain"))],
        ["TLD", _safe(domain.get("tld"))],
        ["Lookup status", _safe(domain.get("lookup_status"))],
        ["Registrar", _safe(registration.get("registrar"))],
        ["Registration", _safe(registration.get("created_date") or registration.get("creation_date"))],
        ["IP addresses", ", ".join(map(str, infrastructure.get("ips") or [])) or "Not reported"],
        ["ASN", f"AS{infrastructure.get('asn')}" if infrastructure.get("asn") else "Not reported"],
        ["Hosting / ISP", _safe(infrastructure.get("isp") or infrastructure.get("organization") or infrastructure.get("hosting"))],
        ["Country", _safe(infrastructure.get("country") or infrastructure.get("location"))],
        ["DNS A", ", ".join(map(str, dns.get("A") or dns.get("a") or [])) or "Not reported"],
        ["DNS AAAA", ", ".join(map(str, dns.get("AAAA") or dns.get("aaaa") or [])) or "Not reported"],
        ["DNS MX", ", ".join(map(str, dns.get("MX") or dns.get("mx") or [])) or "Not reported"],
        ["DNS NS", ", ".join(map(str, dns.get("NS") or dns.get("ns") or [])) or "Not reported"],
    ]
    dt = Table([[ _paragraph(k, label), _paragraph(v, body)] for k, v in infra_rows], colWidths=[42 * mm, 128 * mm])
    dt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.35, BORDER), ("BACKGROUND", (0, 0), (0, -1), NAVY), ("BACKGROUND", (1, 0), (1, -1), PANEL), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(dt)

    story.append(_paragraph("RECOMMENDATION", section))
    rec = Table([[_paragraph(recommendation, body)]], colWidths=[170 * mm])
    rec.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.6, _risk_color(level)), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(rec)
    story += [Spacer(1, 8), HRFlowable(width="100%", thickness=0.5, color=BORDER), Spacer(1, 5), _paragraph("FraudLens AI • Security intelligence report • Generated from recorded scan evidence. This report is an analytical assessment, not a guarantee of safety.", small)]

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.setFillColor(CYAN)
        canvas.rect(15 * mm, A4[1] - 8 * mm, 22 * mm, 1.1 * mm, fill=1, stroke=0)
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 6.5)
        canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"FRAUDLENS-X  /  PAGE {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buffer.getvalue()
