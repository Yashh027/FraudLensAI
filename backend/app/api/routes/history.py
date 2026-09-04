from datetime import date, datetime, time, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.routes.auth import get_current_user
from app.database import get_db
from app.models.scan_history import ScanHistory, User
from app.services.report_generator import build_security_report

router = APIRouter(prefix="/api/v1/history", tags=["Scan History"])


def _record_summary(record: ScanHistory) -> dict[str, Any]:
    return {
        "id": record.id,
        "target": record.target,
        "target_type": record.target_type,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "verdict": record.verdict,
        "confidence": record.confidence,
        "status": record.status or "completed",
        "created_at": record.created_at,
        "has_report": bool(record.report_data),
    }


def _parse_date_start(value: str | None):
    if not value:
        return None
    try:
        return datetime.combine(date.fromisoformat(value), time.min, tzinfo=timezone.utc).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid start_date: {value}. Use YYYY-MM-DD.") from exc


def _parse_date_end(value: str | None):
    if not value:
        return None
    try:
        return datetime.combine(date.fromisoformat(value), time.max, tzinfo=timezone.utc).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid end_date: {value}. Use YYYY-MM-DD.") from exc


def _apply_user_filter(statement, current_user: User):
    """Apply user filter to a query."""
    return statement.where(ScanHistory.user_id == current_user.id)


def _apply_user_filter_count(count_statement, current_user: User):
    """Apply user filter to a count query."""
    return count_statement.where(ScanHistory.user_id == current_user.id)


@router.get("")
def get_scan_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None, max_length=300),
    risk_level: str | None = Query(None),
    status: str | None = Query(None),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    statement = _apply_user_filter(select(ScanHistory), current_user)
    count_statement = _apply_user_filter_count(select(func.count()).select_from(ScanHistory), current_user)
    filters = []

    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(ScanHistory.target.ilike(pattern))

    if risk_level:
        normalized = risk_level.strip().lower()
        if normalized not in {"low", "medium", "high", "critical"}:
            raise HTTPException(status_code=400, detail="risk_level must be low, medium, high, or critical.")
        filters.append(ScanHistory.risk_level == normalized)

    if status:
        normalized = status.strip().lower()
        if normalized not in {"completed", "failed", "partial"}:
            raise HTTPException(status_code=400, detail="status must be completed, partial, or failed.")
        filters.append(ScanHistory.status == normalized)

    start = _parse_date_start(start_date)
    end = _parse_date_end(end_date)
    if start:
        filters.append(ScanHistory.created_at >= start)
    if end:
        filters.append(ScanHistory.created_at <= end)

    if filters:
        statement = statement.where(*filters)
        count_statement = count_statement.where(*filters)

    statement = statement.order_by(ScanHistory.created_at.desc()).offset(offset).limit(limit)
    records = db.execute(statement).scalars().all()
    total = db.execute(count_statement).scalar_one()

    return {
        "items": [_record_summary(record) for record in records],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/compare")
def compare_scans(
    left_id: int = Query(..., ge=1),
    right_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if left_id == right_id:
        raise HTTPException(status_code=400, detail="Choose two different scans to compare.")

    left = db.execute(
        select(ScanHistory).where(ScanHistory.id == left_id, ScanHistory.user_id == current_user.id)
    ).scalar_one_or_none()
    right = db.execute(
        select(ScanHistory).where(ScanHistory.id == right_id, ScanHistory.user_id == current_user.id)
    ).scalar_one_or_none()
    if left is None or right is None:
        raise HTTPException(status_code=404, detail="One or both scan records were not found.")
    # Older history rows may predate detailed report storage. They are still
    # valid comparison targets for the fields that were persisted (score,
    # level, verdict, confidence). Treat missing report data as an empty
    # evidence set rather than hiding the scan from the selector or failing
    # the entire comparison.
    left_report = left.report_data if isinstance(left.report_data, dict) else {}
    right_report = right.report_data if isinstance(right.report_data, dict) else {}

    def finding_map(report):
        return {str(item.get("rule")): item for item in report.get("findings", []) if item.get("rule")}

    def intel_map(report):
        return {str(item.get("provider")): item for item in report.get("intelligence", []) if item.get("provider")}

    lf, rf = finding_map(left_report), finding_map(right_report)
    li, ri = intel_map(left_report), intel_map(right_report)

    local_changes = []
    for rule in sorted(set(lf) | set(rf)):
        before = lf.get(rule)
        after = rf.get(rule)
        before_score = int((before or {}).get("score", 0) or 0)
        after_score = int((after or {}).get("score", 0) or 0)
        if before_score != after_score or (before is None) != (after is None):
            local_changes.append({
                "rule": rule,
                "before": before,
                "after": after,
                "score_delta": after_score - before_score,
                "change": "increased" if after_score > before_score else "decreased" if after_score < before_score else "added" if after else "removed",
            })

    intelligence_changes = []
    for provider in sorted(set(li) | set(ri)):
        before = li.get(provider, {})
        after = ri.get(provider, {})
        before_score = before.get("score")
        after_score = after.get("score")
        before_malicious = before.get("malicious")
        after_malicious = after.get("malicious")
        if before_score != after_score or before_malicious != after_malicious or before.get("available") != after.get("available"):
            score_delta = None if before_score is None or after_score is None else int(after_score) - int(before_score)
            intelligence_changes.append({
                "provider": provider,
                "before": before,
                "after": after,
                "score_delta": score_delta,
                "change": "increased" if score_delta is not None and score_delta > 0 else "decreased" if score_delta is not None and score_delta < 0 else "changed",
            })

    left_score, right_score = left.risk_score, right.risk_score
    return {
        "left": _record_summary(left),
        "right": _record_summary(right),
        "summary": {
            "risk_score_delta": right_score - left_score,
            "risk_level_changed": left.risk_level != right.risk_level,
            "confidence_changed": left.confidence != right.confidence,
            "verdict_changed": left.verdict != right.verdict,
        },
        "local_signal_changes": local_changes,
        "intelligence_changes": intelligence_changes,
        "confidence": {"before": left.confidence, "after": right.confidence},
        "verdict": {"before": left.verdict, "after": right.verdict},
        "evidence_availability": {
            "before": bool(left.report_data),
            "after": bool(right.report_data),
            "note": "Signal-level comparison is limited for scans whose detailed report was not stored."
            if not left.report_data or not right.report_data
            else None,
        },
    }


@router.get("/stats/overview")
def get_history_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    records = db.execute(
        select(ScanHistory)
        .where(ScanHistory.user_id == current_user.id)
        .order_by(ScanHistory.created_at.desc())
    ).scalars().all()
    total = len(records)
    completed = sum(1 for r in records if (r.status or "completed") == "completed")
    safe = sum(1 for r in records if r.risk_score < 25)
    suspicious = sum(1 for r in records if 25 <= r.risk_score < 50)
    high_risk = sum(1 for r in records if 50 <= r.risk_score < 70)
    critical = sum(1 for r in records if r.risk_score >= 70)

    distribution = {
        "low": safe,
        "medium": suspicious,
        "high": high_risk,
        "critical": critical,
    }

    provider_stats: dict[str, dict[str, int]] = {}
    for record in records:
        for provider in ((record.report_data or {}).get("intelligence", []) or []):
            name = str(provider.get("provider") or "Unknown")
            item = provider_stats.setdefault(name, {"checks": 0, "malicious_matches": 0, "available": 0})
            item["checks"] += 1
            if provider.get("available"):
                item["available"] += 1
            if provider.get("malicious") is True:
                item["malicious_matches"] += 1

    average_score = round(sum(r.risk_score for r in records) / total, 1) if total else 0
    recent = [_record_summary(r) for r in records[:10]]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_scans": total,
        "completed_scans": completed,
        "safe_scans": safe,
        "suspicious_scans": suspicious,
        "high_risk_scans": high_risk,
        "critical_scans": critical,
        "average_risk_score": average_score,
        "risk_distribution": distribution,
        "threat_statistics": provider_stats,
        "recent_scans": recent,
    }


@router.get("/{scan_id}/report.pdf")
def export_security_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    record = db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id)
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Scan history record not found.")
    data = record.report_data if isinstance(record.report_data, dict) else {
        "target": record.target,
        "target_type": record.target_type,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "risk_assessment": {
            "confidence": record.confidence,
            "verdict": record.verdict,
        },
    }
    pdf = build_security_report(data, scanned_at=record.created_at)
    filename = f"FraudLens_Security_Report_{record.id}.pdf"
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    })


@router.get("/{scan_id}")
def get_scan_history_item(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    record = db.execute(
        select(ScanHistory).where(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id)
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=404, detail="Scan history record not found.")

    response = _record_summary(record)
    if record.report_data:
        response["report"] = record.report_data
    else:
        response["report"] = None
    return response
