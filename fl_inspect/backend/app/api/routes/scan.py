from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import (
    ScanRequest,
    ScanResponse,
)
from app.models.scan_history import ScanHistory
from app.services.scan_engine import scan_url_target
from app.services.url_normalizer import normalize_url_target
from app.services.report_generator import build_security_report


router = APIRouter(
    prefix="/api/v1/scan",
    tags=["Scanning"],
)


@router.post(
    "/url",
    response_model=ScanResponse,
)
async def scan_url(
    request: ScanRequest,
    db: Session = Depends(get_db),
):
    try:
        target = normalize_url_target(request.target)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # Run the existing scan engine.
    response = scan_url_target(
        target=target,
        enrich_domain=True,
    )

    # Save the important result to PostgreSQL.
    history = ScanHistory(
        target=response.target,
        target_type=response.target_type,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
        verdict=response.risk_assessment.verdict,
        confidence=response.risk_assessment.confidence,
        status="completed",
        report_data=response.model_dump(mode="json"),
    )

    try:
        db.add(history)
        db.commit()
        db.refresh(history)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=(
                "Scan analysis completed, but the database is currently unavailable, "
                "so the result could not be saved. Please try again when the database is online."
            ),
        ) from exc

    # Keep the existing API response unchanged.
    return response

@router.post("/report.pdf")
def export_security_report(scan: ScanResponse):
    pdf = build_security_report(scan.model_dump(mode="json"))
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="FraudLens_Security_Report.pdf"',
            "Cache-Control": "no-store",
        },
    )
