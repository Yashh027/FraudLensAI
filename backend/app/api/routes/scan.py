from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import (
    ScanRequest,
    ScanResponse,
)
from app.models.scan_history import ScanHistory
from app.services.scan_engine import scan_url_target
from app.services.url_normalizer import normalize_url_target


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
    )

    # Save the important result to PostgreSQL.
    history = ScanHistory(
        target=response.target,
        target_type=response.target_type,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
        verdict=response.risk_assessment.verdict,
        confidence=response.risk_assessment.confidence,
    )

    db.add(history)
    db.commit()
    db.refresh(history)

    # Keep the existing API response unchanged.
    return response