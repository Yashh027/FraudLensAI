from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan_history import ScanHistory


router = APIRouter(
    prefix="/api/v1/history",
    tags=["Scan History"],
)


@router.get("")
def get_scan_history(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of history records to return.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of records to skip.",
    ),
    db: Session = Depends(get_db),
):
    statement = (
        select(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    records = db.execute(statement).scalars().all()

    return [
        {
            "id": record.id,
            "target": record.target,
            "target_type": record.target_type,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "verdict": record.verdict,
            "confidence": record.confidence,
            "created_at": record.created_at,
        }
        for record in records
    ]


@router.get("/{scan_id}")
def get_scan_history_item(
    scan_id: int,
    db: Session = Depends(get_db),
):
    record = db.get(ScanHistory, scan_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Scan history record not found.",
        )

    return {
        "id": record.id,
        "target": record.target,
        "target_type": record.target_type,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "verdict": record.verdict,
        "confidence": record.confidence,
        "created_at": record.created_at,
    }