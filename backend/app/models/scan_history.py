from datetime import datetime, UTC
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, SessionLocal


def _default_user_id() -> int:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "system@fraudlens.local").first()
        if user is None:
            user = User(
                email="system@fraudlens.local",
                hashed_password="$2b$12$dummy.hash.for.migration.only",
                is_active=False,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user.id
    finally:
        db.close()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True, default=_default_user_id)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    verdict: Mapped[str] = mapped_column(String(80), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    report_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationship to user
    user: Mapped["User"] = relationship(back_populates="scans")


# Add the back-reference to User
User.scans = relationship("ScanHistory", back_populates="user", order_by=ScanHistory.created_at.desc())
