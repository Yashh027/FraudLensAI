import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured")

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def ensure_phase3_schema() -> None:
    """Add Phase 3 history columns without destroying existing scan records."""
    try:
        with engine.begin() as connection:
            columns = {column["name"] for column in inspect(connection).get_columns("scan_history")}
            if "status" not in columns:
                if connection.dialect.name == "postgresql":
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'completed'"))
                else:
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'completed'"))
            if "report_data" not in columns:
                if connection.dialect.name == "postgresql":
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS report_data JSON"))
                else:
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN report_data JSON"))
    except Exception:
        # Table creation/migrations are handled by create_tables.py in fresh
        # environments. Do not make imports fail when the database is temporarily
        # unavailable during local development or tests.
        return


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
