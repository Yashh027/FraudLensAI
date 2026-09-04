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
    """Ensure the database has the schema needed for scan history and auth."""
    try:
        Base.metadata.create_all(bind=engine)
        with engine.begin() as connection:
            table_names = set(inspect(connection).get_table_names())
            if "users" not in table_names:
                Base.metadata.tables["users"].create(bind=connection)
            if "scan_history" not in table_names:
                Base.metadata.tables["scan_history"].create(bind=connection)

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

            if "user_id" not in columns:
                if connection.dialect.name == "postgresql":
                    default_user_id = connection.execute(
                        text("SELECT id FROM users ORDER BY id LIMIT 1")
                    ).scalar_one_or_none()
                    if default_user_id is None:
                        connection.execute(
                            text("INSERT INTO users (email, hashed_password, is_active, created_at) VALUES (:email, :hashed_password, :is_active, NOW() AT TIME ZONE 'UTC')"),
                            {
                                "email": "system@fraudlens.local",
                                "hashed_password": "$2b$12$dummy.hash.for.migration.only",
                                "is_active": False,
                            },
                        )
                        default_user_id = connection.execute(
                            text("SELECT id FROM users ORDER BY id LIMIT 1")
                        ).scalar_one()
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS user_id INTEGER"))
                    connection.execute(text("UPDATE scan_history SET user_id = :user_id WHERE user_id IS NULL"), {"user_id": default_user_id})
                    connection.execute(text("ALTER TABLE scan_history ALTER COLUMN user_id SET DEFAULT :user_id"), {"user_id": default_user_id})
                    connection.execute(text("ALTER TABLE scan_history ALTER COLUMN user_id SET NOT NULL"))
                    try:
                        connection.execute(text("ALTER TABLE scan_history ADD CONSTRAINT fk_scan_history_user FOREIGN KEY (user_id) REFERENCES users(id)"))
                    except Exception:
                        pass
                else:
                    default_user_id = connection.execute(
                        text("SELECT id FROM users ORDER BY id LIMIT 1")
                    ).scalar_one_or_none()
                    if default_user_id is None:
                        connection.execute(
                            text("INSERT INTO users (email, hashed_password, is_active, created_at) VALUES (:email, :hashed_password, :is_active, CURRENT_TIMESTAMP)"),
                            {
                                "email": "system@fraudlens.local",
                                "hashed_password": "$2b$12$dummy.hash.for.migration.only",
                                "is_active": False,
                            },
                        )
                        default_user_id = connection.execute(
                            text("SELECT id FROM users ORDER BY id LIMIT 1")
                        ).scalar_one()
                    connection.execute(text("ALTER TABLE scan_history ADD COLUMN user_id INTEGER"))
                    connection.execute(text("UPDATE scan_history SET user_id = :user_id WHERE user_id IS NULL"), {"user_id": default_user_id})
                    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history(user_id)"))

            current_columns = {column["name"] for column in inspect(connection).get_columns("scan_history")}
            if "user_id" in current_columns:
                try:
                    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history(user_id)"))
                except Exception:
                    pass
    except Exception:
        return


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
