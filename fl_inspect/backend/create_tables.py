from app.database import Base, engine, ensure_phase3_schema
from app.models.scan_history import ScanHistory

Base.metadata.create_all(bind=engine)
ensure_phase3_schema()
print("Database tables created successfully.")
