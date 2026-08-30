from app.database import Base, engine
from app.models.scan_history import ScanHistory

Base.metadata.create_all(bind=engine)

print("Database tables created successfully.")