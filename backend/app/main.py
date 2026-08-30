from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

# Uvicorn does not automatically load a project .env file. Load the backend
# configuration explicitly so the threat-intelligence API keys are available
# to the provider classes in every launch directory.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.api.routes.scan import router as scan_router
from app.api.routes.history import router as history_router

app = FastAPI(
    title="FraudLens AI",
    description=(
        "AI-powered fraud detection and intelligence platform "
        "for analyzing suspicious digital activity."
    ),
    version="0.1.0",
)


app.include_router(scan_router)
app.include_router(history_router)


@app.get("/")
async def root():
    return {
        "name": "FraudLens AI",
        "status": "online",
        "version": "0.1.0",
        "message": "Fraud intelligence backend is running.",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "fraudlens-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }