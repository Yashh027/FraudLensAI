import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.api.routes.scan import router as scan_router
from app.api.routes.history import router as history_router



def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero.")
    return value


MAX_REQUEST_BYTES = _positive_int_env("MAX_REQUEST_BYTES", 16384)
RATE_LIMIT_PER_MINUTE = _positive_int_env("RATE_LIMIT_PER_MINUTE", 30)

ALLOWED_ORIGINS = [
    origin.strip() for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",") if origin.strip()
]

app = FastAPI(
    title="FraudLens AI",
    description="AI-powered fraud detection and intelligence platform for analyzing suspicious digital activity.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request is too large."})

    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket = _rate_buckets[client]
    while bucket and now - bucket[0] >= 60:
        bucket.popleft()
    if request.url.path.startswith("/api/") and len(bucket) >= RATE_LIMIT_PER_MINUTE:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again later."})
    if request.url.path.startswith("/api/"):
        bucket.append(now)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


app.include_router(scan_router)
app.include_router(history_router)


@app.get("/")
async def root():
    return {"name": "FraudLens AI", "status": "online", "version": "0.1.0", "message": "Fraud intelligence backend is running."}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "fraudlens-backend", "timestamp": datetime.now(timezone.utc).isoformat()}
