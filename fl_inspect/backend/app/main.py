import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.api.routes.scan import router as scan_router
from app.api.routes.history import router as history_router
from app.database import ensure_phase3_schema, engine



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
_SERVICE_STARTED_AT = time.monotonic()


@app.middleware("http")
async def reliability_middleware(request: Request, call_next):
    """Apply request guards and convert unexpected failures into useful API errors."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request is too large."})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})

    is_health = request.url.path in {"/health", "/health/live"}
    if request.url.path.startswith("/api/") and not is_health:
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = _rate_buckets[client]
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many API requests. Please wait a moment and try again.",
                    "error": "rate_limited",
                },
            )
        bucket.append(now)

    try:
        response = await call_next(request)
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Database service is temporarily unavailable. Your scan was not saved.",
                "error": "database_unavailable",
            },
        )
    except Exception:
        return JSONResponse(
            status_code=500,
            content={
                "detail": "FraudLens encountered an unexpected server error. No unsafe action was performed.",
                "error": "internal_server_error",
            },
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


ensure_phase3_schema()

app.include_router(scan_router)
app.include_router(history_router)


@app.get("/")
async def root():
    return {"name": "FraudLens AI", "status": "online", "version": "0.1.0", "message": "Fraud intelligence backend is running."}


def _health_component(status: str, message: str, **extra):
    return {"status": status, "message": message, **extra}


@app.get("/health/live")
async def liveness_check():
    return {
        "status": "healthy",
        "service": "fraudlens-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health_check():
    """Return real component health without requiring the database to be healthy."""
    components = {}

    components["api"] = _health_component(
        "healthy",
        "Backend API is responding.",
    )

    try:
        from app.services.scan_engine import scan_url_target
        engine_ready = callable(scan_url_target)
        components["engine"] = _health_component(
            "healthy" if engine_ready else "unhealthy",
            "Scan engine is loaded and ready." if engine_ready else "Scan engine is not available.",
        )
    except Exception:
        components["engine"] = _health_component(
            "unhealthy",
            "Scan engine could not be loaded.",
        )

    db_started = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - db_started) * 1000, 1)
        components["database"] = _health_component(
            "healthy",
            "Database connection is operational.",
            latency_ms=latency_ms,
        )
    except Exception:
        components["database"] = _health_component(
            "unhealthy",
            "Database connection failed.",
        )

    configured = []
    for env_name, provider_name in (
        ("URLHAUS_API_KEY", "URLhaus"),
        ("VIRUSTOTAL_API_KEY", "VirusTotal"),
        ("URLSCAN_API_KEY", "urlscan.io"),
    ):
        if os.getenv(env_name, "").strip():
            configured.append(provider_name)

    intelligence_status = "healthy" if configured else "degraded"
    if configured and len(configured) < 3:
        intelligence_status = "degraded"
    components["intelligence"] = _health_component(
        intelligence_status,
        f"{len(configured)} of 3 threat-intelligence providers configured.",
        configured=configured,
        configured_count=len(configured),
        total=3,
    )

    core_healthy = all(
        components[name]["status"] == "healthy"
        for name in ("api", "engine", "database")
    )
    overall = "healthy" if core_healthy and intelligence_status == "healthy" else "degraded"

    return {
        "status": overall,
        "service": "fraudlens-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": round(time.monotonic() - _SERVICE_STARTED_AT, 1),
        "components": components,
    }
