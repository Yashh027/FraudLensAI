# FraudLens AI — Backend Dockerfile
# Multi-stage build for a minimal production image.
#
# Build:
#   docker build -t fraudlens-backend .
#
# Run:
#   docker run -p 8000:8000 \
#     -e DATABASE_URL=postgresql+psycopg://... \
#     -e ALLOWED_ORIGINS=https://your-frontend.com \
#     fraudlens-backend

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS dependencies required by psycopg (PostgreSQL driver)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY backend/app/ ./app/
COPY backend/create_tables.py .

# Non-root user for production
RUN groupadd -r fraudlens && useradd -r -g fraudlens fraudlens
RUN chown -R fraudlens:fraudlens /app
USER fraudlens

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT:-8000}/health/live')"

CMD ["sh", "-c", "python create_tables.py && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]
