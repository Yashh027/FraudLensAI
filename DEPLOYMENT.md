# FraudLens AI — Deployment Guide

This document explains how to deploy FraudLens AI to production.

## Architecture

```
User Browser
     │
     │ HTTPS
     ▼
GitHub Pages (React/Vite Frontend)
     │
     │ HTTPS API requests
     ▼
Production FastAPI Backend (Render / Railway / Docker)
     │
     ├──────────────────────┐
     │                      │
     ▼                      ▼
PostgreSQL           Threat Intelligence
                    URLhaus / VirusTotal / urlscan.io
```

**Key principle:** The frontend is a static site. It communicates with the backend over HTTPS. The backend talks to threat intelligence providers. Secrets never reach the frontend.

---

## 1. Frontend → GitHub Pages

### Setup Steps

1. **Push your code to GitHub** (repository name: `FraudLensAI`)

2. **Set repository variables** (Settings → Secrets and variables → Actions → Variables):
   | Variable | Value | Example |
   |----------|-------|---------|
   | `VITE_API_BASE_URL` | Your deployed backend URL | `https://fraudlens-api.onrender.com` |
   | `VITE_BASE_PATH` | Empty for user sites, `/REPO/` for project sites | (leave empty for `username.github.io`) |

3. **Enable GitHub Pages** (Settings → Pages):
   - Source: **GitHub Actions**

4. **Push to `main` branch** — the workflow `.github/workflows/deploy-frontend.yml` builds and deploys automatically.

5. **Verify** — visit `https://YOUR_USERNAME.github.io/`

### Important Notes
- `VITE_API_BASE_URL` must be set as a **repository variable** (not a secret) because Vite replaces `import.meta.env.VITE_*` at build time
- Never put API keys into `VITE_*` variables — only the backend URL is public
- The Vite proxy (`vite.config.js`) is only active during `npm run dev` and is not used in production builds

---

## 2. Backend → Render (Recommended)

### Option A: Docker (Recommended)

The repository includes a `Dockerfile` and `render.yaml` for one-click deployment.

For multi-instance deployments, provision a Redis instance separately and set `REDIS_URL` in the service environment. The app returns a `503` if Redis is unavailable so production traffic is never silently unthrottled.

1. **Fork/clone the repository**

2. **Create a new Web Service on Render** (render.com):
   - Environment: **Docker**
   - Dockerfile: `./Dockerfile`
   - Branch: `main`

3. **Create a PostgreSQL database on Render**:
   - Type: **PostgreSQL** (Free tier available)
   - Note the **Internal Database URL** — this is your `DATABASE_URL`

4. **Set environment variables** on the Web Service:
   | Variable | Required | Description |
   |----------|----------|-------------|
   | `DATABASE_URL` | Yes | PostgreSQL connection string from Render |
   | `ALLOWED_ORIGINS` | Yes | `https://YOUR_USERNAME.github.io` |
   | `VIRUSTOTAL_API_KEY` | No | VirusTotal API key |
   | `URLHAUS_API_KEY` | No | URLhaus API key |
   | `URLSCAN_API_KEY` | No | urlscan.io API key |
   | `LOG_LEVEL` | No | `INFO` (default) |
   | `REDIS_URL` | Yes for multi-instance deployments | Redis connection string for the shared rate limiter |
| `RATE_LIMIT_PER_MINUTE` | No | `30` (default) |

5. **Deploy** — Render auto-deploys on push to `main`

6. **Initialize database** — On first deploy, the backend runs `create_tables.py` automatically via the Dockerfile CMD

7. **Verify** — visit `https://YOUR_SERVICE.onrender.com/health`

### Option B: Native Render (No Docker)

If Docker is not preferred, Render can run Python directly:
- Build command: `cd backend && pip install -r requirements.txt`
- Start command: `cd backend && python create_tables.py && uvicorn app.main:app --host 0.0.0.0 --port $PORT`

### Option C: Railway

1. Create a new Railway project
2. Add a PostgreSQL service
3. Deploy the backend service from the repository
4. Set the same environment variables
5. Railway automatically detects the Dockerfile

---

## 3. Database Setup

### Production (PostgreSQL)

The application requires PostgreSQL for scan history, dashboard statistics, and comparison features.

**If using Render:** A managed PostgreSQL database is created automatically via `render.yaml`. No manual setup required.

**If using external PostgreSQL:**
```sql
CREATE DATABASE fraudlens;
CREATE USER fraudlens_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE fraudlens TO fraudlens_user;
```

Set `DATABASE_URL` to:
```
postgresql+psycopg://fraudlens_user:your_password@host:5432/fraudlens
```

### Local Development (SQLite)

For quick local development without PostgreSQL:
```
DATABASE_URL=sqlite:///./fraudlens.db
```

The `create_tables.py` script creates/updates tables automatically.

---

## 4. Environment Variables Reference

| Variable | Required | Used By | Description | Secret? |
|----------|----------|---------|-------------|---------|
| `DATABASE_URL` | Yes | Backend | PostgreSQL/SQLite connection string | Yes |
| `ALLOWED_ORIGINS` | Yes | Backend | Comma-separated frontend origins for CORS | No |
| `VIRUSTOTAL_API_KEY` | No | Backend | VirusTotal API key | Yes |
| `URLHAUS_API_KEY` | No | Backend | URLhaus API key | Yes |
| `URLSCAN_API_KEY` | No | Backend | urlscan.io API key | Yes |
| `REDIS_URL` | Yes for distributed rate limiting | Backend | Redis connection string for shared rate limiting | Yes |
| `RATE_LIMIT_PER_MINUTE` | No | Backend | Max requests/IP/minute (default: 30) | No |
| `MAX_REQUEST_BYTES` | No | Backend | Max request body size (default: 16384) | No |
| `LOG_LEVEL` | No | Backend | DEBUG/INFO/WARNING/ERROR (default: INFO) | No |
| `VITE_API_BASE_URL` | Yes (prod) | Frontend build | Backend public URL | No |
| `VITE_BASE_PATH` | No | Frontend build | Vite base path for GitHub Pages | No |

---

## 5. CORS Configuration

The backend's `ALLOWED_ORIGINS` must include your frontend's public URL.

| Environment | `ALLOWED_ORIGINS` |
|------------|-------------------|
| Local development | `http://localhost:5173,http://127.0.0.1:5173` |
| GitHub Pages | `https://YOUR_USERNAME.github.io` |
| Custom domain | `https://your-domain.com` |

Multiple origins can be comma-separated. CORS is enforced on all `/api/*` and `/health` endpoints.

---

## 6. Health Endpoints

| Endpoint | Purpose | Dependencies |
|----------|---------|-------------|
| `GET /health/live` | Liveness probe (always returns 200 if server is up) | None |
| `GET /health` | Readiness probe (reports component status) | Database connectivity |

The `/health` endpoint reports the status of: API, scan engine, database, and threat intelligence configuration.

**Never expose these endpoints to authentication** — monitoring systems need unauthenticated access.

---

## 7. Running Tests

### Backend
```bash
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1     # Windows
pip install -r requirements.txt
pytest tests/ -v
```

### Frontend
```bash
cd frontend
npm install
npm run build    # verify production build
```

The test suite should report **212/212 tests passing**.

---

## 8. Troubleshooting

### CORS errors in browser console
- Verify `ALLOWED_ORIGINS` on the backend includes your frontend's exact URL
- Must include the protocol (`https://`) and no trailing slash
- Example: `https://username.github.io` not `https://username.github.io/`

### Frontend shows "Could not connect to backend"
- Verify `VITE_API_BASE_URL` is set correctly in the build environment
- Rebuild the frontend after changing environment variables
- Check the backend is running and accessible at the configured URL

### 429 Too Many Requests
- The rate limiter allows 30 requests per IP per minute by default
- Increase `RATE_LIMIT_PER_MINUTE` if needed
- The limiter is Redis-backed and shared across backend instances; if Redis is unavailable, the API returns `503` instead of silently disabling protection

### Database connection failure
- Verify `DATABASE_URL` is correct
- Check the database is accessible from the backend hosting environment
- Render PostgreSQL: use the Internal Database URL, not the External one

### GitHub Pages blank page
- Check `VITE_BASE_PATH` matches your repository name
- For `username.github.io/REPO_NAME/`, set `VITE_BASE_PATH=/REPO_NAME/`
- For `username.github.io`, leave `VITE_BASE_PATH` empty or `/`
- Verify the GitHub Actions workflow completed successfully

### Health endpoint returns unhealthy
- Check database connectivity from the backend
- Verify the backend can resolve the database hostname
- Check backend logs for connection errors

---

## 9. Production Security Checklist

- [ ] `.env` is never committed to git
- [ ] `ALLOWED_ORIGINS` is restricted (not `*`)
- [ ] API keys are stored as environment variables, not in code
- [ ] The frontend never contains API keys or secrets
- [ ] Rate limiting is active
- [ ] SSRF protections are active (blocks localhost, private IPs)
- [ ] Security headers are present (X-Content-Type-Options, CSP, etc.)
- [ ] Database credentials are not in source code
- [ ] Error responses do not expose stack traces
- [ ] Health endpoints do not expose secrets

---

## 10. Architecture Notes

- **History is not user-isolated** — all scans are stored in a shared database table. Authentication/authorization can be added later.
- **Rate limiting is process-local** — each backend instance has its own rate limiter. For multi-instance deployments, consider a distributed rate limiter.
- **Threat intelligence providers are optional** — the local URL analyzer always runs. Providers that are not configured are reported as "degraded" in health checks.
- **PDF generation is in-memory** — no temporary files are written to disk.
