# FraudLens AI — Threat Intelligence Platform

> **URL Scanner → Local Analysis → Threat Intelligence → Domain/DNS Intelligence → Deterministic Risk Engine → Explainable Assessment → Historical Tracking → Scan Comparison → Dashboard → PDF Security Report**

FraudLens AI is a full-stack threat intelligence platform that analyzes suspicious URLs using deterministic local indicators and external threat intelligence to identify malicious infrastructure before interaction.

---

## Architecture Overview

```
FraudLensAI/
├── backend/                    # FastAPI Python backend
│   ├── app/
│   │   ├── main.py             # FastAPI app, middleware, CORS, rate limiting
│   │   ├── database.py         # SQLAlchemy setup, schema migration
│   │   ├── api/routes/
│   │   │   ├── scan.py         # POST /api/v1/scan/url, POST /api/v1/scan/report.pdf
│   │   │   └── history.py      # GET /api/v1/history, /compare, /stats/overview
│   │   ├── models/
│   │   │   ├── scan.py         # Pydantic request/response models
│   │   │   └── scan_history.py # SQLAlchemy ORM for scan persistence
│   │   ├── services/
│   │   │   ├── scan_engine.py  # Pipeline orchestrator (normalize → analyze → intel → risk)
│   │   │   ├── risk_engine.py  # Deterministic risk calculation
│   │   │   ├── url_normalizer.py    # URL normalization + SSRF protection
│   │   │   ├── domain_intelligence.py  # RDAP/DNS/IP passive enrichment
│   │   │   ├── report_generator.py     # PDF report generation (ReportLab)
│   │   │   ├── reputation.py          # URLhaus wrapper
│   │   │   └── threat_intelligence/
│   │   │       ├── base.py            # ThreatIntelResult dataclass
│   │   │       ├── registry.py        # Provider registry
│   │   │       ├── urlhaus.py         # abuse.ch URLhaus API
│   │   │       ├── virustotal.py      # VirusTotal v3 API
│   │   │       └── urlscan.py         # urlscan.io submit+poll API
│   │   └── analyzers/
│   │       └── url_analyzer.py  # 18+ local URL detection rules
│   ├── tests/                   # 212+ automated tests
│   ├── requirements.txt
│   ├── .env.example
│   └── create_tables.py
├── frontend/                   # React 19 + Vite SPA
│   ├── src/
│   │   ├── App.jsx             # Single-page application (~2600 lines)
│   │   ├── App.css             # Full custom CSS (~3200 lines)
│   │   ├── main.jsx            # React entry point
│   │   └── index.css           # Global reset
│   ├── index.html
│   ├── package.json
│   └── vite.config.js          # Dev proxy to backend
└── data/                       # Reserved for datasets
```

---

## Detection Engine

### Local Analysis (18+ Rules)
The URL analyzer runs entirely locally with no network calls:

| Rule | Score | Description |
|------|-------|-------------|
| `brand_impersonation` | +30 | Brand name in non-official domain |
| `at_symbol_in_url` | +25 | `@` symbol used to disguise destination |
| `punycode_domain` | +25 | Homograph attack via punycode |
| `embedded_credentials` | +25 | Credentials in URL |
| `ip_based_url` | +20 | IP address instead of domain |
| `suspicious_keywords` | +15 | Credential/payment/security terms |
| `very_long_url` | +15 | Over 150 characters |
| `url_shortener` | +15 | Known shortener domain |
| `excessive_subdomains` | +15 | 5+ subdomain levels |
| `invalid_url_scheme` | +15 | Non-HTTP/HTTPS scheme |
| `no_https` | +5 | HTTP instead of HTTPS |
| `suspicious_tld` | +10 | High-risk TLD (.xyz, .top, etc.) |
| `excessive_url_encoding` | +10 | 5+ encoded characters |
| `unusual_port` | +10 | Non-standard port |
| `nested_url_parameter` | +12 | URL inside query parameter |
| `redirect_parameter` | +8 | Redirect-style parameter |
| `excessive_hyphens` | +5 | 3+ hyphens in hostname |
| `many_query_parameters` | +5 | 8+ query parameters |

### Risk Scoring Methodology
The risk engine combines three independent evidence sources:
1. **Local analysis score** — deterministic URL-level signals (0–100)
2. **Infrastructure score** — domain age, hosting, DNS signals (0–100)
3. **Threat intelligence** — external provider results

**Scoring rules:**
- The final score starts as the maximum of (local + infrastructure) and the strongest provider
- Supporting provider scores get a bounded boost (max +15)
- 2+ independent malicious providers → score forced to **100**
- 1 strong malicious provider (score ≥ 70) → score at least **90**
- 1 weak malicious provider → score capped at **69**
- A single provider never reaches 100 without independent corroboration

### Risk Levels
| Level | Score Range | Description |
|-------|------------|-------------|
| **Low** | 0–24 | No major indicators |
| **Medium** | 25–49 | Suspicious characteristics |
| **High** | 50–69 | Strong threat indicators |
| **Critical** | 70–100 | Confirmed or highly suspicious |

---

## Threat Intelligence Providers

| Provider | API | What it does |
|----------|-----|-------------|
| **URLhaus** | POST to abuse.ch | Checks if URL appears in URLhaus malicious URL database |
| **VirusTotal** | GET v3 API | Checks detection rate across 70+ antivirus engines |
| **urlscan.io** | Submit + poll | Submits URL for live web analysis, waits for verdict |

Providers run **concurrently** via `ThreadPoolExecutor` and failures are isolated — one provider crashing does not affect others.

---

## API Endpoints

### Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan/url` | Scan a URL and return full analysis |
| `POST` | `/api/v1/scan/report.pdf` | Generate PDF report from scan data |

### History
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/history` | Paginated scan history with filters |
| `GET` | `/api/v1/history/{id}` | Full scan detail with report |
| `GET` | `/api/v1/history/{id}/report.pdf` | Export PDF from stored record |
| `GET` | `/api/v1/history/compare` | Compare two scans side-by-side |
| `GET` | `/api/v1/history/stats/overview` | Dashboard statistics |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Component health (API, engine, DB, intelligence) |
| `GET` | `/health/live` | Liveness check |

---

## Security Measures

- **Rate limiting** — Sliding-window per-IP limit (default: 30 req/min)
- **Request size limits** — Max 16 KB request body
- **CORS** — Configurable allowed origins
- **SSRF protection** — Blocks localhost, private IPs, metadata endpoints
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, CSP, Referrer-Policy, Permissions-Policy
- **Graceful degradation** — Provider failures never crash the scan; database errors return 503

---

## Setup Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL (recommended) or SQLite

### Backend
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env    # Fill in DATABASE_URL and API keys
python create_tables.py
uvicorn app.main:app --reload
```

Backend runs at `http://127.0.0.1:8000`

### Frontend
```powershell
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` (Vite proxies `/api` and `/health` to the backend)

### Environment Variables
See [`backend/.env.example`](backend/.env.example) for all configuration options.

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL or SQLite connection string |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key |
| `URLHAUS_API_KEY` | No | URLhaus API key |
| `URLSCAN_API_KEY` | No | urlscan.io API key |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins |
| `RATE_LIMIT_PER_MINUTE` | No | Max requests per IP per minute |
| `LOG_LEVEL` | No | DEBUG, INFO, WARNING, ERROR |

---

## Testing

```powershell
cd backend
.\venv\Scripts\Activate.ps1
pytest tests/ -v
```

The test suite contains **212+ tests** covering:
- URL normalization (20 tests)
- Local URL analysis (15 tests)
- Risk engine logic (15 tests)
- API endpoints and validation (20 tests)
- Provider integration and failure isolation (15 tests)
- Domain intelligence (10 tests)
- Scan comparison and history (10 tests)
- Security and SSRF protection (20+ tests)
- Edge cases: empty input, malformed URLs, Unicode domains, conflicting providers, all-unavailable providers, private targets

---

## Frontend Features

- **Boot animation** — Branded 1.85s startup sequence
- **Live system status** — API, Engine, Intelligence, Database, Uptime
- **Operations Dashboard** — Real-time statistics from PostgreSQL
- **URL Scanner** — Terminal-style input with 8-stage scan animation
- **Results** — Score ring, explainability panel, URL decomposition, domain intelligence, DNS records
- **History** — Searchable/filterable table with date range, risk/status filters
- **Scan Comparison** — Side-by-side comparison with delta analysis
- **PDF Export** — Professional security reports
- **Responsive** — Optimized for desktop, tablet, and mobile
- **Accessible** — ARIA labels, keyboard navigation, skip links, reduced-motion support

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, Vite 8, Lucide React |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Database | PostgreSQL (prod) / SQLite (dev) |
| PDF | ReportLab |
| Testing | pytest, httpx |
| Threat Intel | URLhaus (abuse.ch), VirusTotal v3, urlscan.io |

---

## License

## Quick Start

### Local Development
```powershell
# Backend
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env    # Fill in DATABASE_URL and API keys
python create_tables.py
uvicorn app.main:app --reload

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Running Tests
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pytest tests/ -v          # 212/212 tests
```

---

## Production Deployment

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete deployment instructions.

### Architecture
```
User Browser → HTTPS → GitHub Pages (Frontend)
                              ↓ HTTPS API
                        FastAPI Backend (Render/Railway/Docker)
                              ↓
                        PostgreSQL + Threat Intelligence
```

### Deployment Steps
1. **Frontend** → GitHub Pages (automatic via GitHub Actions)
2. **Backend** → Render / Railway / Docker
3. **Database** → PostgreSQL (managed by hosting platform)

### Required Environment Variables

| Variable | Required | Used By | Secret? |
|----------|----------|---------|---------|
| `DATABASE_URL` | Yes | Backend | Yes |
| `ALLOWED_ORIGINS` | Yes | Backend | No |
| `VITE_API_BASE_URL` | Yes (prod) | Frontend build | No |
| `VIRUSTOTAL_API_KEY` | No | Backend | Yes |
| `URLHAUS_API_KEY` | No | Backend | Yes |
| `URLSCAN_API_KEY` | No | Backend | Yes |

### Health Check
- `GET /health/live` — Liveness (always 200 if server is up)
- `GET /health` — Readiness (reports API, engine, database, intelligence status)

---

## Security

- **SSRF protection** — Blocks localhost, private IPs, metadata endpoints
- **Rate limiting** — 30 requests/IP/minute (configurable)
- **Security headers** — X-Content-Type-Options, CSP, X-Frame-Options, Referrer-Policy
- **Secrets** — Never committed to git; all via environment variables
- **CORS** — Restricted to configured frontend origins only

---

## Project Status

| Phase | Status |
|-------|--------|
| Phase 1: Core Detection Engine | ✅ Complete |
| Phase 2: Explainability & Domain Intelligence | ✅ Complete |
| Phase 3: History & Investigation | ✅ Complete |
| Phase 4: PDF Reporting | ✅ Complete |
| Phase 5: System Reliability | ✅ Complete |
| Phase 6: Automated Testing (212 tests) | ✅ Complete |
| Phase 7: UI/UX & Accessibility | ✅ Complete |
| Phase 8: Production Deployment | ✅ Complete |

---

## License

This project is for educational and research purposes.