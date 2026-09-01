# FraudLens backend fixes

## What was fixed

1. The backend now explicitly loads `backend/.env` instead of relying on the process working directory. This fixes the three threat-intelligence providers being reported as unavailable when the API keys are present in `.env`.
2. URL input is normalized at the API boundary. Bare domains are treated as HTTPS, normal HTTP URLs remain HTTP, and common `https;//`, `https:/`, and `https;://` typos are repaired. Unsupported schemes are rejected instead of being silently rewritten.
3. The normalized URL is passed consistently to local analysis, domain intelligence, URLhaus, VirusTotal, and urlscan.io.
4. urlscan.io now uses the documented `api-key` header spelling and the duplicate `raise_for_status()` call was removed.
5. The provider registry/test setup is aligned with all three providers: URLhaus, VirusTotal, and urlscan.io.
6. The opening frontend animation was not touched by these backend changes.

## Required configuration

Create `backend/.env` from `.env.example` and add your own credentials:

```text
DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/fraudlens
VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_API_KEY
URLHAUS_API_KEY=YOUR_URLHAUS_AUTH_KEY
URLSCAN_API_KEY=YOUR_URLSCAN_API_KEY
```

Do not commit or upload `.env`.

## Run

From the `backend` directory:

```bash
python -m uvicorn app.main:app --reload
```

The API should then load all three keys from `.env`.
