# FraudLens AI — Phase 5 Reliability Changes

## System health
- Added `/health` component checks for API, scan engine, database connectivity, threat-intelligence configuration, and real backend uptime.
- Added `/health/live` liveness endpoint.
- Frontend API / ENGINE / INTEL / DB indicators now use live health data instead of static claims.
- Removed the fake randomized uptime percentage; uptime now reflects the backend process.
- Dashboard and history no longer display fake zero/empty data when PostgreSQL is unavailable.

## Error handling
- Added safe handling for oversized/malformed request headers, unexpected server exceptions, and SQLAlchemy failures.
- Database persistence failures now return a clear HTTP 503 instead of crashing the request.
- Provider failures remain isolated from the rest of a scan.
- Provider timeout, rate-limit, network, and malformed-response cases are handled explicitly where applicable.
- Threat-intelligence requests are run concurrently so one slow provider does not unnecessarily serialize every provider lookup.
- Frontend API calls have bounded timeouts and clearer user-facing failure messages.
- Scan request timeout was extended to accommodate the existing passive intelligence workflow.

## Preserved
- Existing provider card presentation.
- Existing scan animation / opening boot animation.
- Phase 1 scoring and analysis behavior.
- Phase 2 explainability, URL/DNS/domain intelligence.
- Phase 3 history, comparison, and real PostgreSQL dashboard data.
- Phase 4 PDF reporting.
