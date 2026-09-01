# Repository Guidelines

## Project Structure & Module Organization

FraudLens AI is currently organized around a FastAPI backend. Backend source lives in `backend/app/`: `main.py` creates the app and registers routers, `api/routes/` contains endpoint modules, `models/` holds Pydantic request and response schemas, `services/` wraps intelligence providers, and `analyzers/` contains local scoring logic. Tests live in `backend/tests/` and mirror the feature area they validate, for example `test_scan_api.py` and `test_url_analyzer.py`. `data/` is reserved for datasets or reference inputs, `docs/` for project documentation, and `frontend/` is present but currently empty.

## Build, Test, and Development Commands

Run commands from the repository root unless noted.

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload
```

`pip install -r requirements.txt` installs FastAPI, Uvicorn, pytest, httpx, and related runtime dependencies. `pytest` runs the backend test suite. `uvicorn app.main:app --reload` starts the local API with auto-reload; visit `http://127.0.0.1:8000/health` for a quick health check.

## Coding Style & Naming Conventions

Use Python with 4-space indentation, clear function names, and type-friendly Pydantic models. Keep route modules focused on request handling and orchestration; place reusable scoring or lookup logic in `analyzers/` or `services/`. Use `snake_case` for files, functions, and variables, and `PascalCase` for Pydantic models such as `ScanRequest`. Prefer small, explicit return objects over loosely shaped dictionaries at API boundaries.

## Testing Guidelines

The project uses pytest and FastAPI's `TestClient`. Name test files `test_*.py` and test functions `test_*`. Add tests when changing scoring behavior, API responses, validation, or external-provider fallback logic. Use `monkeypatch` for provider simulations so tests do not depend on live reputation services.

## Commit & Pull Request Guidelines

No Git history is present in this checkout, so there is no established commit convention yet. Use short, imperative commit messages such as `Add URL reputation fallback test` or `Refine scan response model`. Pull requests should include a brief summary, test results, linked issues if applicable, and example API payloads or screenshots when behavior changes.

## Security & Configuration Tips

Do not commit secrets, API keys, or local virtual environments. Keep environment examples in `.env.example`, and document any new configuration in `README.md` or `docs/`. External intelligence lookups should fail gracefully and preserve the local scan path when a provider is unavailable.
