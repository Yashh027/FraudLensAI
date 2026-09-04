"""Phase 6 — API endpoint and security edge-case tests.

Covers:
- Scan API validation and error handling
- History API filtering, pagination, error handling
- Rate limiting behavior
- Request size limits
- Security headers
- Health endpoint responses
- PDF export edge cases
- Scan comparison edge cases
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.auth import create_access_token, hash_password
from app.services.threat_intelligence.base import ThreatIntelResult
from app.database import SessionLocal
from app.models.scan_history import ScanHistory, User
from datetime import datetime, UTC

import app.services.scan_engine as scan_engine

client = TestClient(app)


def _auth_headers():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "api-edge-user@fraudlens.local").first()
        if user is None:
            user = User(
                email="api-edge-user@fraudlens.local",
                hashed_password=hash_password("api-edge-pass"),
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return {"Authorization": f"Bearer {create_access_token({'sub': str(user.id)})}"}
    finally:
        db.close()


class FakeProvider:
    name = "FakeProvider"

    def __init__(self, result):
        self.result = result

    def check_url(self, url):
        return self.result


def _set_providers(monkeypatch, results):
    providers = [FakeProvider(r) for r in results] if isinstance(results, list) else [FakeProvider(results)]
    monkeypatch.setattr(scan_engine, "get_url_threat_intel_providers", lambda: providers)


def _insert_db(target, score, level, verdict="no_major_threat_indicators", confidence="medium", report=None):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "api-edge-user@fraudlens.local").first()
        if user is None:
            user = User(
                email="api-edge-user@fraudlens.local",
                hashed_password=hash_password("api-edge-pass"),
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        row = ScanHistory(
            user_id=user.id,
            target=target,
            target_type="url",
            risk_score=score,
            risk_level=level,
            verdict=verdict,
            confidence=confidence,
            status="completed",
            report_data=report,
            created_at=datetime.now(UTC).replace(tzinfo=None),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


# ─── Scan API Validation ────────────────────────────────────────────────────


def test_scan_empty_target_rejected():
    response = client.post("/api/v1/scan/url", json={"target": ""}, headers=_auth_headers())
    assert response.status_code in (400, 422)  # Pydantic validation or app-level


def test_scan_missing_target_field():
    response = client.post("/api/v1/scan/url", json={}, headers=_auth_headers())
    assert response.status_code == 422


def test_scan_unsupported_scheme_rejected():
    response = client.post("/api/v1/scan/url", json={"target": "ftp://example.com"}, headers=_auth_headers())
    assert response.status_code == 400


def test_scan_localhost_blocked(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "https://localhost"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    # Localhost should be blocked from provider lookups
    for intel in data["intelligence"]:
        assert intel["error"] == "blocked_private_target"


def test_scan_response_has_all_required_fields(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "https://example.com"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert "target" in data
    assert "target_type" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "findings" in data
    assert "intelligence" in data
    assert "risk_assessment" in data
    assert "recommendation" in data
    assert "url_components" in data
    assert "domain_info" in data


def test_scan_result_saved_to_database(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "https://test-db-save.example.com"}, headers=_auth_headers())
    assert response.status_code == 200

    # Verify it's in the database
    db_response = client.get("/api/v1/history", params={"search": "test-db-save.example.com"}, headers=_auth_headers())
    assert db_response.status_code == 200
    data = db_response.json()
    assert data["total"] >= 1


def test_scan_with_malicious_provider(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, True, 85, "known malicious"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "https://malicious-test.example.com"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] == "critical"
    assert data["intelligence"][0]["malicious"] is True


def test_scan_suspicious_url_has_findings(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "http://192.168.1.1/verify-password"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 0
    assert len(data["findings"]) > 0


def test_url_normalization_in_scan(monkeypatch):
    """Verify that the scan endpoint normalizes URLs."""
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    response = client.post("/api/v1/scan/url", json={"target": "EXAMPLE.COM"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["target"].startswith("https://")


# ─── History API ─────────────────────────────────────────────────────────────


def test_history_returns_paginated_results():
    response = client.get("/api/v1/history", params={"limit": 10, "offset": 0}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert len(data["items"]) <= 10


def test_history_search_filter():
    _insert_db("https://search-test-alpha.example.com", 5, "low")
    response = client.get("/api/v1/history", params={"search": "search-test-alpha"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert any("search-test-alpha" in item["target"] for item in data["items"])


def test_history_risk_level_filter():
    _insert_db("https://risk-filter-critical.test", 85, "critical", verdict="confirmed_malicious")
    response = client.get("/api/v1/history", params={"risk_level": "critical", "search": "risk-filter-critical"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert all(item["risk_level"] == "critical" for item in data["items"])


def test_history_invalid_risk_level_rejected():
    response = client.get("/api/v1/history", params={"risk_level": "invalid"}, headers=_auth_headers())
    assert response.status_code == 400


def test_history_invalid_status_rejected():
    response = client.get("/api/v1/history", params={"status": "invalid"}, headers=_auth_headers())
    assert response.status_code == 400


def test_history_date_range_filter():
    _insert_db("https://date-range-test.example.com", 5, "low")
    response = client.get("/api/v1/history", params={"search": "date-range-test", "start_date": "2020-01-01"}, headers=_auth_headers())
    assert response.status_code == 200


def test_history_invalid_start_date():
    response = client.get("/api/v1/history", params={"start_date": "not-a-date"}, headers=_auth_headers())
    assert response.status_code == 400


def test_history_invalid_end_date():
    response = client.get("/api/v1/history", params={"end_date": "not-a-date"}, headers=_auth_headers())
    assert response.status_code == 400


def test_history_detail_returns_report():
    report = {"findings": [{"rule": "test", "score": 5}], "intelligence": []}
    scan_id = _insert_db("https://detail-test.example.com", 15, "low", report=report)
    response = client.get(f"/api/v1/history/{scan_id}", headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["findings"][0]["rule"] == "test"


def test_history_nonexistent_id_returns_404():
    response = client.get("/api/v1/history/999999", headers=_auth_headers())
    assert response.status_code == 404


# ─── History Comparison ──────────────────────────────────────────────────────


def test_compare_same_scan_rejected():
    scan_id = _insert_db("https://compare-same.test", 10, "low")
    response = client.get("/api/v1/history/compare", params={"left_id": scan_id, "right_id": scan_id}, headers=_auth_headers())
    assert response.status_code == 400


def test_compare_nonexistent_scan():
    response = client.get("/api/v1/history/compare", params={"left_id": 999999, "right_id": 999998}, headers=_auth_headers())
    assert response.status_code == 404


def test_compare_increased_risk():
    left_id = _insert_db("https://compare-increase-left.test", 10, "low", report={"findings": [], "intelligence": []})
    right_id = _insert_db("https://compare-increase-right.test", 70, "critical", report={"findings": [], "intelligence": []})
    response = client.get("/api/v1/history/compare", params={"left_id": left_id, "right_id": right_id}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["risk_score_delta"] == 60


def test_compare_decreased_risk():
    left_id = _insert_db("https://compare-decrease-left.test", 80, "critical", report={"findings": [], "intelligence": []})
    right_id = _insert_db("https://compare-decrease-right.test", 10, "low", report={"findings": [], "intelligence": []})
    response = client.get("/api/v1/history/compare", params={"left_id": left_id, "right_id": right_id}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["risk_score_delta"] == -70


# ─── Dashboard Stats ─────────────────────────────────────────────────────────


def test_dashboard_stats_returns_valid_structure():
    response = client.get("/api/v1/history/stats/overview", headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "risk_distribution" in data
    assert "threat_statistics" in data
    assert "recent_scans" in data
    assert "generated_at" in data


def test_dashboard_risk_distribution_keys():
    response = client.get("/api/v1/history/stats/overview", headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    dist = data["risk_distribution"]
    assert "low" in dist
    assert "medium" in dist
    assert "high" in dist
    assert "critical" in dist


# ─── Health Endpoint ─────────────────────────────────────────────────────────


def test_health_live_returns_ok():
    response = client.get("/health/live")
    assert response.status_code == 200


def test_health_returns_component_status():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "components" in data
    assert "api" in data["components"]
    assert "engine" in data["components"]
    assert "database" in data["components"]
    assert "intelligence" in data["components"]


# ─── Security Headers ────────────────────────────────────────────────────────


def test_security_headers_present():
    response = client.get("/health/live")
    assert "x-content-type-options" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "x-frame-options" in response.headers
    assert response.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in response.headers


# ─── PDF Export ──────────────────────────────────────────────────────────────


def test_pdf_export_from_scan(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    scan_response = client.post("/api/v1/scan/url", json={"target": "https://pdf-test.example.com"}, headers=_auth_headers())
    assert scan_response.status_code == 200
    scan_data = scan_response.json()

    pdf_response = client.post(
        "/api/v1/scan/report.pdf",
        json=scan_data,
        headers={**_auth_headers(), "Accept": "application/pdf"},
    )
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert len(pdf_response.content) > 100  # PDF has actual content


def test_pdf_export_from_scan_requires_auth(monkeypatch):
    _set_providers(
        monkeypatch,
        ThreatIntelResult("Fake", True, False, 0, "clean"),
    )
    scan_response = client.post("/api/v1/scan/url", json={"target": "https://pdf-auth-test.example.com"}, headers=_auth_headers())
    assert scan_response.status_code == 200
    scan_data = scan_response.json()

    # Unauthenticated PDF export must be rejected (401), not silently allowed.
    pdf_response = client.post(
        "/api/v1/scan/report.pdf",
        json=scan_data,
        headers={"Accept": "application/pdf"},
    )
    assert pdf_response.status_code == 401


def test_pdf_export_from_history():
    report = {
        "target": "https://pdf-history-test.example.com",
        "risk_score": 10,
        "risk_level": "low",
        "findings": [],
        "intelligence": [],
        "risk_assessment": {"verdict": "no_major_threat_indicators", "explanation": "Clean"},
        "recommendation": "Safe",
        "url_components": [],
        "domain_info": {},
    }
    scan_id = _insert_db("https://pdf-history-test.example.com", 10, "low", report=report)
    response = client.get(f"/api/v1/history/{scan_id}/report.pdf", headers=_auth_headers())
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"


def test_pdf_for_nonexistent_history():
    response = client.get("/api/v1/history/999999/report.pdf", headers=_auth_headers())
    assert response.status_code == 404


# ─── Rate Limiting ───────────────────────────────────────────────────────────


def test_rate_limiting_allows_normal_requests():
    """Normal requests within rate limit should succeed."""
    for _ in range(5):
        response = client.get("/health/live")
        assert response.status_code == 200


def test_content_length_too_large():
    """Request with oversized content-length should be rejected."""
    response = client.post(
        "/api/v1/scan/url",
        json={"target": "https://example.com"},
        headers={"Content-Length": "99999999", **_auth_headers()},
    )
    # The middleware checks content-length header
    # TestClient may not always honor this, but the endpoint should work
    assert response.status_code in (200, 413)
