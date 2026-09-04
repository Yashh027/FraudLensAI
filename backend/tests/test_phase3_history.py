from datetime import datetime, UTC

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.scan_history import ScanHistory, User
from app.services.auth import create_access_token, hash_password

client = TestClient(app)


def _ensure_default_user_id():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.is_active.is_(True)).order_by(User.id.asc()).first()
        if user is None:
            user = User(
                email="history-test-user@fraudlens.local",
                hashed_password=hash_password("history-test-pass"),
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return user.id
    finally:
        db.close()


def _auth_headers():
    return {"Authorization": f"Bearer {create_access_token({'sub': str(_ensure_default_user_id())})}"}


def _insert(target, score, level, verdict="no_major_threat_indicators", confidence="medium", report=None):
    db = SessionLocal()
    try:
        row = ScanHistory(
            user_id=_ensure_default_user_id(),
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


def test_history_filters_and_report_storage():
    report = {"findings": [], "intelligence": [], "risk_assessment": {"verdict": "no_major_threat_indicators"}}
    _insert("https://phase3-example-safe.test", 5, "low", report=report)
    _insert("https://phase3-example-risk.test", 80, "critical", verdict="confirmed_malicious", confidence="high", report=report)

    response = client.get("/api/v1/history", params={"search": "phase3-example-risk", "risk_level": "critical"}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert all(item["risk_level"] == "critical" for item in data["items"])


def test_history_detail_contains_complete_report():
    report = {"target": "https://phase3-report.test", "findings": [{"rule": "test_signal", "score": 12}], "intelligence": []}
    scan_id = _insert("https://phase3-report.test", 12, "low", report=report)
    response = client.get(f"/api/v1/history/{scan_id}", headers=_auth_headers())
    assert response.status_code == 200
    assert response.json()["report"]["findings"][0]["rule"] == "test_signal"


def test_dashboard_stats_are_based_on_persisted_records():
    _insert("https://phase3-stats-safe.test", 0, "low", report={"intelligence": []})
    _insert("https://phase3-stats-critical.test", 75, "critical", report={"intelligence": [{"provider": "TestIntel", "available": True, "malicious": True, "score": 90}]})
    response = client.get("/api/v1/history/stats/overview", headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 2
    assert data["risk_distribution"]["low"] >= 1
    assert data["risk_distribution"]["critical"] >= 1
    assert data["threat_statistics"]["TestIntel"]["malicious_matches"] >= 1


def test_compare_allows_legacy_summary_only_scan():
    left_id = _insert("https://phase3-legacy.test", 20, "low", report=None)
    right_id = _insert("https://phase3-current.test", 65, "high", report={"findings": [], "intelligence": []})
    response = client.get("/api/v1/history/compare", params={"left_id": left_id, "right_id": right_id}, headers=_auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["risk_score_delta"] == 45
    assert data["evidence_availability"]["before"] is False
    assert data["evidence_availability"]["after"] is True


def _other_user_headers():
    """Create a second, distinct user and return headers for them."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "other-isolation-user@fraudlens.local").first()
        if user is None:
            user = User(
                email="other-isolation-user@fraudlens.local",
                hashed_password=hash_password("other-user-pass"),
                is_active=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        return {"Authorization": f"Bearer {create_access_token({'sub': str(user.id)})}"}
    finally:
        db.close()


def test_user_cannot_access_another_users_scan():
    """IDOR protection: a distinct user must not read or compare another user's scans."""
    # Create a scan owned by the default test user.
    scan_id = _insert("https://phase3-isolation.test", 30, "medium", report={"findings": [], "intelligence": []})

    other_headers = _other_user_headers()

    # Other user lists history: must not see the default user's scan.
    response = client.get("/api/v1/history", headers=other_headers)
    assert response.status_code == 200
    assert all(item["id"] != scan_id for item in response.json()["items"])

    # Other user cannot fetch the default user's scan detail.
    response = client.get(f"/api/v1/history/{scan_id}", headers=other_headers)
    assert response.status_code == 404

    # Other user cannot fetch the default user's PDF report.
    response = client.get(f"/api/v1/history/{scan_id}/report.pdf", headers=other_headers)
    assert response.status_code == 404

    # Other user cannot compare against the default user's scan.
    own_id = _insert("https://phase3-other-own.test", 10, "low", report=None)
    response = client.get("/api/v1/history/compare", params={"left_id": own_id, "right_id": scan_id}, headers=other_headers)
    assert response.status_code == 404

    # Other user's stats must not include the default user's scan.
    response = client.get("/api/v1/history/stats/overview", headers=other_headers)
    assert response.status_code == 200
    assert all(item["id"] != scan_id for item in response.json()["recent_scans"])
