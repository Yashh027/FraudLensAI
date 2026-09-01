from datetime import datetime, UTC

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.scan_history import ScanHistory

client = TestClient(app)


def _insert(target, score, level, verdict="no_major_threat_indicators", confidence="medium", report=None):
    db = SessionLocal()
    try:
        row = ScanHistory(
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

    response = client.get("/api/v1/history", params={"search": "phase3-example-risk", "risk_level": "critical"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert all(item["risk_level"] == "critical" for item in data["items"])


def test_history_detail_contains_complete_report():
    report = {"target": "https://phase3-report.test", "findings": [{"rule": "test_signal", "score": 12}], "intelligence": []}
    scan_id = _insert("https://phase3-report.test", 12, "low", report=report)
    response = client.get(f"/api/v1/history/{scan_id}")
    assert response.status_code == 200
    assert response.json()["report"]["findings"][0]["rule"] == "test_signal"


def test_dashboard_stats_are_based_on_persisted_records():
    _insert("https://phase3-stats-safe.test", 0, "low", report={"intelligence": []})
    _insert("https://phase3-stats-critical.test", 75, "critical", report={"intelligence": [{"provider": "TestIntel", "available": True, "malicious": True, "score": 90}]})
    response = client.get("/api/v1/history/stats/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 2
    assert data["risk_distribution"]["low"] >= 1
    assert data["risk_distribution"]["critical"] >= 1
    assert data["threat_statistics"]["TestIntel"]["malicious_matches"] >= 1


def test_compare_allows_legacy_summary_only_scan():
    left_id = _insert("https://phase3-legacy.test", 20, "low", report=None)
    right_id = _insert("https://phase3-current.test", 65, "high", report={"findings": [], "intelligence": []})
    response = client.get("/api/v1/history/compare", params={"left_id": left_id, "right_id": right_id})
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["risk_score_delta"] == 45
    assert data["evidence_availability"]["before"] is False
    assert data["evidence_availability"]["after"] is True
