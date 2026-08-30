from fastapi.testclient import TestClient

from app.main import app
from app.services.threat_intelligence.base import ThreatIntelResult
import app.services.scan_engine as scan_engine


client = TestClient(app)


class FakeProvider:
    name = "URLhaus"

    def __init__(self, result):
        self.result = result

    def check_url(self, url):
        return self.result


def set_provider_result(monkeypatch, result):
    monkeypatch.setattr(
        scan_engine,
        "get_url_threat_intel_providers",
        lambda: [FakeProvider(result)],
    )


def test_url_scan_endpoint(monkeypatch):
    set_provider_result(
        monkeypatch,
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=False,
            score=None,
            details="No URLhaus record found.",
        ),
    )

    response = client.post(
        "/api/v1/scan/url",
        json={
            "target": "https://example.com"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target"] == "https://example.com"
    assert data["target_type"] == "url"
    assert isinstance(data["risk_score"], int)
    assert data["risk_level"] in {"low", "medium", "high", "critical"}
    assert isinstance(data["findings"], list)
    assert isinstance(data["recommendation"], str)
    assert isinstance(data["intelligence"], list)
    assert data["intelligence"][0]["provider"] == "URLhaus"
    assert data["intelligence"][0]["error"] is None


def test_suspicious_url_scan(monkeypatch):
    set_provider_result(
        monkeypatch,
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=False,
            score=None,
            details="No URLhaus record found.",
        ),
    )

    response = client.post(
        "/api/v1/scan/url",
        json={
            "target": "http://192.168.1.100/login/verify/password"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target_type"] == "url"
    assert data["risk_score"] > 0
    assert data["risk_level"] in {"low", "medium", "high", "critical"}
    assert len(data["findings"]) > 0


def test_malicious_reputation_produces_critical_risk(monkeypatch):
    set_provider_result(
        monkeypatch,
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=True,
            score=80,
            details="Test malicious result.",
        ),
    )

    response = client.post(
        "/api/v1/scan/url",
        json={"target": "https://example.com"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 80
    assert data["risk_level"] == "critical"
    assert data["reputation"]["malicious"] is True


def test_unavailable_reputation_does_not_break_scan(monkeypatch):
    set_provider_result(
        monkeypatch,
        ThreatIntelResult(
            provider="URLhaus",
            available=False,
            malicious=None,
            score=None,
            details="Test service unavailable.",
        ),
    )

    response = client.post(
        "/api/v1/scan/url",
        json={"target": "https://example.com"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["reputation"]["available"] is False
    assert data["reputation"]["malicious"] is None
    assert data["intelligence"][0]["available"] is False
    assert data["intelligence"][0]["malicious"] is None
