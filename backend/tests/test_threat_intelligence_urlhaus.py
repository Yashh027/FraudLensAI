import requests

from app.services.threat_intelligence.registry import (
    get_url_threat_intel_providers,
)
from app.services.threat_intelligence.urlhaus import URLhausProvider
from app.services.threat_intelligence.virustotal import VirusTotalProvider
from app.services.threat_intelligence.urlscan import URLScanProvider


class FakeResponse:
    def __init__(self, payload=None, json_error=None):
        self.payload = payload or {}
        self.json_error = json_error

    def raise_for_status(self):
        return None

    def json(self):
        if self.json_error:
            raise self.json_error

        return self.payload


def test_urlhaus_malicious_result(monkeypatch):
    monkeypatch.setenv("URLHAUS_API_KEY", "test-key")
    def fake_post(endpoint, headers, data, timeout):
        return FakeResponse({"query_status": "ok"})

    monkeypatch.setattr(
        "app.services.threat_intelligence.urlhaus.requests.post",
        fake_post,
    )

    result = URLhausProvider().check_url("https://example.com")

    assert result.provider == "URLhaus"
    assert result.available is True
    assert result.malicious is True
    assert result.score == 80
    assert result.error is None


def test_urlhaus_no_results_is_not_claimed_safe(monkeypatch):
    monkeypatch.setenv("URLHAUS_API_KEY", "test-key")
    def fake_post(endpoint, headers, data, timeout):
        return FakeResponse({"query_status": "no_results"})

    monkeypatch.setattr(
        "app.services.threat_intelligence.urlhaus.requests.post",
        fake_post,
    )

    result = URLhausProvider().check_url("https://example.com")

    assert result.available is True
    assert result.malicious is False
    assert result.score is None
    assert "does not confirm" in result.details


def test_urlhaus_unavailable_result(monkeypatch):
    monkeypatch.setenv("URLHAUS_API_KEY", "test-key")
    def fake_post(endpoint, headers, data, timeout):
        raise requests.RequestException("timeout")

    monkeypatch.setattr(
        "app.services.threat_intelligence.urlhaus.requests.post",
        fake_post,
    )

    result = URLhausProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.score is None
    assert result.error == "network_error"


def test_urlhaus_invalid_json_result(monkeypatch):
    monkeypatch.setenv("URLHAUS_API_KEY", "test-key")
    def fake_post(endpoint, headers, data, timeout):
        return FakeResponse(json_error=ValueError("invalid json"))

    monkeypatch.setattr(
        "app.services.threat_intelligence.urlhaus.requests.post",
        fake_post,
    )

    result = URLhausProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.error == "invalid_response"


def test_provider_registry_contains_urlhaus_and_virustotal_providers():
    providers = get_url_threat_intel_providers()

    assert len(providers) == 3
    assert providers[0].name == "URLhaus"
    assert providers[1].name == "VirusTotal"
    assert providers[2].name == "urlscan.io"
    assert isinstance(providers[0], URLhausProvider)
    assert isinstance(providers[1], VirusTotalProvider)
    assert isinstance(providers[2], URLScanProvider)
