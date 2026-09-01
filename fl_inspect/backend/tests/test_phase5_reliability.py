import requests

from app.services.scan_engine import collect_url_threat_intelligence
from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.urlhaus import URLhausProvider
from app.services.threat_intelligence.virustotal import VirusTotalProvider


class FailingProvider:
    name = "FailingProvider"

    def check_url(self, url):
        raise RuntimeError("provider exploded")


def test_provider_exception_is_isolated():
    results = collect_url_threat_intelligence(
        "https://example.com",
        providers=[FailingProvider()],
    )
    assert results[0].available is False
    assert results[0].error == "provider_failure"


def test_collect_preserves_provider_order_with_concurrent_execution():
    class Provider:
        def __init__(self, name):
            self.name = name

        def check_url(self, url):
            return ThreatIntelResult(self.name, True, False, 0, "ok")

    results = collect_url_threat_intelligence(
        "https://example.com",
        providers=[Provider("one"), Provider("two"), Provider("three")],
    )
    assert [result.provider for result in results] == ["one", "two", "three"]


def test_urlhaus_malformed_response_is_unavailable(monkeypatch):
    monkeypatch.setenv("URLHAUS_API_KEY", "test-key")

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"unexpected": "shape"}

    monkeypatch.setattr(
        "app.services.threat_intelligence.urlhaus.requests.post",
        lambda **kwargs: FakeResponse(),
    )

    result = URLhausProvider().check_url("https://example.com")
    assert result.available is False
    assert result.error == "invalid_response"


def test_virustotal_timeout_is_graceful(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(endpoint, headers, timeout):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")
    assert result.available is False
    assert result.malicious is None
    assert "timed out" in result.details.lower()
