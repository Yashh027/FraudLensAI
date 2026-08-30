import requests
import pytest

from app.services.threat_intelligence.virustotal import (
    VirusTotalProvider,
    create_url_identifier,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None):
        self.status_code = status_code
        self.payload = payload or {}
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise self.json_error

        return self.payload


def report_payload(
    malicious=0,
    suspicious=0,
    harmless=0,
    undetected=0,
    timeout=0,
):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                }
            }
        }
    }


def test_missing_virustotal_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.provider == "VirusTotal"
    assert result.available is False
    assert result.malicious is None
    assert result.score is None
    assert result.error == "missing_api_key"
    assert "not configured" in result.details


def test_virustotal_url_identifier_generation():
    url_id = create_url_identifier("https://example.com/path?a=1")

    assert url_id == "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXRoP2E9MQ"
    assert "=" not in url_id


def test_successful_virustotal_response(monkeypatch):
    calls = {}

    def fake_get(endpoint, headers, timeout):
        calls["endpoint"] = endpoint
        calls["headers"] = headers
        calls["timeout"] = timeout
        return FakeResponse(
            payload=report_payload(
                malicious=0,
                suspicious=0,
                harmless=8,
                undetected=2,
            )
        )

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert calls["endpoint"].endswith("/aHR0cHM6Ly9leGFtcGxlLmNvbQ")
    assert calls["headers"] == {"x-apikey": "test-key"}
    assert calls["timeout"] == VirusTotalProvider.timeout
    assert result.available is True
    assert result.malicious is False
    assert result.score == 0
    assert "0 malicious and 0 suspicious" in result.details
    assert "does not prove safety" in result.details


def test_virustotal_single_detection_is_not_confirmed_malicious(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(
            payload=report_payload(
                malicious=1,
                suspicious=0,
                harmless=69,
            )
        )

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://google.com")

    assert result.available is True
    assert result.malicious is False
    assert result.score == 1


def test_virustotal_malicious_detections(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(
            payload=report_payload(
                malicious=2,
                suspicious=2,
                harmless=6,
            )
        )

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is True
    assert result.malicious is True
    assert result.score == 30
    assert "2 malicious and 2 suspicious" in result.details


def test_virustotal_suspicious_only_detections(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(
            payload=report_payload(
                suspicious=2,
                harmless=8,
            )
        )

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is True
    assert result.malicious is False
    assert result.score == 10
    assert "0 malicious and 2 suspicious" in result.details
    assert "does not prove safety" in result.details


def test_virustotal_no_malicious_or_suspicious_detections(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(
            payload=report_payload(
                harmless=5,
                undetected=5,
            )
        )

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is True
    assert result.malicious is False
    assert result.score == 0
    assert "does not prove safety" in result.details


def test_virustotal_no_report(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(status_code=404)

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is True
    assert result.malicious is None
    assert result.score is None
    assert result.error == "not_found"
    assert "does not confirm" in result.details


@pytest.mark.parametrize("status_code", [401, 403])
def test_virustotal_authentication_error(monkeypatch, status_code):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(status_code=status_code)

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.error == f"http_{status_code}"


def test_virustotal_rate_limit(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(status_code=429)

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.error == "rate_limited"


def test_virustotal_network_failure(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        raise requests.ConnectionError("connection failed")

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.score is None
    assert result.error == "network_error"


def test_virustotal_timeout(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        raise requests.Timeout("timed out")

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.score is None
    assert result.error == "network_error"


def test_virustotal_malformed_json(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(json_error=ValueError("bad json"))

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.error == "invalid_response"


def test_virustotal_unexpected_response_structure(monkeypatch):
    def fake_get(endpoint, headers, timeout):
        return FakeResponse(payload={"data": {"attributes": {}}})

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.services.threat_intelligence.virustotal.requests.get",
        fake_get,
    )

    result = VirusTotalProvider().check_url("https://example.com")

    assert result.available is False
    assert result.malicious is None
    assert result.error == "unexpected_response_structure"
