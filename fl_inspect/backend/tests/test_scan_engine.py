from app.services.scan_engine import (
    collect_url_threat_intelligence,
    scan_url_target,
)
from app.services.threat_intelligence.base import ThreatIntelResult


class StaticProvider:
    name = "StaticProvider"

    def __init__(self, result):
        self.result = result
        self.checked_url = None

    def check_url(self, url):
        self.checked_url = url
        return self.result


class FailingProvider:
    name = "FailingProvider"

    def check_url(self, url):
        raise RuntimeError("provider exploded")


def test_scan_engine_uses_provider_result():
    provider = StaticProvider(
        ThreatIntelResult(
            provider="StaticProvider",
            available=True,
            malicious=False,
            score=40,
            details="Provider returned a confidence score.",
        )
    )

    response = scan_url_target(
        target="https://example.com",
        providers=[provider],
    )

    assert provider.checked_url == "https://example.com"

    assert response.reputation.provider == "StaticProvider"
    assert response.reputation.score == 40

    assert response.intelligence[0].provider == "StaticProvider"
    assert response.intelligence[0].score == 40

    assert response.risk_score == 40
    assert response.risk_level == "medium"

    assert response.risk_assessment.score == 40
    assert response.risk_assessment.level == "medium"
    assert response.risk_assessment.confidence == "medium"


def test_provider_failure_does_not_crash_scan():
    results = collect_url_threat_intelligence(
        target="https://example.com",
        providers=[FailingProvider()],
    )

    assert len(results) == 1

    assert results[0].provider == "FailingProvider"
    assert results[0].available is False
    assert results[0].malicious is None
    assert results[0].score is None
    assert results[0].error == "provider_failure"


def test_scan_engine_returns_failed_provider_as_reputation():
    response = scan_url_target(
        target="https://example.com",
        providers=[FailingProvider()],
    )

    assert response.reputation.provider == "FailingProvider"
    assert response.reputation.available is False
    assert response.reputation.malicious is None

    assert response.intelligence[0].provider == "FailingProvider"
    assert response.intelligence[0].available is False
    assert response.intelligence[0].error == "provider_failure"

    assert response.risk_score == 0
    assert response.risk_level == "low"

    assert response.risk_assessment.confidence == "low"
    assert response.risk_assessment.verdict == "insufficient_intelligence"


def test_malicious_provider_intelligence_sets_critical_risk():
    provider = StaticProvider(
        ThreatIntelResult(
            provider="StaticProvider",
            available=True,
            malicious=True,
            score=80,
            details="Known malicious URL.",
        )
    )

    response = scan_url_target(
        target="https://example.com",
        providers=[provider],
    )

    assert response.risk_score == 90
    assert response.risk_level == "critical"

    assert response.reputation.malicious is True

    assert response.risk_assessment.score == 90
    assert response.risk_assessment.level == "critical"
    assert response.risk_assessment.confidence == "high"
    assert response.risk_assessment.verdict == "confirmed_malicious"


def test_second_provider_failure_does_not_break_scan():
    urlhaus_provider = StaticProvider(
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=False,
            score=None,
            details="No URLhaus record found.",
        )
    )

    response = scan_url_target(
        target="https://example.com",
        providers=[
            urlhaus_provider,
            FailingProvider(),
        ],
    )

    assert response.reputation.provider == "URLhaus"
    assert response.reputation.available is True

    assert [
        result.provider
        for result in response.intelligence
    ] == [
        "URLhaus",
        "FailingProvider",
    ]

    assert response.intelligence[1].available is False
    assert response.intelligence[1].error == "provider_failure"

    assert response.risk_level == "low"


def test_second_provider_malicious_intelligence_affects_final_risk():
    urlhaus_provider = StaticProvider(
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=False,
            score=None,
            details="No URLhaus record found.",
        )
    )

    virustotal_provider = StaticProvider(
        ThreatIntelResult(
            provider="VirusTotal",
            available=True,
            malicious=True,
            score=30,
            details="VirusTotal detected malicious engines.",
        )
    )

    response = scan_url_target(
        target="https://example.com",
        providers=[
            urlhaus_provider,
            virustotal_provider,
        ],
    )

    assert response.reputation.provider == "URLhaus"
    assert response.reputation.malicious is False

    assert [
        result.provider
        for result in response.intelligence
    ] == [
        "URLhaus",
        "VirusTotal",
    ]

    assert response.intelligence[1].malicious is True

    assert response.risk_score == 40
    assert response.risk_level == "medium"

    assert (
        response.risk_assessment.verdict
        == "suspicious"
    )


def test_intelligence_preserves_both_provider_results_without_changing_reputation():
    urlhaus_provider = StaticProvider(
        ThreatIntelResult(
            provider="URLhaus",
            available=True,
            malicious=False,
            score=20,
            details="URLhaus did not return a malicious match.",
        )
    )

    virustotal_provider = StaticProvider(
        ThreatIntelResult(
            provider="VirusTotal",
            available=True,
            malicious=False,
            score=60,
            details="VirusTotal reported suspicious detections.",
        )
    )

    response = scan_url_target(
        target="https://example.com",
        providers=[
            urlhaus_provider,
            virustotal_provider,
        ],
    )

    assert response.reputation.provider == "URLhaus"
    assert response.reputation.score == 20

    assert len(response.intelligence) == 2

    assert response.intelligence[0].provider == "URLhaus"
    assert response.intelligence[1].provider == "VirusTotal"

    assert response.risk_score == 62
    assert response.risk_level == "high"

    assert response.risk_assessment.score == 62
    assert response.risk_assessment.level == "high"
    assert response.risk_assessment.confidence == "high"

def test_two_independent_malicious_providers_confirm_critical():
    results = [
        ThreatIntelResult("URLhaus", True, True, 80, "Known malicious URL."),
        ThreatIntelResult("VirusTotal", True, True, 75, "Strong multi-engine evidence."),
    ]
    response = scan_url_target("https://example.com", providers=[StaticProvider(results[0]), StaticProvider(results[1])])
    assert response.risk_score == 100
    assert response.risk_level == "critical"
    assert response.risk_assessment.verdict == "confirmed_by_multiple_sources"
    assert response.risk_assessment.confidence == "high"
