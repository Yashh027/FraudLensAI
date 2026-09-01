import pytest
from app.services.risk_engine import calculate_risk, get_risk_level
from app.services.url_normalizer import is_private_or_local_hostname, normalize_url_target
from app.services.threat_intelligence.base import ThreatIntelResult


def test_single_malicious_provider_is_not_automatically_100():
    score, level, _, verdict, _ = calculate_risk(10, [ThreatIntelResult("VT", True, True, 30, "malicious")])
    assert score == 40
    assert level == "medium"
    assert verdict == "suspicious"


def test_multiple_malicious_providers_are_100():
    results = [
        ThreatIntelResult("A", True, True, 70, "malicious"),
        ThreatIntelResult("B", True, True, 40, "malicious"),
    ]
    assert calculate_risk(0, results)[0] == 100


def test_unavailable_provider_score_is_ignored():
    result = ThreatIntelResult("down", False, None, 100, "unavailable")
    assert calculate_risk(5, [result])[0] == 5


def test_risk_thresholds_are_consistent():
    assert get_risk_level(24) == "low"
    assert get_risk_level(25) == "medium"
    assert get_risk_level(49) == "medium"
    assert get_risk_level(50) == "high"
    assert get_risk_level(69) == "high"
    assert get_risk_level(70) == "critical"
    assert get_risk_level(100) == "critical"


@pytest.mark.parametrize("raw,expected", [
    (" example.com ", "https://example.com"),
    ("HTTPS://example.com", "https://example.com"),
    ("https;//example.com", "https://example.com"),
    ("https:/example.com", "https://example.com"),
    ("http://example.com/path", "http://example.com/path"),
])
def test_url_normalization(raw, expected):
    assert normalize_url_target(raw) == expected


def test_url_length_limit():
    with pytest.raises(ValueError, match="too long"):
        normalize_url_target("https://example.com/" + "a" * 2048)


@pytest.mark.parametrize("value", ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "metadata.google.internal"])
def test_private_and_metadata_targets_are_blocked(value):
    assert is_private_or_local_hostname(value) is True


def test_public_hostname_is_not_blocked():
    assert is_private_or_local_hostname("example.com") is False


def test_single_weak_malicious_provider_does_not_become_critical():
    result = ThreatIntelResult("VT", True, True, 30, "limited malicious signal")
    score, level, _, verdict, _ = calculate_risk(0, [result])
    assert score == 40
    assert level == "medium"
    assert verdict == "suspicious"


def test_single_strong_malicious_provider_is_below_100_without_corroboration():
    result = ThreatIntelResult("VT", True, True, 80, "strong malicious evidence")
    score, level, _, verdict, _ = calculate_risk(0, [result])
    assert score == 90
    assert level == "critical"
    assert verdict == "confirmed_malicious"


def test_clean_google_like_results_remain_low_risk():
    results = [
        ThreatIntelResult("URLhaus", True, False, None, "No malicious URL record."),
        ThreatIntelResult("VirusTotal", True, False, 0, "0 malicious detections."),
    ]
    score, level, _, verdict, _ = calculate_risk(0, results)
    assert score == 0
    assert level == "low"
    assert verdict == "no_major_threat_indicators"
