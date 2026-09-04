"""Phase 6 — Comprehensive edge-case tests for the FraudLens detection pipeline.

Covers:
- URL normalization edge cases (empty, whitespace, very long, Unicode/punycode, malformed schemes)
- Local analyzer edge cases
- Risk engine edge cases (conflicting providers, all unavailable, boundary scores)
- Domain intelligence edge cases
- SSRF / private-target protection
- Provider failure isolation
- Conflicting provider results
"""

import pytest

from app.analyzers.url_analyzer import (
    analyze_url,
    decompose_url,
    get_risk_level,
    get_recommendation,
)
from app.services.risk_engine import (
    calculate_risk,
    calculate_confidence,
    get_verdict,
    clamp_score,
)
from app.services.url_normalizer import (
    normalize_url_target,
    is_private_or_local_hostname,
)
from app.services.domain_intelligence import extract_domain_info, _registrable_domain
from app.services.threat_intelligence.base import ThreatIntelResult


# ─── URL Normalization Edge Cases ───────────────────────────────────────────


def test_empty_string_raises():
    with pytest.raises(ValueError, match="Enter a URL"):
        normalize_url_target("")


def test_whitespace_only_raises():
    with pytest.raises(ValueError, match="Enter a URL"):
        normalize_url_target("     ")


def test_none_raises():
    with pytest.raises(ValueError):
        normalize_url_target(None)


def test_very_long_url_rejected():
    long_url = "https://example.com/" + "a" * 2049
    with pytest.raises(ValueError, match="too long"):
        normalize_url_target(long_url)


def test_exactly_max_length_url_accepted():
    max_url = "https://example.com/" + "a" * (2048 - len("https://example.com/"))
    result = normalize_url_target(max_url)
    assert result.startswith("https://")


def test_ftp_scheme_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        normalize_url_target("ftp://files.example.com/document.pdf")


def test_javascript_scheme_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        normalize_url_target("javascript:alert(1)")


def test_file_scheme_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        normalize_url_target("file:///etc/passwd")


def test_data_scheme_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        normalize_url_target("data:text/html,<h1>hi</h1>")


def test_control_characters_rejected():
    with pytest.raises(ValueError, match="control characters"):
        normalize_url_target("https://example.com/\x00/path")


def test_whitespace_in_hostname_rejected():
    with pytest.raises(ValueError, match="spaces"):
        normalize_url_target("https://exam ple.com")


def test_invalid_port_rejected():
    with pytest.raises(ValueError, match="invalid port"):
        normalize_url_target("https://example.com:99999")


def test_bare_ip_gets_https():
    result = normalize_url_target("192.168.1.1")
    assert result == "https://192.168.1.1"


def test_unicode_domain_normalized():
    result = normalize_url_target("https://münchen.de")
    assert result.startswith("https://")


def test_trailing_whitespace_trimmed():
    result = normalize_url_target("  https://example.com  ")
    assert result == "https://example.com"


def test_typo_semicolon_colon_fixed():
    assert normalize_url_target("https;://example.com") == "https://example.com"


def test_typo_double_slash_missing_fixed():
    assert normalize_url_target("https:/example.com") == "https://example.com"


def test_http_with_path_preserved():
    result = normalize_url_target("http://example.com/login?user=test")
    assert result == "http://example.com/login?user=test"


def test_uppercase_scheme_lowercased():
    result = normalize_url_target("HTTPS://EXAMPLE.COM/PATH")
    assert result.startswith("https://")


# ─── URL Analyzer Edge Cases ────────────────────────────────────────────────


def test_safe_clean_url():
    score, findings = analyze_url("https://google.com")
    assert score == 0
    assert len(findings) == 0


def test_empty_hostname_high_risk():
    score, findings = analyze_url("https://")
    assert score >= 30
    rules = {f.rule for f in findings}
    assert "missing_hostname" in rules


def test_ip_based_http_url_multiple_signals():
    score, findings = analyze_url("http://10.0.0.1/admin/login/verify")
    rules = {f.rule for f in findings}
    assert "ip_based_url" in rules
    assert "no_https" in rules
    assert "suspicious_keywords" in rules
    assert score > 25


def test_brand_impersonation_on_unrelated_domain():
    score, findings = analyze_url("https://paypal-secure-login.phishing.xyz/verify")
    rules = {f.rule for f in findings}
    assert "brand_impersonation" in rules
    assert "suspicious_tld" in rules
    assert score >= 40


def test_legitimate_paypal_url_no_false_positive():
    score, findings = analyze_url("https://www.paypal.com/login")
    rules = {f.rule for f in findings}
    assert "brand_impersonation" not in rules
    assert score < 15


def test_multiple_redirect_params():
    score, findings = analyze_url(
        "https://example.com/auth?redirect=https://evil.com&next=http://malware.net&return=http://phish.org"
    )
    rules = {f.rule for f in findings}
    assert "redirect_parameter" in rules
    assert "nested_url_parameter" in rules


def test_highly_encoded_url():
    score, findings = analyze_url(
        "https://example.com/%41/%42/%43/%44/%45/%46/%47/%48"
    )
    rules = {f.rule for f in findings}
    assert "excessive_url_encoding" in rules


def test_every_possible_local_finding():
    score, findings = analyze_url(
        "http://admin:password@xn--pple-43d.com:9999/a.b.c.d.e/f/g/h/i?verify=1&password=2&payment=3&redirect=http://evil.com&next=http://malware.net&url=http://phish.org&dest=http://bad.org&return=http://hack.net&goto=http://x.org&continue=http://y.org"
    )
    rules = {f.rule for f in findings}
    assert "ip_based_url" not in rules  # xn--pple is not an IP
    assert "embedded_credentials" in rules
    assert "punycode_domain" in rules
    assert "unusual_port" in rules
    assert "redirect_parameter" in rules
    assert "nested_url_parameter" in rules
    assert "many_query_parameters" in rules
    assert "no_https" in rules
    assert "at_symbol_in_url" in rules
    assert score > 50


def test_risk_level_boundaries():
    assert get_risk_level(0) == "low"
    assert get_risk_level(24) == "low"
    assert get_risk_level(25) == "medium"
    assert get_risk_level(49) == "medium"
    assert get_risk_level(50) == "high"
    assert get_risk_level(69) == "high"
    assert get_risk_level(70) == "critical"
    assert get_risk_level(100) == "critical"


def test_recommendation_changes_by_risk_level():
    rec_low = get_recommendation("low")
    rec_med = get_recommendation("medium")
    rec_high = get_recommendation("high")
    rec_crit = get_recommendation("critical")
    assert rec_low != rec_med != rec_high != rec_crit


def test_recommendation_for_insufficient_intelligence():
    rec = get_recommendation("low", [], "insufficient_intelligence")
    assert "limited" in rec.lower() or "unavailable" in rec.lower() or "absence" in rec.lower()


def test_brand_impersonation_recommendation():
    from app.models.scan import Finding
    findings = [Finding(rule="brand_impersonation", severity="high", description="test", score=30)]
    rec = get_recommendation("critical", findings)
    assert "brand" in rec.lower() or "impersonat" in rec.lower()


def test_redirect_recommendation():
    from app.models.scan import Finding
    findings = [Finding(rule="redirect_parameter", severity="medium", description="test", score=8)]
    rec = get_recommendation("medium", findings)
    assert "redirect" in rec.lower()


def test_url_decomposition_full_url():
    parts = decompose_url("https://sub.example.co.uk:8080/path?k=v#section")
    by_key = {p.key: p for p in parts}
    assert "PROTOCOL" in by_key
    assert "SUBDOMAIN" in by_key
    assert "DOMAIN" in by_key
    assert "TLD" in by_key
    assert "PATH" in by_key
    assert "QUERY PARAMETERS" in by_key
    assert "FRAGMENT" in by_key
    assert "REDIRECT BEHAVIOR" in by_key
    assert len(parts) == 8


def test_url_decomposition_root_path():
    parts = decompose_url("https://example.com/")
    by_key = {p.key: p for p in parts}
    assert by_key["PATH"].status == "ROOT"


# ─── Risk Engine Edge Cases ─────────────────────────────────────────────────


def test_all_providers_unavailable():
    results = [
        ThreatIntelResult("A", False, None, None, "unavailable"),
        ThreatIntelResult("B", False, None, None, "unavailable"),
        ThreatIntelResult("C", False, None, None, "unavailable"),
    ]
    score, level, confidence, verdict, explanation = calculate_risk(10, results)
    assert score == 10
    assert level == "low"
    assert confidence == "low"


def test_two_malicious_providers_override_high_local():
    results = [
        ThreatIntelResult("A", True, True, 70, "malicious"),
        ThreatIntelResult("B", True, True, 50, "malicious"),
    ]
    score, level, confidence, verdict, explanation = calculate_risk(60, results)
    assert score == 100
    assert level == "critical"
    assert verdict == "confirmed_by_multiple_sources"


def test_conflicting_providers_one_malicious_one_clean():
    results = [
        ThreatIntelResult("A", True, True, 80, "malicious"),
        ThreatIntelResult("B", True, False, 0, "clean"),
    ]
    score, level, confidence, verdict, explanation = calculate_risk(10, results)
    # One strong malicious → at least 90
    assert score >= 80
    assert level == "critical"


def test_weak_malicious_provider_bounded():
    results = [
        ThreatIntelResult("VT", True, True, 20, "very low detection"),
    ]
    score, level, confidence, verdict, explanation = calculate_risk(0, results)
    assert score <= 69
    assert level in ("medium", "low")


def test_strong_malicious_provider_is_critical_but_not_100():
    results = [
        ThreatIntelResult("VT", True, True, 95, "strong malicious"),
    ]
    score, level, confidence, verdict, explanation = calculate_risk(0, results)
    assert score < 100  # Single strong provider never reaches 100 without corroboration
    assert level == "critical"


def test_score_always_0_to_100():
    # Ensure extreme local scores are clamped
    score, *_ = calculate_risk(200, [])
    assert 0 <= score <= 100

    score, *_ = calculate_risk(-50, [])
    assert 0 <= score <= 100


def test_clamp_score_edge_cases():
    assert clamp_score(None) == 0
    assert clamp_score(-10) == 0
    assert clamp_score(150) == 100
    assert clamp_score(50) == 50
    assert clamp_score(0) == 0
    assert clamp_score(100) == 100


def test_confidence_with_no_providers():
    conf = calculate_confidence(10, [], [], [])
    assert conf == "low"


def test_confidence_with_two_clean_providers():
    avail = [
        ThreatIntelResult("A", True, False, 0, "clean"),
        ThreatIntelResult("B", True, False, 0, "clean"),
    ]
    scored = [r for r in avail if r.score is not None]
    conf = calculate_confidence(10, avail, [], scored)
    assert conf in ("medium", "high")


def test_confidence_with_two_malicious_providers():
    avail = [
        ThreatIntelResult("A", True, True, 80, "malicious"),
        ThreatIntelResult("B", True, True, 70, "malicious"),
    ]
    scored = [r for r in avail if r.score is not None]
    conf = calculate_confidence(0, avail, avail, scored)
    assert conf == "high"


def test_verdict_all_malicious():
    malicious = [ThreatIntelResult("A", True, True, 80, ""), ThreatIntelResult("B", True, True, 70, "")]
    strong = [r for r in malicious if r.score >= 70]
    verdict = get_verdict(100, "high", malicious, strong)
    assert verdict == "confirmed_by_multiple_sources"


def test_verdict_single_strong():
    malicious = [ThreatIntelResult("VT", True, True, 80, "")]
    strong = [r for r in malicious if r.score >= 70]
    verdict = get_verdict(90, "high", malicious, strong)
    assert verdict == "confirmed_malicious"


def test_verdict_insufficient_intelligence():
    verdict = get_verdict(5, "low", [], [])
    assert verdict == "insufficient_intelligence"


def test_verdict_no_major_threats():
    verdict = get_verdict(10, "medium", [], [])
    assert verdict == "no_major_threat_indicators"


def test_explanation_mentions_infrastructure_score():
    signals = [{"rule": "new_domain", "severity": "medium", "description": "recent", "score": 8}]
    _, _, _, _, explanation = calculate_risk(10, [], infrastructure_score=8, infrastructure_signals=signals)
    assert "infrastructure" in explanation.lower()


# ─── SSRF / Private Target Protection ───────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "metadata.google.internal",
        "192.168.0.1",
        "10.255.255.255",
        "172.31.255.255",
        "0.0.0.0",
    ],
)
def test_private_and_internal_targets_blocked(value):
    assert is_private_or_local_hostname(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "google.com",
        "example.com",
        "8.8.8.8",
        "1.1.1.1",
        "cloudflare.com",
    ],
)
def test_public_targets_not_blocked(value):
    assert is_private_or_local_hostname(value) is False


def test_empty_hostname_blocked():
    assert is_private_or_local_hostname("") is True
    assert is_private_or_local_hostname(None) is True


def test_localhost_subdomain_blocked():
    assert is_private_or_local_hostname("sub.localhost") is True


def test_local_subdomain_blocked():
    assert is_private_or_local_hostname("server.local") is True


def test_scan_engine_blocks_private_targets(monkeypatch):
    from app.services.scan_engine import scan_url_target

    # The scan engine should block private targets at the provider level
    response = scan_url_target("https://192.168.1.1")
    # Domain info for an IP target
    assert response.target_type == "url"
    # Intelligence should show blocked
    for intel in response.intelligence:
        assert intel.error == "blocked_private_target"


# ─── Domain Intelligence Edge Cases ─────────────────────────────────────────


def test_ip_address_domain_extraction():
    info = extract_domain_info("http://1.2.3.4/test")
    assert info["is_ip"] is True
    assert info["domain"] is None
    assert info["hostname"] == "1.2.3.4"
    assert "1.2.3.4" in info["infrastructure"]["ips"]


def test_no_hostname_returns_unavailable():
    info = extract_domain_info("https://")
    assert info["lookup_status"] == "unavailable"


def test_subdomain_multi_label_tld():
    domain, subdomain, tld = _registrable_domain("www.news.example.co.uk")
    assert domain == "example.co.uk"
    assert tld == "co.uk"
    assert subdomain == "www.news"


def test_single_label_domain():
    domain, subdomain, tld = _registrable_domain("localhost")
    assert domain == "localhost"
    assert tld is None
    assert subdomain is None


def test_two_label_domain():
    domain, subdomain, tld = _registrable_domain("example.com")
    assert domain == "example.com"
    assert tld == "com"
    assert subdomain is None


def test_three_label_normal_tld():
    domain, subdomain, tld = _registrable_domain("sub.example.com")
    assert domain == "example.com"
    assert tld == "com"
    assert subdomain == "sub"


# ─── Provider Failure Isolation ─────────────────────────────────────────────


def test_provider_timeout_isolated():
    """Simulate a provider that times out."""
    class TimeoutProvider:
        name = "TimeoutProvider"
        def check_url(self, url):
            import requests
            raise requests.Timeout("connection timed out")

    from app.services.scan_engine import scan_url_target
    response = scan_url_target("https://example.com", providers=[TimeoutProvider()])
    assert response.reputation.available is False
    assert response.risk_score == 0
    assert response.risk_level == "low"


def test_provider_returns_wrong_type():
    """Provider returns something other than ThreatIntelResult."""
    class BadProvider:
        name = "BadProvider"
        def check_url(self, url):
            return "not a result"

    from app.services.scan_engine import collect_url_threat_intelligence
    results = collect_url_threat_intelligence("https://example.com", providers=[BadProvider()])
    assert len(results) == 1
    assert results[0].available is False
    assert results[0].error == "invalid_provider_result"


def test_provider_returns_none():
    class NoneProvider:
        name = "NoneProvider"
        def check_url(self, url):
            return None

    from app.services.scan_engine import collect_url_threat_intelligence
    results = collect_url_threat_intelligence("https://example.com", providers=[NoneProvider()])
    assert results[0].available is False


def test_empty_provider_list():
    from app.services.scan_engine import collect_url_threat_intelligence
    results = collect_url_threat_intelligence("https://example.com", providers=[])
    assert results == []


# ─── Conflicting Provider Results ────────────────────────────────────────────


def test_three_providers_one_malicious_two_clean():
    results = [
        ThreatIntelResult("URLhaus", True, True, 80, "malicious"),
        ThreatIntelResult("VirusTotal", True, False, 5, "clean"),
        ThreatIntelResult("urlscan", True, False, 0, "clean"),
    ]
    score, level, confidence, verdict, _ = calculate_risk(10, results)
    assert score >= 80
    assert level == "critical"


def test_all_three_providers_malicious():
    results = [
        ThreatIntelResult("A", True, True, 80, "malicious"),
        ThreatIntelResult("B", True, True, 70, "malicious"),
        ThreatIntelResult("C", True, True, 60, "malicious"),
    ]
    score, level, confidence, verdict, _ = calculate_risk(0, results)
    assert score == 100
    assert verdict == "confirmed_by_multiple_sources"


def test_mixed_available_and_unavailable():
    results = [
        ThreatIntelResult("A", True, True, 80, "malicious"),
        ThreatIntelResult("B", False, None, None, "unavailable"),
        ThreatIntelResult("C", True, False, 0, "clean"),
    ]
    score, level, confidence, verdict, _ = calculate_risk(10, results)
    # Two independent results (one malicious, one clean) → still scores high
    assert score >= 80
    assert level == "critical"


# ─── Decompose URL Edge Cases ───────────────────────────────────────────────


def test_ip_url_decomposition():
    parts = decompose_url("http://192.168.1.1/login")
    by_key = {p.key: p for p in parts}
    assert by_key["PROTOCOL"].suspicious is True  # HTTP is suspicious


def test_malformed_url_fallback():
    # urlparse still produces a result for non-URL strings; the path becomes
    # the entire string. Verify decomposition handles this gracefully.
    parts = decompose_url("not-a-url")
    by_key = {p.key: p for p in parts}
    assert by_key["PROTOCOL"].value == "NONE"
    assert by_key["PATH"].value == "not-a-url"


def test_suspicious_tld_in_decomposition():
    parts = decompose_url("https://example.xyz/path")
    by_key = {p.key: p for p in parts}
    assert by_key["TLD"].suspicious is True


def test_nested_url_in_query_detected():
    parts = decompose_url("https://example.com/page?url=https://evil.com")
    by_key = {p.key: p for p in parts}
    assert by_key["QUERY PARAMETERS"].suspicious is True


def test_large_number_of_query_params():
    params = "&".join(f"k{i}=v{i}" for i in range(15))
    parts = decompose_url(f"https://example.com/page?{params}")
    by_key = {p.key: p for p in parts}
    assert by_key["QUERY PARAMETERS"].suspicious is True
