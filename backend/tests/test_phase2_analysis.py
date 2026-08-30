from unittest.mock import patch

from app.analyzers.url_analyzer import analyze_url, decompose_url, get_recommendation
from app.services.domain_intelligence import enrich_domain_info, extract_domain_info
from app.services.scan_engine import scan_url_target
from app.services.threat_intelligence.base import ThreatIntelResult


def test_google_like_url_has_clean_structure_and_no_false_brand_signal():
    score, findings = analyze_url("https://google.com/")
    rules = {finding.rule for finding in findings}
    assert score == 0
    assert "brand_impersonation" not in rules
    assert "suspicious_keywords" not in rules


def test_brand_impersonation_is_detected():
    score, findings = analyze_url("https://google-security-login.example.com/verify")
    rules = {finding.rule for finding in findings}
    assert "brand_impersonation" in rules
    assert score >= 30


def test_redirect_parameter_and_nested_url_are_detected():
    score, findings = analyze_url("https://example.com/login?next=https%3A%2F%2Fevil.example%2Flogin")
    rules = {finding.rule for finding in findings}
    assert "redirect_parameter" in rules
    assert "nested_url_parameter" in rules
    assert score >= 20


def test_url_decomposition_marks_suspicious_components():
    parts = decompose_url("https://secure.example.xyz/login?redirect=https%3A%2F%2Fevil.test")
    by_key = {part.key: part for part in parts}
    assert set(by_key) == {"PROTOCOL", "SUBDOMAIN", "DOMAIN", "TLD", "PATH", "QUERY PARAMETERS", "REDIRECT BEHAVIOR", "FRAGMENT"}
    assert by_key["SUBDOMAIN"].suspicious is True
    assert by_key["TLD"].suspicious is True
    assert by_key["QUERY PARAMETERS"].suspicious is True
    assert by_key["REDIRECT BEHAVIOR"].status == "PASSIVE MODE"


def test_domain_enrichment_parses_rdap_dns_and_ip_data_without_target_request():
    base = extract_domain_info("https://example.com/")
    rdap = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        "nameservers": [{"ldhName": "ns1.example.net"}],
    }

    def fake_json(session, url, **kwargs):
        if "/domain/" in url:
            return rdap
        if kwargs.get("params", {}).get("type") == "A":
            return {"Answer": [{"data": "93.184.216.34"}]}
        if kwargs.get("params", {}).get("type") == "AAAA":
            return {"Answer": []}
        if kwargs.get("params", {}).get("type") == "MX":
            return {"Answer": [{"data": "10 mail.example.com."}]}
        if kwargs.get("params", {}).get("type") == "NS":
            return {"Answer": [{"data": "ns1.example.net."}]}
        if url.startswith("https://ipwho.is/"):
            return {"success": True, "country": "United States", "country_code": "US", "city": "Los Angeles", "region": "California", "connection": {"asn": 64500, "org": "Example Network", "isp": "Example ISP", "domain": "example.net"}}
        raise AssertionError(url)

    with patch("app.services.domain_intelligence._SafeSession.get_json", fake_json):
        enriched = enrich_domain_info(base)

    assert enriched["registration"]["registrar"] == "Example Registrar"
    assert enriched["registration"]["age_days"] > 1000
    assert enriched["dns"]["A"] == ["93.184.216.34"]
    assert enriched["dns"]["MX"] == ["10 mail.example.com"]
    assert enriched["dns"]["NS"] == ["ns1.example.net"]
    assert enriched["infrastructure"]["asn"] == 64500
    assert enriched["infrastructure"]["country"] == "United States"


def test_new_domain_signal_is_integrated_into_scan_risk():
    provider = type("Provider", (), {"name": "Static", "check_url": lambda self, target: ThreatIntelResult("Static", True, False, 0, "Clean")})()
    base = extract_domain_info("https://new.example.com")
    with patch("app.services.scan_engine.enrich_domain_info", return_value={**base, "risk_signals": [{"rule": "new_domain", "severity": "medium", "description": "Recently registered", "score": 8}], "lookup_status": "complete"}):
        response = scan_url_target("https://new.example.com", providers=[provider], enrich_domain=True)
    assert response.risk_score == 8
    assert response.domain_info.risk_signals[0]["rule"] == "new_domain"
    assert "new_domain" in response.risk_assessment.explanation
    assert "recently" in get_recommendation("low", response.findings, response.risk_assessment.verdict).lower() or response.risk_level == "low"
