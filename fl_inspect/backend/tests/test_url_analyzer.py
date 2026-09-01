from app.analyzers.url_analyzer import (
    analyze_url,
    get_risk_level,
    get_recommendation,
)


def test_safe_https_url():
    score, findings = analyze_url("https://example.com")

    assert score >= 0
    assert score <= 100
    assert isinstance(findings, list)


def test_ip_based_url():
    score, findings = analyze_url("http://192.168.1.10/login")

    rules = [finding.rule for finding in findings]

    assert "ip_based_url" in rules
    assert score > 0


def test_at_symbol_detection():
    score, findings = analyze_url(
        "https://example.com@malicious.com/login"
    )

    rules = [finding.rule for finding in findings]

    assert "at_symbol_in_url" in rules
    assert score > 0


def test_punycode_detection():
    score, findings = analyze_url(
        "https://xn--pple-43d.com"
    )

    rules = [finding.rule for finding in findings]

    assert "punycode_domain" in rules
    assert score > 0


def test_http_detection():
    score, findings = analyze_url("http://example.com")

    rules = [finding.rule for finding in findings]

    assert "no_https" in rules
    assert score > 0


def test_suspicious_keyword_detection():
    score, findings = analyze_url(
        "https://example.com/login/verify-account"
    )

    rules = [finding.rule for finding in findings]

    assert "suspicious_keywords" in rules
    assert score > 0


def test_risk_levels():
    assert get_risk_level(10) == "low"
    assert get_risk_level(30) == "medium"
    assert get_risk_level(60) == "high"
    assert get_risk_level(80) == "critical"


def test_recommendations():
    assert isinstance(get_recommendation("low"), str)
    assert isinstance(get_recommendation("medium"), str)
    assert isinstance(get_recommendation("high"), str)
    assert isinstance(get_recommendation("critical"), str)

def test_embedded_credentials_detection():
    score, findings = analyze_url(
        "https://admin:password@example.com/login"
    )

    rules = [finding.rule for finding in findings]

    assert "embedded_credentials" in rules
    assert score > 0


def test_unusual_port_detection():
    score, findings = analyze_url(
        "https://example.com:4444/login"
    )

    rules = [finding.rule for finding in findings]

    assert "unusual_port" in rules
    assert score > 0


def test_excessive_subdomains_detection():
    score, findings = analyze_url(
        "https://login.account.verify.security.example.com"
    )

    rules = [finding.rule for finding in findings]

    assert "excessive_subdomains" in rules
    assert score > 0


def test_suspicious_tld_detection():
    score, findings = analyze_url(
        "https://example.xyz"
    )

    rules = [finding.rule for finding in findings]

    assert "suspicious_tld" in rules
    assert score > 0


def test_url_shortener_detection():
    score, findings = analyze_url(
        "https://bit.ly/example"
    )

    rules = [finding.rule for finding in findings]

    assert "url_shortener" in rules
    assert score > 0


def test_excessive_hyphens_detection():
    score, findings = analyze_url(
        "https://secure-login-account-verify.example.com"
    )

    rules = [finding.rule for finding in findings]

    assert "excessive_hyphens" in rules
    assert score > 0


def test_excessive_encoding_detection():
    score, findings = analyze_url(
        "https://example.com/%41/%42/%43/%44/%45/%46"
    )

    rules = [finding.rule for finding in findings]

    assert "excessive_url_encoding" in rules
    assert score > 0