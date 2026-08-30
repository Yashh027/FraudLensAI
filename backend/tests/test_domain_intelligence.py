from app.services.domain_intelligence import extract_domain_info


def test_extract_normal_domain():
    result = extract_domain_info("https://example.com/login")

    assert result["hostname"] == "example.com"
    assert result["is_ip"] is False
    assert result["domain"] == "example.com"
    assert result["subdomain"] is None
    assert result["tld"] == "com"


def test_extract_subdomain():
    result = extract_domain_info(
        "https://login.example.com/verify"
    )

    assert result["hostname"] == "login.example.com"
    assert result["domain"] == "example.com"
    assert result["subdomain"] == "login"
    assert result["tld"] == "com"


def test_extract_ip_address():
    result = extract_domain_info(
        "http://192.168.1.10/login"
    )

    assert result["hostname"] == "192.168.1.10"
    assert result["is_ip"] is True
    assert result["domain"] is None
    assert result["subdomain"] is None
    assert result["tld"] is None


def test_extract_uppercase_domain():
    result = extract_domain_info(
        "https://LOGIN.Example.COM"
    )

    assert result["hostname"] == "login.example.com"
    assert result["domain"] == "example.com"
    assert result["tld"] == "com"