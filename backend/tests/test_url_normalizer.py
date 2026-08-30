import pytest

from app.services.url_normalizer import normalize_url_target


def test_https_url_is_preserved():
    assert normalize_url_target("https://www.google.com") == "https://www.google.com"


def test_bare_domain_gets_https():
    assert normalize_url_target("www.google.com") == "https://www.google.com"


def test_http_url_is_preserved():
    assert normalize_url_target("http://example.com/login") == "http://example.com/login"


def test_common_https_typo_is_repaired():
    assert normalize_url_target("https;//example.com") == "https://example.com"
    assert normalize_url_target("https:/example.com") == "https://example.com"
    assert normalize_url_target("https;://example.com") == "https://example.com"


def test_unsupported_scheme_is_rejected():
    with pytest.raises(ValueError, match="Only HTTP and HTTPS"):
        normalize_url_target("ftp://example.com/file")


def test_missing_hostname_is_rejected():
    with pytest.raises(ValueError, match="valid hostname"):
        normalize_url_target("https://")
