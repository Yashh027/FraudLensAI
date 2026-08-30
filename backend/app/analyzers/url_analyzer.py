from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlparse

from app.models.scan import Finding, URLComponent
from app.services.domain_intelligence import BRAND_OFFICIAL_DOMAINS, _registrable_domain


SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "password", "payment", "billing", "confirm",
    "wallet", "bank", "crypto", "recover", "account-update", "security-alert",
]
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support", "gq", "tk", "ml", "cf"}
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"}
REDIRECT_KEYS = {"url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "return", "returnto", "continue", "dest", "destination", "target", "link", "goto"}
SUSPICIOUS_SUBDOMAIN_TOKENS = {"login", "signin", "secure", "security", "verify", "verification", "account", "auth", "update", "support", "wallet", "payment"}


def _display(value: str | None, fallback: str = "NONE") -> str:
    return value if value else fallback


def decompose_url(url: str) -> list[URLComponent]:
    parsed = urlparse(url.strip())
    hostname = (parsed.hostname or "").lower().rstrip(".")
    domain, subdomain, tld = _registrable_domain(hostname) if hostname else (None, None, None)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = [key.lower() for key, _ in params]
    redirect_keys = sorted(set(query_keys) & REDIRECT_KEYS)
    decoded_query = unquote(parsed.query).lower()

    components = [
        URLComponent(key="PROTOCOL", value=f"{parsed.scheme.upper()}://" if parsed.scheme else "NONE", status="PARSED", suspicious=parsed.scheme == "http", reason="HTTP is unencrypted; HTTPS is preferred." if parsed.scheme == "http" else None),
        URLComponent(key="SUBDOMAIN", value=_display(subdomain), status="PRESENT" if subdomain else "NONE", suspicious=bool(subdomain and any(token in subdomain.split(".") for token in SUSPICIOUS_SUBDOMAIN_TOKENS)), reason="Contains security/login-style subdomain tokens." if subdomain and any(token in subdomain.split(".") for token in SUSPICIOUS_SUBDOMAIN_TOKENS) else None),
        URLComponent(key="DOMAIN", value=_display(domain), status="PARSED", suspicious=False),
        URLComponent(key="TLD", value=f".{tld}" if tld else "NONE", status="PARSED" if tld else "NONE", suspicious=bool(tld in SUSPICIOUS_TLDS), reason=f".{tld} is in FraudLens's higher-risk TLD watchlist." if tld in SUSPICIOUS_TLDS else None),
        URLComponent(key="PATH", value=parsed.path or "/", status="ROOT" if parsed.path in {"", "/"} else "PARSED", suspicious=False),
        URLComponent(key="QUERY PARAMETERS", value=parsed.query or "NONE", status="PRESENT" if parsed.query else "NONE", suspicious=bool(redirect_keys or len(params) > 8), reason="Contains redirect-style parameters." if redirect_keys else ("Contains an unusually large number of parameters." if len(params) > 8 else None)),
        URLComponent(key="REDIRECT BEHAVIOR", value="NOT FOLLOWED", status="PASSIVE MODE", suspicious=False, reason="FraudLens does not fetch or execute the target, so an HTTP redirect chain is not followed."),
        URLComponent(key="FRAGMENT", value=parsed.fragment or "NONE", status="PRESENT" if parsed.fragment else "NONE", suspicious=False),
    ]
    if redirect_keys:
        for component in components:
            if component.key == "QUERY PARAMETERS":
                component.reason = f"Redirect-style key(s): {', '.join(redirect_keys)}."
                break
    if "http://" in decoded_query or "https://" in decoded_query:
        for component in components:
            if component.key == "QUERY PARAMETERS":
                component.suspicious = True
                component.reason = "A query value contains a nested URL, which can hide a redirect destination."
                break
    return components


def _add(findings: list[Finding], rule: str, severity: str, description: str, score: int) -> int:
    findings.append(Finding(rule=rule, severity=severity, description=description, score=score))
    return score


def analyze_url(url: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    score = 0
    url = url.strip()
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if parsed.scheme not in {"http", "https"}:
        score += _add(findings, "invalid_url_scheme", "medium", "The submitted target does not use HTTP or HTTPS.", 15)
    if not hostname:
        score += _add(findings, "missing_hostname", "high", "The URL does not contain a valid hostname.", 30)
        return min(score, 100), findings

    try:
        ipaddress.ip_address(hostname)
        score += _add(findings, "ip_based_url", "medium", "The URL uses an IP address instead of a domain name.", 20)
    except ValueError:
        pass

    if len(url) > 150:
        score += _add(findings, "very_long_url", "medium", "The URL is unusually long and may contain obfuscated parameters.", 15)
    if "@" in url:
        score += _add(findings, "at_symbol_in_url", "high", "The URL contains '@', which can be abused to disguise the actual destination.", 25)
    if "xn--" in hostname:
        score += _add(findings, "punycode_domain", "high", "The domain contains punycode, which can be used in homograph-style attacks.", 25)

    # Only high-value credential/payment/security language is scored locally.
    # Ordinary /login paths are common on legitimate sites and should not be
    # treated as malicious by themselves.
    lowered_url = url.lower()
    matched_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_url]
    if matched_keywords:
        score += _add(findings, "suspicious_keywords", "medium", "The URL contains potentially sensitive or deceptive terms: " + ", ".join(sorted(set(matched_keywords))), 15)

    if parsed.scheme == "http":
        score += _add(findings, "no_https", "low", "The URL does not use HTTPS. This reduces transport security but does not by itself prove malicious intent.", 5)
    if parsed.username or parsed.password:
        score += _add(findings, "embedded_credentials", "high", "The URL contains embedded user credentials.", 25)
    if parsed.port is not None and parsed.port not in {80, 443, 8080, 8443}:
        score += _add(findings, "unusual_port", "medium", f"The URL uses the non-standard port {parsed.port}, which may require additional investigation.", 10)

    parts = hostname.split(".")
    if len(parts) >= 5:
        score += _add(findings, "excessive_subdomains", "medium", "The hostname contains an unusually large number of subdomain levels.", 15)

    domain, subdomain, tld = _registrable_domain(hostname)
    if tld in SUSPICIOUS_TLDS:
        score += _add(findings, "suspicious_tld", "medium", f"The domain uses the potentially high-risk TLD '.{tld}'.", 10)
    if hostname in SHORTENER_DOMAINS:
        score += _add(findings, "url_shortener", "medium", "The URL uses a known URL-shortening service, which hides the final destination.", 15)
    if hostname.count("-") >= 3:
        score += _add(findings, "excessive_hyphens", "low", "The hostname contains an unusually high number of hyphens.", 5)

    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(encoded_matches) >= 5:
        score += _add(findings, "excessive_url_encoding", "medium", "The URL contains an unusually high number of encoded characters.", 10)

    # Brand impersonation: a brand token appears in a non-official registrable
    # domain, or in a suspicious subdomain over an unrelated registrable domain.
    labels = set(re.split(r"[^a-z0-9]+", hostname))
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand in labels and domain not in official_domains:
            score += _add(findings, "brand_impersonation", "high", f"The hostname contains the brand name '{brand}' but the registered domain is '{domain}'. This pattern can indicate impersonation.", 30)
            break

    if subdomain:
        sub_labels = set(subdomain.split("."))
        suspicious_sub = sorted(sub_labels & SUSPICIOUS_SUBDOMAIN_TOKENS)
        if suspicious_sub and domain not in {f"{brand}.com" for brand in BRAND_OFFICIAL_DOMAINS}:
            score += _add(findings, "suspicious_subdomain", "low", f"The subdomain uses security/login-style terms: {', '.join(suspicious_sub)}. This is not malicious by itself, but it deserves context from the registered domain and other evidence.", 6)

    params = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = {key.lower() for key, _ in params}
    redirect_keys = sorted(query_keys & REDIRECT_KEYS)
    if redirect_keys:
        score += _add(findings, "redirect_parameter", "medium", f"The query contains redirect-style parameter(s): {', '.join(redirect_keys)}.", 8)
    decoded_query = unquote(parsed.query).lower()
    if "http://" in decoded_query or "https://" in decoded_query:
        score += _add(findings, "nested_url_parameter", "medium", "A query parameter contains another URL, which can conceal a redirect destination.", 12)
    if len(params) > 8:
        score += _add(findings, "many_query_parameters", "low", "The URL contains many query parameters, increasing complexity and potential for obfuscation.", 5)

    return min(score, 100), findings


def get_risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def get_recommendation(risk_level: str, findings: list[Finding] | None = None, verdict: str | None = None) -> str:
    findings = findings or []
    rules = {finding.rule for finding in findings}
    if risk_level == "critical":
        if "brand_impersonation" in rules:
            return "Do not open the target or enter credentials. The hostname resembles a known brand on a different registered domain and should be treated as high risk."
        return "Do not interact with this target or enter credentials. Verify it through a trusted channel before taking any action."
    if risk_level == "high":
        if "punycode_domain" in rules or "at_symbol_in_url" in rules:
            return "Avoid opening the target directly. Inspect the registered domain carefully and use the organization's known official site instead."
        return "Use caution and verify the destination independently before signing in, paying, downloading files, or sharing information."
    if risk_level == "medium":
        if "redirect_parameter" in rules or "nested_url_parameter" in rules:
            return "Treat redirects cautiously. Confirm the final destination before following the link, especially if it asks for credentials or payment."
        return "Some URL characteristics deserve caution. Verify the sender and destination before interacting with the target."
    if verdict == "insufficient_intelligence":
        return "Threat intelligence was limited or unavailable. The URL showed no major local indicators, but absence of evidence is not proof of safety."
    return "No major indicators were detected. This is not a guarantee of safety; verify the source before entering credentials or sensitive information."
