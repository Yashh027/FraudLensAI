from urllib.parse import urlparse
import ipaddress
import re

from app.models.scan import Finding


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "payment",
    "billing",
    "confirm",
    "wallet",
    "bank",
    "crypto",
    "recover",
]


SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "work",
    "support",
    "gq",
    "tk",
    "ml",
    "cf",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
}


def analyze_url(url: str) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    score = 0

    url = url.strip()
    parsed = urlparse(url)

    # ---------------------------------------------------------
    # 1. URL scheme validation
    # ---------------------------------------------------------

    if parsed.scheme not in {"http", "https"}:
        findings.append(
            Finding(
                rule="invalid_url_scheme",
                severity="medium",
                description=(
                    "The submitted target does not use HTTP or HTTPS."
                ),
                score=15,
            )
        )
        score += 15

    hostname = parsed.hostname

    if not hostname:
        findings.append(
            Finding(
                rule="missing_hostname",
                severity="high",
                description=(
                    "The URL does not contain a valid hostname."
                ),
                score=30,
            )
        )
        return min(score, 100), findings

    hostname = hostname.lower()

    # ---------------------------------------------------------
    # 2. IP address detection
    # ---------------------------------------------------------

    try:
        ipaddress.ip_address(hostname)

        findings.append(
            Finding(
                rule="ip_based_url",
                severity="medium",
                description=(
                    "The URL uses an IP address instead of a domain name."
                ),
                score=20,
            )
        )
        score += 20

    except ValueError:
        pass

    # ---------------------------------------------------------
    # 3. Extremely long URL
    # ---------------------------------------------------------

    if len(url) > 150:
        findings.append(
            Finding(
                rule="very_long_url",
                severity="medium",
                description=(
                    "The URL is unusually long and may contain "
                    "obfuscated parameters."
                ),
                score=15,
            )
        )
        score += 15

    # ---------------------------------------------------------
    # 4. @ symbol / user-info abuse
    # ---------------------------------------------------------

    if "@" in url:
        findings.append(
            Finding(
                rule="at_symbol_in_url",
                severity="high",
                description=(
                    "The URL contains '@', which can be abused to "
                    "disguise the actual destination."
                ),
                score=25,
            )
        )
        score += 25

    # ---------------------------------------------------------
    # 5. Punycode / internationalized domain detection
    # ---------------------------------------------------------

    if "xn--" in hostname:
        findings.append(
            Finding(
                rule="punycode_domain",
                severity="high",
                description=(
                    "The domain contains punycode, which can be used "
                    "in homograph-style attacks."
                ),
                score=25,
            )
        )
        score += 25

    # ---------------------------------------------------------
    # 6. Suspicious keywords
    # ---------------------------------------------------------

    lowered_url = url.lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowered_url
    ]

    if matched_keywords:
        findings.append(
            Finding(
                rule="suspicious_keywords",
                severity="medium",
                description=(
                    "The URL contains potentially suspicious terms: "
                    + ", ".join(sorted(set(matched_keywords)))
                ),
                score=15,
            )
        )
        score += 15

    # ---------------------------------------------------------
    # 7. HTTP instead of HTTPS
    # ---------------------------------------------------------

    if parsed.scheme == "http":
        findings.append(
            Finding(
                rule="no_https",
                severity="low",
                description="The URL does not use HTTPS.",
                score=10,
            )
        )
        score += 10

    # ---------------------------------------------------------
    # 8. Explicit username/password in URL
    # ---------------------------------------------------------

    if parsed.username or parsed.password:
        findings.append(
            Finding(
                rule="embedded_credentials",
                severity="high",
                description="The URL contains embedded user credentials.",
                score=25,
            )
        )
        score += 25

    # ---------------------------------------------------------
    # 9. Suspicious port
    # ---------------------------------------------------------

    if parsed.port is not None:
        common_ports = {80, 443, 8080, 8443}

        if parsed.port not in common_ports:
            findings.append(
                Finding(
                    rule="unusual_port",
                    severity="medium",
                    description=(
                        f"The URL uses the non-standard port {parsed.port}, "
                        "which may require additional investigation."
                    ),
                    score=10,
                )
            )
            score += 10

    # ---------------------------------------------------------
    # 10. Excessive subdomains
    # ---------------------------------------------------------

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:
        findings.append(
            Finding(
                rule="excessive_subdomains",
                severity="medium",
                description=(
                    "The hostname contains an unusually large number "
                    "of subdomain levels."
                ),
                score=15,
            )
        )
        score += 15

    # ---------------------------------------------------------
    # 11. Suspicious TLD
    # ---------------------------------------------------------

    if "." in hostname:
        tld = hostname.rsplit(".", 1)[-1]

        if tld in SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    rule="suspicious_tld",
                    severity="medium",
                    description=(
                        f"The domain uses the potentially high-risk "
                        f"TLD '.{tld}'."
                    ),
                    score=10,
                )
            )
            score += 10

    # ---------------------------------------------------------
    # 12. URL shortener detection
    # ---------------------------------------------------------

    if hostname in SHORTENER_DOMAINS:
        findings.append(
            Finding(
                rule="url_shortener",
                severity="medium",
                description=(
                    "The URL uses a known URL-shortening service, "
                    "which hides the final destination."
                ),
                score=15,
            )
        )
        score += 15

    # ---------------------------------------------------------
    # 13. Excessive hyphens in hostname
    # ---------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        findings.append(
            Finding(
                rule="excessive_hyphens",
                severity="low",
                description=(
                    "The hostname contains an unusually high "
                    "number of hyphens."
                ),
                score=5,
            )
        )
        score += 5

    # ---------------------------------------------------------
    # 14. Suspicious encoded characters
    # ---------------------------------------------------------

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        url,
    )

    if len(encoded_matches) >= 5:
        findings.append(
            Finding(
                rule="excessive_url_encoding",
                severity="medium",
                description=(
                    "The URL contains an unusually high number "
                    "of encoded characters."
                ),
                score=10,
            )
        )
        score += 10

    # ---------------------------------------------------------
    # Final score
    # ---------------------------------------------------------

    return min(score, 100), findings


def get_recommendation(risk_level: str) -> str:
    recommendations = {
        "low": (
            "No major local indicators were detected. "
            "Continue to verify the source before interacting with it."
        ),
        "medium": (
            "Exercise caution. Some characteristics of this target "
            "may require additional investigation."
        ),
        "high": (
            "Do not trust the target without additional verification. "
            "Further threat-intelligence checks are recommended."
        ),
        "critical": (
            "Treat this target as potentially malicious. "
            "Avoid interacting with it until additional intelligence "
            "confirms its safety."
        ),
    }

def get_risk_level(score: int) -> str:
    if score >= 70:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"


def get_recommendation(risk_level: str) -> str:
    recommendations = {
        "low": (
            "No major local indicators were detected. "
            "Continue to verify the source before interacting with it."
        ),
        "medium": (
            "Exercise caution. Some characteristics of this target "
            "may require additional investigation."
        ),
        "high": (
            "Do not trust the target without additional verification. "
            "Further threat-intelligence checks are recommended."
        ),
        "critical": (
            "Treat this target as potentially malicious. "
            "Avoid interacting with it until additional intelligence "
            "confirms its safety."
        ),
    }

    return recommendations[risk_level]