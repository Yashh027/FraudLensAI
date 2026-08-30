import re
from urllib.parse import urlparse


_MALFORMED_HTTP_SCHEME_RE = re.compile(
    r"^(https?)\s*[:;]\s*(?::\s*)?/{1,2}",
    re.IGNORECASE,
)


def normalize_url_target(target: str) -> str:
    """Normalize a user-entered web URL without changing its destination.

    Accepted input includes:
      - https://example.com
      - http://example.com/path
      - example.com/path  -> https://example.com/path
      - common mistypes such as https;//example.com -> https://example.com

    Only HTTP(S) targets are accepted. We deliberately do not rewrite an
    unsupported scheme such as ftp:// into HTTPS because that would change
    the meaning of the submitted indicator.
    """

    value = (target or "").strip()
    if not value:
        raise ValueError("Enter a URL to scan.")

    # Repair only the common punctuation/spacing typo around http(s)://.
    value = _MALFORMED_HTTP_SCHEME_RE.sub(r"\1://", value)

    parsed = urlparse(value)

    # If the user entered a bare domain, treat it as HTTPS. This prevents
    # urlparse() from interpreting the domain as a path and avoids the
    # recurring "missing/invalid scheme" issue in downstream providers.
    if not parsed.scheme:
        value = f"https://{value}"
        parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    if not hostname:
        raise ValueError("The URL must contain a valid hostname.")

    if any(char.isspace() for char in hostname):
        raise ValueError("The URL hostname cannot contain spaces.")

    # Keep the user's path/query/fragment intact while normalizing the scheme.
    if parsed.scheme != parsed.scheme.lower():
        value = f"{parsed.scheme.lower()}://{value.split('://', 1)[1]}"

    # Accessing parsed.port above validates malformed ports.
    _ = port

    return value
