import ipaddress
import re
import socket
from urllib.parse import urlparse


_MALFORMED_HTTP_SCHEME_RE = re.compile(
    r"^(https?)\s*[:;]\s*(?::\s*)?/{1,2}",
    re.IGNORECASE,
)
MAX_URL_LENGTH = 2048


def normalize_url_target(target: str) -> str:
    """Normalize and validate an HTTP(S) URL without changing its destination."""
    value = (target or "").strip()
    if not value:
        raise ValueError("Enter a URL to scan.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL is too long. Maximum length is {MAX_URL_LENGTH} characters.")

    value = _MALFORMED_HTTP_SCHEME_RE.sub(r"\1://", value)
    parsed = urlparse(value)

    if not parsed.scheme:
        value = f"https://{value}"
        parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if parsed.username or parsed.password:
        # Credentials are valid URL syntax, so leave them intact for analysis.
        pass

    try:
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    if not hostname:
        raise ValueError("The URL must contain a valid hostname.")
    if any(char.isspace() for char in hostname):
        raise ValueError("The URL hostname cannot contain spaces.")
    if any(ord(char) < 32 for char in value):
        raise ValueError("The URL contains invalid control characters.")

    normalized_scheme = parsed.scheme.lower()
    if "://" in value:
        value = f"{normalized_scheme}://{value.split('://', 1)[1]}"

    return value


def is_private_or_local_hostname(hostname: str | None) -> bool:
    """Return True for literal/private/local targets that must not be sent to providers."""
    if not hostname:
        return True

    host = hostname.strip().lower().rstrip(".")
    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "local",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
        "metadata",
    }
    if host in blocked_names or host.endswith(".localhost") or host.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Also protect against hostnames resolving to private/internal IPs.
        # If DNS cannot be resolved, leave the decision to the provider; this
        # helper must not turn a transient local DNS failure into a false block.
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except (socket.gaierror, OSError):
            return False
        return any(is_private_or_local_hostname(address) for address in addresses)

    return any((
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
    ))
