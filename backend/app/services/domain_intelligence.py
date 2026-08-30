from urllib.parse import urlparse
import ipaddress


def extract_domain_info(url: str) -> dict:
    """
    Extract useful domain-level information from a URL.

    This function does not determine whether a domain is malicious.
    It only extracts and classifies domain information.
    """

    parsed = urlparse(url.strip())
    hostname = parsed.hostname

    if not hostname:
        return {
            "hostname": None,
            "is_ip": False,
            "domain": None,
            "subdomain": None,
            "tld": None,
        }

    hostname = hostname.lower().rstrip(".")

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)

        return {
            "hostname": hostname,
            "is_ip": True,
            "domain": None,
            "subdomain": None,
            "tld": None,
        }

    except ValueError:
        pass

    parts = hostname.split(".")

    # Basic domain extraction strategy.
    #
    # This intentionally does not attempt to fully understand
    # every public suffix, such as co.uk.
    if len(parts) >= 2:
        domain = ".".join(parts[-2:])
        tld = parts[-1]
        subdomain = ".".join(parts[:-2]) or None
    else:
        domain = hostname
        tld = None
        subdomain = None

    return {
        "hostname": hostname,
        "is_ip": False,
        "domain": domain,
        "subdomain": subdomain,
        "tld": tld,
    }