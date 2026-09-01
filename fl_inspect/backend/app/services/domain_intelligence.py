from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "net.nz", "org.nz", "co.in", "firm.in", "net.in", "org.in",
    "gen.in", "ind.in", "co.jp", "ne.jp", "or.jp", "com.br", "com.mx",
    "com.cn", "com.sg", "com.tr", "co.za",
}

BRAND_OFFICIAL_DOMAINS = {
    "google": {"google.com", "google.co.uk", "google.co.in"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "paypal": {"paypal.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "netflix": {"netflix.com"},
    "github": {"github.com"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
}


class _SafeSession:
    """Small wrapper that keeps enrichment failures isolated."""

    def __init__(self, timeout: float = 4.0):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "FraudLensAI/1.0 domain-intelligence"})
        self.timeout = timeout

    def get_json(self, url: str, **kwargs):
        response = self.session.get(url, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response.json()

    def close(self):
        self.session.close()


def _registrable_domain(hostname: str) -> tuple[str | None, str | None, str | None]:
    hostname = hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(hostname)
        return None, None, None
    except ValueError:
        pass

    parts = [part for part in hostname.split(".") if part]
    if len(parts) < 2:
        return hostname, None, None

    suffix = ".".join(parts[-2:])
    if suffix in COMMON_MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        domain = ".".join(parts[-3:])
        tld = suffix
        subdomain = ".".join(parts[:-3]) or None
    else:
        domain = ".".join(parts[-2:])
        tld = parts[-1]
        subdomain = ".".join(parts[:-2]) or None
    return domain, subdomain, tld


def extract_domain_info(url: str) -> dict:
    parsed = urlparse(url.strip())
    hostname = parsed.hostname

    if not hostname:
        return {
            "hostname": None, "is_ip": False, "domain": None, "subdomain": None,
            "tld": None, "registration": {}, "dns": {}, "infrastructure": {},
            "risk_signals": [], "data_sources": [], "lookup_status": "unavailable",
        }

    hostname = hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(hostname)
        return {
            "hostname": hostname, "is_ip": True, "domain": None, "subdomain": None,
            "tld": None, "registration": {}, "dns": {},
            "infrastructure": {"ips": [hostname]}, "risk_signals": [],
            "data_sources": ["local URL parser"], "lookup_status": "structural_only",
        }
    except ValueError:
        pass

    domain, subdomain, tld = _registrable_domain(hostname)
    return {
        "hostname": hostname,
        "is_ip": False,
        "domain": domain,
        "subdomain": subdomain,
        "tld": tld,
        "registration": {},
        "dns": {},
        "infrastructure": {},
        "risk_signals": [],
        "data_sources": ["local URL parser"],
        "lookup_status": "pending",
    }


def _parse_rdap_domain(data: dict) -> dict:
    events = {}
    for event in data.get("events", []) or []:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            events[action] = date

    registrar = None
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray", [None, []])
        for item in vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                registrar = item[3]
                break
        if registrar:
            break
        registrar = entity.get("handle") or entity.get("name")

    nameservers = []
    for ns in data.get("nameservers", []) or []:
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            nameservers.append(name.rstrip("."))

    return {
        "created": events.get("registration"),
        "updated": events.get("last changed") or events.get("last update of RDAP database"),
        "expires": events.get("expiration"),
        "registrar": registrar,
        "nameservers": sorted(set(nameservers)),
    }


def _domain_age_days(created: str | None) -> int | None:
    if not created:
        return None
    try:
        value = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - value).days)
    except (TypeError, ValueError):
        return None


def _dns_query(session: _SafeSession, hostname: str, record_type: str) -> list[str]:
    url = "https://cloudflare-dns.com/dns-query"
    data = session.get_json(
        url,
        params={"name": hostname, "type": record_type},
        headers={"Accept": "application/dns-json"},
    )
    answers = []
    for answer in data.get("Answer", []) or []:
        value = answer.get("data")
        if value:
            answers.append(str(value).rstrip("."))
    return answers


def _resolve_local_ips(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})
    except (OSError, socket.gaierror):
        return []


def _ip_intelligence(session: _SafeSession, ip: str) -> dict:
    try:
        data = session.get_json(f"https://ipwho.is/{ip}")
        if not data.get("success", True):
            return {}
        connection = data.get("connection") or {}
        return {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "region": data.get("region"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": connection.get("asn"),
            "org": connection.get("org"),
            "isp": connection.get("isp"),
            "network": connection.get("domain"),
        }
    except Exception:
        return {"ip": ip}


def enrich_domain_info(base_info: dict, *, timeout: float = 4.0) -> dict:
    """Add passive RDAP/DNS/IP intelligence. Never requests the target URL."""
    info = dict(base_info)
    hostname = info.get("hostname")
    if not hostname or info.get("is_ip"):
        info["lookup_status"] = "structural_only"
        return info

    domain = info.get("domain") or hostname
    session = _SafeSession(timeout=timeout)
    sources = list(info.get("data_sources") or [])

    try:
        registration = {}
        try:
            rdap = session.get_json(f"https://rdap.org/domain/{domain}")
            registration = _parse_rdap_domain(rdap)
            sources.append("RDAP")
        except Exception:
            registration = {}

        info["registration"] = registration

        dns: dict[str, list[str]] = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(_dns_query, session, hostname, kind): kind for kind in ("A", "AAAA", "MX", "NS")}
            for future in as_completed(futures):
                kind = futures[future]
                try:
                    dns[kind] = future.result()
                except Exception:
                    dns[kind] = []
        info["dns"] = dns
        sources.append("Cloudflare DNS-over-HTTPS")

        ips = list(dict.fromkeys(dns.get("A", []) + dns.get("AAAA", [])))
        if not ips:
            ips = _resolve_local_ips(hostname)
        infrastructure = {"ips": ips}

        if ips:
            with ThreadPoolExecutor(max_workers=min(3, len(ips))) as pool:
                futures = [pool.submit(_ip_intelligence, session, ip) for ip in ips[:3]]
                ip_records = [future.result() for future in futures]
            usable = [record for record in ip_records if len(record) > 1]
            infrastructure["ip_records"] = usable
            if usable:
                primary = usable[0]
                for key in ("country", "country_code", "city", "region", "asn", "org", "isp", "network"):
                    if primary.get(key) is not None:
                        infrastructure[key] = primary[key]
                sources.append("IP geolocation/ASN intelligence")

        info["infrastructure"] = infrastructure
        info["data_sources"] = sorted(set(sources))
        info["lookup_status"] = "complete" if registration or dns or ips else "partial"

        age = _domain_age_days(registration.get("created"))
        info["registration"]["age_days"] = age

        risk_signals = []
        if age is not None and age < 30:
            risk_signals.append({
                "rule": "new_domain",
                "severity": "medium",
                "description": f"The domain was registered approximately {age} days ago.",
                "score": 8,
            })
        if age is not None and age < 7:
            risk_signals.append({
                "rule": "very_new_domain",
                "severity": "high",
                "description": "The domain appears to be less than one week old.",
                "score": 12,
            })
        if not dns.get("A") and not dns.get("AAAA"):
            risk_signals.append({
                "rule": "no_address_records",
                "severity": "low",
                "description": "No public A or AAAA record was returned for the hostname.",
                "score": 0,
            })
        info["risk_signals"] = risk_signals
        return info
    finally:
        session.close()
