from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.urlhaus import URLhausProvider


ReputationResult = ThreatIntelResult


def check_urlhaus(url: str) -> ReputationResult:
    """
    Query URLhaus for known malicious URL intelligence.

    URLhaus is used only as an external intelligence source.
    Failure to contact the service does not mean the URL is safe.
    """

    return URLhausProvider().check_url(url)
