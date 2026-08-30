from app.services.threat_intelligence.base import ThreatIntelProvider
from app.services.threat_intelligence.urlhaus import URLhausProvider
from app.services.threat_intelligence.virustotal import VirusTotalProvider


def get_url_threat_intel_providers() -> list[ThreatIntelProvider]:
    return [
        URLhausProvider(),
        VirusTotalProvider(),
    ]
