from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class ThreatIntelResult:
    provider: str
    available: bool
    malicious: Optional[bool]
    score: Optional[int]
    details: str
    error: Optional[str] = None


class ThreatIntelProvider(Protocol):
    name: str

    def check_url(self, url: str) -> ThreatIntelResult:
        ...
