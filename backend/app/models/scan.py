from typing import List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description=(
            "URL, domain, IP address, email address, "
            "or other indicator to analyze."
        ),
    )


class Finding(BaseModel):
    rule: str
    severity: str
    description: str
    score: int


class DomainInfo(BaseModel):
    hostname: Optional[str] = None
    is_ip: bool = False
    domain: Optional[str] = None
    subdomain: Optional[str] = None
    tld: Optional[str] = None
    registration: dict = Field(default_factory=dict)
    dns: dict = Field(default_factory=dict)
    infrastructure: dict = Field(default_factory=dict)
    risk_signals: List[dict] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    lookup_status: str = "unavailable"


class ReputationInfo(BaseModel):
    provider: str
    available: bool
    malicious: Optional[bool] = None
    score: Optional[int] = None
    details: str


class ThreatIntelligenceInfo(BaseModel):
    provider: str
    available: bool
    malicious: Optional[bool] = None
    score: Optional[int] = None
    details: str
    error: Optional[str] = None


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str
    confidence: str
    verdict: str
    explanation: str


class URLComponent(BaseModel):
    key: str
    value: str
    status: str
    suspicious: bool = False
    reason: Optional[str] = None


class ScanResponse(BaseModel):
    target: str
    target_type: str

    risk_score: int = Field(ge=0, le=100)
    risk_level: str

    findings: List[Finding]
    url_components: List[URLComponent] = Field(default_factory=list)
    recommendation: str

    domain_info: Optional[DomainInfo] = None
    reputation: Optional[ReputationInfo] = None

    intelligence: List[ThreatIntelligenceInfo] = Field(
        default_factory=list
    )

    risk_assessment: Optional[RiskAssessment] = None