from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.analyzers.url_analyzer import (
    analyze_url,
    decompose_url,
    get_recommendation,
)
from app.models.scan import (
    DomainInfo,
    ReputationInfo,
    RiskAssessment,
    ScanResponse,
    ThreatIntelligenceInfo,
)
from app.services.domain_intelligence import extract_domain_info, enrich_domain_info
from app.services.risk_engine import calculate_risk
from app.services.threat_intelligence.base import (
    ThreatIntelProvider,
    ThreatIntelResult,
)
from app.services.threat_intelligence.registry import (
    get_url_threat_intel_providers,
)
from app.services.url_normalizer import normalize_url_target, is_private_or_local_hostname
from urllib.parse import urlparse


def scan_url_target(
    target: str,
    providers: Sequence[ThreatIntelProvider] | None = None,
    enrich_domain: bool = False,
) -> ScanResponse:
    """
    Run the complete URL scanning pipeline.
    """

    # Normalize once at the boundary so every analyzer/provider sees the
    # exact same canonical HTTP(S) target.
    target = normalize_url_target(target)

    # 1. Local URL analysis.
    local_score, findings = analyze_url(target)

    # 2. Domain intelligence.
    domain_info_data = extract_domain_info(target)
    if enrich_domain:
        domain_info_data = enrich_domain_info(domain_info_data)
    domain_info = DomainInfo(**domain_info_data)

    url_components = decompose_url(target)
    infrastructure_score = sum(int(signal.get("score", 0) or 0) for signal in domain_info.risk_signals)

    # 3. External threat-intelligence providers.
    provider_results = collect_url_threat_intelligence(
        target=target,
        providers=providers,
    )

    # 4. Preserve the first provider as the legacy reputation field.
    reputation_result = select_primary_reputation(
        provider_results
    )

    reputation = ReputationInfo(
        provider=reputation_result.provider,
        available=reputation_result.available,
        malicious=reputation_result.malicious,
        score=reputation_result.score,
        details=reputation_result.details,
    )

    # 5. Expose all provider results through the new intelligence field.
    intelligence = [
        ThreatIntelligenceInfo(
            provider=result.provider,
            available=result.available,
            malicious=result.malicious,
            score=result.score,
            details=result.details,
            error=result.error,
        )
        for result in provider_results
    ]

    # 6. Centralized risk calculation.
    (
        final_score,
        risk_level,
        confidence,
        verdict,
        explanation,
    ) = calculate_risk(
        local_score=local_score,
        provider_results=provider_results,
        infrastructure_score=infrastructure_score,
        infrastructure_signals=domain_info.risk_signals,
    )

    risk_assessment = RiskAssessment(
        score=final_score,
        level=risk_level,
        confidence=confidence,
        verdict=verdict,
        explanation=explanation,
    )

    # 7. Build the backward-compatible API response.
    return ScanResponse(
        target=target,
        target_type="url",
        risk_score=final_score,
        risk_level=risk_level,
        findings=findings,
        url_components=url_components,
        recommendation=get_recommendation(risk_level, findings, verdict),
        domain_info=domain_info,
        reputation=reputation,
        intelligence=intelligence,
        risk_assessment=risk_assessment,
    )


def collect_url_threat_intelligence(
    target: str,
    providers: Sequence[ThreatIntelProvider] | None = None,
) -> list[ThreatIntelResult]:
    """Query all configured providers concurrently while isolating failures."""
    active_providers = (
        list(providers)
        if providers is not None
        else get_url_threat_intel_providers()
    )

    if not active_providers:
        return []

    parsed = urlparse(target)
    blocked_target = is_private_or_local_hostname(parsed.hostname)
    if blocked_target:
        return [
            ThreatIntelResult(
                provider=provider.name,
                available=False,
                malicious=None,
                score=None,
                details="External threat-intelligence lookup was blocked for a private or local target.",
                error="blocked_private_target",
            )
            for provider in active_providers
        ]

    def run_provider(provider: ThreatIntelProvider) -> ThreatIntelResult:
        try:
            result = provider.check_url(target)
            if not isinstance(result, ThreatIntelResult):
                return ThreatIntelResult(
                    provider=provider.name,
                    available=False,
                    malicious=None,
                    score=None,
                    details=f"{provider.name} returned an invalid provider result.",
                    error="invalid_provider_result",
                )
            return result
        except Exception:
            return ThreatIntelResult(
                provider=provider.name,
                available=False,
                malicious=None,
                score=None,
                details=f"{provider.name} provider failed during lookup.",
                error="provider_failure",
            )

    results_by_index: dict[int, ThreatIntelResult] = {}
    with ThreadPoolExecutor(max_workers=min(4, len(active_providers))) as pool:
        futures = {pool.submit(run_provider, provider): index for index, provider in enumerate(active_providers)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                results_by_index[index] = future.result()
            except Exception:
                provider = active_providers[index]
                results_by_index[index] = ThreatIntelResult(
                    provider=provider.name,
                    available=False,
                    malicious=None,
                    score=None,
                    details=f"{provider.name} provider failed during lookup.",
                    error="provider_failure",
                )

    return [results_by_index[index] for index in range(len(active_providers))]


def select_primary_reputation(
    provider_results: Sequence[ThreatIntelResult],
) -> ThreatIntelResult:
    """
    Select the first provider result for the legacy reputation field.

    The complete provider set remains available through intelligence.
    """

    if provider_results:
        return provider_results[0]

    return ThreatIntelResult(
        provider="None",
        available=False,
        malicious=None,
        score=None,
        details=(
            "No threat intelligence providers "
            "are configured."
        ),
        error="no_providers_configured",
    )