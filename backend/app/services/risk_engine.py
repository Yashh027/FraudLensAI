from collections.abc import Sequence

from app.services.threat_intelligence.base import ThreatIntelResult


def calculate_risk(
    local_score: int,
    provider_results: Sequence[ThreatIntelResult],
) -> tuple[int, str, str, str, str]:
    """
    Calculate a deterministic, explainable risk assessment.

    Score meaning:
        0-24   = low
        25-49  = medium
        50-69  = high
        70-100 = critical

    The score is an evidence score, NOT a probability of maliciousness.

    The model combines:
        1. Local heuristic evidence
        2. Provider risk scores
        3. Malicious provider verdicts
        4. Agreement between independent providers
    """

    local_score = clamp_score(local_score)

    available_results = [
        result
        for result in provider_results
        if result.available
    ]

    scored_results = [
        result
        for result in available_results
        if result.score is not None
    ]

    malicious_results = [
        result
        for result in available_results
        if result.malicious is True
    ]

    # ---------------------------------------------------------
    # 1. Start with local heuristic evidence.
    # ---------------------------------------------------------

    risk_score = local_score

    # ---------------------------------------------------------
    # 2. Provider scores represent quantitative evidence.
    #
    # We use the strongest provider score rather than adding
    # provider scores together. This prevents double-counting
    # the same underlying threat intelligence.
    # ---------------------------------------------------------

    provider_scores = [
        clamp_score(result.score)
        for result in scored_results
        if result.score is not None
    ]

    if provider_scores:
        risk_score = max(
            risk_score,
            max(provider_scores),
        )

    # ---------------------------------------------------------
    # 3. Malicious verdicts.
    #
    # A malicious=True result is stronger than merely having a
    # numerical score, but the strength depends on the provider's
    # actual score.
    #
    # A very small detection ratio should not automatically become
    # critical.
    # ---------------------------------------------------------

    for result in malicious_results:
        provider_score = (
            clamp_score(result.score)
            if result.score is not None
            else None
        )

        # A provider explicitly reporting malicious=True is strong
        # threat intelligence. Any confirmed malicious provider
        # produces a minimum critical-risk score of 75.
        #
        # The provider's numerical score can still increase the
        # result above that threshold.
        if provider_score is None:
            risk_score = max(risk_score, 75)
        else:
            risk_score = max(risk_score, 75, provider_score)

    # ---------------------------------------------------------
    # 4. Multiple independent malicious providers.
    #
    # Agreement is powerful evidence.
    # ---------------------------------------------------------

    if len(malicious_results) >= 2:
        risk_score = max(risk_score, 90)

    risk_score = clamp_score(risk_score)

    # ---------------------------------------------------------
    # 5. Classification.
    # ---------------------------------------------------------

    risk_level = get_risk_level(risk_score)

    confidence = calculate_confidence(
        local_score=local_score,
        available_results=available_results,
        malicious_results=malicious_results,
        scored_results=scored_results,
    )

    verdict = get_verdict(
        risk_score=risk_score,
        confidence=confidence,
        malicious_results=malicious_results,
    )

    explanation = build_explanation(
        local_score=local_score,
        available_results=available_results,
        malicious_results=malicious_results,
        scored_results=scored_results,
        risk_score=risk_score,
        confidence=confidence,
    )

    return (
        risk_score,
        risk_level,
        confidence,
        verdict,
        explanation,
    )


def clamp_score(score: int | None) -> int:
    """Keep a score inside the valid 0-100 range."""

    if score is None:
        return 0

    return max(0, min(int(score), 100))


def get_risk_level(score: int) -> str:
    """
    Convert score to the public risk category.

    These thresholds are fixed and should remain consistent
    throughout the application.
    """

    score = clamp_score(score)

    if score >= 70:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"


def calculate_confidence(
    local_score: int,
    available_results: Sequence[ThreatIntelResult],
    malicious_results: Sequence[ThreatIntelResult],
    scored_results: Sequence[ThreatIntelResult],
) -> str:
    """
    Estimate confidence from the breadth and strength of evidence.

    Confidence describes how much evidence supports the assessment.
    It is NOT the probability that the target is malicious.
    """

    provider_count = len(available_results)

    # Multiple independent providers with meaningful evidence.
    if provider_count >= 2 and (
        len(malicious_results) >= 2
        or len(scored_results) >= 2
    ):
        return "high"

    # One provider with meaningful evidence.
    if provider_count >= 1 and (
        malicious_results
        or scored_results
        or local_score >= 50
    ):
        return "medium"

    # Only local weak evidence or no usable intelligence.
    return "low"


def get_verdict(
    risk_score: int,
    confidence: str,
    malicious_results: Sequence[ThreatIntelResult],
) -> str:
    """Generate the deterministic verdict."""

    if len(malicious_results) >= 2:
        return "confirmed_by_multiple_sources"

    if malicious_results:
        return "potentially_malicious"

    if risk_score >= 70:
        return "highly_suspicious"

    if risk_score >= 50:
        return "suspicious"

    if risk_score >= 25:
        return "low_confidence_suspicious"

    if confidence == "low":
        return "insufficient_intelligence"

    return "no_major_threat_indicators"


def build_explanation(
    local_score: int,
    available_results: Sequence[ThreatIntelResult],
    malicious_results: Sequence[ThreatIntelResult],
    scored_results: Sequence[ThreatIntelResult],
    risk_score: int,
    confidence: str,
) -> str:
    """Build an explanation of the final assessment."""

    parts: list[str] = []

    if local_score > 0:
        parts.append(
            f"Local analysis produced a risk score of "
            f"{local_score}/100."
        )
    else:
        parts.append(
            "Local analysis did not identify significant "
            "heuristic risk."
        )

    if malicious_results:
        providers = ", ".join(
            result.provider
            for result in malicious_results
        )

        parts.append(
            f"Malicious intelligence was reported by: {providers}."
        )

    elif scored_results:
        providers = ", ".join(
            result.provider
            for result in scored_results
        )

        parts.append(
            "Threat-intelligence scoring was available from: "
            f"{providers}."
        )

    else:
        parts.append(
            "No scored threat-intelligence evidence was available."
        )

    if available_results:
        parts.append(
            f"{len(available_results)} threat-intelligence "
            "provider(s) were available for this assessment."
        )
    else:
        parts.append(
            "No threat-intelligence providers were available."
        )

    parts.append(
        f"Final deterministic risk score: {risk_score}/100 "
        f"with {confidence} confidence."
    )

    return " ".join(parts)