from collections.abc import Sequence

from app.services.threat_intelligence.base import ThreatIntelResult


def calculate_risk(local_score: int, provider_results: Sequence[ThreatIntelResult]) -> tuple[int, str, str, str, str]:
    """Calculate a deterministic risk score from independent evidence.

    The score is intentionally conservative: a single weak provider signal is
    not allowed to turn into a 100/100 verdict. Provider ``malicious=True`` is
    treated as a strong claim only when the provider also supplies substantial
    evidence. Multiple independent malicious providers can confirm the result.
    """
    local_score = clamp_score(local_score)
    available_results = [r for r in provider_results if r.available]
    scored_results = [r for r in available_results if r.score is not None]

    provider_scores = [clamp_score(r.score) for r in scored_results if r.score is not None]
    strongest_provider_score = max(provider_scores, default=0)

    malicious_results = [r for r in available_results if r.malicious is True]
    strong_malicious_results = [
        r for r in malicious_results
        if r.score is not None and clamp_score(r.score) >= 70
    ]

    # Start with the strongest independent signal. Supporting evidence gets a
    # small bounded boost instead of being blindly added together.
    risk_score = max(local_score, strongest_provider_score)

    supporting_scores = sorted(provider_scores, reverse=True)[1:]
    if supporting_scores:
        supporting_boost = min(15, round(sum(s * 0.10 for s in supporting_scores)))
        risk_score += supporting_boost

    # Two independent malicious providers are high-confidence confirmation.
    if len(malicious_results) >= 2:
        risk_score = 100

    # One strong malicious provider is serious evidence, but not mathematical
    # certainty. Keep it below 100 unless independent sources agree.
    elif strong_malicious_results:
        risk_score = max(risk_score, 90)

    # A weak/low-count malicious provider signal should increase suspicion but
    # must not automatically become Critical.
    elif malicious_results:
        risk_score = max(risk_score, min(69, strongest_provider_score + 10))

    risk_score = clamp_score(risk_score)
    risk_level = get_risk_level(risk_score)
    confidence = calculate_confidence(
        local_score,
        available_results,
        malicious_results,
        scored_results,
    )
    verdict = get_verdict(
        risk_score,
        confidence,
        malicious_results,
        strong_malicious_results,
    )
    explanation = build_explanation(
        local_score,
        available_results,
        malicious_results,
        strong_malicious_results,
        scored_results,
        risk_score,
        confidence,
    )

    return risk_score, risk_level, confidence, verdict, explanation


def clamp_score(score: int | None) -> int:
    if score is None:
        return 0
    return max(0, min(int(score), 100))


def get_risk_level(score: int) -> str:
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
    provider_count = len(available_results)

    if len(malicious_results) >= 2:
        return "high"

    if malicious_results:
        # A single strong provider is high-confidence evidence, while a weak
        # provider signal remains medium-confidence until corroborated.
        if malicious_results[0].score is not None and clamp_score(malicious_results[0].score) >= 70:
            return "high"
        return "medium"

    if provider_count >= 2 and (len(scored_results) >= 2 or local_score >= 50):
        return "high"
    if provider_count >= 1 and (scored_results or local_score >= 50):
        return "medium"
    return "low"


def get_verdict(
    risk_score: int,
    confidence: str,
    malicious_results: Sequence[ThreatIntelResult],
    strong_malicious_results: Sequence[ThreatIntelResult],
) -> str:
    if len(malicious_results) >= 2:
        return "confirmed_by_multiple_sources"
    if strong_malicious_results:
        return "confirmed_malicious"
    if malicious_results:
        return "suspicious"
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
    strong_malicious_results: Sequence[ThreatIntelResult],
    scored_results: Sequence[ThreatIntelResult],
    risk_score: int,
    confidence: str,
) -> str:
    parts: list[str] = []

    if local_score > 0:
        parts.append(f"Local analysis produced a risk score of {local_score}/100.")

    if scored_results:
        strongest = max(clamp_score(r.score) for r in scored_results if r.score is not None)
        parts.append(f"Threat intelligence contributed a strongest provider score of {strongest}/100.")

    if len(malicious_results) >= 2:
        names = ", ".join(r.provider for r in malicious_results)
        parts.append(
            f"{len(malicious_results)} independent threat-intelligence providers reported the target as malicious: {names}."
        )
        parts.append("Independent malicious-provider agreement sets the final evidence score to 100/100.")
    elif strong_malicious_results:
        names = ", ".join(r.provider for r in strong_malicious_results)
        parts.append(
            f"Strong malicious evidence was reported by {names}; the score is capped below 100 until independent corroboration is available."
        )
    elif malicious_results:
        names = ", ".join(r.provider for r in malicious_results)
        parts.append(
            f"A provider reported a limited malicious signal ({names}), but the evidence is not strong enough by itself to confirm the target as malicious."
        )
    elif available_results:
        parts.append(
            f"{len(available_results)} threat-intelligence provider(s) returned usable results; no provider reported a confirmed malicious verdict."
        )
    else:
        parts.append("No usable threat-intelligence provider result was available.")

    parts.append(f"Final evidence score: {risk_score}/100 with {confidence} confidence.")
    return " ".join(parts)
