import base64
import os
from typing import Any

import requests

from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.http_utils import request_with_retry


class VirusTotalProvider:
    name = "VirusTotal"
    endpoint = "https://www.virustotal.com/api/v3/urls"
    timeout = 10

    def check_url(self, url: str) -> ThreatIntelResult:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not api_key:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details=(
                    "VirusTotal is not configured. Set VIRUSTOTAL_API_KEY "
                    "to enable URL report lookups."
                ),
                error="missing_api_key",
            )

        url_id = create_url_identifier(url)

        try:
            response = request_with_retry(
                lambda: requests.get(
                    f"{self.endpoint}/{url_id}",
                    headers={"x-apikey": api_key},
                    timeout=self.timeout,
                )
            )
        except requests.RequestException as exc:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="VirusTotal could not be reached.",
                error="network_error",
            )

        if response.status_code == 404:
            return ThreatIntelResult(
                provider=self.name,
                available=True,
                malicious=None,
                score=None,
                details=(
                    "VirusTotal has no existing URL report for this target. "
                    "This does not confirm the URL is safe."
                ),
                error="not_found",
            )

        if response.status_code in {401, 403}:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="VirusTotal authentication failed.",
                error=f"http_{response.status_code}",
            )

        if response.status_code == 429:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="VirusTotal rate limit was reached.",
                error="rate_limited",
            )

        if response.status_code != 200:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details=f"VirusTotal returned HTTP {response.status_code}.",
                error=f"http_{response.status_code}",
            )

        try:
            payload = response.json()
        except ValueError as exc:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="VirusTotal returned malformed JSON.",
                error="invalid_response",
            )

        return parse_url_report(payload)


def create_url_identifier(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")

    return encoded.rstrip("=")


def parse_url_report(payload: dict[str, Any]) -> ThreatIntelResult:
    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats")
    )

    if not isinstance(stats, dict):
        return ThreatIntelResult(
            provider=VirusTotalProvider.name,
            available=False,
            malicious=None,
            score=None,
            details="VirusTotal response did not include analysis statistics.",
            error="unexpected_response_structure",
        )

    malicious_count = _get_stat_count(stats, "malicious")
    suspicious_count = _get_stat_count(stats, "suspicious")
    harmless_count = _get_stat_count(stats, "harmless")
    undetected_count = _get_stat_count(stats, "undetected")
    timeout_count = _get_stat_count(stats, "timeout")

    analyzed_count = (
        malicious_count
        + suspicious_count
        + harmless_count
        + undetected_count
        + timeout_count
    )

    # A single engine can be a false positive. Treat VirusTotal as
    # "confirmed malicious" only when there is meaningful multi-engine
    # agreement; the numeric score still reflects weaker signals.
    malicious_rate = (malicious_count / analyzed_count) if analyzed_count else 0
    malicious = (
        malicious_count >= 2
        and malicious_rate >= 0.05
    ) or malicious_count >= 5

    # Score formula: malicious detections carry full weight and suspicious
    # detections carry half weight, normalized by analyzed engines.
    # Examples: 2 malicious of 10 => 20, 2 suspicious of 10 => 10.
    score = None
    if analyzed_count > 0:
        weighted_detections = malicious_count + (suspicious_count * 0.5)
        score = round((weighted_detections / analyzed_count) * 100)
        score = min(max(score, 0), 100)

    details = (
        "VirusTotal detected "
        f"{malicious_count} malicious and {suspicious_count} suspicious "
        f"engines out of {analyzed_count} analyzed."
    )

    if malicious_count == 0:
        details += " No malicious detections were reported; this does not prove safety."

    return ThreatIntelResult(
        provider=VirusTotalProvider.name,
        available=True,
        malicious=malicious,
        score=score,
        details=details,
    )


def _get_stat_count(stats: dict[str, Any], key: str) -> int:
    value = stats.get(key, 0)

    if isinstance(value, int):
        return max(value, 0)

    return 0
