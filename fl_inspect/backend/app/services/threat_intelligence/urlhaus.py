import os

import requests

from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.http_utils import request_with_retry


class URLhausProvider:
    name = "URLhaus"
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    timeout = 10

    def check_url(self, url: str) -> ThreatIntelResult:
        """
        Query URLhaus for known malicious URL intelligence.

        Failure to contact URLhaus does not mean the URL is safe.
        """

        api_key = os.getenv("URLHAUS_API_KEY", "").strip()

        if not api_key:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details=(
                    "URLhaus is not configured. Set "
                    "URLHAUS_API_KEY to enable URLhaus lookups."
                ),
                error="missing_api_key",
            )

        try:
            response = request_with_retry(
                lambda: requests.post(
                    self.endpoint,
                    headers={"Auth-Key": api_key},
                    data={"url": url},
                    timeout=self.timeout,
                )
            )

            if getattr(response, "status_code", None) == 429:
                return ThreatIntelResult(
                    provider=self.name,
                    available=False,
                    malicious=None,
                    score=None,
                    details="URLhaus rate limit was reached. Try again later.",
                    error="rate_limited",
                )

            response.raise_for_status()

            data = response.json()
            if not isinstance(data, dict):
                raise TypeError("URLhaus returned a non-object response")
            query_status = data.get("query_status")

            if query_status == "no_results":
                return ThreatIntelResult(
                    provider=self.name,
                    available=True,
                    malicious=False,
                    score=None,
                    details=(
                        "No matching malicious URL record was returned by "
                        "URLhaus. This does not confirm the URL is safe."
                    ),
                )

            if query_status == "ok":
                return ThreatIntelResult(
                    provider=self.name,
                    available=True,
                    malicious=True,
                    score=80,
                    details=(
                        "The URL was found in URLhaus threat intelligence."
                    ),
                )

            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="URLhaus returned an unexpected response structure.",
                error="invalid_response",
            )

        except requests.Timeout:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="URLhaus timed out before returning a result.",
                error="timeout",
            )

        except requests.RequestException:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="URLhaus could not be reached.",
                error="network_error",
            )

        except (ValueError, TypeError, AttributeError) as exc:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="URLhaus returned an invalid response.",
                error="invalid_response",
            )