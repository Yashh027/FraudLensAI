import os
import time

import requests

from app.services.threat_intelligence.base import ThreatIntelResult
from app.services.threat_intelligence.http_utils import request_with_retry


class URLScanProvider:
    name = "urlscan.io"

    submit_endpoint = "https://urlscan.io/api/v1/scan"
    result_endpoint = "https://urlscan.io/api/v1/result/{scan_id}"

    timeout = 15
    max_wait = 45
    poll_interval = 5

    def check_url(self, url: str) -> ThreatIntelResult:
        """
        Submit a URL to urlscan.io and retrieve the completed scan result.

        urlscan.io is an active website-analysis service. A scan may take
        several seconds to complete, so the provider polls the result
        endpoint for a limited amount of time.
        """

        api_key = os.getenv("URLSCAN_API_KEY", "").strip()

        if not api_key:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details=(
                    "urlscan.io is not configured. Set "
                    "URLSCAN_API_KEY to enable urlscan.io analysis."
                ),
                error="missing_api_key",
            )

        headers = {
            "api-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "FraudLensAI/1.0",
        }

        try:
            # ---------------------------------------------------------
            # 1. Submit URL for scanning.
            # ---------------------------------------------------------
            response = request_with_retry(
                lambda: requests.post(
                    self.submit_endpoint,
                    headers=headers,
                    json={
                        "url": url,
                        "visibility": "private",
                    },
                    timeout=self.timeout,
                )
            )
            response.raise_for_status()

            submission = response.json()
            scan_id = submission.get("uuid")

            if not scan_id:
                return ThreatIntelResult(
                    provider=self.name,
                    available=False,
                    malicious=None,
                    score=None,
                    details="urlscan.io did not return a scan ID.",
                    error="missing_scan_id",
                )

            # ---------------------------------------------------------
            # 2. Poll for completed result.
            # ---------------------------------------------------------
            result_url = self.result_endpoint.format(
                scan_id=scan_id
            )

            deadline = time.monotonic() + self.max_wait

            while time.monotonic() < deadline:
                result_response = request_with_retry(
                    lambda: requests.get(
                        result_url,
                        headers={
                            "api-key": api_key,
                            "User-Agent": "FraudLensAI/1.0",
                        },
                        timeout=self.timeout,
                    )
                )

                if result_response.status_code == 200:
                    result = result_response.json()
                    return self._build_result(
                        result=result,
                        scan_id=scan_id,
                    )

                if result_response.status_code not in (404, 429):
                    result_response.raise_for_status()

                time.sleep(self.poll_interval)

            # ---------------------------------------------------------
            # 3. Scan did not finish within our time limit.
            # ---------------------------------------------------------
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details=(
                    "urlscan.io accepted the scan but the result was "
                    "not ready within the configured time limit."
                ),
                error=f"scan_pending:{scan_id}",
            )

        except requests.RequestException as exc:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="urlscan.io could not be reached.",
                error="network_error",
            )

        except ValueError as exc:
            return ThreatIntelResult(
                provider=self.name,
                available=False,
                malicious=None,
                score=None,
                details="urlscan.io returned an invalid response.",
                error="invalid_response",
            )

    def _build_result(
        self,
        result: dict,
        scan_id: str,
    ) -> ThreatIntelResult:
        """
        Convert urlscan.io's result into our common ThreatIntelResult.

        The exact urlscan result schema can evolve, so extraction is
        intentionally defensive.
        """

        verdicts = result.get("verdicts", {}) or {}

        overall = verdicts.get("overall", {}) or {}

        malicious = overall.get("malicious")
        score = None

        if malicious is True:
            score = 80

        elif malicious is False:
            score = 0

        details_parts = []

        if malicious is True:
            details_parts.append(
                "urlscan.io classified the scanned page as malicious."
            )

        elif malicious is False:
            details_parts.append(
                "urlscan.io did not classify the scanned page as malicious."
            )

        else:
            details_parts.append(
                "urlscan.io completed the scan but did not provide "
                "a definitive malicious verdict."
            )

        # Extract phishing verdict when available.
        phishing = overall.get("phishing")

        if phishing is True:
            details_parts.append(
                "A phishing verdict was reported by urlscan.io."
            )

            if score is None or score < 90:
                score = 90

            malicious = True

        # Extract page metadata when available.
        page = result.get("page", {}) or {}

        page_url = page.get("url")

        if page_url:
            details_parts.append(
                f"Scanned page: {page_url}"
            )

        details_parts.append(
            f"Scan ID: {scan_id}"
        )

        return ThreatIntelResult(
            provider=self.name,
            available=True,
            malicious=malicious,
            score=score,
            details=" ".join(details_parts),
        )