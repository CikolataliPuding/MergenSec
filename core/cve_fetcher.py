"""Fetch and normalize CVE data from the NVD API."""

import asyncio
import json
import os
from typing import Any
from dotenv import load_dotenv

import aiohttp

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_SLEEP = 0.6
RETRY_SLEEP = 2.0
MAX_RETRIES = 1
RESULTS_PER_PAGE = 20


class CVEFetcher:
    """Fetch CVEs from NVD and return normalized vulnerability records."""

    def __init__(self, api_key: str):
        """Initialize fetcher with an API key provided by caller."""
        self._api_key = api_key.strip()
        if not self._api_key:
            raise RuntimeError("NVD_API_KEY is missing or empty.")

    async def fetch_cves(self, service: str, version: str) -> list[dict[str, Any]]:
        """Fetch CVEs for the given service and version."""
        params = self._build_params(service=service, version=version)
        headers = {"apiKey": self._api_key}

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for attempt in range(MAX_RETRIES + 1):
                await asyncio.sleep(RATE_LIMIT_SLEEP)
                try:
                    async with session.get(
                        NVD_BASE_URL,
                        headers=headers,
                        params=params,
                    ) as response:
                        if response.status == 429:
                            if attempt < MAX_RETRIES:
                                await asyncio.sleep(RETRY_SLEEP)
                                continue
                            raise RuntimeError(
                                "NVD API rate limit exceeded after retry.",
                            )

                        if 400 <= response.status < 500:
                            error_text = await response.text()
                            raise ValueError(
                                f"NVD API client error ({response.status}): {error_text}",
                            )

                        if 500 <= response.status < 600:
                            error_text = await response.text()
                            raise RuntimeError(
                                f"NVD API server error ({response.status}): {error_text}",
                            )

                        raw_data = await response.json()
                        if not isinstance(raw_data, dict):
                            raise TypeError("NVD API response must be a JSON object.")
                        return self._parse_response(raw_data)
                except aiohttp.ContentTypeError as error:
                    raise ValueError(
                        "NVD API returned unexpected content type.",
                    ) from error
                except json.JSONDecodeError as error:
                    raise ValueError("NVD API returned invalid JSON payload.") from error
                except aiohttp.ClientError as error:
                    raise ConnectionError(
                        "NVD API request failed due to network/client error.",
                    ) from error
                except asyncio.TimeoutError as error:
                    raise TimeoutError("NVD API request timed out.") from error

        return []

    @staticmethod
    def _build_params(service: str, version: str) -> dict[str, str | int]:
        """Build request query parameters for NVD CVE search."""
        return {
            "keywordSearch": f"{service.strip()} {version.strip()}",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        }

    @staticmethod
    def _parse_response(raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Validate and transform raw NVD API data into CVE records."""
        vulnerabilities = raw.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return []

        parsed_items: list[dict[str, Any]] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            cve_data = vulnerability.get("cve", {})
            if not isinstance(cve_data, dict):
                continue

            cve_id = cve_data.get("id")
            if not isinstance(cve_id, str) or not cve_id.strip():
                continue

            description = CVEFetcher._extract_description(None, cve_data)
            metrics = cve_data.get("metrics", {})
            metrics = metrics if isinstance(metrics, dict) else {}
            cvss_score, severity = CVEFetcher._extract_cvss(None, metrics)

            published = cve_data.get("published")
            published_value = published if isinstance(published, str) else None

            parsed_items.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "published": published_value,
                },
            )

        return parsed_items

    def _extract_description(self, cve_data: dict[str, Any]) -> str:
        """Extract the most appropriate CVE description text."""
        descriptions = cve_data.get("descriptions", [])
        if not isinstance(descriptions, list):
            return ""

        for description_item in descriptions:
            if (
                isinstance(description_item, dict)
                and description_item.get("lang") == "en"
                and isinstance(description_item.get("value"), str)
            ):
                return description_item["value"]

        for description_item in descriptions:
            if isinstance(description_item, dict) and isinstance(
                description_item.get("value"),
                str,
            ):
                return description_item["value"]

        return ""

    def _extract_cvss(self, metrics: dict[str, Any]) -> tuple[float | None, str]:
        """Extract CVSS score and severity with v3.1 priority."""
        cvss_sources = ("cvssMetricV31", "cvssMetricV30")
        for source in cvss_sources:
            metric_list = metrics.get(source, [])
            if not isinstance(metric_list, list) or not metric_list:
                continue

            first_metric = metric_list[0]
            if not isinstance(first_metric, dict):
                continue

            cvss_data = first_metric.get("cvssData", {})
            if not isinstance(cvss_data, dict):
                continue

            raw_score = cvss_data.get("baseScore")
            score = float(raw_score) if isinstance(raw_score, (int, float)) else None
            raw_severity = cvss_data.get("baseSeverity")
            severity = raw_severity if isinstance(raw_severity, str) else "UNKNOWN"
            return score, severity

        return None, "UNKNOWN"

async def fetch_cves(service: str, version: str) -> list[dict[str, Any]]:
    """Backward-compatible public API for fetching CVEs."""
    load_dotenv()
    api_key = os.getenv("NVD_API_KEY", "")
    fetcher = CVEFetcher(api_key=api_key)
    return await fetcher.fetch_cves(service=service, version=version)


if __name__ == "__main__":
    import asyncio, json, os

    from dotenv import load_dotenv

    load_dotenv()
    api_key = os.getenv("NVD_API_KEY", "")
    fetcher = CVEFetcher(api_key=api_key)
    results = asyncio.run(fetcher.fetch_cves("Apache httpd", "2.4.51"))
    print(json.dumps(results, indent=2, ensure_ascii=False))
