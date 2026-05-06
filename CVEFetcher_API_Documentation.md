# MergenSec CVEFetcher API v1.0 Documentation

## Base URL
All CVE data requests are made to the NVD (National Vulnerability Database) REST API:
https://services.nvd.nist.gov/rest/json/cves/2.0

## Authentication
The CVEFetcher module uses API Key authentication. The key is loaded from the .env file and sent in the header of every request.
apiKey: YOUR_NVD_API_KEY
Note: Keep your API key secret. Never commit it to Git. Store it only in the .env file which is listed in .gitignore.

## Endpoints
### 1. Fetch CVEs for a Service
Fetches a list of known CVE records from the NVD database for a given software service and version.

Method: GET
Path: /rest/json/cves/2.0
Query Parameters:

| Parameter | Type | Required | Description |
|---|---|---|---|
| keywordSearch | string | Yes | Service name and version (e.g., Apache httpd 2.4.51) |
| resultsPerPage | integer | No | Number of results to return (default: 20) |
| startIndex | integer | No | Pagination start index (default: 0) |

Example Request (Python):
```python
import asyncio
from core.cve_fetcher import fetch_cves

results = asyncio.run(fetch_cves("Apache httpd", "2.4.51"))
```

Example Request (HTTP):
```http
GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache+httpd+2.4.51&resultsPerPage=20
apiKey: YOUR_NVD_API_KEY
```

Success Response (200 OK):
```json
json[
  {
    "cve_id": "CVE-2021-44790",
    "description": "A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser...",
    "cvss_score": 9.8,
    "severity": "CRITICAL",
    "published": "2021-12-20T12:15:07.440"
  },
  {
    "cve_id": "CVE-2021-44224",
    "description": "A crafted URI sent to httpd configured as a forward proxy can cause a crash...",
    "cvss_score": 8.2,
    "severity": "HIGH",
    "published": "2021-12-20T12:15:07.393"
  }
]
```

## Response Fields
Each CVE record in the response contains the following fields:

| Field | Type | Description |
|---|---|---|
| cve_id | string | Unique CVE identifier (e.g., CVE-2021-44790) |
| description | string | English description of the vulnerability |
| cvss_score | float or null | CVSS base score between 0.0 and 10.0 |
| severity | string | Risk level: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN |
| published | string or null | Publication date in ISO 8601 format |

### Severity Classification:
| Severity | CVSS Score Range |
|---|---|
| CRITICAL | 9.0 – 10.0 |
| HIGH | 7.0 – 8.9 |
| MEDIUM | 4.0 – 6.9 |
| LOW | 0.1 – 3.9 |
| UNKNOWN | Score not available |

## Error Handling
The module handles NVD API responses and raises typed exceptions accordingly.

| HTTP Code | Meaning | Module Behavior |
|---|---|---|
| 200 | OK | Returns parsed CVE list |
| 429 | Too Many Requests | Waits 2 seconds and retries once |
| 401 | Unauthorized | Raises ValueError — invalid or missing API key |
| 404 | Not Found | Raises ValueError — endpoint or resource not found |
| 5xx | Server Error | Raises RuntimeError — NVD server problem |

Error Response Example:
```text
ValueError: NVD API client error (401): Unauthorized
RuntimeError: NVD API rate limit exceeded after retry.
ConnectionError: NVD API request failed due to network/client error.
TimeoutError: NVD API request timed out.
```

## Rate Limiting
NVD enforces rate limits per API key. The module handles this automatically.

| Condition | Limit |
|---|---|
| Without API key | 5 requests / 30 seconds |
| With API key | 50 requests / 30 seconds |

The module applies the following automatic protections:

- 0.6 second sleep between every request
- On HTTP 429: waits 2.0 seconds and retries once
- After retry fails: raises RuntimeError

## Dependencies
| Package | Version | Purpose |
|---|---|---|
| aiohttp | 3.11.18 | Async HTTP client for NVD requests |
| python-dotenv | 1.0.0 | Loads API key from .env file |
| asyncio | stdlib | Async runtime for non-blocking requests |
