"""CLI entry point for MergenSec — Autonomous Vulnerability Mapping Framework."""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from core.cve_fetcher import fetch_cves
from core.scanner import AsyncScanner
from core.vuln_mapper import VulnMapper
from database.db import get_session, init_db

REPORT_PATH = Path("reports") / "latest_scan.json"


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments.

    Returns:
        Namespace containing the --target value.
    """
    parser = argparse.ArgumentParser(
        prog="mergensec",
        description="MergenSec — Autonomous Vulnerability Mapping Framework",
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="IP/CIDR",
        help="Target IP address or CIDR range to scan (e.g. 192.168.1.1 or 10.0.0.0/24)",
    )
    return parser.parse_args()


async def _collect_cves(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fetch CVEs for every port concurrently and return a deduplicated list.

    Ports with no service name are skipped. Individual fetch failures are logged
    and skipped so that a single unreachable service does not abort the whole run.

    Args:
        ports: Port records from AsyncScanner.scan().

    Returns:
        Deduplicated list of CVE dicts ready for VulnMapper.
    """
    tasks: list[asyncio.Task[list[dict[str, Any]]]] = []
    for port in ports:
        service: str = port.get("service", "").strip()
        version: str = port.get("version", "").strip()
        if not service:
            continue
        tasks.append(asyncio.create_task(fetch_cves(service, version)))

    seen_ids: set[str] = set()
    all_cves: list[dict[str, Any]] = []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            print(f"[WARN] CVE fetch error: {result}")
            continue
        for cve in result:
            cve_id: str = cve.get("cve_id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                all_cves.append(cve)

    return all_cves


def _print_summary(scan_results: dict[str, Any], cve_data: list[dict[str, Any]]) -> None:
    """Print a human-readable scan summary to stdout.

    Args:
        scan_results: Output from AsyncScanner.scan().
        cve_data: Deduplicated CVE list collected for this scan.
    """
    ports: list[dict[str, Any]] = scan_results.get("ports", [])
    open_ports = [p for p in ports if p.get("state") == "open"]

    scores: list[float] = [
        c["cvss_score"] for c in cve_data if isinstance(c.get("cvss_score"), (int, float))
    ]
    highest_cvss = max(scores) if scores else None

    print("\n" + "=" * 50)
    print(f"  MergenSec Scan Report")
    print("=" * 50)
    print(f"  Host        : {scan_results.get('host', 'N/A')}")
    print(f"  Scan time   : {scan_results.get('scan_time', 'N/A')}")
    print(f"  Total ports : {len(ports)}")
    print(f"  Open ports  : {len(open_ports)}")
    print(f"  CVEs found  : {len(cve_data)}")
    print(f"  Highest CVSS: {highest_cvss if highest_cvss is not None else 'N/A'}")
    print(f"  Report      : {REPORT_PATH}")
    print("=" * 50 + "\n")


async def _run(target: str) -> None:
    """Orchestrate the full scan → CVE fetch → mapping → report pipeline.

    Args:
        target: IP address or CIDR range supplied via --target.
    """
    print(f"[*] Initializing database...")
    init_db()
    _ = get_session()

    print(f"[*] Scanning target: {target}")
    scanner = AsyncScanner(target)
    scan_results = await scanner.scan()

    ports: list[dict[str, Any]] = scan_results.get("ports", [])
    if not ports:
        print("[!] No ports found. Exiting.")
        return

    print(f"[*] Fetching CVEs for {len(ports)} port(s)...")
    cve_data = await _collect_cves(ports)
    print(f"[*] {len(cve_data)} unique CVE(s) retrieved.")

    print("[*] Mapping vulnerabilities...")
    mapper = VulnMapper(scan_results=scan_results, cve_data=cve_data)
    mapper.map()

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    mapper.to_json(str(REPORT_PATH))
    print(f"[*] Report saved to {REPORT_PATH}")

    _print_summary(scan_results, cve_data)


def main() -> None:
    """Parse arguments and launch the async pipeline."""
    args = _parse_args()

    try:
        asyncio.run(_run(args.target))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except RuntimeError as exc:
        print(f"[ERROR] Runtime error: {exc}")
        sys.exit(1)
    except ConnectionError as exc:
        print(f"[ERROR] Network error: {exc}")
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
