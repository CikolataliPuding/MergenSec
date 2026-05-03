"""Async network scanner using python-nmap for service and version detection."""

import asyncio
from datetime import datetime
from typing import Any

import nmap


class AsyncScanner:
    """Asynchronous network scanner that performs nmap-based service version detection."""

    def __init__(self, target: str) -> None:
        """Initialize the scanner with a target IP or CIDR range.

        Args:
            target: IP address or CIDR notation (e.g. '192.168.1.1' or '192.168.1.0/24').
        """
        self.target = target
        self._nm = nmap.PortScanner()

    async def scan(self) -> dict[str, Any]:
        """Perform an nmap -sV scan asynchronously and return structured results.

        Returns:
            A dict containing host, scan_time, and a list of open port details.

        Raises:
            nmap.PortScannerError: If nmap is not installed or the scan fails.
            ValueError: If the target host is not found in scan results.
        """
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: self._nm.scan(hosts=self.target, arguments="-sT -F --host-timeout 30s"),
            )

            hosts = self._nm.all_hosts()
            if not hosts:
                return {
                    "host": self.target,
                    "scan_time": datetime.now(datetime.UTC).isoformat(),
                    "ports": [],
                }

            host = hosts[0]
            ports = self._extract_ports(host)

            return {
                "host": host,
                "scan_time": datetime.now(datetime.UTC).isoformat(),
                "ports": ports,
            }

        except nmap.PortScannerError as exc:
            raise nmap.PortScannerError(
                f"Nmap scan failed for target '{self.target}': {exc}"
            ) from exc

    def _extract_ports(self, host: str) -> list[dict[str, Any]]:
        """Extract TCP port information from nmap scan results for a given host.

        Args:
            host: The scanned host IP address.

        Returns:
            A list of dicts, each describing an open port and its service details.
        """
        ports: list[dict[str, Any]] = []

        if "tcp" not in self._nm[host]:
            return ports

        for port_num, port_data in self._nm[host]["tcp"].items():
            ports.append(
                {
                    "port": int(port_num),
                    "protocol": "tcp",
                    "state": port_data.get("state", ""),
                    "service": port_data.get("name", ""),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                }
            )

        return ports
