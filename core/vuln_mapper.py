"""Vulnerability mapper that correlates scan results with CVE data using pandas."""

import json
from typing import Any

import pandas as pd


class VulnMapper:
    """Maps open ports from scan results to CVE entries and categorizes risk levels."""

    def __init__(self, scan_results: dict[str, Any], cve_data: list[dict[str, Any]]) -> None:
        """Initialize the mapper with scan results and external CVE data.

        Args:
            scan_results: Output from AsyncScanner.scan() containing host and port list.
            cve_data: List of CVE records, each with cve_id, cvss_score, severity,
                      and description fields.
        """
        self.scan_results = scan_results
        self.cve_data = cve_data
        self._df: pd.DataFrame | None = None

    def map(self) -> pd.DataFrame:
        """Match each scanned port/service against CVE data and return a DataFrame.

        The matching strategy joins on the service name: a CVE entry is associated
        with a port when the port's 'service' field appears in the CVE's 'description'
        (case-insensitive). All ports are included; unmatched ports carry null CVE fields.

        Returns:
            A DataFrame with columns: host, port, protocol, state, service, product,
            version, cve_id, cvss_score, severity, description, risk_category.
        """
        host = self.scan_results.get("host", "")
        ports: list[dict[str, Any]] = self.scan_results.get("ports", [])

        if not ports:
            self._df = pd.DataFrame()
            return self._df

        ports_df = pd.DataFrame(ports)
        ports_df.insert(0, "host", host)

        cve_df = pd.DataFrame(self.cve_data) if self.cve_data else pd.DataFrame(
            columns=["cve_id", "cvss_score", "severity", "description"]
        )

        rows: list[dict[str, Any]] = []
        for _, port_row in ports_df.iterrows():
            service_name: str = str(port_row.get("service", "")).lower()
            matched = self._match_cve(service_name, cve_df)

            if matched:
                for cve_entry in matched:
                    row = port_row.to_dict()
                    row.update(cve_entry)
                    row["risk_category"] = self.categorize_risk(cve_entry["cvss_score"])
                    rows.append(row)
            else:
                row = port_row.to_dict()
                row.update({"cve_id": None, "cvss_score": None, "severity": None,
                             "description": None, "risk_category": None})
                rows.append(row)

        self._df = pd.DataFrame(rows).reset_index(drop=True)
        return self._df

    def _match_cve(
        self, service_name: str, cve_df: pd.DataFrame
    ) -> list[dict[str, Any]]:
        """Find CVE entries whose description contains the given service name.

        Args:
            service_name: Lowercase service identifier (e.g. 'http', 'ssh').
            cve_df: DataFrame of CVE records.

        Returns:
            List of matching CVE dicts, or an empty list if none match.
        """
        if cve_df.empty or not service_name:
            return []

        mask = cve_df["description"].str.lower().str.contains(service_name, na=False)
        return cve_df[mask][["cve_id", "cvss_score", "severity", "description"]].to_dict(
            orient="records"
        )

    @staticmethod
    def categorize_risk(score: float | None) -> str:
        """Map a CVSS score to a human-readable risk category.

        Args:
            score: CVSS v3 base score in the range 0.0–10.0, or None if unknown.

        Returns:
            One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'UNKNOWN' for invalid scores.
        """
        if not isinstance(score, (int, float)) or pd.isna(score):
            return "UNKNOWN"
        if not 0.0 <= score <= 10.0:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def to_json(self, path: str) -> None:
        """Serialize the mapped DataFrame to a JSON file.

        Calls map() automatically if it has not been called yet.

        Args:
            path: Filesystem path for the output JSON file.

        Raises:
            OSError: If the file cannot be written.
        """
        df = self._df if self._df is not None else self.map()

        records = df.to_dict(orient="records")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, ensure_ascii=False, indent=2, default=str)
