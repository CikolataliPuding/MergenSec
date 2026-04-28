"""Streamlit dashboard for MergenSec vulnerability mapping framework."""

import asyncio
import json
import math
import os
from datetime import datetime
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cve_fetcher import fetch_cves
from core.scanner import AsyncScanner
from core.vuln_mapper import VulnMapper

st.set_page_config(
    page_title="MergenSec - Vulnerability Mapping",
    page_icon="🏹",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .risk-critical { color: #dc2626; font-weight: bold; }
    .risk-high     { color: #ea580c; font-weight: bold; }
    .risk-medium   { color: #ca8a04; font-weight: bold; }
    .risk-low      { color: #16a34a; font-weight: bold; }
    .stAlert { padding: 10px; }
</style>
""", unsafe_allow_html=True)


def load_sample_data() -> list[dict[str, Any]]:
    """Return static sample vulnerability records for the dashboard overview."""
    return [
        {"port": 80,   "service": "http",       "cve_id": "CVE-2021-41773", "description": "Apache Path Traversal",          "cvss_score": 7.5, "severity": "HIGH"},
        {"port": 22,   "service": "ssh",         "cve_id": "CVE-2018-15473", "description": "OpenSSH User Enumeration",        "cvss_score": 5.3, "severity": "MEDIUM"},
        {"port": 21,   "service": "ftp",         "cve_id": "CVE-2015-3306",  "description": "ProFTPd Remote Code Execution",   "cvss_score": 9.8, "severity": "CRITICAL"},
        {"port": 443,  "service": "https",       "cve_id": "CVE-2022-3602",  "description": "OpenSSL Buffer Overflow",         "cvss_score": 9.8, "severity": "CRITICAL"},
        {"port": 3306, "service": "mysql",       "cve_id": "CVE-2016-6662",  "description": "MySQL Remote Code Execution",     "cvss_score": 9.8, "severity": "CRITICAL"},
        {"port": 8080, "service": "http-proxy",  "cve_id": "CVE-2020-1147",  "description": "Liferay Portal RCE",             "cvss_score": 7.3, "severity": "HIGH"},
        {"port": 25,   "service": "smtp",        "cve_id": "CVE-2018-19433", "description": "Exim Mail Server RCE",           "cvss_score": 8.0, "severity": "HIGH"},
        {"port": 53,   "service": "dns",         "cve_id": "CVE-2020-1350",  "description": "Windows DNS Server RCE",         "cvss_score": 8.8, "severity": "HIGH"},
    ]


async def _run_scan_async(target: str) -> list[dict[str, Any]]:
    """Run the full scan pipeline: nmap → CVE fetch → VulnMapper.

    Args:
        target: IP address or CIDR range to scan.

    Returns:
        List of matched vulnerability records ready for the dashboard.
    """
    scanner = AsyncScanner(target)
    scan_results = await scanner.scan()

    ports: list[dict[str, Any]] = scan_results.get("ports", [])
    if not ports:
        return []

    tasks = [
        fetch_cves(port.get("service", "").strip(), port.get("version", "").strip())
        for port in ports
        if port.get("service", "").strip()
    ]

    seen_ids: set[str] = set()
    all_cves: list[dict[str, Any]] = []
    for result in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(result, BaseException):
            continue
        for cve in result:
            cve_id: str = cve.get("cve_id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                all_cves.append(cve)

    mapper = VulnMapper(scan_results=scan_results, cve_data=all_cves)
    df = mapper.map()

    if df.empty:
        return []

    matched = df[df["cve_id"].notna()].copy()
    output: list[dict[str, Any]] = []
    for _, row in matched.iterrows():
        score = row.get("cvss_score")
        output.append({
            "port": int(row["port"]),
            "service": str(row.get("service", "")),
            "cve_id": str(row.get("cve_id", "")),
            "description": str(row.get("description", "")),
            "cvss_score": float(score) if score is not None else 0.0,
            "severity": str(row.get("severity", "UNKNOWN")),
        })
    return output


def run_scan(target: str) -> list[dict[str, Any]]:
    """Synchronous wrapper around the async scan pipeline for Streamlit.

    Args:
        target: IP address or CIDR range.

    Returns:
        List of vulnerability dicts.
    """
    return asyncio.run(_run_scan_async(target))


def display_metrics(results: list[dict[str, Any]]) -> None:
    """Display key vulnerability metrics in a five-column card layout.

    Args:
        results: List of vulnerability records with a 'cvss_score' field.
    """
    if not results:
        st.info("No vulnerabilities found.")
        return

    total_vulns = len(results)
    critical_count = sum(1 for r in results if r["cvss_score"] >= 9.0)
    high_count     = sum(1 for r in results if 7.0 <= r["cvss_score"] < 9.0)
    medium_count   = sum(1 for r in results if 4.0 <= r["cvss_score"] < 7.0)
    valid_scores = [r["cvss_score"] for r in results if r.get("cvss_score") and not math.isnan(r["cvss_score"])]
    avg_cvss = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Vulnerabilities", total_vulns)
    with col2:
        st.metric("Critical", critical_count, delta_color="inverse" if critical_count > 0 else "normal")
    with col3:
        st.metric("High", high_count, delta_color="inverse" if high_count > 0 else "normal")
    with col4:
        st.metric("Medium", medium_count)
    with col5:
        st.metric("Avg. CVSS", f"{avg_cvss:.1f}", delta="Risk Score")


def _normalize_report(report_data: Any, filename: str) -> dict[str, Any]:
    """Normalize a JSON report to a common summary structure regardless of format.

    Handles two on-disk formats:
    - Format 1 (main.py): a bare list of vulnerability records.
    - Format 2 (dashboard): a dict with 'scan_info' and 'summary' keys.

    Args:
        report_data: Parsed JSON (list or dict).
        filename: Source filename used as a fallback label.

    Returns:
        Dict with keys: target, timestamp, total, critical, high, medium, low,
        vulnerabilities (list).
    """
    if isinstance(report_data, list):
        vulns = report_data
        scores = [v.get("cvss_score") for v in vulns if isinstance(v.get("cvss_score"), (int, float))]
        target = vulns[0].get("host", filename) if vulns else filename
        return {
            "target": target,
            "timestamp": "N/A",
            "total": len(vulns),
            "critical": sum(1 for s in scores if s >= 9.0),
            "high":     sum(1 for s in scores if 7.0 <= s < 9.0),
            "medium":   sum(1 for s in scores if 4.0 <= s < 7.0),
            "low":      sum(1 for s in scores if s < 4.0),
            "vulnerabilities": vulns,
        }

    info = report_data.get("scan_info", {})
    summary = report_data.get("summary", {})
    return {
        "target": info.get("target", filename),
        "timestamp": info.get("timestamp", "N/A"),
        "total": summary.get("total_vulnerabilities", 0),
        "critical": summary.get("critical_count", 0),
        "high":     summary.get("high_count", 0),
        "medium":   summary.get("medium_count", 0),
        "low":      summary.get("low_count", 0),
        "vulnerabilities": report_data.get("vulnerabilities", []),
    }


def display_risk_distribution(results: list[dict[str, Any]], key: str = "default") -> None:
    """Render a donut chart showing the count of vulnerabilities per risk tier.

    Args:
        results: Vulnerability records with 'cvss_score'.
        key: Unique Streamlit widget key suffix to avoid duplicate-key errors.
    """
    if not results:
        return

    risk_counts = {
        "Critical": sum(1 for r in results if r["cvss_score"] >= 9.0),
        "High":     sum(1 for r in results if 7.0 <= r["cvss_score"] < 9.0),
        "Medium":   sum(1 for r in results if 4.0 <= r["cvss_score"] < 7.0),
        "Low":      sum(1 for r in results if r["cvss_score"] < 4.0),
    }

    fig = go.Figure(data=[go.Pie(
        labels=list(risk_counts.keys()),
        values=list(risk_counts.values()),
        hole=0.4,
        marker=dict(colors=["#dc2626", "#ea580c", "#ca8a04", "#16a34a"]),
    )])
    fig.update_layout(
        title="Risk Distribution",
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
    )
    st.plotly_chart(fig, use_container_width=True, key=f"risk_dist_{key}")


def display_cvss_histogram(results: list[dict[str, Any]], key: str = "default") -> None:
    """Render a histogram of CVSS scores.

    Args:
        results: Vulnerability records with 'cvss_score'.
        key: Unique Streamlit widget key suffix.
    """
    if not results:
        return

    fig = px.histogram(
        x=[r["cvss_score"] for r in results],
        nbins=10,
        labels={"x": "CVSS Score", "y": "Count"},
        color_discrete_sequence=["#1f77b4"],
    )
    fig.update_layout(title="CVSS Score Distribution", showlegend=False, bargap=0.1)
    st.plotly_chart(fig, use_container_width=True, key=f"cvss_hist_{key}")


def display_vulnerability_table(results: list[dict[str, Any]]) -> None:
    """Display an interactive, filterable vulnerability table with a CVE detail pane.

    Args:
        results: Vulnerability records using the new key schema
                 (cve_id, cvss_score, severity).
    """
    if not results:
        st.info("No vulnerabilities found.")
        return

    df = pd.DataFrame(results)[["port", "service", "cve_id", "description", "cvss_score", "severity"]]

    st.subheader("Vulnerability Details")

    risk_filter = st.multiselect(
        "Filter by Severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
    )
    filtered_df = df[df["severity"].isin(risk_filter)]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "port":        st.column_config.NumberColumn("Port", format="%d"),
            "service":     st.column_config.TextColumn("Service"),
            "cve_id":      st.column_config.TextColumn("CVE ID"),
            "description": st.column_config.TextColumn("Description"),
            "cvss_score":  st.column_config.NumberColumn("CVSS", format="%.1f"),
            "severity":    st.column_config.TextColumn("Severity"),
        },
    )

    if not filtered_df.empty:
        st.subheader("CVE Details")
        selected_cve = st.selectbox("Select a CVE to view details", options=filtered_df["cve_id"].unique())

        if selected_cve:
            row = filtered_df[filtered_df["cve_id"] == selected_cve].iloc[0]
            with st.expander(f"CVE Details: {selected_cve}", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Port:** {row['port']}")
                    st.write(f"**Service:** {row['service']}")
                    st.write(f"**CVSS Score:** {row['cvss_score']}")
                with col2:
                    st.write(f"**Severity:** {row['severity']}")
                    st.write(f"**Description:** {row['description']}")


def generate_report(results: list[dict[str, Any]], target: str) -> dict[str, Any]:
    """Build a structured JSON report from scan results.

    Args:
        results: Vulnerability records with 'cvss_score' key.
        target: The scanned host/CIDR.

    Returns:
        Report dict ready for JSON serialisation.
    """
    return {
        "scan_info": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "tool": "MergenSec",
            "version": "1.0.0",
        },
        "summary": {
            "total_vulnerabilities": len(results),
            "critical_count": sum(1 for r in results if r["cvss_score"] >= 9.0),
            "high_count":     sum(1 for r in results if 7.0 <= r["cvss_score"] < 9.0),
            "medium_count":   sum(1 for r in results if 4.0 <= r["cvss_score"] < 7.0),
            "low_count":      sum(1 for r in results if r["cvss_score"] < 4.0),
            "avg_cvss": sum(r["cvss_score"] for r in results) / len(results) if results else 0,
        },
        "vulnerabilities": results,
    }


def save_report(report: dict[str, Any]) -> str:
    """Persist the report to the reports/ directory and return its file path.

    Args:
        report: Structured report dict.

    Returns:
        Absolute path of the saved file.
    """
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(reports_dir, f"report_{timestamp}.json")
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return filepath


def main() -> None:
    """Render the MergenSec Streamlit dashboard."""
    st.markdown('<p class="main-header">🏹 MergenSec</p>', unsafe_allow_html=True)
    st.markdown("**Autonomous Vulnerability Mapping Framework**")
    st.markdown("---")

    st.sidebar.header("Scan Configuration")
    target = st.sidebar.text_input(
        "Target IP or CIDR",
        value="192.168.1.1",
        help="Enter the target IP address or CIDR range to scan",
    )
    scan_type = st.sidebar.selectbox("Scan Type", ["Quick Scan", "Full Scan", "Custom"])  # noqa: F841

    st.sidebar.markdown("---")
    st.sidebar.header("Settings")
    st.sidebar.checkbox("Auto-refresh results", value=False)

    if st.sidebar.checkbox("Show advanced options", value=False):
        st.sidebar.text_input("NVD API Key", type="password")
        st.sidebar.slider("Request timeout (seconds)", 10, 60, 30)

    tab1, tab2, tab3 = st.tabs(["Dashboard", "Scan Results", "Reports"])

    with tab1:
        st.header("Security Overview")

        if "scan_results" in st.session_state and st.session_state["scan_results"]:
            dashboard_results = st.session_state["scan_results"]
            st.info(f"Showing results from last scan on target: **{st.session_state.get('scan_target', 'N/A')}**")
        else:
            dashboard_results = load_sample_data()
            st.caption("Showing sample data — run a scan in the 'Scan Results' tab to see real results.")

        display_metrics(dashboard_results)

        col1, col2 = st.columns(2)
        with col1:
            display_risk_distribution(dashboard_results, key="dashboard")
        with col2:
            display_cvss_histogram(dashboard_results, key="dashboard")

        st.markdown("---")
        st.header("Recent Scans")

        if os.path.exists("reports"):
            report_files = sorted(
                [f for f in os.listdir("reports") if f.endswith(".json")],
                reverse=True,
            )[:5]
            if report_files:
                for report_file in report_files:
                    with open(os.path.join("reports", report_file), "r", encoding="utf-8") as fh:
                        report_data = json.load(fh)
                    rpt = _normalize_report(report_data, report_file)
                    ts_label = rpt["timestamp"][:19] if rpt["timestamp"] != "N/A" else "N/A"
                    with st.expander(f"Scan: {rpt['target']} - {ts_label}"):
                        st.write(f"**Target:** {rpt['target']}")
                        st.write(f"**Total Vulnerabilities:** {rpt['total']}")
                        st.write(f"**Critical:** {rpt['critical']}")
                        st.write(f"**High:** {rpt['high']}")
            else:
                st.info("No previous scans found.")
        else:
            st.info("Reports directory not found.")

    with tab2:
        st.header("Vulnerability Scan Results")

        if st.button("Start Scan", type="primary"):
            with st.spinner(f"Scanning {target} — this may take a minute..."):
                try:
                    results = run_scan(target)
                    st.session_state["scan_results"] = results
                    st.session_state["scan_target"] = target
                    st.success(f"Scan completed! Found {len(results)} vulnerabilit{'y' if len(results) == 1 else 'ies'}.")
                except Exception as exc:
                    st.error(f"Scan failed: {exc}")

        if "scan_results" in st.session_state:
            results = st.session_state["scan_results"]
            if results:
                st.markdown("### Scan Results")
                display_metrics(results)

                col1, col2 = st.columns(2)
                with col1:
                    display_risk_distribution(results, key="scan")
                with col2:
                    display_cvss_histogram(results, key="scan")

                display_vulnerability_table(results)

                st.markdown("---")
                report = generate_report(results, st.session_state["scan_target"])
                report_path = save_report(report)
                st.success(f"Report saved to: {report_path}")

                st.download_button(
                    label="Download JSON Report",
                    data=json.dumps(report, indent=2, ensure_ascii=False),
                    file_name=os.path.basename(report_path),
                    mime="application/json",
                )
            else:
                st.info("No vulnerabilities found in the scan.")

    with tab3:
        st.header("Generated Reports")

        if os.path.exists("reports"):
            report_files = sorted(
                [f for f in os.listdir("reports") if f.endswith(".json")],
                reverse=True,
            )
            if report_files:
                for report_file in report_files:
                    report_path = os.path.join("reports", report_file)
                    with open(report_path, "r", encoding="utf-8") as fh:
                        report_data = json.load(fh)
                    rpt = _normalize_report(report_data, report_file)

                    with st.expander(f"📄 {report_file}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Target:** {rpt['target']}")
                            st.write(f"**Timestamp:** {rpt['timestamp']}")
                            st.write(f"**Total:** {rpt['total']}")
                        with col2:
                            st.write(f"**Critical:** {rpt['critical']}")
                            st.write(f"**High:** {rpt['high']}")
                            st.write(f"**Medium:** {rpt['medium']}")
                            st.write(f"**Low:** {rpt['low']}")

                        st.markdown("---")
                        with open(report_path, "r", encoding="utf-8") as fh:
                            report_content = fh.read()
                        st.download_button(
                            label="⬇️ Download JSON Report",
                            data=report_content,
                            file_name=report_file,
                            mime="application/json",
                            key=f"dl_{report_file}",
                        )
            else:
                st.info("No reports found. Run a scan to generate reports.")
        else:
            st.info("Reports directory not found.")

    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666;'>
            <p>🏹 MergenSec - Autonomous Vulnerability Mapping Framework</p>
            <p>Built with Python, Streamlit, and Nmap</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
