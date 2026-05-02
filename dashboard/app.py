"""
Streamlit Dashboard for MergenSec — Vulnerability Mapping Framework

SPRINT 1 (Days 2): Basic dashboard with 'Hello World' ✅
SPRINT 3 (Days 11-17): Full UI with forms, charts, and tables ✅
SPRINT 4 (Days 18+): Integration, error handling, and finalization ✅

COMPLETED:
- Real module integration with core.scanner.AsyncScanner
- Real CVE fetching with core.cve_fetcher.fetch_cves
- Automatic report saving to reports/ directory
- Scan history tracking and management
- Full error handling with detailed messages

Author: Mustafa Bite
"""

import asyncio
import json
import os
import time
import ipaddress
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

# Import core modules
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.scanner import AsyncScanner
from core.cve_fetcher import fetch_cves

# Load environment variables
load_dotenv()

# Page configuration (SPRINT 1)
st.set_page_config(
    page_title="🏹 MergenSec - Vulnerability Dashboard",
    page_icon="🏹",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS Styling
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    
    /* Metric card styling */
    .metric-card {
        background: linear-gradient(135deg, #f0f2f6 0%, #e9ecef 100%);
        border-left: 4px solid #667eea;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    /* Risk severity colors */
    .risk-critical {
        color: #dc2626;
        font-weight: bold;
        font-size: 1.1rem;
    }
    .risk-high {
        color: #ea580c;
        font-weight: bold;
        font-size: 1.1rem;
    }
    .risk-medium {
        color: #ca8a04;
        font-weight: bold;
        font-size: 1.1rem;
    }
    .risk-low {
        color: #16a34a;
        font-weight: bold;
        font-size: 1.1rem;
    }
    
    /* Table styling */
    .dataframe {
        font-size: 0.9rem;
    }
    
    /* Alert styling */
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# INITIALIZATION & SESSION STATE MANAGEMENT (SPRINT 1 & 3)
# ============================================================================

def initialize_session_state():
    """Initialize Streamlit session state variables."""
    if "scan_results" not in st.session_state:
        st.session_state.scan_results = None
    if "cve_data" not in st.session_state:
        st.session_state.cve_data = None
    if "vulnerability_map" not in st.session_state:
        st.session_state.vulnerability_map = None
    if "scan_timestamp" not in st.session_state:
        st.session_state.scan_timestamp = None
    if "is_scanning" not in st.session_state:
        st.session_state.is_scanning = False
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    if "port_range" not in st.session_state:
        st.session_state.port_range = "1-1000"
    if "scan_type" not in st.session_state:
        st.session_state.scan_type = "Standard"


# ============================================================================
# UTILITY FUNCTIONS (SPRINT 3)
# ============================================================================

def is_valid_target(target: str) -> bool:
    """Validate IP address or CIDR range."""
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def classify_risk(cvss_score: float) -> str:
    """Classify vulnerability severity based on CVSS score."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def get_risk_color(risk_level: str) -> str:
    """Get color for risk level badge."""
    color_map = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#16a34a"
    }
    return color_map.get(risk_level, "#6b7280")


async def perform_real_scan(target: str, port_range: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Perform real network scan using AsyncScanner and fetch CVEs.
    
    Args:
        target: IP address or CIDR range
        port_range: Port range to scan (e.g., "1-1000" or "22,80,443")
    
    Returns:
        tuple: (scan_results, cve_data)
    """
    # Step 1: Perform network scan
    scanner = AsyncScanner(target)
    scan_results = await scanner.scan(ports=port_range)
    
    # Step 2: Fetch CVEs for each discovered service
    all_cves = []
    discovered_ports = scan_results.get("ports", [])
    
    for service_info in discovered_ports:
        product = service_info.get("product", "").strip()
        version = service_info.get("version", "").strip()
        
        # Skip if no product information
        if not product or product == "N/A":
            continue
        
        # Skip if no version information
        if not version or version == "N/A":
            continue
        
        try:
            # Fetch CVEs for this service
            cves = await fetch_cves(service=product, version=version)
            
            # Add service context to each CVE
            for cve in cves:
                cve["port"] = service_info["port"]
                cve["service"] = service_info["service"]
                cve["product"] = product
                cve["version"] = version
            
            all_cves.extend(cves)
            
        except Exception as e:
            # Log error but continue with other services
            print(f"Error fetching CVEs for {product} {version}: {e}")
            continue
    
    return scan_results, all_cves


def save_report_to_file(scan_results: dict, cve_data: list) -> str:
    """
    Save scan report to reports/ directory.
    
    Args:
        scan_results: Scan results dictionary
        cve_data: List of CVE data
    
    Returns:
        str: Path to saved report file
    """
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    reports_dir = os.path.abspath(reports_dir)
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename with timestamp
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(reports_dir, filename)
    
    # Generate report content
    report_json = generate_report_json(scan_results, cve_data)
    
    # Save to file
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_json)
    
    return filepath


def save_to_history(target: str, scan_results: dict, cve_data: list):
    """
    Save completed scan to session history.
    
    Args:
        target: Target IP or CIDR range
        scan_results: Scan results dictionary
        cve_data: List of CVE data
    """
    history_entry = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp_obj": datetime.now().isoformat(),
        "scan_type": st.session_state.get("scan_type", "Standard"),
        "cve_count": len(cve_data),
        "critical_count": len([c for c in cve_data if c.get("severity") == "CRITICAL"]),
        "results": scan_results,
        "cve_data": cve_data
    }
    
    # Add to history (limit to last 10 scans)
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    
    st.session_state.scan_history.append(history_entry)
    
    # Keep only last 10 scans
    if len(st.session_state.scan_history) > 10:
        st.session_state.scan_history = st.session_state.scan_history[-10:]


def generate_report_json(scan_results: dict, cve_data: list) -> str:
    """Generate JSON report from scan and CVE data (SPRINT 3 - Day 14)."""
    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "MergenSec",
            "version": "1.0.0"
        },
        "scan_info": {
            "target": scan_results.get("host"),
            "scan_time": scan_results.get("scan_time"),
            "total_ports": len(scan_results.get("ports", []))
        },
        "vulnerabilities": cve_data,
        "summary": {
            "total_cves": len(cve_data),
            "critical": len([c for c in cve_data if c.get("severity") == "CRITICAL"]),
            "high": len([c for c in cve_data if c.get("severity") == "HIGH"]),
            "medium": len([c for c in cve_data if c.get("severity") == "MEDIUM"]),
            "low": len([c for c in cve_data if c.get("severity") == "LOW"]),
        }
    }
    return json.dumps(report, indent=2)


# ============================================================================
# SPRINT 1: BASIC HELLO WORLD PAGE (Days 1-2)
# ============================================================================

def render_header():
    """Render main header (SPRINT 1 - Day 2)."""
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("<div class='main-header'>🏹 MergenSec</div>", unsafe_allow_html=True)
        st.markdown("**Autonomous Vulnerability Mapping Framework**")
        st.markdown("_Scan networks, detect services, and map CVE vulnerabilities automatically._")
    with col2:
        st.info("📊 **Dashboard Status**: Ready for Scanning")


# ============================================================================
# SPRINT 3: MAIN UI COMPONENTS (Days 11-17)
# ============================================================================

def render_input_form():
    """Render IP input form and scan button (SPRINT 3 - Days 11-12)."""
    st.subheader("🔍 Network Scan Configuration")

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input(
            "Target IP Address or CIDR Range",
            placeholder="e.g., 192.168.1.1 or 192.168.1.0/24",
            help="Enter a single IP or CIDR notation for range scanning"
        )
        # Custom port selection
        custom_ports = st.text_input(
            "Custom Ports (optional)",
            value=st.session_state.get("custom_ports", ""),
            placeholder="e.g., 22,80,443 or 1000-2000",
            help="Comma-separated ports or ranges. Overrides scan type if filled."
        )
        st.session_state.custom_ports = custom_ports
    with col2:
        st.markdown("")  # Spacer
        scan_button = st.button("🚀 Start Scan", use_container_width=True)

    return target, scan_button


def render_metric_cards(scan_results: dict, cve_data: list):
    """Render metric cards (SPRINT 3 - Days 12-13)."""
    col1, col2, col3, col4 = st.columns(4)
    
    total_ports = len(scan_results.get("ports", [])) if scan_results else 0
    total_cves = len(cve_data) if cve_data else 0
    max_cvss = max([c.get("cvss_score", 0) for c in cve_data], default=0) if cve_data else 0
    
    critical_count = len([c for c in cve_data if c.get("severity") == "CRITICAL"]) if cve_data else 0
    
    with col1:
        st.metric(
            label="Open Ports",
            value=total_ports,
            delta=None,
            help="Number of discovered open ports"
        )
    
    with col2:
        st.metric(
            label="Total CVEs",
            value=total_cves,
            delta=None,
            help="Total vulnerabilities found"
        )
    
    with col3:
        st.metric(
            label="Max CVSS Score",
            value=f"{max_cvss:.1f}",
            delta=None,
            help="Highest CVSS score among all CVEs"
        )
    
    with col4:
        st.metric(
            label="🔴 Critical",
            value=critical_count,
            delta=None,
            help="Number of CRITICAL severity vulnerabilities"
        )


def render_risk_distribution_chart(cve_data: list):
    """Render risk distribution pie chart (SPRINT 3 - Day 13)."""
    st.subheader("📊 Risk Distribution")
    
    if not cve_data:
        st.info("No vulnerability data to display")
        return
    
    # Count by severity
    severity_counts = {}
    for cve in cve_data:
        severity = cve.get("severity", "UNKNOWN")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        marker=dict(
            colors=["#dc2626", "#ea580c", "#ca8a04", "#16a34a", "#6b7280"],
            line=dict(color="#fff", width=2)
        ),
        textposition="inside",
        textinfo="label+percent"
    )])
    
    fig.update_layout(
        title="Vulnerability Severity Distribution",
        height=400,
        showlegend=True,
        font=dict(size=12)
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_vulnerability_table(cve_data: list):
    """Render filterable CVE vulnerability table (SPRINT 3 - Day 14)."""
    st.subheader("📋 Vulnerability Details")
    
    if not cve_data:
        st.info("No vulnerability data to display")
        return
    
    # Create DataFrame
    df = pd.DataFrame(cve_data)
    
    # Reorder columns
    columns_to_display = [
        "cve_id", "service", "product", "version",
        "severity", "cvss_score", "description", "published"
    ]
    available_columns = [col for col in columns_to_display if col in df.columns]
    df_display = df[available_columns].copy()
    
    # Rename columns for display
    df_display.columns = ["CVE ID", "Service", "Product", "Version", "Severity", "CVSS", "Description", "Published"]
    
    # Display table with sorting and filtering
    st.dataframe(
        df_display.sort_values("CVSS", ascending=False),
        use_container_width=True,
        hide_index=True,
        column_config={
            "CVSS": st.column_config.NumberColumn(format="%.1f"),
            "CVE ID": st.column_config.TextColumn(width="medium"),
            "Severity": st.column_config.TextColumn(width="small"),
            "Description": st.column_config.TextColumn(width="large"),
        }
    )


def render_report_download(scan_results: dict, cve_data: list):
    """Render report download buttons (SPRINT 3/4 - Day 14)."""
    st.subheader("💾 Export Report")
    
    col1, col2 = st.columns(2)
    
    if scan_results and cve_data:
        # JSON Report
        with col1:
            json_report = generate_report_json(scan_results, cve_data)
            st.download_button(
                label="📥 Download JSON Report",
                data=json_report,
                file_name=f"mergensec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        # CSV Report
        with col2:
            df = pd.DataFrame(cve_data)
            csv_data = df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV Report",
                data=csv_data,
                file_name=f"mergensec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("Run a scan first to generate reports")


def render_sidebar_info():
    """Render sidebar information and help (SPRINT 3)."""
    with st.sidebar:
        st.header("⚙️ Scan Configuration")

        # Scan Type Selection
        st.subheader("Scan Type")
        scan_type = st.radio(
            "Select scan type:",
            ["Quick Scan (Top 20 ports)", "Standard Scan (1-1000 ports)", "Full Scan (All ports)"],
            index=1,
            help="Choose the scope of your port scan"
        )

        # Map selection to port range
        scan_type_map = {
            "Quick Scan (Top 20 ports)": "20,21,22,23,25,53,80,110,143,443,445,1433,1521,3306,3389,5432,5984,8080,8443,27017",
            "Standard Scan (1-1000 ports)": "1-1000",
            "Full Scan (All ports)": "1-65535"
        }
        # If custom_ports is entered, use it, otherwise set port_range according to scan_type
        custom_ports = st.session_state.get("custom_ports", "")
        if custom_ports.strip():
            st.session_state.port_range = custom_ports.strip()
        else:
            st.session_state.port_range = scan_type_map[scan_type]
        st.session_state.scan_type = scan_type

        st.divider()

        # Additional Options
        st.subheader("Options")
        service_detection = st.checkbox("Service Detection (-sV)", value=True)
        os_detection = st.checkbox("OS Detection (-O)", value=False)
        aggressive_scan = st.checkbox("Aggressive Scan (-A)", value=False)

        # Store options in session state
        st.session_state.service_detection = service_detection
        st.session_state.os_detection = os_detection
        st.session_state.aggressive_scan = aggressive_scan

        st.divider()

        # Scan History
        st.header("📜 Scan History")

        if st.session_state.scan_history:
            for idx, scan in enumerate(reversed(st.session_state.scan_history), 1):
                with st.expander(f"Scan {idx}: {scan['target']} - {scan['timestamp']}"):
                    st.write(f"**Target:** {scan['target']}")
                    st.write(f"**Type:** {scan['scan_type']}")
                    st.write(f"**Time:** {scan['timestamp']}")
                    st.write(f"**CVEs Found:** {scan['cve_count']}")
                    st.write(f"**Critical:** {scan['critical_count']}")

                    # Option to load previous scan
                    if st.button(f"Load Scan {idx}", key=f"load_scan_{idx}"):
                        st.session_state.scan_results = scan['results']
                        st.session_state.cve_data = scan['cve_data']
                        st.session_state.scan_timestamp = datetime.fromisoformat(scan['timestamp_obj'])
                        st.success("Previous scan loaded!")
                        st.rerun()
        else:
            st.info("No scan history yet. Run a scan to see it here.")

        st.divider()

        # Help Section
        with st.expander("📖 How to Use"):
            st.markdown("""
            1. **Select Scan Type**: Choose from Quick, Standard, or Full scan
            2. **Configure Options**: Enable service/OS detection if needed
            3. **Enter Target**: Provide an IP address or CIDR range
            4. **Start Scan**: Click the scan button
            5. **View Results**: Check metrics, charts, and vulnerability table
            6. **Export Report**: Download JSON or CSV report
            7. **View History**: Click on previous scans to reload them

            **Examples:**
            - Single IP: `192.168.1.1`
            - CIDR Range: `192.168.1.0/24`
            - Full Subnet: `10.0.0.0/8`
            """)

        with st.expander("⚠️ Risk Levels"):
            st.markdown("""
            - **🔴 CRITICAL**: CVSS 9.0–10.0
            - **🟠 HIGH**: CVSS 7.0–8.9
            - **🟡 MEDIUM**: CVSS 4.0–6.9
            - **🟢 LOW**: CVSS 0.1–3.9
            """)

        st.divider()
        st.caption("🏹 MergenSec v1.0 | Python 3.12+")


# ============================================================================
# SPRINT 4: ERROR HANDLING & INTEGRATION (Days 18+)
# ============================================================================

def handle_scan_execution(target: str):
    """Execute scan with error handling and real module integration."""
    # Validate input
    if not target.strip():
        st.error("❌ Error: Please enter a target IP or CIDR range")
        return
    
    if not is_valid_target(target):
        st.error(f"❌ Invalid Target: '{target}' is not a valid IP address or CIDR notation")
        return
    
    # Get port range from session state
    port_range = st.session_state.get("port_range", "1-1000")
    
    # Run scan with spinner
    with st.spinner("🔄 Scanning network... This may take a few minutes."):
        try:
            # Run async scanner with real modules
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Perform real scan
            scan_results, cve_data = loop.run_until_complete(
                perform_real_scan(target, port_range)
            )
            
            # Store results in session state
            st.session_state.scan_results = scan_results
            st.session_state.cve_data = cve_data
            st.session_state.scan_timestamp = datetime.now()
            
            # Save report to file
            try:
                report_path = save_report_to_file(scan_results, cve_data)
                st.success(f"✅ Scan Complete! Found {len(cve_data)} vulnerabilities")
                st.info(f"📄 Report saved to: {os.path.basename(report_path)}")
            except Exception as e:
                st.warning(f"⚠️ Scan completed but failed to save report: {str(e)}")
            
            # Save to history
            try:
                save_to_history(target, scan_results, cve_data)
            except Exception as e:
                st.warning(f"⚠️ Failed to save to history: {str(e)}")
            
        except ImportError as e:
            st.error(f"❌ Module Import Error: {str(e)}")
            st.info("💡 Make sure all core modules are properly installed")
        except RuntimeError as e:
            st.error(f"❌ Scan Error: {str(e)}")
            st.info("💡 Check if Nmap is installed and you have proper permissions")
        except ConnectionError as e:
            st.error(f"❌ Network Error: {str(e)}")
            st.info("💡 Check your internet connection and NVD API key")
        except Exception as e:
            st.error(f"❌ Unexpected Error: {str(e)}")
            with st.expander("Show Error Details"):
                import traceback
                st.code(traceback.format_exc())


# ============================================================================
# MAIN APP EXECUTION
# ============================================================================

def main():
    """Main application entry point."""
    initialize_session_state()
    initialize_session_state()

    # Header
    render_header()
    st.divider()

    # Sidebar
    render_sidebar_info()

    # Tabs
    tabs = st.tabs(["Network Scan", "Previous Reports"])

    # 1. Tab: Network Scan
    with tabs[0]:
        target, scan_button = render_input_form()
        if scan_button:
            handle_scan_execution(target)
        st.divider()
        if st.session_state.scan_results and st.session_state.cve_data:
            render_metric_cards(st.session_state.scan_results, st.session_state.cve_data)
            st.divider()
            render_risk_distribution_chart(st.session_state.cve_data)
            st.divider()
            render_vulnerability_table(st.session_state.cve_data)
            st.divider()
            render_report_download(st.session_state.scan_results, st.session_state.cve_data)
            if st.session_state.scan_timestamp:
                st.caption(
                    f"Scan completed at: {st.session_state.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                )
        else:
            st.info("👆 Enter a target and click 'Start Scan' to begin vulnerability assessment")

    # 2. Tab: Previous Reports
    with tabs[1]:
        st.subheader("🗂️ Previous Scan Reports")
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        reports_dir = os.path.abspath(reports_dir)
        report_files = []
        if os.path.exists(reports_dir):
            report_files = [f for f in os.listdir(reports_dir) if f.endswith(".json")]
            report_files.sort(reverse=True)
        if report_files:
            for rf in report_files:
                report_path = os.path.join(reports_dir, rf)
                with open(report_path, "r", encoding="utf-8") as f:
                    try:
                        report_data = json.load(f)
                        target = report_data.get("scan_info", {}).get("target", "-")
                        scan_time = report_data.get("scan_info", {}).get("scan_time", "-")
                        total_ports = report_data.get("scan_info", {}).get("total_ports", "-")
                        total_cves = report_data.get("summary", {}).get("total_cves", "-")
                        critical = report_data.get("summary", {}).get("critical", "-")
                    except Exception:
                        target = scan_time = total_ports = total_cves = critical = "-"
                with st.expander(f"{rf} | Target: {target} | Time: {scan_time}"):
                    st.write(f"**Target:** {target}")
                    st.write(f"**Scan Time:** {scan_time}")
                    st.write(f"**Open Ports:** {total_ports}")
                    st.write(f"**Total CVEs:** {total_cves}")
                    st.write(f"**Critical:** {critical}")
                    with open(report_path, "r", encoding="utf-8") as f2:
                        st.download_button(
                            label="Download JSON",
                            data=f2.read(),
                            file_name=rf,
                            mime="application/json"
                        )
        else:
            st.info("No previous reports found in the reports folder.")


if __name__ == "__main__":
    main()
