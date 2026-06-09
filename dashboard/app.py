"""
dashboard/app.py — Streamlit Security Dashboard
=================================================
Visualizes scan results with:
  - Risk score gauge
  - Vulnerability distribution chart
  - Layer heatmap
  - CVE detail table
  - Threat intelligence panel
  - SBOM viewer
  - Remediation recommendations

Run:
    streamlit run dashboard/app.py
"""

import os
import sys
import json
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Container Threat Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .block-container { padding-top: 1rem; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e, #252a3d);
        border: 1px solid #2d3561;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
    }
    .severity-critical { color: #ff4757; font-weight: bold; }
    .severity-high { color: #ff6348; font-weight: bold; }
    .severity-medium { color: #ffa502; font-weight: bold; }
    .severity-low { color: #2ed573; font-weight: bold; }
    .stDataFrame { font-size: 12px; }
</style>
""", unsafe_allow_html=True)


def load_scan_results():
    """Load the most recent scan result from file or return demo data."""
    report_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "latest_scan.json")
    if os.path.exists(report_path):
        with open(report_path, encoding="utf-8") as f:
            return json.load(f)
    return _demo_data()


def _demo_data():
    """Provide realistic demo data for dashboard demonstration."""
    return {
        "image_metadata": {
            "image_name": "nginx:latest",
            "image_id": "sha256:abc123",
            "os": "linux",
            "architecture": "amd64",
            "size_mb": 187.4,
            "layer_count": 7,
            "created": "2024-01-15T10:30:00Z",
            "config": {"user": "root", "exposed_ports": ["80/tcp"]},
        },
        "risk_score": {
            "score": 7.2,
            "grade": "D",
            "classification": "HIGH RISK — Significant vulnerabilities detected.",
            "breakdown": {"cve_component": 5.1, "threat_component": 1.6, "config_penalty": 0.5},
            "recommendations": [
                "🚨 CRITICAL: Update packages with critical CVEs immediately.",
                "🔒 Add 'USER nonroot' to Dockerfile.",
                "🔑 Remove hardcoded secrets.",
                "📦 Reduce layer count using multi-stage builds.",
            ],
        },
        "vuln_data": {
            "total_count": 16,
            "summary": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 6, "LOW": 3, "INFO": 0},
            "vulnerabilities": [
                {"cve_id": "CVE-2023-38545", "package_name": "curl", "package_version": "7.88.1",
                 "severity": "CRITICAL", "cvss_score": 9.8, "layer_index": 3, "layer_id": "a1b2c3d4e5f6",
                 "description": "SOCKS5 heap buffer overflow in curl.", "fix_version": "8.4.0",
                 "remediation": "apt-get upgrade curl (target: 8.4.0)"},
                {"cve_id": "CVE-2022-37434", "package_name": "zlib1g", "package_version": "1.2.11",
                 "severity": "CRITICAL", "cvss_score": 9.8, "layer_index": 1, "layer_id": "f6e5d4c3b2a1",
                 "description": "Heap buffer overflow via large gzip header.", "fix_version": "1.2.13",
                 "remediation": "apt-get upgrade zlib1g (target: 1.2.13)"},
                {"cve_id": "CVE-2023-0464", "package_name": "openssl", "package_version": "1.1.1n",
                 "severity": "HIGH", "cvss_score": 7.5, "layer_index": 2, "layer_id": "b3c4d5e6f7a8",
                 "description": "Excessive Resource Usage in OpenSSL.", "fix_version": "1.1.1u",
                 "remediation": "apt-get upgrade openssl (target: 1.1.1u)"},
                {"cve_id": "CVE-2022-0778", "package_name": "libssl1.1", "package_version": "1.1.1n",
                 "severity": "HIGH", "cvss_score": 7.5, "layer_index": 2, "layer_id": "b3c4d5e6f7a8",
                 "description": "Infinite loop in BN_mod_sqrt() for non-prime moduli.", "fix_version": "1.1.1n",
                 "remediation": "apt-get upgrade libssl1.1"},
                {"cve_id": "CVE-2023-4911", "package_name": "libc-bin", "package_version": "2.31-13",
                 "severity": "HIGH", "cvss_score": 7.8, "layer_index": 1, "layer_id": "f6e5d4c3b2a1",
                 "description": "Buffer overflow in glibc (Looney Tunables).", "fix_version": "2.38-1",
                 "remediation": "apt-get upgrade libc-bin"},
                {"cve_id": "CVE-2022-43680", "package_name": "libexpat1", "package_version": "2.2.10",
                 "severity": "HIGH", "cvss_score": 7.5, "layer_index": 2, "layer_id": "b3c4d5e6f7a8",
                 "description": "Use-after-free in Expat XML parser.", "fix_version": "2.5.0",
                 "remediation": "apt-get upgrade libexpat1"},
            ],
        },
        "threat_data": {
            "total_count": 4,
            "summary": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 1},
            "threats": [
                {"type": "runs_as_root", "name": "Container runs as root", "severity": "HIGH",
                 "file_path": "Dockerfile", "description": "Container runs as root user.",
                 "remediation": "Add USER nonroot to Dockerfile.", "layer_index": 0},
                {"type": "sensitive_file", "name": "Sensitive File: shadow", "severity": "HIGH",
                 "file_path": "/etc/shadow", "description": "Shadow password file exposed.",
                 "remediation": "Remove /etc/shadow from image.", "layer_index": 1},
                {"type": "suid_binary", "name": "SUID Binary: ping", "severity": "MEDIUM",
                 "file_path": "/usr/bin/ping", "description": "SUID bit set on ping.",
                 "remediation": "chmod u-s /usr/bin/ping", "layer_index": 2},
                {"type": "suspicious_artifact", "name": "Suspicious path: /root/.ssh",
                 "severity": "LOW", "file_path": "/root/.ssh",
                 "description": "SSH keys in root home directory.",
                 "remediation": "Remove SSH keys from image.", "layer_index": 3},
            ],
        },
        "forensic_map": {
            "layer_reports": [
                {"layer_index": 0, "layer_id": "e38bc07ac18e", "command": "Base Image: debian:bullseye-slim",
                 "risk_score": 0.3, "severity": "LOW", "packages_introduced": 78,
                 "vulnerabilities": [], "threats": [{"name": "runs_as_root", "severity": "HIGH"}]},
                {"layer_index": 1, "layer_id": "f6e5d4c3b2a1", "command": "RUN apt-get update && apt-get install -y ...",
                 "risk_score": 6.8, "severity": "HIGH", "packages_introduced": 23,
                 "vulnerabilities": [{"cve_id": "CVE-2022-37434", "severity": "CRITICAL"},
                                     {"cve_id": "CVE-2023-4911", "severity": "HIGH"}],
                 "threats": [{"name": "shadow exposed", "severity": "HIGH"}]},
                {"layer_index": 2, "layer_id": "b3c4d5e6f7a8", "command": "RUN apt-get install -y openssl curl",
                 "risk_score": 8.5, "severity": "CRITICAL", "packages_introduced": 8,
                 "vulnerabilities": [{"cve_id": "CVE-2023-38545", "severity": "CRITICAL"},
                                     {"cve_id": "CVE-2023-0464", "severity": "HIGH"}],
                 "threats": [{"name": "SUID ping", "severity": "MEDIUM"}]},
                {"layer_index": 3, "layer_id": "a1b2c3d4e5f6", "command": "COPY ./app /app",
                 "risk_score": 0.5, "severity": "LOW", "packages_introduced": 0,
                 "vulnerabilities": [], "threats": [{"name": "SSH keys", "severity": "LOW"}]},
                {"layer_index": 4, "layer_id": "c7d8e9f0a1b2", "command": "RUN nginx -v",
                 "risk_score": 2.0, "severity": "MEDIUM", "packages_introduced": 1,
                 "vulnerabilities": [{"cve_id": "CVE-2022-41741", "severity": "HIGH"}], "threats": []},
                {"layer_index": 5, "layer_id": "d9e0f1a2b3c4", "command": "EXPOSE 80",
                 "risk_score": 0.0, "severity": "NONE", "packages_introduced": 0,
                 "vulnerabilities": [], "threats": []},
                {"layer_index": 6, "layer_id": "e1f2a3b4c5d6", "command": "CMD [\"nginx\", \"-g\", \"daemon off;\"]",
                 "risk_score": 0.0, "severity": "NONE", "packages_introduced": 0,
                 "vulnerabilities": [], "threats": []},
            ],
            "critical_path": [
                {"layer_index": 2, "command": "RUN apt-get install -y openssl curl", "risk_score": 8.5},
                {"layer_index": 1, "command": "RUN apt-get update && apt-get install -y ...", "risk_score": 6.8},
                {"layer_index": 4, "command": "RUN nginx -v", "risk_score": 2.0},
            ],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD LAYOUT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    data = load_scan_results()
    meta = data.get("image_metadata", {})
    risk = data.get("risk_score", {})
    vuln = data.get("vuln_data", {})
    threat = data.get("threat_data", {})
    forensic = data.get("forensic_map", {})

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## 🛡️ Container Threat Scanner")
        st.markdown("---")
        st.markdown(f"**Image:** `{meta.get('image_name', 'N/A')}`")
        st.markdown(f"**OS:** {meta.get('os', '?')} / {meta.get('architecture', '?')}")
        st.markdown(f"**Size:** {meta.get('size_mb', 0)} MB")
        st.markdown(f"**Layers:** {meta.get('layer_count', 0)}")
        st.markdown("---")
        page = st.radio(
            "Navigation",
            ["📊 Overview", "🔍 Vulnerabilities", "🚨 Threats", "🗺️ Layer Map", "📦 SBOM", "💡 Remediation"],
        )
        st.markdown("---")
        st.caption("BGS College Mysore — BCA Final Year Project 2025-26")

    # ── Header ────────────────────────────────────────────────────────────────
    st.title("🛡️ Container Image Threat Scanner")
    st.caption("Layer-Aware Forensics Dashboard")

    if page == "📊 Overview":
        _render_overview(meta, risk, vuln, threat)
    elif page == "🔍 Vulnerabilities":
        _render_vulnerabilities(vuln)
    elif page == "🚨 Threats":
        _render_threats(threat)
    elif page == "🗺️ Layer Map":
        _render_layer_map(forensic)
    elif page == "📦 SBOM":
        _render_sbom(data)
    elif page == "💡 Remediation":
        _render_remediation(risk, vuln, threat)


def _render_overview(meta, risk, vuln, threat):
    st.header("📊 Scan Overview")

    # ── Top KPIs ──────────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)
    grade_colors = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}
    icon = grade_colors.get(risk.get("grade", "F"), "⚫")

    col1.metric("Risk Score", f"{risk.get('score', 0)} / 10", delta=None)
    col2.metric("Grade", f"{icon} {risk.get('grade', 'N/A')}")
    col3.metric("Total CVEs", vuln.get("total_count", 0))
    col4.metric("Threats", threat.get("total_count", 0))
    col5.metric("Layers", meta.get("layer_count", 0))

    st.markdown("---")

    col_left, col_right = st.columns([1, 1])

    with col_left:
        # Risk gauge
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk.get("score", 0),
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Risk Score", "font": {"size": 20}},
            gauge={
                "axis": {"range": [0, 10], "tickwidth": 1},
                "bar": {"color": _risk_color(risk.get("score", 0))},
                "steps": [
                    {"range": [0, 3], "color": "#1a3d2b"},
                    {"range": [3, 6], "color": "#3d3a1a"},
                    {"range": [6, 8], "color": "#3d2b1a"},
                    {"range": [8, 10], "color": "#3d1a1a"},
                ],
                "threshold": {
                    "line": {"color": "white", "width": 2},
                    "thickness": 0.75,
                    "value": risk.get("score", 0),
                },
            },
        ))
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "white"},
            height=280,
            margin=dict(t=30, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col_right:
        # Severity donut
        vuln_sum = vuln.get("summary", {})
        labels = [k for k, v in vuln_sum.items() if v > 0]
        values = [v for v in vuln_sum.values() if v > 0]
        colors_map = {
            "CRITICAL": "#ff4757", "HIGH": "#ff6348",
            "MEDIUM": "#ffa502", "LOW": "#2ed573", "INFO": "#747d8c",
        }
        fig_pie = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker=dict(colors=[colors_map.get(l, "#ccc") for l in labels]),
            textfont=dict(size=13),
        ))
        fig_pie.update_layout(
            title="CVE Severity Distribution",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            height=280,
            margin=dict(t=50, b=10, l=10, r=10),
            legend=dict(font=dict(color="white")),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ── Classification banner ─────────────────────────────────────────────────
    classification = risk.get("classification", "")
    color = "#ff4757" if "CRITICAL" in classification else "#ffa502" if "HIGH" in classification else "#2ed573"
    st.markdown(
        f'<div style="background:{color}22;border-left:4px solid {color};'
        f'padding:12px 20px;border-radius:4px;color:{color};font-weight:bold;">'
        f'🎯 {classification}</div>',
        unsafe_allow_html=True,
    )


def _render_vulnerabilities(vuln):
    st.header("🔍 Vulnerability Analysis")

    vulns = vuln.get("vulnerabilities", [])
    if not vulns:
        st.info("No vulnerabilities detected.")
        return

    df = pd.DataFrame(vulns)
    display_cols = ["cve_id", "package_name", "package_version", "severity", "cvss_score", "layer_index", "fix_version"]
    available = [c for c in display_cols if c in df.columns]

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        sev_filter = st.multiselect("Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                     default=["CRITICAL", "HIGH"])
    with col2:
        search = st.text_input("Search CVE / Package", "")

    filtered = df
    if sev_filter:
        filtered = filtered[filtered["severity"].isin(sev_filter)]
    if search:
        mask = (
            filtered["cve_id"].str.contains(search, case=False, na=False) |
            filtered["package_name"].str.contains(search, case=False, na=False)
        )
        filtered = filtered[mask]

    st.dataframe(
        filtered[available].sort_values("cvss_score", ascending=False),
        use_container_width=True,
        height=400,
    )

    # Bar chart: CVEs per layer
    if "layer_index" in df.columns:
        layer_counts = df.groupby(["layer_index", "severity"]).size().reset_index(name="count")
        fig = px.bar(
            layer_counts,
            x="layer_index",
            y="count",
            color="severity",
            color_discrete_map={
                "CRITICAL": "#ff4757", "HIGH": "#ff6348",
                "MEDIUM": "#ffa502", "LOW": "#2ed573",
            },
            title="CVEs per Layer",
            labels={"layer_index": "Layer", "count": "CVE Count"},
            template="plotly_dark",
        )
        st.plotly_chart(fig, use_container_width=True)


def _render_threats(threat):
    st.header("🚨 Threat Intelligence")

    threats = threat.get("threats", [])
    if not threats:
        st.info("No threats detected.")
        return

    # Group by type
    for threat_type in ["secret", "env_secret", "runs_as_root", "suid_binary",
                         "world_writable", "sensitive_file", "suspicious_artifact"]:
        group = [t for t in threats if t.get("type") == threat_type]
        if not group:
            continue
        label_map = {
            "secret": "🔑 Hardcoded Secrets",
            "env_secret": "🔑 Secrets in ENV",
            "runs_as_root": "⚠️ Root User",
            "suid_binary": "🔐 SUID Binaries",
            "world_writable": "📝 World-Writable Files",
            "sensitive_file": "📁 Sensitive Files",
            "suspicious_artifact": "🕵️ Suspicious Artifacts",
        }
        with st.expander(f"{label_map.get(threat_type, threat_type)} ({len(group)})", expanded=True):
            for t in group:
                sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(t.get("severity"), "⚪")
                st.markdown(f"{sev_color} **{t['name']}** — Layer #{t.get('layer_index', '?')}")
                st.caption(f"📂 {t.get('file_path', 'N/A')}")
                st.caption(f"💡 Fix: {t.get('remediation', 'N/A')}")
                st.markdown("---")


def _render_layer_map(forensic):
    st.header("🗺️ Layer Forensic Map")

    layer_reports = forensic.get("layer_reports", [])
    if not layer_reports:
        st.info("No layer data available.")
        return

    # Layer heatmap
    df = pd.DataFrame(layer_reports)
    if "risk_score" in df.columns:
        fig = go.Figure(go.Bar(
            x=[f"Layer {r['layer_index']}" for r in layer_reports],
            y=[r.get("risk_score", 0) for r in layer_reports],
            marker=dict(
                color=[r.get("risk_score", 0) for r in layer_reports],
                colorscale=[[0, "#2ed573"], [0.4, "#ffa502"], [0.7, "#ff6348"], [1.0, "#ff4757"]],
                showscale=True,
                colorbar=dict(title="Risk Score"),
            ),
            text=[r.get("command", "")[:30] for r in layer_reports],
            textposition="outside",
        ))
        fig.update_layout(
            title="Layer Risk Score Heatmap",
            template="plotly_dark",
            yaxis=dict(range=[0, 10], title="Risk Score"),
            xaxis=dict(title="Layer"),
            height=400,
        )
        st.plotly_chart(fig, use_container_width=True)

    # Layer detail table
    st.subheader("Layer Details")
    for lr in layer_reports:
        sev = lr.get("severity", "NONE")
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}.get(sev, "⚪")
        score = lr.get("risk_score", 0)
        n_vulns = len(lr.get("vulnerabilities", []))
        n_threats = len(lr.get("threats", []))
        label = f"{icon} Layer {lr['layer_index']} — Score: {score:.1f} — {lr.get('command', '')[:45]}"
        with st.expander(label):
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Score", f"{score:.1f} / 10")
            col2.metric("CVEs", n_vulns)
            col3.metric("Threats", n_threats)

            if lr.get("vulnerabilities"):
                st.markdown("**CVEs in this layer:**")
                for v in lr["vulnerabilities"]:
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(v.get("severity"), "🟢")
                    st.markdown(f"  {sev_icon} `{v.get('cve_id', '')}` — {v.get('severity', '')}")

            if lr.get("threats"):
                st.markdown("**Threats in this layer:**")
                for t in lr["threats"]:
                    st.markdown(f"  ⚠️ {t.get('name', '')}")


def _render_sbom(data):
    st.header("📦 Software Bill of Materials (SBOM)")

    packages = data.get("package_data", {}).get("packages") or _extract_packages_from_layers(data)

    if not packages:
        st.info("SBOM data not available. Run a full scan to generate.")
        return

    df = pd.DataFrame(packages)
    cols = [c for c in ["name", "version", "ecosystem", "layer_index"] if c in df.columns]
    if not cols:
        st.info("No package details available.")
        return

    search = st.text_input("Search packages", "")
    filtered = df
    if search and "name" in df.columns:
        filtered = df[df["name"].str.contains(search, case=False, na=False)]

    st.dataframe(filtered[cols], use_container_width=True, height=450)

    if "ecosystem" in df.columns:
        eco_counts = df["ecosystem"].value_counts().reset_index()
        eco_counts.columns = ["Ecosystem", "Count"]
        fig = px.pie(eco_counts, names="Ecosystem", values="Count",
                     title="Packages by Ecosystem", template="plotly_dark", hole=0.4)
        st.plotly_chart(fig, use_container_width=True)


def _extract_packages_from_layers(data):
    packages = []
    for lr in data.get("forensic_map", {}).get("layer_reports", []):
        for pkg in lr.get("packages", []):
            packages.append({**pkg, "layer_index": lr["layer_index"]})
    return packages


def _render_remediation(risk, vuln, threat):
    st.header("💡 Remediation Recommendations")

    recs = risk.get("recommendations", [])
    for i, rec in enumerate(recs, 1):
        st.markdown(f"**{i}.** {rec}")

    st.markdown("---")
    st.subheader("Top Fixes by Priority")

    vulns = sorted(vuln.get("vulnerabilities", []), key=lambda v: -v.get("cvss_score", 0))
    for v in vulns[:8]:
        sev = v.get("severity", "LOW")
        color = {"CRITICAL": "#ff4757", "HIGH": "#ff6348", "MEDIUM": "#ffa502", "LOW": "#2ed573"}.get(sev, "#ccc")
        st.markdown(
            f'<div style="border-left:3px solid {color};padding:8px 14px;margin-bottom:8px;'
            f'background:{color}11;border-radius:4px;">'
            f'<b style="color:{color}">[{sev}]</b> <code>{v["cve_id"]}</code> in '
            f'<b>{v["package_name"]} {v["package_version"]}</b><br>'
            f'<small>🔧 {v.get("remediation", "N/A")}</small>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _risk_color(score):
    if score >= 8:
        return "#ff4757"
    elif score >= 6:
        return "#ff6348"
    elif score >= 4:
        return "#ffa502"
    return "#2ed573"


if __name__ == "__main__":
    main()
