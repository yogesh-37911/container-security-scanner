"""
forensic_mapper.py — Forensic Mapping Engine
=============================================
Correlates all vulnerabilities and threats back to their
originating Docker layer. Provides root-cause traceability.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from collections import defaultdict

console = Console(stderr=True)


def build_forensic_map(
    layers: list[dict],
    vuln_data: dict,
    threat_data: dict,
    package_data: dict,
) -> dict:
    """
    Build a complete forensic map linking every finding to its origin layer.

    Returns:
        dict: forensic_map with layer_reports and cross-references.
    """
    console.print(f"\n[bold cyan]🗺️  Building Forensic Layer Map...[/bold cyan]")

    layer_map: dict[int, dict] = {}

    # Initialize map for each layer
    for layer in layers:
        idx = layer["layer_index"]
        layer_map[idx] = {
            "layer_index": idx,
            "layer_id": layer.get("layer_id", ""),
            "command": layer.get("command", ""),
            "file_count": layer.get("file_count", 0),
            "packages": [],
            "vulnerabilities": [],
            "threats": [],
            "risk_score": 0.0,
            "severity": "NONE",
        }

    # Map packages to layers
    for pkg in package_data.get("packages", []):
        idx = pkg.get("layer_index", -1)
        if idx in layer_map:
            layer_map[idx]["packages"].append({
                "name": pkg["name"],
                "version": pkg.get("version", "unknown"),
                "ecosystem": pkg.get("ecosystem", ""),
            })

    # Map CVE vulnerabilities to layers
    for vuln in vuln_data.get("vulnerabilities", []):
        idx = vuln.get("layer_index", -1)
        if idx in layer_map:
            layer_map[idx]["vulnerabilities"].append({
                "cve_id": vuln["cve_id"],
                "package": vuln["package_name"],
                "severity": vuln["severity"],
                "cvss_score": vuln.get("cvss_score", 0.0),
                "description": vuln["description"],
                "fix": vuln.get("fix_version", ""),
                "remediation": vuln.get("remediation", ""),
            })

    # Map threats to layers
    for threat in threat_data.get("threats", []):
        idx = threat.get("layer_index", -1)
        target = idx if idx in layer_map else -1
        # Use last layer as catch-all for image-level findings
        if target == -1 and layer_map:
            target = max(layer_map.keys())
        if target in layer_map:
            layer_map[target]["threats"].append({
                "type": threat.get("type"),
                "name": threat.get("name"),
                "severity": threat.get("severity"),
                "file_path": threat.get("file_path"),
                "description": threat.get("description"),
                "remediation": threat.get("remediation"),
            })

    # Calculate risk score per layer
    for idx, layer_report in layer_map.items():
        score = _calculate_layer_risk(layer_report)
        layer_report["risk_score"] = score
        layer_report["severity"] = _score_to_label(score)

    # Sort layers by index
    sorted_layers = [layer_map[k] for k in sorted(layer_map.keys())]

    # Build forensic summary
    total_cves = sum(len(l["vulnerabilities"]) for l in sorted_layers)
    total_threats = sum(len(l["threats"]) for l in sorted_layers)
    riskiest_layer = max(sorted_layers, key=lambda l: l["risk_score"], default=None)

    forensic_map = {
        "layer_reports": sorted_layers,
        "total_layers": len(sorted_layers),
        "total_cves": total_cves,
        "total_threats": total_threats,
        "riskiest_layer": riskiest_layer,
        "critical_path": _identify_critical_path(sorted_layers),
    }

    _print_forensic_table(sorted_layers)
    return forensic_map


def _calculate_layer_risk(layer: dict) -> float:
    """
    Calculate a 0–10 risk score for a single layer.
    Weighted: CRITICAL=4, HIGH=2, MEDIUM=1, threats add 0.5 each.
    """
    score = 0.0
    weights = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3}

    for vuln in layer.get("vulnerabilities", []):
        score += weights.get(vuln.get("severity", "LOW"), 0.3)

    for threat in layer.get("threats", []):
        score += weights.get(threat.get("severity", "LOW"), 0.3) * 0.5

    return min(round(score, 1), 10.0)


def _score_to_label(score: float) -> str:
    if score >= 7.0:
        return "CRITICAL"
    elif score >= 4.0:
        return "HIGH"
    elif score >= 1.5:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def _identify_critical_path(layers: list[dict]) -> list[dict]:
    """Identify layers that introduced the most risk."""
    risky = [l for l in layers if l["risk_score"] > 0]
    risky.sort(key=lambda l: l["risk_score"], reverse=True)
    return [
        {
            "layer_index": l["layer_index"],
            "layer_id": l["layer_id"],
            "command": l["command"],
            "risk_score": l["risk_score"],
            "cve_count": len(l["vulnerabilities"]),
            "threat_count": len(l["threats"]),
        }
        for l in risky[:5]
    ]


def _print_forensic_table(sorted_layers: list[dict]):
    table = Table(
        title="[bold]Forensic Layer Map[/bold]",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Layer ID", style="cyan", width=14)
    table.add_column("Command", width=40)
    table.add_column("Pkgs", justify="right", width=6)
    table.add_column("CVEs", justify="right", width=6)
    table.add_column("Threats", justify="right", width=8)
    table.add_column("Risk", justify="right", width=6)

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green",
        "NONE": "dim",
    }

    for layer in sorted_layers:
        color = severity_colors.get(layer["severity"], "white")
        risk_display = f"[{color}]{layer['risk_score']:.1f}[/{color}]"
        table.add_row(
            str(layer["layer_index"]),
            layer["layer_id"][:12],
            layer["command"][:38],
            str(len(layer["packages"])),
            str(len(layer["vulnerabilities"])),
            str(len(layer["threats"])),
            risk_display,
        )

    console.print(table)
