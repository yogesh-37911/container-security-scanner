"""
report_generator.py — Report Generator
=======================================
Produces structured forensic security reports in:
  - JSON (machine-readable)
  - YAML (human-readable config-style)
  - TXT (plain-text summary for terminals/emails)
"""

import os
import json
import yaml
from datetime import datetime, timezone
from rich.console import Console

console = Console(stderr=True)


def generate_reports(
    image_metadata: dict,
    package_data: dict,
    vuln_data: dict,
    threat_data: dict,
    forensic_map: dict,
    risk_score: dict,
    output_dir: str = "reports",
) -> dict:
    """
    Generate all report formats and save to output_dir.

    Returns:
        dict with file paths of generated reports.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    image_slug = image_metadata["image_name"].replace("/", "_").replace(":", "_")
    base_name = f"{image_slug}_{timestamp}"

    report_data = _assemble_report(
        image_metadata, package_data, vuln_data, threat_data, forensic_map, risk_score
    )

    paths = {}

    # JSON report
    json_path = os.path.join(output_dir, f"{base_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
    paths["json"] = json_path

    # YAML report
    yaml_path = os.path.join(output_dir, f"{base_name}.yaml")
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(report_data, f, default_flow_style=False, allow_unicode=True)
    paths["yaml"] = yaml_path

    # SBOM JSON
    sbom_path = os.path.join(output_dir, f"{base_name}_sbom.json")
    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(package_data.get("sbom", {}), f, indent=2, default=str)
    paths["sbom"] = sbom_path

    # Plain text summary
    txt_path = os.path.join(output_dir, f"{base_name}_summary.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_generate_text_report(image_metadata, vuln_data, threat_data, risk_score, forensic_map))
    paths["txt"] = txt_path

    console.print(f"\n[bold green]📄 Reports saved:[/bold green]")
    for fmt, path in paths.items():
        console.print(f"  [cyan]{fmt.upper()}:[/cyan] {_display_path(path)}")

    return paths


def _display_path(path: str) -> str:
    """Prefer a shorter relative path when it is clearer in terminal output."""
    normalized = os.path.normpath(path)
    try:
        relative = os.path.relpath(normalized)
    except ValueError:
        return normalized
    return relative if len(relative) < len(normalized) else normalized


def _assemble_report(
    image_metadata, package_data, vuln_data, threat_data, forensic_map, risk_score
) -> dict:
    """Assemble the master report dict."""
    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "ContainerSecurityScanner v1.0.0",
            "report_version": "1.0",
        },
        "image": {
            "name": image_metadata["image_name"],
            "id": image_metadata["image_id"],
            "os": image_metadata["os"],
            "architecture": image_metadata["architecture"],
            "size_mb": image_metadata["size_mb"],
            "layer_count": image_metadata["layer_count"],
            "created": image_metadata["created"],
            "user": image_metadata["config"]["user"] or "root",
        },
        "risk_assessment": {
            "score": risk_score["score"],
            "grade": risk_score["grade"],
            "classification": risk_score["classification"],
            "breakdown": risk_score["breakdown"],
            "recommendations": risk_score["recommendations"],
        },
        "vulnerability_summary": vuln_data.get("summary", {}),
        "threat_summary": threat_data.get("summary", {}),
        "package_count": package_data.get("total_count", 0),
        "vulnerabilities": _format_vulnerabilities(vuln_data.get("vulnerabilities", [])),
        "threats": _format_threats(threat_data.get("threats", [])),
        "forensic_layers": _format_forensic_layers(forensic_map.get("layer_reports", [])),
        "critical_path": forensic_map.get("critical_path", []),
    }


def _format_vulnerabilities(vulns: list) -> list:
    return [
        {
            "cve_id": v["cve_id"],
            "package": v["package_name"],
            "version": v["package_version"],
            "severity": v["severity"],
            "cvss_score": v.get("cvss_score"),
            "description": v["description"],
            "fix_version": v.get("fix_version"),
            "remediation": v.get("remediation"),
            "layer_index": v.get("layer_index"),
            "layer_id": v.get("layer_id"),
            "layer_command": v.get("layer_command"),
        }
        for v in vulns
    ]


def _format_threats(threats: list) -> list:
    return [
        {
            "type": t["type"],
            "name": t["name"],
            "severity": t["severity"],
            "file_path": t.get("file_path"),
            "description": t.get("description"),
            "remediation": t.get("remediation"),
            "layer_index": t.get("layer_index"),
            "layer_id": t.get("layer_id"),
        }
        for t in threats
    ]


def _format_forensic_layers(layer_reports: list) -> list:
    result = []
    for lr in layer_reports:
        result.append({
            "layer_index": lr["layer_index"],
            "layer_id": lr["layer_id"],
            "command": lr["command"],
            "risk_score": lr["risk_score"],
            "severity": lr["severity"],
            "packages_introduced": len(lr.get("packages", [])),
            "vulnerabilities": len(lr.get("vulnerabilities", [])),
            "threats": len(lr.get("threats", [])),
            "cve_list": [v["cve_id"] for v in lr.get("vulnerabilities", [])],
        })
    return result


def _generate_text_report(
    image_metadata, vuln_data, threat_data, risk_score, forensic_map
) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  CONTAINER IMAGE THREAT SCANNER — FORENSIC REPORT")
    lines.append("=" * 70)
    lines.append(f"  Image:       {image_metadata['image_name']}")
    lines.append(f"  Scanned:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"  OS:          {image_metadata['os']} / {image_metadata['architecture']}")
    lines.append(f"  Layers:      {image_metadata['layer_count']}")
    lines.append(f"  Risk Score:  {risk_score['score']} / 10  (Grade: {risk_score['grade']})")
    lines.append(f"  {risk_score['classification']}")
    lines.append("")
    lines.append("─" * 70)
    lines.append("  VULNERABILITY SUMMARY")
    lines.append("─" * 70)
    for sev, count in vuln_data.get("summary", {}).items():
        lines.append(f"  {sev:<12} : {count}")
    lines.append("")
    lines.append("─" * 70)
    lines.append("  TOP VULNERABILITIES")
    lines.append("─" * 70)

    vulns = sorted(
        vuln_data.get("vulnerabilities", []),
        key=lambda v: -v.get("cvss_score", 0),
    )[:10]

    for v in vulns:
        lines.append(f"\n  [{v['severity']}] {v['cve_id']}")
        lines.append(f"    Package:  {v['package_name']} {v['package_version']}")
        lines.append(f"    Layer:    #{v.get('layer_index', '?')} ({v.get('layer_id', '')})")
        lines.append(f"    CVSS:     {v.get('cvss_score', 'N/A')}")
        lines.append(f"    Fix:      {v.get('remediation', 'N/A')}")

    lines.append("")
    lines.append("─" * 70)
    lines.append("  THREATS DETECTED")
    lines.append("─" * 70)
    for t in threat_data.get("threats", [])[:10]:
        lines.append(f"\n  [{t['severity']}] {t['name']}")
        lines.append(f"    Path:  {t.get('file_path', 'N/A')}")
        lines.append(f"    Layer: #{t.get('layer_index', '?')}")
        lines.append(f"    Fix:   {t.get('remediation', 'N/A')}")

    lines.append("")
    lines.append("─" * 70)
    lines.append("  RECOMMENDATIONS")
    lines.append("─" * 70)
    for rec in risk_score.get("recommendations", []):
        lines.append(f"  {rec}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)
