"""
main.py — CLI Entry Point
=========================
Container Image Threat Scanner with Layer-Aware Forensics

Usage:
    python main.py nginx:latest
    python main.py nginx:latest --live-api
    python main.py nginx:latest --output reports/
    python main.py nginx:latest --dashboard
"""

import sys
import argparse
import json
import time
import os
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule


def _configure_utf8_output():
    """Force UTF-8 console output where Python supports stream reconfiguration."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_configure_utf8_output()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Import scanner modules ────────────────────────────────────────────────────
from scanner.image_pull import pull_image
from scanner.layer_extractor import extract_image_layers, get_layer_summary
from scanner.package_enum import enumerate_packages
from scanner.vulnerability_scanner import scan_vulnerabilities
from scanner.threat_intelligence import analyze_threats
from scanner.forensic_mapper import build_forensic_map
from scanner.risk_engine import calculate_overall_risk
from scanner.report_generator import generate_reports

console = Console(stderr=True)

BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║       CONTAINER IMAGE THREAT SCANNER                         ║
║       with Layer-Aware Forensics                             ║
║       v1.0.0  |  BGS College Mysore  |  BCA Final Year       ║
╚═══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Container Image Threat Scanner with Layer-Aware Forensics",
    )
    parser.add_argument(
        "image",
        help="Docker image name/tag to scan (e.g., nginx:latest)",
    )
    parser.add_argument(
        "--live-api",
        action="store_true",
        default=False,
        help="Query live NVD API for CVE data (slower, requires internet)",
    )
    parser.add_argument(
        "--output",
        default="reports",
        metavar="DIR",
        help="Output directory for generated reports (default: reports/)",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        default=False,
        help="Launch Streamlit dashboard after scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print JSON report to stdout instead of files",
    )
    return parser.parse_args()


def _resolve_output_dir(output_dir: str) -> str:
    """Resolve relative output paths from the project root for consistent report storage."""
    if os.path.isabs(output_dir):
        return output_dir
    return os.path.join(BASE_DIR, output_dir)


def run_scan(image_name: str, live_api: bool = False, output_dir: str = "reports") -> dict:
    """
    Execute the full scanning pipeline.

    Returns:
        dict: Complete scan results.
    """
    start = time.time()
    console.print(BANNER, style="bold cyan")
    console.print(Rule("[bold]Starting Scan Pipeline[/bold]", style="cyan"))

    # ── Step 1: Pull image ────────────────────────────────────────────────────
    console.print(Rule("[dim]Step 1 / 7 — Image Acquisition[/dim]"))
    image_metadata = pull_image(image_name)

    # ── Step 2: Extract layers ────────────────────────────────────────────────
    console.print(Rule("[dim]Step 2 / 7 — Layer Extraction[/dim]"))
    layers = extract_image_layers(image_name)

    # ── Step 3: Enumerate packages ────────────────────────────────────────────
    console.print(Rule("[dim]Step 3 / 7 — Package Enumeration[/dim]"))
    package_data = enumerate_packages(layers)

    # ── Step 4: Vulnerability scan ────────────────────────────────────────────
    console.print(Rule("[dim]Step 4 / 7 — CVE Vulnerability Scan[/dim]"))
    vuln_data = scan_vulnerabilities(package_data, use_live_api=live_api)

    # ── Step 5: Threat intelligence ───────────────────────────────────────────
    console.print(Rule("[dim]Step 5 / 7 — Threat Intelligence[/dim]"))
    threat_data = analyze_threats(layers, image_metadata)

    # ── Step 6: Forensic mapping ──────────────────────────────────────────────
    console.print(Rule("[dim]Step 6 / 7 — Forensic Layer Mapping[/dim]"))
    forensic_map = build_forensic_map(layers, vuln_data, threat_data, package_data)

    # ── Step 7: Risk scoring ──────────────────────────────────────────────────
    console.print(Rule("[dim]Step 7 / 7 — Risk Assessment[/dim]"))
    risk_score = calculate_overall_risk(vuln_data, threat_data, image_metadata, forensic_map)

    elapsed = round(time.time() - start, 1)
    console.print(f"\n[dim]Scan completed in {elapsed}s[/dim]")

    # ── Generate reports ──────────────────────────────────────────────────────
    report_paths = generate_reports(
        image_metadata=image_metadata,
        package_data=package_data,
        vuln_data=vuln_data,
        threat_data=threat_data,
        forensic_map=forensic_map,
        risk_score=risk_score,
        output_dir=output_dir,
    )

    return {
        "image_metadata": image_metadata,
        "package_data": package_data,
        "vuln_data": vuln_data,
        "threat_data": threat_data,
        "forensic_map": forensic_map,
        "risk_score": risk_score,
        "report_paths": report_paths,
        "elapsed_seconds": elapsed,
    }


def _write_latest_scan(results: dict, output_dir: str):
    """Persist the latest scan for the dashboard and automation tools."""
    os.makedirs(output_dir, exist_ok=True)
    latest_scan_path = os.path.join(output_dir, "latest_scan.json")
    with open(latest_scan_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def main():
    args = parse_args()
    output_dir = _resolve_output_dir(args.output)

    try:
        results = run_scan(
            image_name=args.image,
            live_api=args.live_api,
            output_dir=output_dir,
        )
        _write_latest_scan(results, output_dir)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)

    # Optional: dump JSON to stdout
    if args.json:
        safe = {
            k: v for k, v in results.items()
            if k not in ("package_data",)
        }
        print(json.dumps(safe, indent=2, default=str))

    # Optional: launch dashboard
    if args.dashboard:
        console.print("\n[bold cyan]🚀 Launching Dashboard...[/bold cyan]")
        import subprocess
        subprocess.run(["streamlit", "run", "dashboard/app.py"], cwd=BASE_DIR)

    console.print(
        Panel(
            f"[bold green]✅ Scan Complete![/bold green]\n"
            f"  Image:      {args.image}\n"
            f"  Risk Score: {results['risk_score']['score']} / 10 (Grade {results['risk_score']['grade']})\n"
            f"  CVEs Found: {results['vuln_data']['total_count']}\n"
            f"  Threats:    {results['threat_data']['total_count']}\n"
            f"  Reports:    {os.path.normpath(output_dir)}",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
