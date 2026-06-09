"""
risk_engine.py — Risk Scoring Engine
=====================================
Calculates an overall image risk score (0–10) based on:
  - CVE severity distribution
  - Threat count and severity
  - Root user usage
  - Layer count (attack surface)
"""

from rich.console import Console
from rich.panel import Panel

console = Console(stderr=True)

SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH": 2.0,
    "MEDIUM": 0.8,
    "LOW": 0.2,
}


def calculate_overall_risk(
    vuln_data: dict,
    threat_data: dict,
    image_metadata: dict,
    forensic_map: dict,
) -> dict:
    """
    Calculate an overall image risk score and risk classification.

    Returns:
        dict with score, grade, breakdown, and recommendations.
    """
    vuln_summary = vuln_data.get("summary", {})
    threat_summary = threat_data.get("summary", {})

    # ── CVE score component (max 6 points) ────────────────────────────────────
    cve_score = 0.0
    for sev, count in vuln_summary.items():
        cve_score += SEVERITY_WEIGHTS.get(sev, 0) * count
    cve_score = min(cve_score / 3.0, 6.0)

    # ── Threat score component (max 3 points) ─────────────────────────────────
    threat_score = 0.0
    for sev, count in threat_summary.items():
        threat_score += SEVERITY_WEIGHTS.get(sev, 0) * count * 0.5
    threat_score = min(threat_score / 2.0, 3.0)

    # ── Configuration penalty (max 1 point) ───────────────────────────────────
    config_penalty = 0.0
    config = image_metadata.get("config", {})
    if config.get("user") in ("", "root", "0"):
        config_penalty += 0.5
    if image_metadata.get("layer_count", 0) > 15:
        config_penalty += 0.3   # many layers = larger attack surface
    if not config.get("cmd") and not config.get("entrypoint"):
        config_penalty += 0.2

    # ── Final score ───────────────────────────────────────────────────────────
    total = round(min(cve_score + threat_score + config_penalty, 10.0), 1)
    grade = _score_to_grade(total)

    breakdown = {
        "cve_component": round(cve_score, 2),
        "threat_component": round(threat_score, 2),
        "config_penalty": round(config_penalty, 2),
        "total_score": total,
    }

    recommendations = _build_recommendations(vuln_data, threat_data, image_metadata)

    _print_risk_panel(total, grade, vuln_summary, threat_summary, image_metadata)

    return {
        "score": total,
        "grade": grade,
        "classification": _grade_to_classification(grade),
        "breakdown": breakdown,
        "recommendations": recommendations,
    }


def _score_to_grade(score: float) -> str:
    if score >= 8.0:
        return "F"
    elif score >= 6.5:
        return "D"
    elif score >= 5.0:
        return "C"
    elif score >= 3.0:
        return "B"
    else:
        return "A"


def _grade_to_classification(grade: str) -> str:
    return {
        "A": "LOW RISK — Image is relatively secure.",
        "B": "MODERATE RISK — Some vulnerabilities need attention.",
        "C": "ELEVATED RISK — Multiple issues require remediation.",
        "D": "HIGH RISK — Significant vulnerabilities detected.",
        "F": "CRITICAL RISK — Do NOT deploy. Immediate action required.",
    }.get(grade, "UNKNOWN")


def _build_recommendations(vuln_data, threat_data, image_metadata) -> list[str]:
    recs = []
    vuln_summary = vuln_data.get("summary", {})
    config = image_metadata.get("config", {})

    if vuln_summary.get("CRITICAL", 0) > 0:
        recs.append("🚨 CRITICAL: Update packages with critical CVEs immediately before any deployment.")
    if vuln_summary.get("HIGH", 0) > 0:
        recs.append("⚠️  HIGH: Patch high-severity packages in the next sprint cycle.")
    if config.get("user") in ("", "root", "0"):
        recs.append("🔒 Add 'USER nonroot' to Dockerfile — never run as root in production.")
    if any(t["type"] == "secret" for t in threat_data.get("threats", [])):
        recs.append("🔑 Remove all hardcoded secrets. Use Kubernetes secrets or Vault instead.")
    if any(t["type"] == "suid_binary" for t in threat_data.get("threats", [])):
        recs.append("🛡️  Remove SUID binaries from image layers unless strictly necessary.")
    if image_metadata.get("layer_count", 0) > 12:
        recs.append("📦 Reduce image layer count using multi-stage builds to shrink attack surface.")
    if not recs:
        recs.append("✅ No critical recommendations. Continue with regular vulnerability monitoring.")

    return recs


def _print_risk_panel(score, grade, vuln_summary, threat_summary, meta):
    grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange3", "F": "red"}
    color = grade_colors.get(grade, "white")

    lines = [
        f"[bold {color}]Risk Score: {score} / 10   Grade: {grade}[/bold {color}]",
        "",
        f"  Critical CVEs : {vuln_summary.get('CRITICAL', 0)}",
        f"  High CVEs     : {vuln_summary.get('HIGH', 0)}",
        f"  Medium CVEs   : {vuln_summary.get('MEDIUM', 0)}",
        f"  Low CVEs      : {vuln_summary.get('LOW', 0)}",
        "",
        f"  Critical Threats : {threat_summary.get('CRITICAL', 0)}",
        f"  High Threats     : {threat_summary.get('HIGH', 0)}",
    ]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]🎯 Image Risk Assessment[/bold]",
            border_style=color,
            padding=(1, 2),
        )
    )
