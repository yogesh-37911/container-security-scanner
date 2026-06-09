"""
threat_intelligence.py — Threat Intelligence Engine
====================================================
Detects:
  - Hardcoded secrets (AWS keys, tokens, passwords)
  - Suspicious binaries and scripts
  - Security misconfigurations (root user, world-writable, SUID)
  - SSH private keys
  - Exposed credential files
"""

import re
import os
from rich.console import Console

console = Console(stderr=True)

# ── Secret Detection Patterns ─────────────────────────────────────────────────
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "CRITICAL",
    },
    {
        "name": "Generic API Token",
        "pattern": r"(?i)(api[_\-]?key|api[_\-]?token|access[_\-]?token)\s*[=:]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "Hardcoded Password",
        "pattern": r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*['\"]?.{4,32}['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "Private Key Block",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
    },
    {
        "name": "GitHub Token",
        "pattern": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "CRITICAL",
    },
    {
        "name": "Docker Hub Token",
        "pattern": r"(?i)dockerhub.{0,10}['\"][a-zA-Z0-9\-_]{20,}['\"]",
        "severity": "HIGH",
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?i)(mysql|postgres|mongodb|redis)://[^'\"\s]{8,}",
        "severity": "HIGH",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
        "severity": "MEDIUM",
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
        "severity": "HIGH",
    },
]

# ── Suspicious File Paths / Binaries ──────────────────────────────────────────
SUSPICIOUS_PATHS = [
    ("/etc/cron", "MEDIUM", "Cron job configured inside container"),
    ("/usr/bin/nc", "HIGH", "Netcat binary detected — potential backdoor"),
    ("/usr/bin/ncat", "HIGH", "Ncat binary detected — potential backdoor"),
    ("/usr/bin/wget", "LOW", "Download utility present"),
    ("/usr/bin/curl", "LOW", "Download utility present"),
    ("/root/.ssh", "HIGH", "SSH keys in root home directory"),
    ("/etc/ssh/ssh_host", "HIGH", "SSH host key exposed in image"),
    ("/var/run/docker.sock", "CRITICAL", "Docker socket mounted — container escape risk"),
    ("/.git", "MEDIUM", "Git repository inside container — source code exposure"),
    ("/tmp/", "LOW", "Files in /tmp may indicate temp payload staging"),
]

SUSPICIOUS_EXTENSIONS = {
    ".sh": ("MEDIUM", "Shell script"),
    ".bash": ("MEDIUM", "Bash script"),
    ".py": ("LOW", "Python script"),
    ".pl": ("MEDIUM", "Perl script"),
    ".rb": ("LOW", "Ruby script"),
    ".php": ("MEDIUM", "PHP script"),
    ".elf": ("HIGH", "ELF binary"),
}

# ── Misconfiguration Checks ───────────────────────────────────────────────────
SENSITIVE_FILES = {
    "/etc/passwd": "Passwd file present — check for suspicious users",
    "/etc/shadow": "Shadow password file exposed",
    "/etc/sudoers": "Sudoers file present — privilege escalation risk",
    "/root/.bash_history": "Root bash history exposed — command history visible",
    "/root/.aws/credentials": "AWS credentials file in root home",
    "/.env": "Dotenv file with potential secrets at filesystem root",
    "/app/.env": "Dotenv file in application directory",
}


def analyze_threats(layers: list[dict], image_metadata: dict) -> dict:
    """
    Run threat intelligence analysis across all layers.

    Args:
        layers: list of extracted layer dicts.
        image_metadata: image pull metadata dict.

    Returns:
        dict with threats categorized by type.
    """
    console.print(f"\n[bold cyan]🔎 Running Threat Intelligence Analysis...[/bold cyan]")

    secrets = []
    suspicious_files = []
    misconfigurations = []

    for layer in layers:
        layer_idx = layer["layer_index"]
        layer_id = layer.get("layer_id", "")

        for f in layer["files"]:
            path = f["path"]

            # ── Secret detection ────────────────────────────────────────────
            content = f.get("content_preview", "")
            if content:
                for pattern_def in SECRET_PATTERNS:
                    matches = re.findall(pattern_def["pattern"], content)
                    if matches:
                        secrets.append({
                            "type": "secret",
                            "name": pattern_def["name"],
                            "severity": pattern_def["severity"],
                            "file_path": path,
                            "layer_index": layer_idx,
                            "layer_id": layer_id,
                            "layer_command": layer.get("command", ""),
                            "match_count": len(matches),
                            "preview": _sanitize_preview(str(matches[0])),
                            "description": f"Hardcoded {pattern_def['name']} found in {path}",
                            "remediation": "Remove secrets from image. Use environment variables or a secrets manager.",
                        })

            # ── Sensitive file presence ─────────────────────────────────────
            for sensitive_path, note in SENSITIVE_FILES.items():
                if path == sensitive_path or path.startswith(sensitive_path):
                    misconfigurations.append({
                        "type": "sensitive_file",
                        "name": f"Sensitive File: {os.path.basename(path)}",
                        "severity": "HIGH",
                        "file_path": path,
                        "layer_index": layer_idx,
                        "layer_id": layer_id,
                        "layer_command": layer.get("command", ""),
                        "description": note,
                        "remediation": "Remove sensitive files from the container image.",
                    })

            # ── Suspicious path checks ──────────────────────────────────────
            for sp, severity, note in SUSPICIOUS_PATHS:
                if path.startswith(sp):
                    suspicious_files.append({
                        "type": "suspicious_artifact",
                        "name": f"Suspicious path: {path}",
                        "severity": severity,
                        "file_path": path,
                        "layer_index": layer_idx,
                        "layer_id": layer_id,
                        "layer_command": layer.get("command", ""),
                        "description": note,
                        "remediation": f"Review necessity of {path} in container image.",
                    })

            # ── SUID/SGID binaries ──────────────────────────────────────────
            if f.get("is_suid") and f.get("type") == "file":
                misconfigurations.append({
                    "type": "suid_binary",
                    "name": f"SUID Binary: {os.path.basename(path)}",
                    "severity": "HIGH",
                    "file_path": path,
                    "layer_index": layer_idx,
                    "layer_id": layer_id,
                    "layer_command": layer.get("command", ""),
                    "description": f"SUID bit set on {path} — privilege escalation risk.",
                    "remediation": "Remove SUID bit unless absolutely required: chmod u-s <file>",
                })

            # ── World-writable files ────────────────────────────────────────
            if f.get("is_world_writable") and f.get("type") == "file":
                misconfigurations.append({
                    "type": "world_writable",
                    "name": f"World-Writable: {os.path.basename(path)}",
                    "severity": "MEDIUM",
                    "file_path": path,
                    "layer_index": layer_idx,
                    "layer_id": layer_id,
                    "layer_command": layer.get("command", ""),
                    "description": f"World-writable file {path} — data tampering risk.",
                    "remediation": "Fix permissions: chmod o-w <file>",
                })

    # ── Image-level misconfiguration checks ───────────────────────────────────
    config = image_metadata.get("config", {})

    if config.get("user") in ("", "root", "0"):
        misconfigurations.append({
            "type": "runs_as_root",
            "name": "Container runs as root",
            "severity": "HIGH",
            "file_path": "Dockerfile / image config",
            "layer_index": -1,
            "layer_id": "image-config",
            "layer_command": "USER directive missing",
            "description": "Container is configured to run as root user.",
            "remediation": "Add 'USER nonroot' in Dockerfile before CMD/ENTRYPOINT.",
        })

    env_vars = config.get("env", [])
    for env in env_vars:
        for pattern_def in SECRET_PATTERNS[:4]:
            if re.search(pattern_def["pattern"], env):
                secrets.append({
                    "type": "env_secret",
                    "name": f"Secret in ENV: {pattern_def['name']}",
                    "severity": pattern_def["severity"],
                    "file_path": "ENV variable (image config)",
                    "layer_index": -1,
                    "layer_id": "image-config",
                    "layer_command": "ENV directive",
                    "match_count": 1,
                    "preview": _sanitize_preview(env[:60]),
                    "description": f"Possible secret detected in environment variable.",
                    "remediation": "Remove secrets from ENV. Inject at runtime via orchestrator secrets.",
                })

    all_threats = secrets + suspicious_files + misconfigurations
    summary = _threat_summary(all_threats)

    console.print(
        f"  [yellow]⚠  Secrets:[/yellow] {len(secrets)}  "
        f"[orange3]Suspicious:[/orange3] {len(suspicious_files)}  "
        f"[red]Misconfigs:[/red] {len(misconfigurations)}"
    )

    return {
        "threats": all_threats,
        "secrets": secrets,
        "suspicious_files": suspicious_files,
        "misconfigurations": misconfigurations,
        "summary": summary,
        "total_count": len(all_threats),
    }


def _threat_summary(threats: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        sev = t.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _sanitize_preview(value: str) -> str:
    """Mask the middle portion of a secret for safe display."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]
