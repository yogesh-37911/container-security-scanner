"""
package_enum.py — Package Enumerator & SBOM Generator
======================================================
Detects installed OS packages (apt/dpkg, apk, rpm/yum)
in each layer and generates a Software Bill of Materials (SBOM).
"""

import re
import json
import os
from rich.console import Console

console = Console(stderr=True)

# ── Package database paths per package manager ───────────────────────────────
DPKG_STATUS_PATHS = [
    "/var/lib/dpkg/status",
    "/var/lib/dpkg/status.d",
]
APK_INSTALLED_PATH = "/lib/apk/db/installed"
RPM_DB_PATHS = [
    "/var/lib/rpm/Packages",
    "/var/lib/rpm/rpmdb.sqlite",
]
PYTHON_DIST_DIRS = [
    "/usr/lib/python3/dist-packages",
    "/usr/local/lib",
]


def enumerate_packages(layers: list[dict]) -> dict:
    """
    Enumerate all packages across all layers and map each to its origin layer.

    Args:
        layers: list of layer dicts from layer_extractor.

    Returns:
        dict with:
          - packages: list of package dicts
          - sbom: structured Software Bill of Materials
          - by_layer: packages grouped by layer index
    """
    all_packages = []
    by_layer = {}

    # Build a cumulative filesystem view layer by layer
    # (later layers override earlier ones — union filesystem)
    cumulative_files: dict[str, dict] = {}

    for layer in layers:
        layer_idx = layer["layer_index"]
        by_layer[layer_idx] = []

        for f in layer["files"]:
            path = f["path"]
            if not f.get("is_whiteout"):
                cumulative_files[path] = {**f, "introduced_layer": layer_idx}
            else:
                # Whiteout = file deleted in this layer
                clean_path = path.replace("/.wh.", "/")
                cumulative_files.pop(clean_path, None)

        # After building cumulative FS up to this layer,
        # detect packages introduced by this specific layer
        layer_pkgs = _detect_packages_in_layer(layer)
        for pkg in layer_pkgs:
            pkg["layer_index"] = layer_idx
            pkg["layer_id"] = layer.get("layer_id", "")
            pkg["layer_command"] = layer.get("command", "")
        all_packages.extend(layer_pkgs)
        by_layer[layer_idx] = layer_pkgs

    # Deduplicate by (name, version) keeping earliest layer
    seen = {}
    deduped = []
    for pkg in all_packages:
        key = f"{pkg['name']}:{pkg['version']}"
        if key not in seen:
            seen[key] = True
            deduped.append(pkg)

    sbom = _generate_sbom(deduped)

    console.print(f"  [green]✔ Enumerated {len(deduped)} packages.[/green]")
    return {
        "packages": deduped,
        "sbom": sbom,
        "by_layer": by_layer,
        "total_count": len(deduped),
    }


def _detect_packages_in_layer(layer: dict) -> list[dict]:
    """
    Detect packages from the files present in a single layer.
    Checks for dpkg, apk, and rpm package databases.
    """
    packages = []
    file_map = {f["path"]: f for f in layer["files"]}

    # ── Debian/Ubuntu: dpkg ──────────────────────────────────────────────────
    for dpkg_path in DPKG_STATUS_PATHS:
        if dpkg_path in file_map:
            content = file_map[dpkg_path].get("content_preview", "")
            if content:
                packages.extend(_parse_dpkg_status(content))

    # ── Alpine: apk ──────────────────────────────────────────────────────────
    if APK_INSTALLED_PATH in file_map:
        content = file_map[APK_INSTALLED_PATH].get("content_preview", "")
        if content:
            packages.extend(_parse_apk_installed(content))

    # ── Python pip packages ──────────────────────────────────────────────────
    for f in layer["files"]:
        if f["path"].endswith("METADATA") and "dist-info" in f["path"]:
            content = f.get("content_preview", "")
            pkg = _parse_python_metadata(content, f["path"])
            if pkg:
                packages.append(pkg)
        elif f["path"].endswith("PKG-INFO"):
            content = f.get("content_preview", "")
            pkg = _parse_python_metadata(content, f["path"])
            if pkg:
                packages.append(pkg)

    return packages


def _parse_dpkg_status(content: str) -> list[dict]:
    """Parse /var/lib/dpkg/status content into package list."""
    packages = []
    current = {}

    for line in content.splitlines():
        if line.startswith("Package:"):
            if current.get("name"):
                packages.append(current)
            current = {"type": "deb", "name": line.split(":", 1)[1].strip()}
        elif line.startswith("Version:"):
            current["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Architecture:"):
            current["arch"] = line.split(":", 1)[1].strip()
        elif line.startswith("Description:"):
            current["description"] = line.split(":", 1)[1].strip()
        elif line.startswith("Status:"):
            current["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("Homepage:"):
            current["homepage"] = line.split(":", 1)[1].strip()
        elif line == "" and current.get("name"):
            if "installed" in current.get("status", ""):
                packages.append({
                    "name": current.get("name", ""),
                    "version": current.get("version", "unknown"),
                    "arch": current.get("arch", ""),
                    "description": current.get("description", ""),
                    "type": "deb",
                    "ecosystem": "debian",
                })
            current = {}

    return packages


def _parse_apk_installed(content: str) -> list[dict]:
    """Parse Alpine /lib/apk/db/installed content."""
    packages = []
    current = {}

    for line in content.splitlines():
        if line.startswith("P:"):
            current["name"] = line[2:].strip()
        elif line.startswith("V:"):
            current["version"] = line[2:].strip()
        elif line.startswith("T:"):
            current["description"] = line[2:].strip()
        elif line.startswith("A:"):
            current["arch"] = line[2:].strip()
        elif line == "" and current.get("name"):
            packages.append({
                "name": current.get("name", ""),
                "version": current.get("version", "unknown"),
                "arch": current.get("arch", ""),
                "description": current.get("description", ""),
                "type": "apk",
                "ecosystem": "alpine",
            })
            current = {}

    return packages


def _parse_python_metadata(content: str, path: str) -> dict | None:
    """Parse Python package METADATA or PKG-INFO files."""
    if not content:
        return None

    name, version, description = "", "unknown", ""
    for line in content.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Summary:"):
            description = line.split(":", 1)[1].strip()

    if name:
        return {
            "name": name,
            "version": version,
            "description": description,
            "type": "python",
            "ecosystem": "pypi",
            "path": path,
        }
    return None


def _generate_sbom(packages: list[dict]) -> dict:
    """
    Generate a CycloneDX-style Software Bill of Materials (SBOM).

    Returns:
        dict representing the SBOM in structured format.
    """
    components = []
    for pkg in packages:
        components.append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg.get("version", "unknown"),
            "purl": _build_purl(pkg),
            "ecosystem": pkg.get("ecosystem", "unknown"),
            "layer_index": pkg.get("layer_index", -1),
            "layer_id": pkg.get("layer_id", ""),
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [{"name": "ContainerSecurityScanner", "version": "1.0.0"}],
        },
        "components": components,
    }


def _build_purl(pkg: dict) -> str:
    """Build a Package URL (purl) string."""
    ecosystem_map = {
        "debian": "deb",
        "alpine": "apk",
        "pypi": "pypi",
        "rpm": "rpm",
    }
    eco = ecosystem_map.get(pkg.get("ecosystem", ""), "generic")
    name = pkg.get("name", "unknown")
    version = pkg.get("version", "unknown")
    return f"pkg:{eco}/{name}@{version}"


def _timestamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
