"""
layer_extractor.py — Image Layer Extractor
===========================================
Extracts filesystem layers from Docker images and maps
each file to its originating layer.
"""

import os
import io
import json
import tarfile
import tempfile
import hashlib
import docker
from typing import Generator
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

console = Console(stderr=True)


def extract_image_layers(image_name: str) -> list[dict]:
    """
    Extract all filesystem layers from a Docker image.

    Each layer includes:
      - layer_index (int): position in the stack (0 = base)
      - layer_id (str): short digest
      - command (str): Dockerfile instruction that created it
      - files (list): files added/modified in this layer

    Args:
        image_name: Docker image name/tag.

    Returns:
        list of layer dicts.
    """
    client = docker.from_env()
    image = client.images.get(image_name)

    console.print(f"\n[bold cyan]🔬 Extracting layers from:[/bold cyan] {image_name}")

    # Export image as tar stream into memory
    raw_tar_bytes = b"".join(image.save(named=True))
    layers = _parse_image_tar(raw_tar_bytes, image.attrs)

    console.print(f"  [green]✔ Extracted {len(layers)} layers.[/green]\n")
    return layers


def _parse_image_tar(raw_bytes: bytes, attrs: dict) -> list[dict]:
    """
    Parse an in-memory Docker image tar archive.
    Returns structured layer data with per-file metadata.
    """
    layers = []
    history = attrs.get("History", [])
    root_layers = attrs.get("RootFS", {}).get("Layers", [])

    with tarfile.open(fileobj=io.BytesIO(raw_bytes)) as image_tar:
        # Read manifest.json to get layer order
        try:
            manifest_member = image_tar.getmember("manifest.json")
            manifest_data = json.loads(image_tar.extractfile(manifest_member).read())
            layer_paths = manifest_data[0].get("Layers", [])
        except KeyError:
            layer_paths = []

        layer_index = 0
        real_history = [h for h in history if not h.get("empty_layer", False)]

        with Progress(
            TextColumn("[cyan]  Analyzing[/cyan]"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} layers"),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("layers", total=max(len(layer_paths), 1))

            for lp in layer_paths:
                try:
                    layer_tar_member = image_tar.getmember(lp)
                    layer_tar_bytes = image_tar.extractfile(layer_tar_member).read()
                except KeyError:
                    progress.advance(task)
                    continue

                # Determine the Dockerfile command for this layer
                command = ""
                if layer_index < len(real_history):
                    command = real_history[layer_index].get("created_by", "")

                # Parse files inside this layer's tar
                files = _extract_layer_files(layer_tar_bytes)

                layer_digest = root_layers[layer_index] if layer_index < len(root_layers) else f"layer_{layer_index}"

                layers.append({
                    "layer_index": layer_index,
                    "layer_id": layer_digest[-12:],          # last 12 chars of digest
                    "full_digest": layer_digest,
                    "command": _clean_command(command),
                    "raw_command": command,
                    "file_count": len(files),
                    "files": files,
                })

                layer_index += 1
                progress.advance(task)

    return layers


def _extract_layer_files(layer_tar_bytes: bytes) -> list[dict]:
    """
    Extract per-file metadata from a single layer tar archive.

    Returns:
        list of file dicts with path, type, size, permissions, etc.
    """
    files = []
    try:
        with tarfile.open(fileobj=io.BytesIO(layer_tar_bytes)) as layer_tar:
            for member in layer_tar.getmembers():
                file_info = {
                    "path": "/" + member.name.lstrip("./"),
                    "type": _get_file_type(member),
                    "size": member.size,
                    "mode": oct(member.mode),
                    "uid": member.uid,
                    "gid": member.gid,
                    "uname": member.uname,
                    "gname": member.gname,
                    "mtime": member.mtime,
                    "is_executable": bool(member.mode & 0o111),
                    "is_suid": bool(member.mode & 0o4000),
                    "is_sgid": bool(member.mode & 0o2000),
                    "is_world_writable": bool(member.mode & 0o002),
                    "is_whiteout": member.name.startswith(".wh.") or "/.wh." in member.name,
                }

                # Try to get content of small text-like files for secret scanning
                if (
                    member.isfile()
                    and member.size > 0
                    and member.size < 512 * 1024  # max 512KB
                    and _looks_like_text(member.name)
                ):
                    try:
                        f = layer_tar.extractfile(member)
                        if f:
                            file_info["content_preview"] = f.read(4096).decode("utf-8", errors="ignore")
                    except Exception:
                        pass

                files.append(file_info)
    except Exception as e:
        console.print(f"  [dim red]Warning: Could not parse layer tar: {e}[/dim red]")

    return files


def _get_file_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    elif member.issym():
        return "symlink"
    elif member.islnk():
        return "hardlink"
    elif member.isfile():
        return "file"
    else:
        return "other"


def _looks_like_text(path: str) -> bool:
    """Heuristic: is this file likely text-readable?"""
    text_exts = {
        ".py", ".sh", ".bash", ".env", ".conf", ".cfg", ".ini",
        ".yaml", ".yml", ".json", ".xml", ".txt", ".md",
        ".properties", ".toml", ".js", ".ts", ".rb", ".php",
        ".dockerfile", ".Dockerfile", "", ".pem", ".key", ".crt",
    }
    _, ext = os.path.splitext(path)
    basename = os.path.basename(path)
    return ext.lower() in text_exts or basename in {
        "Dockerfile", ".env", "config", "credentials", "passwd", "shadow"
    }


def _clean_command(cmd: str) -> str:
    """Simplify raw Dockerfile RUN commands for display."""
    cmd = cmd.replace("/bin/sh -c #(nop) ", "").replace("/bin/sh -c ", "RUN ")
    if len(cmd) > 120:
        cmd = cmd[:117] + "..."
    return cmd.strip()


def get_layer_summary(layers: list[dict]) -> list[dict]:
    """
    Return a lightweight summary of layers (no file contents).
    Useful for reports and dashboards.
    """
    summary = []
    for layer in layers:
        summary.append({
            "layer_index": layer["layer_index"],
            "layer_id": layer["layer_id"],
            "command": layer["command"],
            "file_count": layer["file_count"],
            "executable_count": sum(1 for f in layer["files"] if f.get("is_executable")),
            "suid_count": sum(1 for f in layer["files"] if f.get("is_suid")),
            "world_writable_count": sum(1 for f in layer["files"] if f.get("is_world_writable")),
        })
    return summary
