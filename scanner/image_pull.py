"""
image_pull.py — Image Acquisition Module
=========================================
Pulls Docker container images from local cache or Docker Hub.
Provides metadata extraction and validation utilities.
"""

import docker
import json
import sys
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console(stderr=True)


def get_docker_client():
    """
    Initialize and return a Docker SDK client.
    Raises a clear error if Docker daemon is not running.
    """
    try:
        client = docker.from_env()
        client.ping()
        return client
    except docker.errors.DockerException as e:
        console.print(
            Panel(
                f"[bold red]Docker daemon is not reachable.[/bold red]\n"
                f"Ensure Docker is installed and running.\n\nDetail: {e}",
                title="[red]Connection Error[/red]",
                border_style="red",
            )
        )
        sys.exit(1)


def pull_image(image_name: str) -> dict:
    """
    Pull a Docker image by name (e.g., 'nginx:latest') and return metadata.

    Args:
        image_name: Docker image name with optional tag (e.g., 'nginx:latest')

    Returns:
        dict: Image metadata including ID, tags, size, and layer count.
    """
    client = get_docker_client()

    # Normalize: add :latest if no tag provided
    if ":" not in image_name:
        image_name = f"{image_name}:latest"

    console.print(f"\n[bold cyan]🔍 Acquiring image:[/bold cyan] [yellow]{image_name}[/yellow]")

    # Check if image already exists locally
    try:
        image = client.images.get(image_name)
        console.print(f"  [green]✔ Found locally[/green] — skipping pull.")
    except docker.errors.ImageNotFound:
        console.print(f"  [dim]Not found locally. Pulling from Docker Hub...[/dim]")
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                task = progress.add_task(f"Pulling {image_name}...", total=None)
                image = client.images.pull(image_name)
                progress.update(task, completed=True)
            console.print(f"  [green]✔ Pull complete.[/green]")
        except docker.errors.NotFound:
            console.print(f"[red]✘ Image '{image_name}' not found on Docker Hub.[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]✘ Pull failed: {e}[/red]")
            sys.exit(1)

    # Extract image metadata
    image_info = client.images.get(image_name)
    attrs = image_info.attrs

    metadata = {
        "image_name": image_name,
        "image_id": attrs.get("Id", "")[:19],          # short ID
        "full_id": attrs.get("Id", ""),
        "tags": attrs.get("RepoTags", []),
        "created": attrs.get("Created", ""),
        "size_bytes": attrs.get("Size", 0),
        "size_mb": round(attrs.get("Size", 0) / (1024 * 1024), 2),
        "architecture": attrs.get("Architecture", ""),
        "os": attrs.get("Os", ""),
        "layer_count": len(attrs.get("RootFS", {}).get("Layers", [])),
        "layer_digests": attrs.get("RootFS", {}).get("Layers", []),
        "docker_version": attrs.get("DockerVersion", ""),
        "author": attrs.get("Author", ""),
        "config": {
            "cmd": attrs.get("Config", {}).get("Cmd", []),
            "entrypoint": attrs.get("Config", {}).get("Entrypoint", []),
            "env": attrs.get("Config", {}).get("Env", []),
            "exposed_ports": list(attrs.get("Config", {}).get("ExposedPorts", {}).keys()),
            "user": attrs.get("Config", {}).get("User", "root"),
            "working_dir": attrs.get("Config", {}).get("WorkingDir", "/"),
            "labels": attrs.get("Config", {}).get("Labels", {}),
        },
        "history": _extract_history(attrs),
    }

    _print_image_summary(metadata)
    return metadata


def _extract_history(attrs: dict) -> list:
    """
    Extract the Dockerfile instruction history from image attributes.

    Returns:
        list of dicts with layer creation commands.
    """
    history = []
    raw_history = attrs.get("History", [])
    for idx, entry in enumerate(raw_history):
        history.append({
            "layer_index": idx,
            "created": entry.get("created", ""),
            "created_by": entry.get("created_by", "").strip(),
            "comment": entry.get("comment", ""),
            "empty_layer": entry.get("empty_layer", False),
        })
    return history


def _print_image_summary(metadata: dict):
    """Print a rich-formatted image summary to the terminal."""
    lines = [
        f"[bold]Image:[/bold]        {metadata['image_name']}",
        f"[bold]ID:[/bold]           {metadata['image_id']}",
        f"[bold]OS:[/bold]           {metadata['os']} / {metadata['architecture']}",
        f"[bold]Size:[/bold]         {metadata['size_mb']} MB",
        f"[bold]Layers:[/bold]       {metadata['layer_count']}",
        f"[bold]User:[/bold]         [{'red' if metadata['config']['user'] in ('root', '', '0') else 'green'}]{metadata['config']['user'] or 'root'}[/]",
        f"[bold]Exposed Ports:[/bold] {', '.join(metadata['config']['exposed_ports']) or 'None'}",
    ]
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold green]📦 Image Metadata[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


def save_image_tar(image_name: str, output_path: str) -> str:
    """
    Export a Docker image as a .tar archive for offline layer extraction.

    Args:
        image_name: Docker image name/tag.
        output_path: Path where the .tar file will be saved.

    Returns:
        str: Path to saved tar file.
    """
    client = get_docker_client()
    image = client.images.get(image_name)

    console.print(f"[dim]Exporting image to tar: {output_path}[/dim]")
    with open(output_path, "wb") as f:
        for chunk in image.save(named=True):
            f.write(chunk)

    console.print(f"[green]✔ Image exported:[/green] {output_path}")
    return output_path


if __name__ == "__main__":
    # Quick test
    meta = pull_image("alpine:latest")
    print(json.dumps(meta, indent=2, default=str))
