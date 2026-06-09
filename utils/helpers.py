"""
utils/helpers.py — Shared Utilities
"""

import os
import json
from datetime import datetime, timezone


def timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    return path


def save_json(data: dict, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def severity_sort_key(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)
