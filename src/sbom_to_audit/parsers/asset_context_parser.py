"""Parser for JSON or YAML asset-context records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_json, read_yaml


def parse_asset_context(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if source.suffix.lower() == ".json":
        data = read_json(source)
    elif source.suffix.lower() in {".yaml", ".yml"}:
        data = read_yaml(source)
    else:
        raise ValueError("asset context must be JSON or YAML")
    if not isinstance(data, dict):
        raise ValueError("asset context must be an object")
    return data
