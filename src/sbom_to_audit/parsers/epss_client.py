"""FIRST EPSS API client with deterministic snapshot support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from sbom_to_audit.utils.io import read_json, write_json

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def query_epss(
    cve_id: str,
    *,
    snapshot_path: str | Path | None = None,
    offline: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    if offline:
        if snapshot_path is None or not Path(snapshot_path).exists():
            raise FileNotFoundError("offline EPSS query requires an existing snapshot_path")
        return read_json(snapshot_path)
    response = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if snapshot_path is not None:
        write_json(snapshot_path, data)
    return data


def extract_percentile(response: dict[str, Any]) -> float | None:
    records = response.get("data") or []
    if not records:
        return None
    value = records[0].get("percentile")
    return float(value) if value is not None else None
