"""CISA Known Exploited Vulnerabilities catalog client."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from sbom_to_audit.utils.io import read_json, write_json

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev_catalog(
    *,
    snapshot_path: str | Path | None = None,
    offline: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    if offline:
        if snapshot_path is None or not Path(snapshot_path).exists():
            raise FileNotFoundError("offline KEV lookup requires an existing snapshot_path")
        return read_json(snapshot_path)
    response = requests.get(CISA_KEV_URL, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if snapshot_path is not None:
        write_json(snapshot_path, data)
    return data


def kev_entry(catalog: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    for item in catalog.get("vulnerabilities", []):
        if item.get("cveID") == cve_id:
            return item
    return None
