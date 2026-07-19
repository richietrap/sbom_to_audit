"""OSV client using ecosystem coordinates or versioned PURLs as the primary bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from sbom_to_audit.utils.io import read_json, write_json

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv(
    *,
    purl: str | None = None,
    ecosystem: str | None = None,
    name: str | None = None,
    version: str | None = None,
    snapshot_path: str | Path | None = None,
    offline: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    if offline:
        if snapshot_path is None or not Path(snapshot_path).exists():
            raise FileNotFoundError("offline OSV query requires an existing snapshot_path")
        return read_json(snapshot_path)

    if purl:
        payload: dict[str, Any] = {"package": {"purl": purl}}
    elif ecosystem and name:
        payload = {"package": {"ecosystem": ecosystem, "name": name}}
        if version:
            payload["version"] = version
    else:
        raise ValueError("provide a versioned purl or ecosystem and name coordinates")

    response = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if snapshot_path is not None:
        write_json(snapshot_path, data)
    return data


def cve_aliases(osv_response: dict[str, Any]) -> list[str]:
    aliases = set()
    for vulnerability in osv_response.get("vulns", []):
        for value in vulnerability.get("aliases", []):
            if isinstance(value, str) and value.startswith("CVE-"):
                aliases.add(value)
    return sorted(aliases)
