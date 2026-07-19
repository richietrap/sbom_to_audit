"""Minimal CycloneDX JSON parser for component identity extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_json


def parse_cyclonedx(path: str | Path) -> dict[str, Any]:
    document = read_json(path)
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("input is not a CycloneDX JSON document")

    components = []
    for component in document.get("components", []):
        components.append(
            {
                "bom_ref": component.get("bom-ref"),
                "type": component.get("type"),
                "group": component.get("group"),
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "cpe": component.get("cpe"),
            }
        )

    metadata_component = (document.get("metadata") or {}).get("component") or {}
    return {
        "serial_number": document.get("serialNumber"),
        "spec_version": document.get("specVersion"),
        "metadata_component": metadata_component,
        "components": components,
    }
