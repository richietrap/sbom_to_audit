"""Fail-closed validation and parser dispatch for committed source artefacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.parsers.asset_context_parser import parse_asset_context
from sbom_to_audit.parsers.csaf_parser import parse_csaf
from sbom_to_audit.parsers.cyclonedx_parser import parse_cyclonedx
from sbom_to_audit.parsers.epss_client import extract_percentile
from sbom_to_audit.parsers.kev_client import kev_entry
from sbom_to_audit.parsers.osv_client import cve_aliases
from sbom_to_audit.parsers.telemetry_parser import parse_telemetry
from sbom_to_audit.utils.io import read_json, read_yaml

ARTIFACT_MEDIA_TYPES: dict[str, str] = {
    "cyclonedx_sbom": "application/vnd.cyclonedx+json",
    "csaf_vex": "application/csaf+json",
    "osv_snapshot": "application/json",
    "kev_snapshot": "application/json",
    "epss_snapshot": "application/json",
    "runtime_telemetry": "application/x-ndjson",
    "asset_context": "application/yaml",
    "mitigation_context": "application/yaml",
    "conflict_resolution": "application/yaml",
    "human_authorization": "application/yaml",
    "milestone_satisfaction": "application/yaml",
}


def _require_object(path: Path) -> dict[str, Any]:
    value = read_yaml(path) if path.suffix.lower() in {".yaml", ".yml"} else read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def validate_and_parse(
    path: Path,
    artifact_type: str,
    *,
    target_cve: str | None = None,
) -> tuple[str, str, dict[str, Any] | list[dict[str, Any]], dict[str, Any]]:
    """Validate one artefact and return media type, parser, data, and details."""

    if artifact_type not in ARTIFACT_MEDIA_TYPES:
        raise ValueError(f"unsupported artifact_type: {artifact_type!r}")

    if artifact_type == "cyclonedx_sbom":
        data = parse_cyclonedx(path)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "parse_cyclonedx",
            data,
            {
                "spec_version": data.get("spec_version"),
                "component_count": len(data.get("components") or []),
            },
        )
    if artifact_type == "csaf_vex":
        data = parse_csaf(path)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "parse_csaf",
            data,
            {
                "document_tracking_id": data.get("document_tracking_id"),
                "vulnerability_count": len(data.get("vulnerabilities") or []),
            },
        )
    if artifact_type == "osv_snapshot":
        data = _require_object(path)
        aliases = cve_aliases(data)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "read_json+cve_aliases",
            data,
            {
                "cve_aliases": aliases,
            },
        )
    if artifact_type == "kev_snapshot":
        data = _require_object(path)
        entry = kev_entry(data, target_cve) if target_cve else None
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "read_json+kev_entry",
            data,
            {
                "target_entry_found": entry is not None,
                "catalog_version": data.get("catalogVersion"),
            },
        )
    if artifact_type == "epss_snapshot":
        data = _require_object(path)
        percentile = extract_percentile(data)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "read_json+extract_percentile",
            data,
            {
                "percentile": percentile,
            },
        )
    if artifact_type == "runtime_telemetry":
        telemetry_data = parse_telemetry(path)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "parse_telemetry",
            telemetry_data,
            {
                "record_count": len(telemetry_data),
            },
        )
    if artifact_type in {"asset_context", "mitigation_context"}:
        context_data = parse_asset_context(path)
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "parse_asset_context",
            context_data,
            {
                "field_count": len(context_data),
            },
        )

    event_data = _require_object(path)
    declared_type = str(event_data.get("event_type") or "")
    if declared_type and declared_type != artifact_type:
        raise ValueError(
            f"{path} declares event_type={declared_type!r}, expected {artifact_type!r}"
        )
    return (
        ARTIFACT_MEDIA_TYPES[artifact_type],
        "read_yaml",
        event_data,
        {
            "event_type": declared_type or artifact_type,
        },
    )
