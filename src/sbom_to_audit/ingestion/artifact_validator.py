"""Fail-closed validation and parser dispatch for committed source artefacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.model.identity import identity_confidence
from sbom_to_audit.parsers.asset_context_parser import parse_asset_context
from sbom_to_audit.parsers.csaf_parser import parse_csaf
from sbom_to_audit.parsers.cyclonedx_parser import parse_cyclonedx
from sbom_to_audit.parsers.epss_client import extract_percentile
from sbom_to_audit.parsers.kev_client import kev_entry
from sbom_to_audit.parsers.nvd_client import extract_cvss_metrics
from sbom_to_audit.parsers.osv_client import cve_aliases
from sbom_to_audit.parsers.telemetry_parser import parse_telemetry
from sbom_to_audit.utils.io import read_json, read_yaml
from sbom_to_audit.utils.time import parse_timestamp

ARTIFACT_MEDIA_TYPES: dict[str, str] = {
    "cyclonedx_sbom": "application/vnd.cyclonedx+json",
    "csaf_vex": "application/csaf+json",
    "osv_snapshot": "application/json",
    "nvd_snapshot": "application/json",
    "kev_snapshot": "application/json",
    "epss_snapshot": "application/json",
    "runtime_telemetry": "application/x-ndjson",
    "asset_context": "application/yaml",
    "mitigation_context": "application/yaml",
    "conflict_resolution": "application/yaml",
    "human_authorization": "application/yaml",
    "milestone_satisfaction": "application/yaml",
    "identity_resolution": "application/yaml",
    "public_exploitation_report": "application/yaml",
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
    if artifact_type == "nvd_snapshot":
        data = _require_object(path)
        metrics = extract_cvss_metrics(data, target_cve) if target_cve else None
        if target_cve and metrics is None:
            raise ValueError(f"{path} does not contain CVSS metrics for {target_cve}")
        return (
            ARTIFACT_MEDIA_TYPES[artifact_type],
            "read_json+extract_cvss_metrics",
            data,
            {
                "target_metrics_found": metrics is not None,
                "base_score": metrics.get("base_score") if metrics else None,
                "base_severity": metrics.get("base_severity") if metrics else None,
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
    if artifact_type == "public_exploitation_report":
        required = {
            "event_type",
            "cve_id",
            "observed_at",
            "published_at",
            "publisher",
            "malicious_exploitation_observed",
            "source_urls",
        }
        missing = sorted(required - set(event_data))
        if missing:
            raise ValueError(f"{path} public exploitation report is missing fields: {missing}")
        if target_cve and str(event_data.get("cve_id") or "") != target_cve:
            raise ValueError(f"{path} public exploitation report does not match {target_cve}")
        observed = parse_timestamp(str(event_data["observed_at"]))
        published = parse_timestamp(str(event_data["published_at"]))
        if observed > published:
            raise ValueError(f"{path} observed_at must not follow published_at")
        urls = event_data.get("source_urls")
        if not isinstance(urls, list) or not urls or not all(str(url).strip() for url in urls):
            raise ValueError(f"{path} source_urls must be a non-empty list")
        if event_data.get("local_telemetry") is not False:
            raise ValueError(f"{path} must explicitly declare local_telemetry=false")
    if artifact_type == "identity_resolution":
        required = {
            "component_bom_ref",
            "resolved_component_purl",
            "matching_method",
            "timestamp",
        }
        missing = sorted(required - set(event_data))
        if missing:
            raise ValueError(f"{path} identity resolution is missing fields: {missing}")
        method = str(event_data.get("matching_method") or "")
        identity_confidence(method)
        if (
            method == "exact_cpe_confirmed"
            and not str(event_data.get("confirmed_cpe") or "").strip()
        ):
            raise ValueError(f"{path} exact_cpe_confirmed requires confirmed_cpe")
    return (
        ARTIFACT_MEDIA_TYPES[artifact_type],
        "read_yaml",
        event_data,
        {
            "event_type": declared_type or artifact_type,
        },
    )
