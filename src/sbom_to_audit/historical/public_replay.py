"""Deterministic public-evidence-only historical replay.

This module intentionally does not construct an EvidencePack. Public reporting cannot
establish organisation-local reachability, impact, telemetry, authorization, submission,
or legal applicability, so those dimensions are recorded as unavailable instead of being
fabricated.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from sbom_to_audit.historical.epss_verification import expected_record
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_json, read_yaml
from sbom_to_audit.utils.time import delta_hours, parse_timestamp


def _load_object(path: Path) -> dict[str, Any]:
    value = read_yaml(path) if path.suffix.lower() in {".yaml", ".yml"} else read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _confined(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"historical source path escapes repository root: {relative_path}"
        ) from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"historical source not found: {relative_path}")
    return candidate


def _source_manifest(
    repository_root: Path, registry: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    target_cve = str(registry.get("cve_id") or "").strip()
    entries = registry.get("sources") or []
    if not target_cve or not isinstance(entries, list) or not entries:
        raise ValueError("historical registry requires cve_id and a non-empty sources list")
    manifest: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("historical source entry must be an object")
        source_id = str(item.get("source_id") or "").strip()
        relative_path = str(item.get("path") or "").strip()
        if not source_id or not relative_path:
            raise ValueError("historical source requires source_id and path")
        if source_id in by_id:
            raise ValueError(f"duplicate historical source_id: {source_id}")
        source_path = _confined(repository_root, relative_path)
        extract = _load_object(source_path)
        if str(extract.get("cve_id") or "") != target_cve:
            raise ValueError(f"{relative_path} does not match target CVE {target_cve}")
        observed_at = str(item.get("observed_at") or "")
        published_at = str(item.get("published_at") or "")
        available_at = str(item.get("available_at") or "")
        if not all((observed_at, published_at, available_at)):
            raise ValueError(f"{source_id} requires observed_at, published_at, and available_at")
        observed = parse_timestamp(observed_at)
        published = parse_timestamp(published_at)
        available = parse_timestamp(available_at)
        if observed > published:
            raise ValueError(f"{source_id}: observed_at must not follow published_at")
        if available < published:
            raise ValueError(f"{source_id}: available_at must not precede published_at")
        source_urls = item.get("source_urls") or []
        if not isinstance(source_urls, list) or not source_urls:
            raise ValueError(f"{source_id}: source_urls must be non-empty")
        normalized = {
            "source_id": source_id,
            "kind": str(item.get("kind") or ""),
            "publisher": str(item.get("publisher") or ""),
            "relative_path": relative_path,
            "source_hash": sha256_file(source_path),
            "size_bytes": source_path.stat().st_size,
            "observed_at": observed_at,
            "published_at": published_at,
            "available_at": available_at,
            "publication_lag_hours": delta_hours(observed_at, published_at),
            "publication_precision": str(item.get("publication_precision") or ""),
            "verification_status": str(item.get("verification_status") or "unverified"),
            "source_urls": sorted(str(url) for url in source_urls),
            "validation_status": "valid",
        }
        manifest.append(normalized)
        by_id[source_id] = {**normalized, "extract": extract}
    manifest.sort(key=lambda item: item["source_id"])
    return manifest, by_id


def _validate_online_epss_report(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    report_path = Path(path).resolve()
    if not report_path.is_file():
        raise FileNotFoundError(f"historical EPSS verification report not found: {report_path}")
    value = read_json(report_path)
    if not isinstance(value, dict):
        raise ValueError("historical EPSS verification report must contain an object")
    expected = expected_record()
    if value.get("status") != "authoritative_dual_source_verified":
        raise ValueError("historical EPSS report is not authoritatively verified")
    checks = value.get("checks")
    if not isinstance(checks, dict) or not checks or not all(checks.values()):
        raise ValueError("historical EPSS report contains failed or missing checks")
    for record_name in ("api_record", "archive_record"):
        record = value.get(record_name)
        if not isinstance(record, dict):
            raise ValueError(f"historical EPSS report lacks {record_name}")
        for key in ("cve", "date", "epss", "percentile"):
            if str(record.get(key)) != str(getattr(expected, key)):
                raise ValueError(f"historical EPSS {record_name} {key} mismatch")
    archive = value["archive_record"]
    if archive.get("model_version") != expected.model_version:
        raise ValueError("historical EPSS archive model version mismatch")
    for field in ("api_sha256", "archive_sha256", "extracted_row_sha256"):
        digest = str(value.get(field) or "")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"historical EPSS report has invalid {field}")
    return value


def run_public_historical_replay(
    repository_root: str | Path,
    *,
    registry_path: str | Path = "data/historical_replays/cve_2024_3400/public_source_registry.yaml",
    chronology_path: str | Path = "data/historical_replays/cve_2024_3400/chronology.yaml",
    epss_verification_report_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate and replay public evidence without creating local facts."""

    root = Path(repository_root).resolve()
    online_epss_report = _validate_online_epss_report(epss_verification_report_path)
    registry_file = _confined(root, str(registry_path))
    chronology_file = _confined(root, str(chronology_path))
    registry = _load_object(registry_file)
    chronology = _load_object(chronology_file)
    if registry.get("replay_id") != chronology.get("replay_id"):
        raise ValueError("historical registry and chronology replay_id differ")
    if registry.get("cve_id") != chronology.get("cve_id"):
        raise ValueError("historical registry and chronology cve_id differ")

    manifest, by_id = _source_manifest(root, registry)
    known_ids = set(by_id)
    released: set[str] = set()
    rows: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    previous_timestamp = None
    for event in chronology.get("events") or []:
        if not isinstance(event, dict):
            raise ValueError("historical chronology event must be an object")
        event_id = str(event.get("event_id") or "").strip()
        timestamp = str(event.get("timestamp") or "").strip()
        event_time = parse_timestamp(timestamp)
        if previous_timestamp is not None and event_time < previous_timestamp:
            raise ValueError("historical chronology events must be time-ordered")
        previous_timestamp = event_time
        new_ids = {str(item) for item in (event.get("release_source_ids") or [])}
        unknown = sorted(new_ids - known_ids)
        if unknown:
            raise ValueError(f"{event_id} releases unknown historical sources: {unknown}")
        for source_id in new_ids:
            if event_time < parse_timestamp(by_id[source_id]["available_at"]):
                raise ValueError(
                    f"temporal leakage: {event_id} releases {source_id} before available_at"
                )
        released.update(new_ids)
        active = [by_id[source_id] for source_id in sorted(released)]
        facts = [item["extract"].get("facts") or {} for item in active]
        public_exploitation_known = any(
            bool(fact.get("malicious_exploitation_observed")) for fact in facts
        )
        kev_known = any(item["kind"] == "kev_record" for item in active)
        hotfix_known = any(item["kind"] == "vendor_update" for item in active)
        epss_items = [item for item in active if item["kind"] == "epss_snapshot"]
        provisional = sorted(
            item["source_id"]
            for item in active
            if item["verification_status"].startswith("provisional")
        )
        new_source_ids = sorted(new_ids)
        available_source_ids = sorted(released)
        snapshot = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_class": str(event.get("event_class") or ""),
            "description": str(event.get("description") or ""),
            "new_source_ids": new_source_ids,
            "available_source_ids": available_source_ids,
            "public_exploitation_known": public_exploitation_known,
            "kev_known": kev_known,
            "hotfix_known": hotfix_known,
            "epss_known": bool(epss_items),
            "provisional_source_ids": provisional,
        }
        snapshots.append(snapshot)
        rows.append(
            {
                **snapshot,
                "new_source_ids": ";".join(new_source_ids),
                "available_source_ids": ";".join(available_source_ids),
                "provisional_source_ids": ";".join(provisional),
                "available_source_count": len(released),
            }
        )

    unreleased = sorted(known_ids - released)
    if unreleased:
        raise ValueError(f"historical sources are never released: {unreleased}")
    provisional_all = sorted(
        item["source_id"]
        for item in by_id.values()
        if item["verification_status"].startswith("provisional")
    )
    epss_contract_sources = sorted(
        item["source_id"]
        for item in by_id.values()
        if item["kind"] == "epss_snapshot"
        and item["verification_status"] == "authoritative_dual_source_verification_contract"
    )
    verification_contract_path = _confined(
        root,
        "data/historical_replays/cve_2024_3400/epss/verification_manifest.json",
    )
    boundaries = {
        "full_evidencepack_generated": False,
        "organisation_local_reachability": "unavailable",
        "organisation_local_execution": "unavailable",
        "organisation_local_impact": "unavailable",
        "organisation_local_mitigation": "unavailable",
        "human_authorization": "unavailable",
        "submission_evidence": "unavailable",
        "legal_applicability": "not_determined",
        "reason": "Public sources cannot establish organisation-local facts.",
    }
    source_manifest = {
        "registry_version": str(registry.get("registry_version") or "0.1"),
        "replay_id": registry["replay_id"],
        "classification": registry.get("classification"),
        "cve_id": registry["cve_id"],
        "source_count": len(manifest),
        "sources": manifest,
    }
    bundle = {
        "replay_version": "0.1",
        "replay_id": registry["replay_id"],
        "classification": "HISTORICAL_PUBLIC_REPLAY",
        "cve_id": registry["cve_id"],
        "source_manifest_hash": sha256_json(source_manifest),
        "chronology_hash": sha256_file(chronology_file),
        "source_manifest": source_manifest,
        "timeline": deepcopy(snapshots),
        "evidence_boundaries": boundaries,
        "provisional_source_ids": provisional_all,
        "epss_verification_contract_source_ids": epss_contract_sources,
        "historical_epss_verification": {
            "status": (
                "authoritative_dual_source_verified"
                if online_epss_report is not None
                else "verification_contract_valid_online_gate_required"
            ),
            "verification_contract_hash": sha256_file(verification_contract_path),
            "online_report_hash": (
                sha256_file(Path(epss_verification_report_path).resolve())
                if online_epss_report is not None and epss_verification_report_path is not None
                else None
            ),
            "acceptance_gate": "GitHub online quality gate plus isolated Colab online verification",
        },
        "evaluation_status": (
            "PILOT_VERIFIED_NOT_FROZEN"
            if online_epss_report is not None
            else "PILOT_VERIFICATION_CANDIDATE"
        ),
        "manuscript_eligibility": online_epss_report is not None,
        "eligibility_blockers": (
            []
            if online_epss_report is not None
            else [
                "The required authoritative online EPSS verification report was not supplied "
                "to this replay."
            ]
        ),
    }
    return {"bundle": bundle, "timeline_rows": rows, "source_manifest": source_manifest}
