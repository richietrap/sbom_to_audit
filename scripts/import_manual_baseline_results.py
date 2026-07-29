#!/usr/bin/env python3
"""Hash, validate, and normalize a completed Stage 6.1 manual baseline bundle."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from sbom_to_audit.baseline.evaluation_freeze import verify_freeze
from sbom_to_audit.baseline.evaluation_oracles import (
    load_clock_oracle,
    load_conflict_oracle,
    load_state_oracle,
    validate_oracle_coverage,
)
from sbom_to_audit.baseline.manual_results import normalize_manual_results
from sbom_to_audit.baseline.protocol import load_manual_protocol
from sbom_to_audit.baseline.worksheet_validation import validate_manual_bundle
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml, write_json

ROOT = Path(__file__).resolve().parents[1]


def _known_artifacts(scenarios: tuple[str, ...]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for scenario_id in scenarios:
        payload = read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
        if not isinstance(payload, dict):
            raise ValueError(f"scenario must contain an object: {scenario_id}")
        result[scenario_id] = {
            str(row["artifact_id"]) for row in payload.get("source_catalog") or []
        }
    return result


def _common_fields() -> list[str]:
    payload = read_yaml(ROOT / "evaluation" / "mappings" / "common_field_set_v0.1.yaml")
    if not isinstance(payload, dict) or not isinstance(payload.get("field_paths"), list):
        raise ValueError("common field mapping is invalid")
    return [str(value) for value in payload["field_paths"]]


def import_bundle(bundle: Path, destination: Path) -> dict[str, Path]:
    freeze_errors = verify_freeze(
        ROOT, ROOT / "evaluation" / "freeze" / "stage6_1_protocol_freeze.json"
    )
    if freeze_errors:
        raise ValueError(f"Stage 6.1 protocol freeze drifted: {freeze_errors}")
    protocol = load_manual_protocol(ROOT / "evaluation" / "baseline_protocol_v0.2.yaml")
    state = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    conflicts = load_conflict_oracle(ROOT / "evaluation" / "oracles" / "conflict_oracle_v0.1.yaml")
    clock = load_clock_oracle(
        ROOT / "evaluation" / "oracles" / "clock_opportunity_oracle_v0.1.yaml"
    )
    validate_oracle_coverage(state, conflicts, clock)
    report = validate_manual_bundle(
        bundle,
        protocol,
        state,
        _known_artifacts(protocol.scenario_ids),
        require_complete=True,
    )
    if not report.valid:
        raise ValueError(f"manual baseline validation failed: {report.errors}")

    original_root = destination / "original_submissions"
    normalized_root = destination / "normalized"
    integrity_root = destination / "integrity"
    for path in (original_root, normalized_root, integrity_root):
        path.mkdir(parents=True, exist_ok=True)
    hashes: list[dict[str, str]] = []
    for source in sorted(bundle.iterdir()):
        if source.is_file():
            target = original_root / source.name
            shutil.copy2(source, target)
            hashes.append({"filename": source.name, "sha256": sha256_file(target)})
    hash_path = write_json(integrity_root / "original_submission_hashes.json", hashes)
    validation_path = write_json(
        integrity_root / "import_validation_report.json",
        {
            "valid": report.valid,
            "errors": report.errors,
            "warnings": report.warnings,
            "checks": report.checks,
        },
    )
    normalized = normalize_manual_results(
        original_root,
        ROOT,
        state,
        conflicts,
        clock,
        _common_fields(),
    )
    normalized_path = write_json(
        normalized_root / "stage6_1_manual_baseline_normalized.json", normalized
    )
    provenance_path = write_json(
        integrity_root / "normalization_provenance.json",
        {
            "normalizer": "sbom_to_audit.baseline.manual_results.normalize_manual_results",
            "protocol_version": protocol.protocol_version,
            "original_hash_registry": hash_path.name,
            "normalized_output_sha256": sha256_file(normalized_path),
            "original_files_modified": False,
        },
    )
    return {
        "hashes": hash_path,
        "validation": validation_path,
        "normalized": normalized_path,
        "provenance": provenance_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    paths = import_bundle(args.bundle, args.destination)
    print("Stage 6.1 manual baseline imported:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
