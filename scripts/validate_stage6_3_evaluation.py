#!/usr/bin/env python3
"""Validate the Stage 6.3 mutation protocol and candidate result bundle."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.mutation import (
    ALLOWED_OUTCOMES,
    mutation_score,
    summarize_outcomes,
    validate_mutant_registry,
)
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "stage6_3_mutation_protocol_v0.1.yaml"
DEFAULT_RESULTS = ROOT / "evaluation" / "stage6_3_candidate"
EXPECTED_PARENT_COMMIT = "36cb40fed9be39a19da25df70bb524c2cc05e316"
EXPECTED_PARENT_COLAB_SHA256 = "01b184fb95dcec987cd599e2a50dc1ad6027b8d0dfce2d0d9af2fdf20090d3f1"
EXPECTED_FAMILIES = {
    "authorization",
    "conflict",
    "evidence_semantics",
    "identity_uncertainty",
    "metrics",
    "temporal_decision",
    "traceability_integrity",
}
EXPECTED_OUTPUTS = {
    "stage6_3_mutant_registry.csv",
    "stage6_3_mutation_results.csv",
    "stage6_3_family_summary.csv",
    "stage6_3_surviving_mutants.csv",
    "stage6_3_mutation_summary.json",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def validate(results_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    try:
        protocol = read_yaml(PROTOCOL_PATH)
    except (OSError, ValueError) as exc:
        return {"valid": False, "errors": [f"protocol cannot be loaded: {exc}"], "checks": {}}
    if not isinstance(protocol, dict):
        return {"valid": False, "errors": ["protocol must contain an object"], "checks": {}}

    raw_mutants = protocol.get("mutants")
    if not isinstance(raw_mutants, list) or not all(isinstance(item, dict) for item in raw_mutants):
        return {"valid": False, "errors": ["protocol mutants must be objects"], "checks": {}}
    try:
        mutants = validate_mutant_registry(raw_mutants)
    except ValueError as exc:
        return {"valid": False, "errors": [f"mutant registry is invalid: {exc}"], "checks": {}}

    _error(
        errors,
        protocol.get("protocol_id") == "stage6_3_controlled_mutation_testing",
        "unexpected protocol_id",
    )
    _error(errors, str(protocol.get("protocol_version")) == "0.1", "unexpected protocol_version")
    _error(
        errors,
        protocol.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "protocol must remain CANDIDATE_NOT_FROZEN",
    )
    _error(
        errors,
        protocol.get("manuscript_eligible") is False,
        "protocol became prematurely manuscript-eligible",
    )
    parent = protocol.get("parent_checkpoint") or {}
    _error(
        errors,
        parent.get("git_commit") == EXPECTED_PARENT_COMMIT,
        "parent Stage 6.2 commit does not match the accepted checkpoint",
    )
    _error(
        errors,
        parent.get("colab_evidence_sha256") == EXPECTED_PARENT_COLAB_SHA256,
        "parent Stage 6.2 Colab evidence hash changed",
    )
    locked = protocol.get("locked_controls") or {}
    _error(
        errors,
        str(locked.get("evidencepack_schema_version")) == "0.2",
        "EvidencePack schema boundary changed",
    )
    _error(
        errors,
        int(locked.get("evidence_completeness_denominator", -1)) == 34,
        "EC denominator changed",
    )
    _error(
        errors,
        list(locked.get("metrics") or []) == ["EC", "TR", "CD", "CA", "AR", "SC", "EPG"],
        "locked metrics changed",
    )
    _error(errors, float(locked.get("tau_E_hours", -1)) == 18.0, "tau_E changed")
    _error(errors, {mutant.family for mutant in mutants} == EXPECTED_FAMILIES, "family set changed")

    for mutant in mutants:
        target = ROOT / mutant.target_file
        _error(errors, target.is_file(), f"mutation target is missing: {mutant.target_file}")
        if target.is_file():
            text = target.read_text(encoding="utf-8")
            for index, replacement in enumerate(mutant.replacements):
                _error(
                    errors,
                    text.count(replacement.original) == 1,
                    f"{mutant.mutant_id} replacement {index} no longer has one source match",
                )
        _error(
            errors,
            not any("test_stage6_3" in node for node in mutant.baseline_tests),
            f"{mutant.mutant_id} baseline phase uses a Stage 6.3 test",
        )

    if not results_root.is_dir():
        errors.append(f"results directory is missing: {results_root}")
        return {
            "valid": False,
            "errors": errors,
            "checks": {
                "protocol_version": str(protocol.get("protocol_version")),
                "mutant_count": len(mutants),
                "results_validated": False,
            },
        }

    required = EXPECTED_OUTPUTS | {"stage6_3_output_manifest.json"}
    missing = sorted(name for name in required if not (results_root / name).is_file())
    if missing:
        errors.append(f"Stage 6.3 result files are missing: {missing}")
        return {
            "valid": False,
            "errors": errors,
            "checks": {
                "protocol_version": str(protocol.get("protocol_version")),
                "mutant_count": len(mutants),
                "results_validated": False,
            },
        }

    try:
        report = json.loads((results_root / "stage6_3_mutation_summary.json").read_text())
        manifest = json.loads((results_root / "stage6_3_output_manifest.json").read_text())
        result_rows = _read_csv(results_root / "stage6_3_mutation_results.csv")
        registry_rows = _read_csv(results_root / "stage6_3_mutant_registry.csv")
        family_rows = _read_csv(results_root / "stage6_3_family_summary.csv")
        survivor_rows = _read_csv(results_root / "stage6_3_surviving_mutants.csv")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"Stage 6.3 results cannot be loaded: {exc}")
        return {"valid": False, "errors": errors, "checks": {}}

    _error(errors, report.get("run_id") == "STAGE6-3-MUTATION-CANDIDATE-001", "run_id changed")
    _error(
        errors,
        report.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "report status changed",
    )
    _error(errors, report.get("manuscript_eligible") is False, "report became manuscript-eligible")
    _error(errors, report.get("parent_checkpoint") == parent, "report parent checkpoint changed")
    _error(errors, report.get("locked_controls") == locked, "report locked controls changed")
    _error(errors, len(result_rows) == len(mutants), "result row count differs from registry")
    _error(
        errors,
        len(registry_rows) == len(mutants),
        "registry CSV row count differs from protocol",
    )
    _error(errors, len(family_rows) == len(EXPECTED_FAMILIES), "family summary row count changed")

    expected_ids = [mutant.mutant_id for mutant in mutants]
    observed_ids = [row.get("mutant_id", "") for row in result_rows]
    registry_ids = [row.get("mutant_id", "") for row in registry_rows]
    _error(errors, observed_ids == expected_ids, "result mutant order differs from protocol")
    _error(errors, registry_ids == expected_ids, "registry CSV order differs from protocol")

    normalized_rows: list[dict[str, Any]] = []
    for row in result_rows:
        baseline = row.get("baseline_outcome", "")
        strengthened = row.get("strengthened_outcome", "")
        _error(errors, baseline in ALLOWED_OUTCOMES, f"invalid baseline outcome: {baseline}")
        _error(
            errors,
            strengthened in ALLOWED_OUTCOMES,
            f"invalid strengthened outcome: {strengthened}",
        )
        normalized_rows.append(
            {
                "baseline_outcome": baseline,
                "strengthened_outcome": strengthened,
            }
        )

    baseline_counts = summarize_outcomes(normalized_rows, "baseline_outcome")
    strengthened_counts = summarize_outcomes(normalized_rows, "strengthened_outcome")
    _error(errors, report.get("baseline_outcomes") == baseline_counts, "baseline counts mismatch")
    _error(
        errors,
        report.get("strengthened_outcomes") == strengthened_counts,
        "strengthened counts mismatch",
    )
    _error(
        errors,
        report.get("baseline_mutation_score")
        == mutation_score(normalized_rows, "baseline_outcome"),
        "baseline mutation score mismatch",
    )
    _error(
        errors,
        report.get("strengthened_mutation_score")
        == mutation_score(normalized_rows, "strengthened_outcome"),
        "strengthened mutation score mismatch",
    )
    _error(
        errors,
        strengthened_counts["SURVIVED"] <= baseline_counts["SURVIVED"],
        "strengthened suite has more survivors than baseline",
    )
    _error(
        errors,
        len(survivor_rows) == baseline_counts["SURVIVED"],
        "survivor register does not match baseline survivors",
    )

    target_hashes = report.get("target_source_hashes") or {}
    expected_targets = sorted({mutant.target_file for mutant in mutants})
    _error(
        errors,
        sorted(target_hashes) == expected_targets,
        "target source hash inventory changed",
    )
    for relative, expected_hash in target_hashes.items():
        path = ROOT / str(relative)
        _error(
            errors,
            path.is_file() and sha256_file(path) == expected_hash,
            f"target source hash mismatch: {relative}",
        )
    safety_path = ROOT / "tests" / "test_stage6_3_safety_guards.py"
    _error(
        errors,
        safety_path.is_file() and sha256_file(safety_path) == report.get("safety_test_sha256"),
        "Stage 6.3 safety-test hash mismatch",
    )

    output_hashes = manifest.get("output_files") or {}
    _error(errors, set(output_hashes) == EXPECTED_OUTPUTS, "output manifest inventory changed")
    _error(errors, manifest.get("run_id") == report.get("run_id"), "manifest run_id mismatch")
    _error(
        errors,
        manifest.get("protocol_sha256") == sha256_file(PROTOCOL_PATH),
        "protocol hash mismatch",
    )
    for name, expected_hash in output_hashes.items():
        path = results_root / str(name)
        _error(
            errors,
            path.is_file() and sha256_file(path) == expected_hash,
            f"candidate output hash mismatch: {name}",
        )

    return {
        "valid": not errors,
        "errors": errors,
        "checks": {
            "protocol_version": str(protocol.get("protocol_version")),
            "mutant_count": len(mutants),
            "family_count": len(EXPECTED_FAMILIES),
            "baseline_outcomes": baseline_counts,
            "baseline_mutation_score": mutation_score(normalized_rows, "baseline_outcome"),
            "strengthened_outcomes": strengthened_counts,
            "strengthened_mutation_score": mutation_score(normalized_rows, "strengthened_outcome"),
            "results_validated": True,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = validate(args.results.resolve())
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
