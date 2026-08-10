#!/usr/bin/env python3
"""Run the deterministic Stage 6.3 controlled mutation evaluation."""

from __future__ import annotations

import argparse
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.mutation import (
    Mutant,
    apply_mutant,
    mutation_score,
    summarize_outcomes,
    validate_mutant_registry,
)
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_yaml, write_csv, write_json

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "stage6_3_mutation_protocol_v0.1.yaml"
RUN_ID = "STAGE6-3-MUTATION-CANDIDATE-001"

REGISTRY_FIELDS = [
    "mutant_id",
    "family",
    "target_file",
    "target_symbol",
    "description",
    "rationale",
    "replacement_count",
    "replacement_sha256",
    "baseline_test_count",
    "strengthened_test_count",
]
RESULT_FIELDS = [
    "mutant_id",
    "family",
    "target_file",
    "target_symbol",
    "baseline_outcome",
    "strengthened_outcome",
    "baseline_returncode",
    "strengthened_returncode",
    "strengthening_required",
    "final_disposition",
]
FAMILY_FIELDS = [
    "family",
    "mutant_count",
    "baseline_killed",
    "baseline_survived",
    "baseline_invalid",
    "baseline_timeout",
    "baseline_score",
    "strengthened_killed",
    "strengthened_survived",
    "strengthened_invalid",
    "strengthened_timeout",
    "strengthened_score",
]
SURVIVOR_FIELDS = [
    "mutant_id",
    "family",
    "description",
    "baseline_outcome",
    "strengthened_outcome",
    "disposition",
]


def _write_csv_lf(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> Path:
    output = write_csv(path, rows, fieldnames)
    output.write_bytes(output.read_bytes().replace(b"\r\n", b"\n"))
    return output


def _load_protocol() -> tuple[dict[str, Any], list[Mutant]]:
    value = read_yaml(PROTOCOL_PATH)
    if not isinstance(value, dict):
        raise ValueError("Stage 6.3 protocol must contain an object")
    if value.get("protocol_id") != "stage6_3_controlled_mutation_testing":
        raise ValueError("unexpected Stage 6.3 protocol_id")
    if str(value.get("protocol_version")) != "0.1":
        raise ValueError("unexpected Stage 6.3 protocol_version")
    raw_mutants = value.get("mutants")
    if not isinstance(raw_mutants, list):
        raise ValueError("Stage 6.3 protocol mutants must be a list")
    mappings = [item for item in raw_mutants if isinstance(item, dict)]
    if len(mappings) != len(raw_mutants):
        raise ValueError("every Stage 6.3 mutant must be an object")
    return value, validate_mutant_registry(mappings)


def _copy_repository(destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".qa-venv",
        ".quality-venv",
        "__pycache__",
        "*.pyc",
        "*.egg-info",
    )
    shutil.copytree(ROOT, destination, ignore=ignored)


def _classify_test_run(
    repository: Path,
    tests: tuple[str, ...],
    *,
    timeout_seconds: int,
) -> tuple[str, int | None]:
    command = [sys.executable, "-m", "pytest", "-q", *tests]
    environment = {
        **os.environ,
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPATH": str(repository / "src"),
    }
    try:
        completed = subprocess.run(
            command,
            cwd=repository,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    if completed.returncode == 0:
        return "SURVIVED", 0
    if completed.returncode == 1:
        return "KILLED", 1
    return "INVALID", completed.returncode


def _execute_mutant(
    repository: Path,
    mutant: Mutant,
    timeout_seconds: int,
) -> dict[str, Any]:
    target = repository / mutant.target_file
    original_bytes = target.read_bytes() if target.is_file() else None
    try:
        try:
            mutated_target = apply_mutant(repository, mutant)
            py_compile.compile(str(mutated_target), doraise=True)
        except (OSError, ValueError, py_compile.PyCompileError):
            return {
                "mutant_id": mutant.mutant_id,
                "family": mutant.family,
                "target_file": mutant.target_file,
                "target_symbol": mutant.target_symbol,
                "baseline_outcome": "INVALID",
                "strengthened_outcome": "INVALID",
                "baseline_returncode": "",
                "strengthened_returncode": "",
                "strengthening_required": False,
                "final_disposition": "INVALID_MUTANT",
            }

        baseline_outcome, baseline_returncode = _classify_test_run(
            repository,
            mutant.baseline_tests,
            timeout_seconds=timeout_seconds,
        )
        if baseline_outcome == "KILLED":
            strengthened_outcome = "KILLED"
            strengthened_returncode: int | None = baseline_returncode
            final_disposition = "KILLED_BY_PRE_STAGE6_3_TESTS"
        elif baseline_outcome in {"INVALID", "TIMEOUT"}:
            strengthened_outcome = baseline_outcome
            strengthened_returncode = baseline_returncode
            final_disposition = f"{baseline_outcome}_DURING_BASELINE_PHASE"
        else:
            strengthened_suite = tuple(
                dict.fromkeys((*mutant.baseline_tests, *mutant.strengthened_tests))
            )
            strengthened_outcome, strengthened_returncode = _classify_test_run(
                repository,
                strengthened_suite,
                timeout_seconds=timeout_seconds,
            )
            if strengthened_outcome == "KILLED":
                final_disposition = "KILLED_AFTER_TARGETED_TEST_STRENGTHENING"
            elif strengthened_outcome == "SURVIVED":
                final_disposition = "SURVIVED_STRENGTHENED_SUITE"
            else:
                final_disposition = f"{strengthened_outcome}_DURING_STRENGTHENED_PHASE"

        return {
            "mutant_id": mutant.mutant_id,
            "family": mutant.family,
            "target_file": mutant.target_file,
            "target_symbol": mutant.target_symbol,
            "baseline_outcome": baseline_outcome,
            "strengthened_outcome": strengthened_outcome,
            "baseline_returncode": "" if baseline_returncode is None else baseline_returncode,
            "strengthened_returncode": (
                "" if strengthened_returncode is None else strengthened_returncode
            ),
            "strengthening_required": baseline_outcome == "SURVIVED",
            "final_disposition": final_disposition,
        }
    finally:
        if original_bytes is not None:
            target.write_bytes(original_bytes)
        for cache in repository.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)


def _registry_rows(mutants: list[Mutant]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mutant in mutants:
        replacement_payload = [
            {"original": replacement.original, "mutated": replacement.mutated}
            for replacement in mutant.replacements
        ]
        rows.append(
            {
                "mutant_id": mutant.mutant_id,
                "family": mutant.family,
                "target_file": mutant.target_file,
                "target_symbol": mutant.target_symbol,
                "description": mutant.description,
                "rationale": mutant.rationale,
                "replacement_count": len(mutant.replacements),
                "replacement_sha256": sha256_json(replacement_payload),
                "baseline_test_count": len(mutant.baseline_tests),
                "strengthened_test_count": len(mutant.strengthened_tests),
            }
        )
    return rows


def _family_rows(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in results:
        grouped[str(row["family"])].append(row)
    output: list[dict[str, Any]] = []
    for family in sorted(grouped):
        rows = grouped[family]
        baseline = summarize_outcomes(rows, "baseline_outcome")
        strengthened = summarize_outcomes(rows, "strengthened_outcome")
        output.append(
            {
                "family": family,
                "mutant_count": len(rows),
                "baseline_killed": baseline["KILLED"],
                "baseline_survived": baseline["SURVIVED"],
                "baseline_invalid": baseline["INVALID"],
                "baseline_timeout": baseline["TIMEOUT"],
                "baseline_score": mutation_score(rows, "baseline_outcome"),
                "strengthened_killed": strengthened["KILLED"],
                "strengthened_survived": strengthened["SURVIVED"],
                "strengthened_invalid": strengthened["INVALID"],
                "strengthened_timeout": strengthened["TIMEOUT"],
                "strengthened_score": mutation_score(rows, "strengthened_outcome"),
            }
        )
    return output


def _survivor_rows(mutants: list[Mutant], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {mutant.mutant_id: mutant for mutant in mutants}
    output: list[dict[str, Any]] = []
    for result in results:
        if result["baseline_outcome"] != "SURVIVED":
            continue
        mutant = by_id[str(result["mutant_id"])]
        output.append(
            {
                "mutant_id": mutant.mutant_id,
                "family": mutant.family,
                "description": mutant.description,
                "baseline_outcome": result["baseline_outcome"],
                "strengthened_outcome": result["strengthened_outcome"],
                "disposition": result["final_disposition"],
            }
        )
    return output


def run(destination: Path) -> dict[str, Path]:
    protocol, mutants = _load_protocol()
    destination.mkdir(parents=True, exist_ok=True)
    timeout_seconds = int((protocol.get("execution") or {}).get("timeout_seconds", 45))

    with tempfile.TemporaryDirectory(prefix="stage63-mutation-workspace-") as temp:
        repository = Path(temp) / "repository"
        _copy_repository(repository)
        results = []
        for mutant in mutants:
            print(f"Running {mutant.mutant_id}...", flush=True)
            result = _execute_mutant(repository, mutant, timeout_seconds)
            print(
                f"{mutant.mutant_id}: {result['baseline_outcome']} -> "
                f"{result['strengthened_outcome']}",
                flush=True,
            )
            results.append(result)
    registry_rows = _registry_rows(mutants)
    family_rows = _family_rows(results)
    survivor_rows = _survivor_rows(mutants, results)

    baseline_counts = summarize_outcomes(results, "baseline_outcome")
    strengthened_counts = summarize_outcomes(results, "strengthened_outcome")
    report = {
        "run_id": RUN_ID,
        "stage": "6.3",
        "protocol_id": protocol["protocol_id"],
        "protocol_version": str(protocol["protocol_version"]),
        "evaluation_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "parent_checkpoint": protocol["parent_checkpoint"],
        "mutant_count": len(mutants),
        "family_count": len({mutant.family for mutant in mutants}),
        "baseline_outcomes": baseline_counts,
        "baseline_mutation_score": mutation_score(results, "baseline_outcome"),
        "strengthened_outcomes": strengthened_counts,
        "strengthened_mutation_score": mutation_score(results, "strengthened_outcome"),
        "baseline_survivor_count": baseline_counts["SURVIVED"],
        "strengthened_survivor_count": strengthened_counts["SURVIVED"],
        "targeted_tests_added": len(
            {node for mutant in mutants for node in mutant.strengthened_tests}
        ),
        "target_source_hashes": {
            target: sha256_file(ROOT / target)
            for target in sorted({mutant.target_file for mutant in mutants})
        },
        "safety_test_sha256": sha256_file(ROOT / "tests" / "test_stage6_3_safety_guards.py"),
        "locked_controls": protocol["locked_controls"],
        "interpretation_boundary": [
            (
                "Mutation testing evaluates test sensitivity to registered faults, "
                "not legal correctness."
            ),
            "The baseline phase uses only tests that pre-date Stage 6.3.",
            (
                "The strengthened phase transparently records tests added after baseline "
                "survivors were identified."
            ),
            "No universal acceptable mutation-score threshold is claimed.",
            "Candidate outputs remain ineligible until exact-commit reproduction and final freeze.",
        ],
        "limitations": [
            (
                "The registry is a bounded set of plausible first-order mutants rather than "
                "an exhaustive search."
            ),
            (
                "Exact-text mutations are intentionally fail-closed and may require registry "
                "maintenance after source refactoring."
            ),
            (
                "Targeted test execution does not substitute for the repository-wide quality "
                "and regression suite."
            ),
            (
                "Equivalent mutants are not asserted automatically; unresolved survivors "
                "remain visible."
            ),
        ],
    }

    paths = {
        "registry": _write_csv_lf(
            destination / "stage6_3_mutant_registry.csv",
            registry_rows,
            REGISTRY_FIELDS,
        ),
        "results": _write_csv_lf(
            destination / "stage6_3_mutation_results.csv",
            results,
            RESULT_FIELDS,
        ),
        "family_summary": _write_csv_lf(
            destination / "stage6_3_family_summary.csv",
            family_rows,
            FAMILY_FIELDS,
        ),
        "survivors": _write_csv_lf(
            destination / "stage6_3_surviving_mutants.csv",
            survivor_rows,
            SURVIVOR_FIELDS,
        ),
        "summary": write_json(destination / "stage6_3_mutation_summary.json", report),
    }
    manifest = {
        "run_id": RUN_ID,
        "protocol_sha256": sha256_file(PROTOCOL_PATH),
        "output_files": {
            path.name: sha256_file(path)
            for path in sorted(paths.values(), key=lambda item: item.name)
        },
    }
    paths["manifest"] = write_json(destination / "stage6_3_output_manifest.json", manifest)
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=ROOT / "evaluation" / "stage6_3_candidate",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    paths = run(args.destination)
    print("Stage 6.3 controlled mutation evaluation completed:")
    for name, path in paths.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
