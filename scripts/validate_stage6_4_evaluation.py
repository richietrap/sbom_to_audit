#!/usr/bin/env python3
"""Validate Stage 6.4 performance/scale protocol and observed candidate results."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.performance import AXES, registered_workloads
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml"
DEFAULT_RESULTS = ROOT / "evaluation/stage6_4_candidate"
EXPECTED_OUTPUTS = {
    "stage6_4_performance_report.json",
    "stage6_4_raw_trials.csv",
    "stage6_4_scale_summary.csv",
}
EXPECTED_METRICS = ["EC", "TR", "CD", "CA", "AR", "SC", "EPG"]


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def validate(results_root: Path, *, allow_smoke: bool = False) -> dict[str, Any]:
    errors: list[str] = []
    try:
        protocol = read_yaml(PROTOCOL_PATH)
        report = json.loads(
            (results_root / "stage6_4_performance_report.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (results_root / "stage6_4_output_manifest.json").read_text(encoding="utf-8")
        )
        summary_rows = _read_csv(results_root / "stage6_4_scale_summary.csv")
        raw_rows = _read_csv(results_root / "stage6_4_raw_trials.csv")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"valid": False, "errors": [str(exc)], "checks": {}}

    profile = str(report.get("profile") or "")
    _error(errors, profile in {"full", "smoke"}, "unsupported Stage 6.4 profile")
    if profile == "smoke" and not allow_smoke:
        errors.append("smoke result is not a full Stage 6.4 candidate")

    _error(
        errors,
        protocol.get("protocol_id") == "stage6_4_performance_and_scale",
        "protocol_id changed",
    )
    _error(errors, str(protocol.get("protocol_version")) == "0.1", "protocol version changed")
    _error(
        errors,
        protocol.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "protocol status changed",
    )
    _error(
        errors,
        protocol.get("manuscript_eligible") is False,
        "protocol became prematurely manuscript-eligible",
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
    _error(errors, list(locked.get("metrics") or []) == EXPECTED_METRICS, "locked metrics changed")
    _error(errors, float(locked.get("tau_E_hours", -1)) == 18.0, "tau_E boundary changed")
    _error(
        errors,
        locked.get("production_thresholds_changed") is False,
        "performance stage changed production thresholds",
    )
    _error(
        errors,
        locked.get("scenario_oracles_changed") is False,
        "performance stage changed scenario oracles",
    )

    full_workloads = registered_workloads(protocol)
    expected_count = len(full_workloads) if profile == "full" else len(AXES)
    _error(
        errors,
        int(report.get("workload_count", -1)) == expected_count,
        "workload count changed",
    )
    _error(errors, len(summary_rows) == expected_count, "summary workload count mismatch")
    _error(errors, int(report.get("axis_count", -1)) == len(AXES), "scale axis count changed")
    _error(errors, report.get("all_decision_equivalent") is True, "decision equivalence failed")
    _error(
        errors,
        report.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "candidate result status changed",
    )
    _error(
        errors,
        report.get("manuscript_eligible") is False,
        "candidate result became prematurely manuscript-eligible",
    )
    _error(errors, report.get("locked_controls") == locked, "candidate locked controls changed")

    observed_axes = {row.get("axis") for row in summary_rows}
    _error(errors, observed_axes == set(AXES), "summary does not contain all registered axes")
    measured_runs = int(report.get("measured_runs", 0))
    _error(errors, measured_runs > 0, "measured_runs must be positive")
    _error(
        errors,
        len(raw_rows) == len(summary_rows) * measured_runs,
        "raw trial count does not match workload_count * measured_runs",
    )

    for row in summary_rows:
        workload_id = str(row.get("workload_id") or "")
        try:
            scale_value = int(row["scale_value"])
            median_wall = float(row["median_wall_ms"])
            p95_wall = float(row["p95_wall_ms"])
            median_cpu = float(row["median_cpu_ms"])
            peak_rss = int(row["peak_rss_bytes"])
            input_bytes = int(row["input_bytes"])
            output_bytes = int(row["output_bytes"])
            slowdown = float(row["slowdown_vs_axis_minimum"])
            throughput = float(row["scale_units_per_second"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{workload_id or '<unknown>'}: invalid numeric summary field")
            continue
        _error(errors, scale_value > 0, f"{workload_id}: scale_value must be positive")
        _error(errors, median_wall > 0, f"{workload_id}: median wall time must be positive")
        _error(errors, p95_wall >= median_wall, f"{workload_id}: p95 wall time < median")
        _error(errors, median_cpu >= 0, f"{workload_id}: median CPU time must be non-negative")
        _error(errors, peak_rss > 0, f"{workload_id}: peak RSS must be positive")
        _error(errors, input_bytes > 0, f"{workload_id}: input bytes must be positive")
        _error(errors, output_bytes > 0, f"{workload_id}: output bytes must be positive")
        _error(errors, slowdown > 0, f"{workload_id}: slowdown must be positive")
        _error(errors, throughput > 0, f"{workload_id}: throughput must be positive")
        _error(
            errors,
            str(row.get("decision_equivalent") or "").lower() == "true",
            f"{workload_id}: decision equivalence changed",
        )
        _error(
            errors,
            len(str(row.get("decision_fingerprint_sha256") or "")) == 64,
            f"{workload_id}: decision fingerprint hash missing",
        )

    for axis in AXES:
        axis_rows = [row for row in summary_rows if row.get("axis") == axis]
        if not axis_rows:
            continue
        baseline = min(axis_rows, key=lambda row: int(row["scale_value"]))
        _error(
            errors,
            abs(float(baseline["slowdown_vs_axis_minimum"]) - 1.0) < 1e-6,
            f"{axis}: minimum workload slowdown must equal 1.0",
        )

    output_hashes = manifest.get("output_files") or {}
    _error(errors, set(output_hashes) == EXPECTED_OUTPUTS, "output manifest inventory changed")
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
            "profile": profile,
            "axis_count": len(observed_axes),
            "workload_count": len(summary_rows),
            "measured_runs": measured_runs,
            "raw_trial_count": len(raw_rows),
            "all_decision_equivalent": report.get("all_decision_equivalent"),
            "results_validated": True,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--allow-smoke", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = validate(args.results.resolve(), allow_smoke=args.allow_smoke)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
