#!/usr/bin/env python3
"""Validate Stage 6.5 performance-remediation evidence from raw timing and RSS records."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.performance import registered_workloads
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml"
DEFAULT_RESULTS = ROOT / "evaluation/stage6_5_candidate/performance_remediation"
EXPECTED_V01_SHA256 = "c5001c5ef760ed37d72971970c119848e06f6fec481677e73895c1ab32745035"
MEMORY_API = "resource.getrusage(resource.RUSAGE_SELF).ru_maxrss"
MEMORY_SCOPE = "fresh_workload_worker"
MEMORY_CAPTURE_POINT = "after_warmups_and_all_measured_replays"


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _recompute(trials: list[dict[str, str]]) -> dict[str, float]:
    wall = [float(row["wall_ms"]) for row in trials]
    cpu = [float(row["cpu_ms"]) for row in trials]
    mean_wall = statistics.fmean(wall)
    sample_stdev = statistics.stdev(wall) if len(wall) > 1 else 0.0
    return {
        "median_wall_ms": round(statistics.median(wall), 6),
        "p95_wall_ms": round(_nearest_rank(wall, 0.95), 6),
        "mean_wall_ms": round(mean_wall, 6),
        "wall_cv": round(sample_stdev / mean_wall, 6) if mean_wall else 0.0,
        "median_cpu_ms": round(statistics.median(cpu), 6),
        "p95_cpu_ms": round(_nearest_rank(cpu, 0.95), 6),
    }


def validate(results_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    protocol = read_yaml(PROTOCOL_PATH)
    _error(
        errors,
        protocol.get("protocol_id") == "stage6_4_performance_and_scale",
        "protocol_id changed",
    )
    _error(errors, str(protocol.get("protocol_version")) == "0.2", "protocol_version changed")
    _error(
        errors,
        protocol.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "protocol status changed",
    )
    _error(
        errors,
        protocol.get("manuscript_eligible") is False,
        "protocol became manuscript-eligible",
    )
    _error(
        errors,
        sha256_file(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
        == EXPECTED_V01_SHA256,
        "historical Stage 6.4 protocol v0.1 changed",
    )
    measurement = (protocol.get("measurement_scope") or {}).get("memory_measurement") or {}
    _error(errors, measurement.get("api") == MEMORY_API, "memory measurement API changed")
    _error(
        errors,
        measurement.get("measured_process") == "workload_worker",
        "memory process scope changed",
    )
    _error(
        errors,
        measurement.get("raw_observation_granularity") == "one observation per workload worker",
        "memory observation granularity changed",
    )
    statistics_spec = protocol.get("statistics") or {}
    _error(
        errors,
        statistics_spec.get("wall_cv_definition")
        == "sample_standard_deviation_n_minus_1_divided_by_arithmetic_mean",
        "wall CV convention is not explicit sample CV",
    )
    locked = protocol.get("locked_controls") or {}
    _error(
        errors,
        str(locked.get("evidencepack_schema_version")) == "0.2",
        "EvidencePack version changed",
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

    required_names = {
        "stage6_5_raw_trials.csv",
        "stage6_5_memory_observations.csv",
        "stage6_5_scale_summary.csv",
        "stage6_5_performance_report.json",
        "stage6_5_output_manifest.json",
    }
    missing = sorted(name for name in required_names if not (results_root / name).is_file())
    if missing:
        errors.append(f"missing performance-remediation outputs: {missing}")
        return {"valid": False, "errors": errors, "checks": {"results_present": False}}

    raw_rows = _read_csv(results_root / "stage6_5_raw_trials.csv")
    memory_rows = _read_csv(results_root / "stage6_5_memory_observations.csv")
    summary_rows = _read_csv(results_root / "stage6_5_scale_summary.csv")
    report = json.loads(
        (results_root / "stage6_5_performance_report.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (results_root / "stage6_5_output_manifest.json").read_text(encoding="utf-8")
    )

    profile = str(report.get("profile"))
    _error(errors, profile in {"full", "smoke"}, "unexpected performance profile")
    workloads = registered_workloads(protocol)
    if profile == "full":
        expected_workloads = workloads
        expected_trials_per_workload = int((protocol.get("execution") or {})["measured_runs"])
        expected_memory_count = 20
    else:
        smoke = (protocol.get("execution") or {}).get("smoke_values") or {}
        expected_workloads = [
            workload
            for workload in workloads
            if int(smoke.get(workload.axis, -1)) == workload.scale_value
        ]
        expected_trials_per_workload = 1
        expected_memory_count = 4

    expected_ids = {workload.workload_id for workload in expected_workloads}
    summary_ids = {row["workload_id"] for row in summary_rows}
    memory_ids = {row["workload_id"] for row in memory_rows}
    raw_ids = {row["workload_id"] for row in raw_rows}
    _error(errors, summary_ids == expected_ids, "summary workload inventory differs from protocol")
    _error(errors, memory_ids == expected_ids, "memory workload inventory differs from protocol")
    _error(errors, raw_ids == expected_ids, "raw trial workload inventory differs from protocol")
    _error(errors, len(summary_rows) == len(expected_workloads), "summary row count changed")
    _error(errors, len(memory_rows) == expected_memory_count, "memory observation count changed")
    _error(
        errors,
        len(raw_rows) == len(expected_workloads) * expected_trials_per_workload,
        "raw timing row count changed",
    )

    raw_by_id: dict[str, list[dict[str, str]]] = {}
    for row in raw_rows:
        raw_by_id.setdefault(row["workload_id"], []).append(row)
    memory_by_id = {row["workload_id"]: row for row in memory_rows}
    summary_by_id = {row["workload_id"]: row for row in summary_rows}

    for workload_id in sorted(expected_ids):
        trials = raw_by_id.get(workload_id, [])
        _error(
            errors,
            len(trials) == expected_trials_per_workload,
            f"{workload_id}: timing trial count changed",
        )
        if not trials:
            continue
        recomputed = _recompute(trials)
        summary = summary_by_id[workload_id]
        for field, expected_value in recomputed.items():
            _error(
                errors,
                float(summary[field]) == expected_value,
                f"{workload_id}: {field} does not recompute from raw trials",
            )
        memory = memory_by_id[workload_id]
        _error(
            errors,
            memory["measurement_api"] == MEMORY_API,
            f"{workload_id}: memory API changed",
        )
        _error(
            errors,
            memory["measured_process"] == MEMORY_SCOPE,
            f"{workload_id}: measured process changed",
        )
        _error(
            errors,
            memory["capture_point"] == MEMORY_CAPTURE_POINT,
            f"{workload_id}: memory capture point changed",
        )
        raw_peak = int(memory["raw_peak_rss"])
        normalized = int(memory["normalized_peak_rss_bytes"])
        if memory["raw_unit"] == "bytes":
            expected_normalized = raw_peak
        elif memory["raw_unit"] == "KiB":
            expected_normalized = raw_peak * 1024
        else:
            expected_normalized = -1
            errors.append(f"{workload_id}: unsupported raw RSS unit {memory['raw_unit']!r}")
        _error(
            errors,
            normalized == expected_normalized,
            f"{workload_id}: RSS normalization mismatch",
        )
        _error(
            errors,
            int(summary["peak_rss_bytes"]) == normalized,
            f"{workload_id}: summary peak RSS is not derived from raw memory observation",
        )
        _error(
            errors,
            summary["decision_fingerprint_sha256"] == memory["decision_fingerprint_sha256"],
            f"{workload_id}: decision fingerprint differs across summary and memory evidence",
        )
        _error(
            errors,
            str(summary["decision_equivalent"]).lower() == "true",
            f"{workload_id}: decision equivalence failed",
        )

    _error(
        errors,
        report.get("evaluation_status") == "CANDIDATE_NOT_FROZEN",
        "report status changed",
    )
    _error(errors, report.get("manuscript_eligible") is False, "report became manuscript-eligible")
    _error(
        errors,
        report.get("all_decision_equivalent") is True,
        "not all workloads are decision-equivalent",
    )
    _error(
        errors,
        report.get("memory_observation_count") == len(memory_rows),
        "report memory observation count mismatch",
    )
    _error(
        errors,
        report.get("memory_observation_granularity")
        == "one_worker_high_water_observation_per_workload",
        "report memory granularity changed",
    )
    _error(errors, report.get("locked_controls") == locked, "report locked controls changed")

    output_hashes = manifest.get("output_files") or {}
    expected_manifest_files = required_names - {"stage6_5_output_manifest.json"}
    _error(
        errors,
        set(output_hashes) == expected_manifest_files,
        "output manifest inventory changed",
    )
    _error(
        errors,
        manifest.get("protocol_sha256") == sha256_file(PROTOCOL_PATH),
        "protocol hash mismatch",
    )
    for name, expected_hash in output_hashes.items():
        path = results_root / name
        _error(
            errors,
            path.is_file() and sha256_file(path) == expected_hash,
            f"output hash mismatch: {name}",
        )

    return {
        "valid": not errors,
        "errors": errors,
        "checks": {
            "profile": profile,
            "workload_count": len(summary_rows),
            "raw_timing_rows": len(raw_rows),
            "memory_observations": len(memory_rows),
            "memory_observation_granularity": "one_per_workload_worker",
            "wall_cv_convention": "sample_standard_deviation_n_minus_1",
            "all_decision_equivalent": report.get("all_decision_equivalent"),
            "historical_v0_1_protocol_sha256": EXPECTED_V01_SHA256,
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
