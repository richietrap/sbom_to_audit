#!/usr/bin/env python3
"""Run the Stage 6.5 performance remediation with raw workload-level RSS evidence."""

from __future__ import annotations

import argparse
import csv
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.performance import (
    build_workload_fixture,
    core_decision_fingerprint,
    environment_metadata,
    execution_order,
    registered_workloads,
    summarize_trials,
)
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_yaml, write_json

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml"
DEFAULT_DESTINATION = ROOT / "evaluation/stage6_5_candidate/performance_remediation"
RUN_ID = "STAGE6-5-PERFORMANCE-REMEDIATION-CANDIDATE-001"
MEMORY_API = "resource.getrusage(resource.RUSAGE_SELF).ru_maxrss"
MEMORY_SCOPE = "fresh_workload_worker"
MEMORY_CAPTURE_POINT = "after_warmups_and_all_measured_replays"


def _git_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return "unavailable"
    return completed.stdout.strip()


def _git_dirty() -> bool | None:
    completed = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return bool(completed.stdout.strip())


def _rss_observation() -> dict[str, Any]:
    raw_value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        native_unit = "bytes"
        normalized = raw_value
    else:
        native_unit = "KiB"
        normalized = raw_value * 1024
    return {
        "measurement_api": MEMORY_API,
        "measured_process": MEMORY_SCOPE,
        "capture_point": MEMORY_CAPTURE_POINT,
        "raw_peak_rss": raw_value,
        "raw_unit": native_unit,
        "normalized_peak_rss_bytes": normalized,
        "platform": sys.platform,
    }


def _worker(scenario_path: Path, repository_root: Path, warmups: int, repetitions: int) -> int:
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
    for _ in range(warmups):
        replay_scenario(scenario, repository_root=repository_root)

    trials: list[dict[str, Any]] = []
    final_result: dict[str, Any] | None = None
    for index in range(repetitions):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        result = replay_scenario(scenario, repository_root=repository_root)
        cpu_end = time.process_time_ns()
        wall_end = time.perf_counter_ns()
        trials.append(
            {
                "trial": index + 1,
                "wall_ms": round((wall_end - wall_start) / 1_000_000, 6),
                "cpu_ms": round((cpu_end - cpu_start) / 1_000_000, 6),
            }
        )
        final_result = result

    if final_result is None:
        raise ValueError("worker requires at least one measured repetition")
    if not all(bool(row["state_match"]) for row in final_result["state_rows"]):
        raise AssertionError("performance workload changed a registered expected state")
    if not all(bool(row["authorization_match"]) for row in final_result["state_rows"]):
        raise AssertionError("performance workload changed a registered authorization state")
    if not all(bool(row["deadline_match"]) for row in final_result["state_rows"]):
        raise AssertionError("performance workload changed a registered deadline posture")

    payload = {
        "trials": trials,
        "statistics": summarize_trials(trials),
        "memory_observation": _rss_observation(),
        "output_bytes": len(
            json.dumps(final_result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
        "decision_fingerprint": core_decision_fingerprint(final_result),
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _run_worker(
    scenario: dict[str, Any],
    repository_root: Path,
    warmups: int,
    repetitions: int,
) -> dict[str, Any]:
    scenario_path = repository_root / "stage6_5_worker_scenario.json"
    scenario_path.write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8", newline="\n")
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            "--scenario-json",
            str(scenario_path),
            "--repository-root",
            str(repository_root),
            "--warmups",
            str(warmups),
            "--repetitions",
            str(repetitions),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Stage 6.5 performance worker failed:\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _profile_workloads(protocol: dict[str, Any], profile: str) -> list[Any]:
    workloads = registered_workloads(protocol)
    if profile == "full":
        return workloads
    smoke = (protocol.get("execution") or {}).get("smoke_values") or {}
    selected = [
        workload
        for workload in workloads
        if int(smoke.get(workload.axis, -1)) == workload.scale_value
    ]
    if len(selected) != 4:
        raise ValueError("smoke profile must select exactly one workload for each scale axis")
    return selected


def run(destination: Path, *, profile: str = "full") -> dict[str, Path]:
    protocol = read_yaml(PROTOCOL_PATH)
    base_scenario = read_yaml(ROOT / str(protocol["reference_scenario"]))
    base_result = replay_scenario(base_scenario, repository_root=ROOT)
    canonical_fingerprint = core_decision_fingerprint(base_result)
    execution = protocol.get("execution") or {}
    if profile == "full":
        warmups = int(execution["warmup_runs"])
        repetitions = int(execution["measured_runs"])
    else:
        warmups = 0
        repetitions = 1

    workloads = execution_order(
        _profile_workloads(protocol, profile), int(execution["execution_order_seed"])
    )
    destination.mkdir(parents=True, exist_ok=True)
    raw_rows: list[dict[str, Any]] = []
    memory_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    semantic_hashes: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="stage65-performance-fixtures-") as temporary:
        fixture_root = Path(temporary)
        for execution_index, workload in enumerate(workloads, 1):
            print(
                f"Stage 6.5 performance remediation workload "
                f"{execution_index}/{len(workloads)}: {workload.workload_id}"
            )
            workload_root = fixture_root / workload.workload_id
            scenario = build_workload_fixture(ROOT, workload_root, base_scenario, workload)
            fixture_metadata = json.loads(
                (workload_root / "stage6_4_fixture_metadata.json").read_text(encoding="utf-8")
            )
            worker = _run_worker(scenario, workload_root, warmups, repetitions)
            fingerprint = worker["decision_fingerprint"]
            if fingerprint != canonical_fingerprint:
                raise AssertionError(
                    f"{workload.workload_id}: scale-only fixture changed decision semantics"
                )
            semantic_hashes[workload.workload_id] = sha256_json(fingerprint)
            statistics_row = worker["statistics"]
            memory = worker["memory_observation"]
            memory_rows.append(
                {
                    "workload_id": workload.workload_id,
                    "axis": workload.axis,
                    "scale_value": workload.scale_value,
                    "execution_index": execution_index,
                    "measurement_api": memory["measurement_api"],
                    "measured_process": memory["measured_process"],
                    "capture_point": memory["capture_point"],
                    "raw_peak_rss": int(memory["raw_peak_rss"]),
                    "raw_unit": memory["raw_unit"],
                    "normalized_peak_rss_bytes": int(memory["normalized_peak_rss_bytes"]),
                    "platform": memory["platform"],
                    "warmup_runs_completed": warmups,
                    "measured_runs_completed": repetitions,
                    "decision_fingerprint_sha256": semantic_hashes[workload.workload_id],
                }
            )
            summary = {
                "workload_id": workload.workload_id,
                "axis": workload.axis,
                "scale_value": workload.scale_value,
                "execution_index": execution_index,
                "warmup_runs": warmups,
                "measured_runs": repetitions,
                "input_bytes": int(fixture_metadata["input_bytes"]),
                "output_bytes": int(worker["output_bytes"]),
                "source_artifact_count": int(fixture_metadata["source_artifact_count"]),
                "replay_event_count": int(fixture_metadata["replay_event_count"]),
                "median_wall_ms": statistics_row["median_wall_ms"],
                "p95_wall_ms": statistics_row["p95_wall_ms"],
                "mean_wall_ms": statistics_row["mean_wall_ms"],
                "wall_cv": statistics_row["wall_cv"],
                "median_cpu_ms": statistics_row["median_cpu_ms"],
                "p95_cpu_ms": statistics_row["p95_cpu_ms"],
                "peak_rss_bytes": int(memory["normalized_peak_rss_bytes"]),
                "scale_units_per_second": round(
                    workload.scale_value / (float(statistics_row["median_wall_ms"]) / 1000.0),
                    6,
                ),
                "slowdown_vs_axis_minimum": "",
                "decision_equivalent": True,
                "decision_fingerprint_sha256": semantic_hashes[workload.workload_id],
                "fixture_scenario_sha256": fixture_metadata["scenario_sha256"],
            }
            summary_rows.append(summary)
            for trial in worker["trials"]:
                raw_rows.append(
                    {
                        "workload_id": workload.workload_id,
                        "axis": workload.axis,
                        "scale_value": workload.scale_value,
                        "execution_index": execution_index,
                        "trial": int(trial["trial"]),
                        "wall_ms": trial["wall_ms"],
                        "cpu_ms": trial["cpu_ms"],
                    }
                )

    by_axis: dict[str, list[dict[str, Any]]] = {}
    for row in summary_rows:
        by_axis.setdefault(str(row["axis"]), []).append(row)
    for axis_rows in by_axis.values():
        baseline = min(axis_rows, key=lambda row: int(row["scale_value"]))
        baseline_wall = float(baseline["median_wall_ms"])
        for row in axis_rows:
            row["slowdown_vs_axis_minimum"] = round(
                float(row["median_wall_ms"]) / baseline_wall,
                6,
            )

    summary_rows.sort(key=lambda row: (str(row["axis"]), int(row["scale_value"])))
    raw_rows.sort(key=lambda row: (str(row["axis"]), int(row["scale_value"]), int(row["trial"])))
    memory_rows.sort(key=lambda row: (str(row["axis"]), int(row["scale_value"])))

    raw_path = destination / "stage6_5_raw_trials.csv"
    memory_path = destination / "stage6_5_memory_observations.csv"
    summary_path = destination / "stage6_5_scale_summary.csv"
    _write_csv(
        raw_path,
        [
            "workload_id",
            "axis",
            "scale_value",
            "execution_index",
            "trial",
            "wall_ms",
            "cpu_ms",
        ],
        raw_rows,
    )
    _write_csv(
        memory_path,
        [
            "workload_id",
            "axis",
            "scale_value",
            "execution_index",
            "measurement_api",
            "measured_process",
            "capture_point",
            "raw_peak_rss",
            "raw_unit",
            "normalized_peak_rss_bytes",
            "platform",
            "warmup_runs_completed",
            "measured_runs_completed",
            "decision_fingerprint_sha256",
        ],
        memory_rows,
    )
    _write_csv(
        summary_path,
        [
            "workload_id",
            "axis",
            "scale_value",
            "execution_index",
            "warmup_runs",
            "measured_runs",
            "input_bytes",
            "output_bytes",
            "source_artifact_count",
            "replay_event_count",
            "median_wall_ms",
            "p95_wall_ms",
            "mean_wall_ms",
            "wall_cv",
            "median_cpu_ms",
            "p95_cpu_ms",
            "peak_rss_bytes",
            "scale_units_per_second",
            "slowdown_vs_axis_minimum",
            "decision_equivalent",
            "decision_fingerprint_sha256",
            "fixture_scenario_sha256",
        ],
        summary_rows,
    )

    report = {
        "run_id": RUN_ID if profile == "full" else "STAGE6-5-PERFORMANCE-REMEDIATION-SMOKE",
        "stage": "6.5",
        "package_version": "0.6.5",
        "protocol_id": protocol["protocol_id"],
        "protocol_version": str(protocol["protocol_version"]),
        "evaluation_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "profile": profile,
        "source_commit": _git_commit(),
        "source_tree_dirty": _git_dirty(),
        "environment": environment_metadata(),
        "warmup_runs": warmups,
        "measured_runs": repetitions,
        "workload_count": len(summary_rows),
        "memory_observation_count": len(memory_rows),
        "memory_observation_granularity": "one_worker_high_water_observation_per_workload",
        "axis_count": len({row["axis"] for row in summary_rows}),
        "all_decision_equivalent": all(bool(row["decision_equivalent"]) for row in summary_rows),
        "canonical_decision_fingerprint_sha256": sha256_json(canonical_fingerprint),
        "semantic_fingerprint_hashes": dict(sorted(semantic_hashes.items())),
        "locked_controls": protocol["locked_controls"],
        "interpretation_limits": protocol["interpretation_limits"],
    }
    report_path = write_json(destination / "stage6_5_performance_report.json", report)
    output_files = [raw_path, memory_path, summary_path, report_path]
    manifest = {
        "run_id": report["run_id"],
        "profile": profile,
        "protocol_sha256": sha256_file(PROTOCOL_PATH),
        "output_files": {path.name: sha256_file(path) for path in sorted(output_files)},
    }
    manifest_path = write_json(destination / "stage6_5_output_manifest.json", manifest)
    return {
        "raw_trials": raw_path,
        "raw_memory": memory_path,
        "summary": summary_path,
        "report": report_path,
        "manifest": manifest_path,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    parser.add_argument("--profile", choices=("full", "smoke"), default="full")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--scenario-json", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=1)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.worker:
        if args.scenario_json is None or args.repository_root is None:
            raise SystemExit("worker mode requires --scenario-json and --repository-root")
        return _worker(
            args.scenario_json.resolve(),
            args.repository_root.resolve(),
            args.warmups,
            args.repetitions,
        )
    outputs = run(args.destination.resolve(), profile=args.profile)
    print("Stage 6.5 performance remediation completed:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
