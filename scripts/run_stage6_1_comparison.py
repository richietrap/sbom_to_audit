#!/usr/bin/env python3
"""Run the hardened Stage 6.1 comparison using completed manual baseline records."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.evaluation_oracles import (
    conflict_quality,
    load_conflict_oracle,
)
from sbom_to_audit.baseline.fairness_metrics import common_field_completeness
from sbom_to_audit.baseline.source_access_accounting import summarize_source_accesses
from sbom_to_audit.cli import run as run_orchestrated
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_json, read_yaml, write_csv, write_json

ROOT = Path(__file__).resolve().parents[1]
PRIMARY = {"ghost_logger", "false_comfort", "operational_outlier", "rapid_pivot"}
METRICS = ("EC", "TR", "CD", "CA", "AR", "SC", "EPG")


def _common_fields() -> list[str]:
    payload = read_yaml(ROOT / "evaluation" / "mappings" / "common_field_set_v0.1.yaml")
    if not isinstance(payload, dict) or not isinstance(payload.get("field_paths"), list):
        raise ValueError("common field mapping is invalid")
    return [str(value) for value in payload["field_paths"]]


def _orchestrated_conflicts(output_root: Path, scenario_ids: list[str]) -> set[tuple[str, str]]:
    detected: set[tuple[str, str]] = set()
    for scenario_id in scenario_ids:
        report = read_json(output_root / "conflict_reports" / f"{scenario_id}.json")
        for conflict in report.get("conflicts") or []:
            event_id = str(conflict.get("detected_at_event_id") or "")
            if event_id:
                detected.add((scenario_id, event_id))
    return detected


def _orchestrated_source_accesses(scenario_id: str) -> list[dict[str, str]]:
    scenario = read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
    if not isinstance(scenario, dict):
        raise ValueError(f"scenario must contain an object: {scenario_id}")
    rows: list[dict[str, str]] = []
    for event in scenario.get("replay_events") or []:
        for artifact_id in event.get("release_artifact_ids") or []:
            rows.append(
                {
                    "scenario_id": scenario_id,
                    "event_id": str(event["event_id"]),
                    "artifact_id": str(artifact_id),
                }
            )
    return rows


def _mean(values: list[float | int | None]) -> float | None:
    numeric = [float(value) for value in values if value is not None]
    return round(sum(numeric) / len(numeric), 6) if numeric else None


def run(normalized_manual: Path, destination: Path) -> dict[str, Path]:
    manual = read_json(normalized_manual)
    scenarios = manual.get("scenarios") or {}
    scenario_ids = list(scenarios)
    if not scenario_ids:
        raise ValueError("normalized manual baseline contains no scenarios")
    orchestrated_root = destination / "orchestrated"
    comparison_root = destination / "comparison"
    if destination.exists():
        shutil.rmtree(destination)
    orchestrated_root.mkdir(parents=True)
    comparison_root.mkdir(parents=True)
    for scenario_id in scenario_ids:
        run_orchestrated(
            ROOT / "data" / "scenarios" / f"{scenario_id}.yaml", orchestrated_root
        )

    common_fields = _common_fields()
    scenario_rows: list[dict[str, Any]] = []
    for scenario_id, manual_result in scenarios.items():
        orchestrated_metrics = read_json(
            orchestrated_root / "metrics" / f"{scenario_id}_metrics.json"
        )
        evidence_pack = read_json(
            orchestrated_root / "evidence_packs" / f"{scenario_id}.json"
        )
        manual_metrics = manual_result["metrics"]
        orchestrated_access = summarize_source_accesses(
            _orchestrated_source_accesses(scenario_id)
        )
        manual_access = manual_metrics["supplemental"]["source_access"]
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "scenario_role": "primary" if scenario_id in PRIMARY else "matched_control",
                **{
                    f"orchestrated_{metric}": orchestrated_metrics.get(metric)
                    for metric in METRICS
                },
                **{
                    f"manual_{metric}": manual_metrics.get(metric) for metric in METRICS
                },
                "orchestrated_common_field_completeness": common_field_completeness(
                    evidence_pack, common_fields
                ),
                "manual_common_field_completeness": manual_metrics["supplemental"][
                    "common_field_completeness"
                ],
                "manual_partial_lineage_ratio": manual_metrics["supplemental"][
                    "partial_lineage_ratio"
                ],
                "orchestrated_equivalent_record_bundle_generation": 1,
                "manual_equivalent_record_bundle_generation": manual_metrics["supplemental"][
                    "equivalent_record_bundle_generation"
                ],
                "orchestrated_distinct_source_artifacts_accessed": orchestrated_access[
                    "distinct_source_artifacts_accessed"
                ],
                "manual_distinct_source_artifacts_accessed": manual_access[
                    "distinct_source_artifacts_accessed"
                ],
                "manual_human_time_to_decision_minutes": manual_metrics["supplemental"][
                    "human_time_to_decision_minutes"
                ],
            }
        )

    primary_rows = [row for row in scenario_rows if row["scenario_role"] == "primary"]
    metric_rows: list[dict[str, Any]] = []
    for metric in METRICS:
        orchestrated_mean = _mean([row[f"orchestrated_{metric}"] for row in primary_rows])
        manual_mean = _mean([row[f"manual_{metric}"] for row in primary_rows])
        metric_rows.append(
            {
                "metric": metric,
                "orchestrated_primary_mean": orchestrated_mean,
                "manual_primary_mean": manual_mean,
                "difference": (
                    round(orchestrated_mean - manual_mean, 6)
                    if orchestrated_mean is not None and manual_mean is not None
                    else None
                ),
            }
        )

    conflict_oracle = load_conflict_oracle(
        ROOT / "evaluation" / "oracles" / "conflict_oracle_v0.1.yaml"
    )
    orchestrated_conflict = conflict_quality(
        _orchestrated_conflicts(orchestrated_root, scenario_ids), conflict_oracle
    )
    manual_conflict = manual["overall_conflict_quality"]
    report = {
        "comparison_id": "STAGE6-1-MATCHED-MANUAL-BASELINE-CANDIDATE-001",
        "evaluation_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "manual_baseline_classification": (
            "NON_BLINDED_RESEARCHER_EXECUTED"
            if manual.get("declaration", {}).get("automated_outputs_seen_before_execution")
            else "BLINDED_MANUAL_ASSISTED"
        ),
        "scenario_count": len(scenario_rows),
        "primary_scenario_count": len(primary_rows),
        "locked_metrics": metric_rows,
        "conflict_quality": {
            "orchestrated": orchestrated_conflict.__dict__,
            "manual_baseline": manual_conflict,
        },
        "fairness_controls": {
            "common_field_completeness_reported": True,
            "partial_lineage_reported": True,
            "equivalent_record_bundle_reported": True,
            "source_access_accounting_like_for_like": True,
            "clock_interpretation": (
                "CA remains locked. Automatic tau_E ablation and recorded human clock awareness "
                "must be interpreted separately."
            ),
        },
        "scenario_comparison_sha256": sha256_json(scenario_rows),
        "manual_normalized_sha256": sha256_file(normalized_manual),
        "limitations": [
            "The 34-field EC and EPG metrics remain schema-specific.",
            "State correctness is rule-conformance against controlled oracles.",
            "A researcher-executed run is not independent practitioner validation.",
            "No legal or industrial effectiveness claim is supported.",
        ],
    }
    scenario_path = write_csv(
        comparison_root / "stage6_1_scenario_comparison.csv",
        scenario_rows,
        list(scenario_rows[0]),
    )
    metric_path = write_csv(
        comparison_root / "stage6_1_locked_metric_summary.csv",
        metric_rows,
        ["metric", "orchestrated_primary_mean", "manual_primary_mean", "difference"],
    )
    report_path = write_json(comparison_root / "stage6_1_comparison_report.json", report)
    return {
        "scenario_comparison": scenario_path,
        "metric_summary": metric_path,
        "report": report_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("normalized_manual", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    paths = run(args.normalized_manual, args.destination)
    print("Stage 6.1 comparison generated:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
