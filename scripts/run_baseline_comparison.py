#!/usr/bin/env python3
"""Run the matched structured-but-unorchestrated PSIRT baseline comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any

from sbom_to_audit.baseline.protocol import load_protocol
from sbom_to_audit.baseline.workflow import (
    BASELINE_SOURCE_FIELDS,
    BASELINE_STATE_FIELDS,
    run_baseline_scenario,
)
from sbom_to_audit.cli import run as run_orchestrated
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_json, read_yaml, write_csv, write_json, write_jsonl

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "baseline_protocol_v0.1.yaml"
PRIMARY_SCENARIOS = (
    "ghost_logger",
    "false_comfort",
    "operational_outlier",
    "rapid_pivot",
)

OBSERVATION_FIELDS = [
    "observation_id",
    "event_id",
    "proposition",
    "value",
    "source_artifact_id",
    "source_uri",
    "source_hash",
    "timestamp",
    "confidence",
]

SCENARIO_COMPARISON_FIELDS = [
    "scenario_id",
    "scenario_role",
    "event_count",
    "orchestrated_final_state",
    "baseline_final_state",
    "orchestrated_EC",
    "baseline_EC",
    "orchestrated_TR",
    "baseline_TR",
    "orchestrated_CD",
    "baseline_CD",
    "orchestrated_CA",
    "baseline_CA",
    "orchestrated_AR",
    "baseline_AR",
    "orchestrated_SC",
    "baseline_SC",
    "orchestrated_EPG",
    "baseline_EPG",
    "orchestrated_conflict_count",
    "baseline_conflict_episode_count",
    "baseline_false_positive_conflict_count",
    "baseline_partial_traceability_ratio",
    "baseline_cumulative_source_review_count",
    "baseline_unique_source_count",
]

DIVERGENCE_FIELDS = [
    "scenario_id",
    "event_id",
    "timestamp",
    "expected_state",
    "orchestrated_state",
    "baseline_state",
    "orchestrated_match",
    "baseline_match",
    "baseline_conflict_flag",
    "baseline_rationale",
]

SUMMARY_FIELDS = [
    "metric",
    "orchestrated_primary_mean",
    "baseline_primary_mean",
    "difference",
    "applicable_primary_scenarios",
    "interpretation",
]


def _csv_safe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for row in rows:
        converted: dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, (dict, list)):
                converted[key] = json.dumps(value, sort_keys=True, separators=(",", ":"))
            else:
                converted[key] = value
        safe.append(converted)
    return safe


def _mean_applicable(rows: list[dict[str, Any]], key: str) -> tuple[float | None, int]:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    if not values:
        return None, 0
    return round(mean(values), 6), len(values)


def _metric_summary(primary_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    descriptions = {
        "EC": "Completeness of the final decision record against the frozen 34-field denominator.",
        "TR": (
            "Strict claim-level traceability; the baseline records sources but no "
            "standardized confidence."
        ),
        "CD": (
            "Recall of the intentionally seeded Ghost-Logger conflict; precision is "
            "reported separately."
        ),
        "CA": "Escalation at an eligible Prepare-at-18h safeguard opportunity.",
        "AR": "Presence of the minimum event fields needed to reconstruct the decision sequence.",
        "SC": "Agreement with controlled state oracles; not external legal or operational truth.",
        "EPG": "Generation of the defined EvidencePack outputs.",
    }
    output: list[dict[str, Any]] = []
    for metric in ("EC", "TR", "CD", "CA", "AR", "SC", "EPG"):
        orchestrated, applicable = _mean_applicable(primary_rows, f"orchestrated_{metric}")
        baseline, _ = _mean_applicable(primary_rows, f"baseline_{metric}")
        difference = None
        if orchestrated is not None and baseline is not None:
            difference = round(orchestrated - baseline, 6)
        output.append(
            {
                "metric": metric,
                "orchestrated_primary_mean": orchestrated,
                "baseline_primary_mean": baseline,
                "difference": difference,
                "applicable_primary_scenarios": applicable,
                "interpretation": descriptions[metric],
            }
        )
    return output


def _load_state_rows(path: Path) -> list[dict[str, Any]]:
    import csv

    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def run(output_root: str | Path) -> dict[str, Path]:
    """Run orchestrated and baseline workflows using the same controlled scenarios."""

    destination = Path(output_root).resolve()
    protocol = load_protocol(PROTOCOL_PATH)
    orchestrated_root = destination / "orchestrated"
    baseline_root = destination / "baseline"
    comparison_root = destination / "comparison"

    scenario_rows: list[dict[str, Any]] = []
    divergence_rows: list[dict[str, Any]] = []
    baseline_results: dict[str, dict[str, Any]] = {}

    for scenario_id in protocol.scenario_ids:
        scenario_path = ROOT / "data" / "scenarios" / f"{scenario_id}.yaml"
        scenario = read_yaml(scenario_path)
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario must contain an object: {scenario_path}")
        run_orchestrated(scenario_path, orchestrated_root)
        baseline = run_baseline_scenario(
            scenario,
            repository_root=ROOT,
            protocol=protocol,
        )
        baseline_results[scenario_id] = baseline

        write_json(
            baseline_root / "case_records" / f"{scenario_id}.json",
            baseline["case_record"],
        )
        write_csv(
            baseline_root / "source_worksheets" / f"{scenario_id}.csv",
            _csv_safe(baseline["source_rows"]),
            list(BASELINE_SOURCE_FIELDS),
        )
        write_csv(
            baseline_root / "decision_logs" / f"{scenario_id}.csv",
            _csv_safe(baseline["decision_rows"]),
            list(BASELINE_STATE_FIELDS),
        )
        write_csv(
            baseline_root / "observation_worksheets" / f"{scenario_id}.csv",
            _csv_safe(baseline["observation_rows"]),
            OBSERVATION_FIELDS,
        )
        write_jsonl(
            baseline_root / "audit_ledgers" / f"{scenario_id}.jsonl",
            baseline["audit_log"],
        )
        write_json(
            baseline_root / "metrics" / f"{scenario_id}_baseline_metrics.json",
            baseline["metrics"],
        )

        orchestrated_metrics = read_json(
            orchestrated_root / "metrics" / f"{scenario_id}_metrics.json"
        )
        orchestrated_states = _load_state_rows(
            orchestrated_root / "state_logs" / f"{scenario_id}.csv"
        )
        baseline_states = baseline["decision_rows"]
        if len(orchestrated_states) != len(baseline_states):
            raise AssertionError("matched comparison produced unequal event counts")
        for orchestrated, baseline_row in zip(orchestrated_states, baseline_states, strict=True):
            if orchestrated["event_id"] != baseline_row["event_id"]:
                raise AssertionError("matched comparison event IDs diverged")
            if orchestrated["observed_state"] != baseline_row["observed_state"]:
                divergence_rows.append(
                    {
                        "scenario_id": scenario_id,
                        "event_id": orchestrated["event_id"],
                        "timestamp": orchestrated["timestamp"],
                        "expected_state": orchestrated["expected_state"],
                        "orchestrated_state": orchestrated["observed_state"],
                        "baseline_state": baseline_row["observed_state"],
                        "orchestrated_match": orchestrated["state_match"],
                        "baseline_match": baseline_row["state_match"],
                        "baseline_conflict_flag": baseline_row["conflict_flag"],
                        "baseline_rationale": baseline_row["rationale"],
                    }
                )
        orchestrated_conflicts = read_json(
            orchestrated_root / "conflict_reports" / f"{scenario_id}.json"
        )
        baseline_metrics = baseline["metrics"]
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "scenario_role": (
                    "primary" if scenario_id in PRIMARY_SCENARIOS else "matched_control"
                ),
                "event_count": len(baseline_states),
                "orchestrated_final_state": orchestrated_states[-1]["observed_state"],
                "baseline_final_state": baseline_states[-1]["observed_state"],
                "orchestrated_EC": orchestrated_metrics["EC"],
                "baseline_EC": baseline_metrics["EC"],
                "orchestrated_TR": orchestrated_metrics["TR"],
                "baseline_TR": baseline_metrics["TR"],
                "orchestrated_CD": orchestrated_metrics["CD"],
                "baseline_CD": baseline_metrics["CD"],
                "orchestrated_CA": orchestrated_metrics["CA"],
                "baseline_CA": baseline_metrics["CA"],
                "orchestrated_AR": orchestrated_metrics["AR"],
                "baseline_AR": baseline_metrics["AR"],
                "orchestrated_SC": orchestrated_metrics["SC"],
                "baseline_SC": baseline_metrics["SC"],
                "orchestrated_EPG": orchestrated_metrics["EPG"],
                "baseline_EPG": baseline_metrics["EPG"],
                "orchestrated_conflict_count": orchestrated_conflicts["detected_conflicts"],
                "baseline_conflict_episode_count": baseline_metrics["supplemental"][
                    "conflict_episode_count"
                ],
                "baseline_false_positive_conflict_count": baseline_metrics["supplemental"][
                    "false_positive_conflict_count"
                ],
                "baseline_partial_traceability_ratio": baseline_metrics["supplemental"][
                    "partial_traceability_ratio"
                ],
                "baseline_cumulative_source_review_count": baseline_metrics["supplemental"][
                    "cumulative_source_review_count"
                ],
                "baseline_unique_source_count": baseline_metrics["supplemental"][
                    "unique_source_count"
                ],
            }
        )

    primary_rows = [row for row in scenario_rows if row["scenario_role"] == "primary"]
    metric_rows = _metric_summary(primary_rows)
    true_conflicts = sum(
        int(row["baseline_conflict_episode_count"])
        for row in scenario_rows
        if row["scenario_id"] == "ghost_logger"
    )
    baseline_total_conflicts = sum(
        int(row["baseline_conflict_episode_count"]) for row in scenario_rows
    )
    orchestrated_total_conflicts = sum(
        int(row["orchestrated_conflict_count"]) for row in scenario_rows
    )
    report = {
        "comparison_id": "STAGE6-MATCHED-BASELINE-PILOT-001",
        "evaluation_status": "PILOT_BASELINE_NOT_FROZEN",
        "manuscript_eligible": False,
        "protocol": {
            "path": str(PROTOCOL_PATH.relative_to(ROOT)),
            "sha256": sha256_file(PROTOCOL_PATH),
            "protocol_id": protocol.protocol_id,
            "protocol_version": protocol.protocol_version,
            "classification": protocol.classification,
        },
        "scenario_count": len(scenario_rows),
        "primary_scenario_count": len(primary_rows),
        "control_count": len(scenario_rows) - len(primary_rows),
        "primary_metrics": metric_rows,
        "state_divergence_count": len(divergence_rows),
        "conflict_precision": {
            "orchestrated": (
                1.0 if orchestrated_total_conflicts == true_conflicts and true_conflicts else None
            ),
            "baseline": (
                round(true_conflicts / baseline_total_conflicts, 6)
                if baseline_total_conflicts
                else None
            ),
            "true_conflict_episodes": true_conflicts,
            "orchestrated_total_detected": orchestrated_total_conflicts,
            "baseline_total_detected": baseline_total_conflicts,
        },
        "source_review_operation_proxy": {
            "definition": (
                "The orchestrated count is unique source ingestion; the baseline count is the "
                "sum of all sources visible at each repeated worksheet review. This is not human "
                "time or cognitive workload."
            ),
            "orchestrated_unique_source_ingestions": sum(
                int(row["baseline_unique_source_count"]) for row in scenario_rows
            ),
            "baseline_cumulative_source_reviews": sum(
                int(row["baseline_cumulative_source_review_count"]) for row in scenario_rows
            ),
        },
        "scenario_comparison_hash": sha256_json(scenario_rows),
        "divergence_hash": sha256_json(divergence_rows),
        "limitations": list(protocol.limitations),
        "interpretation_boundary": (
            "The comparison supports controlled functional differences attributable to the "
            "orchestration layer. It does not measure human analyst speed, legal correctness, "
            "or industrial effectiveness."
        ),
    }

    scenario_path = write_csv(
        comparison_root / "stage6_scenario_comparison.csv",
        _csv_safe(scenario_rows),
        SCENARIO_COMPARISON_FIELDS,
    )
    divergence_path = write_csv(
        comparison_root / "stage6_decision_divergence.csv",
        _csv_safe(divergence_rows),
        DIVERGENCE_FIELDS,
    )
    summary_csv = write_csv(
        comparison_root / "stage6_metric_summary.csv",
        _csv_safe(metric_rows),
        SUMMARY_FIELDS,
    )
    summary_json = write_json(
        comparison_root / "stage6_metric_summary.json",
        metric_rows,
    )
    report_path = write_json(
        comparison_root / "stage6_baseline_report.json",
        report,
    )
    return {
        "scenario_comparison": scenario_path,
        "decision_divergence": divergence_path,
        "metric_summary_csv": summary_csv,
        "metric_summary_json": summary_json,
        "baseline_report": report_path,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT / "outputs" / "stage6_baseline",
        help="Destination for matched orchestrated, baseline, and comparison outputs.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    paths = run(args.output_root)
    print("Stage 6 matched baseline comparison completed:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
