"""Independent validation of Stage 6.1 comparison evidence."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.evaluation_oracles import conflict_quality
from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_json

STRING_FIELDS = {"scenario_id", "scenario_role"}
INTEGER_FIELDS = {
    "orchestrated_EPG",
    "manual_EPG",
    "orchestrated_equivalent_record_bundle_generation",
    "manual_equivalent_record_bundle_generation",
    "orchestrated_distinct_source_artifacts_accessed",
    "manual_distinct_source_artifacts_accessed",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _typed_scenario_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in _read_csv(path):
        row: dict[str, Any] = {}
        for field, value in raw.items():
            if field in STRING_FIELDS:
                row[field] = value
            elif value == "":
                row[field] = None
            elif field in INTEGER_FIELDS:
                row[field] = int(value)
            else:
                row[field] = float(value)
        rows.append(row)
    return rows


def _typed_metric_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in _read_csv(path):
        row: dict[str, Any] = {"metric": raw["metric"]}
        for field in (
            "orchestrated_primary_mean",
            "manual_primary_mean",
            "difference",
        ):
            row[field] = None if raw[field] == "" else float(raw[field])
        rows.append(row)
    return rows


def _mean(values: list[float | int | None]) -> float | None:
    numeric = [float(value) for value in values if value is not None]
    return round(sum(numeric) / len(numeric), 6) if numeric else None


def _expected_metrics(
    rows: list[dict[str, Any]],
    metrics: tuple[str, ...],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]]]:
    primary = [row for row in rows if row["scenario_role"] == "primary"]
    result: list[dict[str, Any]] = []
    counts: dict[str, dict[str, int]] = {}

    for metric in metrics:
        ov = [row[f"orchestrated_{metric}"] for row in primary]
        mv = [row[f"manual_{metric}"] for row in primary]
        om = _mean(ov)
        mm = _mean(mv)

        result.append(
            {
                "metric": metric,
                "orchestrated_primary_mean": om,
                "manual_primary_mean": mm,
                "difference": (round(om - mm, 6) if om is not None and mm is not None else None),
            }
        )
        counts[metric] = {
            "orchestrated": sum(value is not None for value in ov),
            "manual": sum(value is not None for value in mv),
        }

    return result, counts


def _manual_conflicts(manual: dict[str, Any]) -> set[tuple[str, str]]:
    detected: set[tuple[str, str]] = set()
    for scenario_id, result in (manual.get("scenarios") or {}).items():
        for row in result.get("conflict_rows") or []:
            if str(row.get("classification") or "").upper() != "CONFLICT":
                continue
            event_id = str(row.get("event_id") or "")
            if event_id:
                detected.add((str(scenario_id), event_id))
    return detected


def _orchestrated_conflicts(
    root: Path,
    scenario_ids: list[str],
    errors: list[str],
) -> set[tuple[str, str]]:
    detected: set[tuple[str, str]] = set()
    for scenario_id in scenario_ids:
        path = root / "conflict_reports" / f"{scenario_id}.json"
        if not path.is_file():
            errors.append(f"missing orchestrated conflict report: {path}")
            continue
        payload = read_json(path)
        for conflict in payload.get("conflicts") or []:
            event_id = str(conflict.get("detected_at_event_id") or "")
            if event_id:
                detected.add((scenario_id, event_id))
    return detected


def validate_comparison_evidence(
    comparison_report: Path,
    *,
    protocol: Any,
    conflict_oracle: Any,
    normalized_manual: Path | None = None,
) -> tuple[list[str], dict[str, object]]:
    errors: list[str] = []
    checks: dict[str, object] = {}

    try:
        report = read_json(comparison_report)
    except Exception as exc:
        return [f"comparison report could not be read: {exc}"], checks

    if not isinstance(report, dict):
        return ["comparison report must contain a JSON object"], checks

    comparison_root = comparison_report.parent
    run_root = comparison_root.parent.parent

    scenario_path = comparison_root / "stage6_1_scenario_comparison.csv"
    metric_path = comparison_root / "stage6_1_locked_metric_summary.csv"
    orchestrated_root = comparison_root.parent / "orchestrated"

    if normalized_manual is None:
        normalized_manual = (
            run_root / "imported" / "normalized" / "stage6_1_manual_baseline_normalized.json"
        )

    required = {
        "scenario comparison": scenario_path,
        "metric summary": metric_path,
        "normalized manual baseline": normalized_manual,
    }

    for label, path in required.items():
        if not path.is_file():
            errors.append(f"missing {label}: {path}")

    if errors:
        return errors, checks

    try:
        scenario_rows = _typed_scenario_rows(scenario_path)
        metric_rows = _typed_metric_rows(metric_path)
        manual = read_json(normalized_manual)
    except Exception as exc:
        return [f"comparison evidence could not be parsed: {exc}"], checks

    if not isinstance(manual, dict):
        return ["normalized manual baseline must contain a JSON object"], checks

    scenario_ids = [str(row["scenario_id"]) for row in scenario_rows]
    expected_ids = list(protocol.scenario_ids)

    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("scenario comparison contains duplicate scenario identifiers")

    if set(scenario_ids) != set(expected_ids):
        errors.append("scenario comparison scenario identifiers do not match protocol")

    primary_ids = {
        scenario_id for scenario_id in expected_ids if not scenario_id.endswith("_control")
    }

    for row in scenario_rows:
        expected_role = "primary" if row["scenario_id"] in primary_ids else "matched_control"
        if row["scenario_role"] != expected_role:
            errors.append(f"scenario role mismatch: {row['scenario_id']}")

    primary_rows = [row for row in scenario_rows if row["scenario_role"] == "primary"]

    metrics = tuple(protocol.locked_metrics)
    expected_metrics, applicable = _expected_metrics(
        scenario_rows,
        metrics,
    )

    if report.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        errors.append("Stage 6.1 comparison status must remain CANDIDATE_NOT_FROZEN")

    if report.get("manuscript_eligible") is not False:
        errors.append("Stage 6.1 candidate must remain manuscript-ineligible before final tag")

    if report.get("scenario_count") != len(scenario_rows):
        errors.append("comparison report scenario_count does not match CSV")

    if report.get("primary_scenario_count") != len(primary_rows):
        errors.append("comparison report primary_scenario_count does not match CSV")

    reported_metric_names = [row.get("metric") for row in report.get("locked_metrics") or []]

    if reported_metric_names != list(metrics):
        errors.append("comparison report locked metric order does not match protocol")

    if report.get("locked_metrics") != expected_metrics:
        errors.append("comparison report locked metrics do not match recomputed means")

    if metric_rows != expected_metrics:
        errors.append("metric summary CSV does not match recomputed means")

    scenario_hash = sha256_json(scenario_rows)
    if report.get("scenario_comparison_sha256") != scenario_hash:
        errors.append("scenario comparison semantic SHA-256 mismatch")

    manual_hash = sha256_file(normalized_manual)
    if report.get("manual_normalized_sha256") != manual_hash:
        errors.append("normalized manual baseline SHA-256 mismatch")

    expected_classification = (
        "NON_BLINDED_RESEARCHER_EXECUTED"
        if manual.get("declaration", {}).get("automated_outputs_seen_before_execution")
        else "BLINDED_MANUAL_ASSISTED"
    )

    if report.get("manual_baseline_classification") != expected_classification:
        errors.append("manual baseline classification does not match declaration")

    manual_quality = conflict_quality(
        _manual_conflicts(manual),
        conflict_oracle,
    ).__dict__

    if manual.get("overall_conflict_quality") != manual_quality:
        errors.append("normalized manual conflict quality does not match frozen oracle")

    orchestrated_detected = _orchestrated_conflicts(
        orchestrated_root,
        expected_ids,
        errors,
    )

    orchestrated_quality = conflict_quality(
        orchestrated_detected,
        conflict_oracle,
    ).__dict__

    expected_conflict_quality = {
        "orchestrated": orchestrated_quality,
        "manual_baseline": manual_quality,
    }

    if report.get("conflict_quality") != expected_conflict_quality:
        errors.append("comparison report conflict quality does not match frozen oracle")

    checks.update(
        {
            "comparison_id": report.get("comparison_id"),
            "comparison_integrity_verified": not errors,
            "scenario_rows": len(scenario_rows),
            "primary_rows": len(primary_rows),
            "applicable_primary_counts": applicable,
            "scenario_comparison_semantic_sha256": scenario_hash,
            "scenario_comparison_file_sha256": sha256_file(scenario_path),
            "metric_summary_file_sha256": sha256_file(metric_path),
            "manual_normalized_sha256": manual_hash,
            "conflict_quality_verified": (
                report.get("conflict_quality") == expected_conflict_quality
            ),
        }
    )

    return errors, checks
