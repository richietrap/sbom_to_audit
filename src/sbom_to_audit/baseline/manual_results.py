"""Normalize completed manual baseline records and calculate evaluation metrics."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.evaluation_oracles import conflict_quality
from sbom_to_audit.baseline.fairness_metrics import (
    common_field_completeness,
    traceability_ratios,
)
from sbom_to_audit.baseline.manual_worksheet import load_manual_bundle
from sbom_to_audit.baseline.source_access_accounting import summarize_source_accesses
from sbom_to_audit.model.metrics import (
    audit_reconstructability,
    clock_aware_escalation,
    conflict_detection,
    evidence_completeness,
    state_correctness,
)
from sbom_to_audit.utils.io import read_yaml

FIELD_MAP = {
    "product_id": "product_context.product_id",
    "product_version": "product_context.product_version",
    "product_purl": "product_context.purl",
    "sbom_reference": "product_context.sbom_reference",
    "primary_identifier": "identity_resolution.primary_identifier",
    "matching_method": "identity_resolution.matching_method",
    "identity_confidence": "identity_resolution.gamma_id",
    "cve_id": "vulnerability_intelligence.cve_id",
    "cisa_kev_status": "vulnerability_intelligence.cisa_kev_status",
    "epss_percentile": "vulnerability_intelligence.epss_percentile",
    "csaf_vex_status": "supplier_assertions.csaf_vex_status",
    "csaf_reference": "supplier_assertions.csaf_reference",
    "execution_observed": "local_evidence.execution_observed",
    "reachability_confirmed": "local_evidence.reachability_confirmed",
    "telemetry_reference": "local_evidence.telemetry_reference",
    "asset_criticality": "asset_context.asset_criticality",
    "deployment_scope": "asset_context.deployment_scope",
    "mitigation_status": "mitigation_context.mitigation_status",
}


def _coerce(value: str) -> Any:
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    try:
        return float(text) if "." in text else int(text)
    except ValueError:
        return text


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    target = document
    parts = path.split(".")
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = value


def _hours(start: str, end: str) -> float:
    left = datetime.fromisoformat(start.replace("Z", "+00:00"))
    right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return round((right - left).total_seconds() / 3600.0, 6)


def normalize_manual_results(
    bundle_root: str | Path,
    repository_root: str | Path,
    state_oracle: dict[tuple[str, str], dict[str, Any]],
    conflict_oracle: dict[tuple[str, str], dict[str, Any]],
    clock_oracle: dict[tuple[str, str], dict[str, Any]],
    common_fields: list[str],
) -> dict[str, Any]:
    """Create evaluation-only records without modifying the analyst's original files."""

    root = Path(repository_root)
    bundle = load_manual_bundle(bundle_root)
    decisions = bundle["case_decisions.csv"]
    observations = bundle["evidence_observations.csv"]
    accesses = bundle["source_access_log.csv"]
    conflicts = bundle["conflict_log.csv"]
    timing = bundle["timing_log.csv"]

    by_scenario_decisions: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_scenario_observations: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_scenario_accesses: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_scenario_conflicts: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_scenario_timing: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in decisions:
        by_scenario_decisions[row["scenario_id"]].append(row)
    for row in observations:
        if row["observation_status"] == "OBSERVED":
            by_scenario_observations[row["scenario_id"]].append(row)
    for row in accesses:
        by_scenario_accesses[row["scenario_id"]].append(row)
    for row in conflicts:
        by_scenario_conflicts[row["scenario_id"]].append(row)
    for row in timing:
        by_scenario_timing[row["scenario_id"]].append(row)

    scenarios: dict[str, Any] = {}
    all_detected_conflicts: set[tuple[str, str]] = set()
    for scenario_id, scenario_decisions in by_scenario_decisions.items():
        scenario = read_yaml(root / "data" / "scenarios" / f"{scenario_id}.yaml")
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario must contain an object: {scenario_id}")
        order = {
            event["event_id"]: index for index, event in enumerate(scenario["replay_events"])
        }
        scenario_decisions.sort(key=lambda row: order[row["event_id"]])
        scenario_observations = by_scenario_observations[scenario_id]
        scenario_accesses = by_scenario_accesses[scenario_id]
        scenario_conflicts = by_scenario_conflicts[scenario_id]
        scenario_timing = by_scenario_timing[scenario_id]
        final_decision = scenario_decisions[-1]
        final_event = final_decision["event_id"]
        final_observations = [
            row for row in scenario_observations if row["event_id"] == final_event
        ]

        record: dict[str, Any] = {
            "schema_version": "0.2-evaluation-view",
            "case_metadata": {
                "case_id": scenario["case_metadata"]["case_id"],
                "generated_at": final_decision["decision_recorded_at"],
                "clock_start_time": scenario["case_metadata"]["clock_start_time"],
                "delta_t_hours": _hours(
                    scenario["case_metadata"]["clock_start_time"],
                    final_decision["event_timestamp"],
                ),
            },
            "product_context": {},
            "identity_resolution": {},
            "vulnerability_intelligence": {},
            "supplier_assertions": {},
            "local_evidence": {},
            "asset_context": {},
            "mitigation_context": {},
            "orchestration_metrics": {
                "E_t": None,
                "A_t": None,
                "I_t": None,
                "M_t": None,
                "U_t": None,
                "C_t": None,
            },
            "decision_state": {
                "recommended_state": final_decision["recommended_state"],
                "authorized_state": final_decision["authorized_state"] or None,
                "human_authorization_required": _coerce(
                    final_decision["human_authorization_required"]
                ),
                "rationale": final_decision["rationale"],
            },
            "claims": [],
            "source_artifacts": [],
            "audit_log": [],
        }
        for row in final_observations:
            mapped = FIELD_MAP.get(row["proposition"])
            if mapped:
                _set_path(record, mapped, _coerce(row["value"]))
        record["identity_resolution"]["matching_method"] = (
            final_decision["identity_matching_method"]
            or record["identity_resolution"].get("matching_method")
        )
        identity_confidence = _coerce(final_decision["identity_confidence"])
        if identity_confidence is not None:
            record["identity_resolution"]["gamma_id"] = identity_confidence

        claims: list[dict[str, Any]] = []
        for row in scenario_observations:
            claims.append(
                {
                    "claim_id": row["observation_id"],
                    "event_id": row["event_id"],
                    "proposition": row["proposition"],
                    "value": _coerce(row["value"]),
                    "source_artifact_id": row["source_artifact_id"],
                    "source_uri": row["source_uri"],
                    "source_hash": row["source_hash"],
                    "timestamp": row["source_timestamp"],
                    "confidence": _coerce(row["confidence"]),
                }
            )
        record["claims"] = claims
        source_ids: set[str] = set()
        for row in scenario_accesses:
            artifact_id = row["artifact_id"]
            if artifact_id not in source_ids:
                source_ids.add(artifact_id)
                record["source_artifacts"].append(
                    {
                        "artifact_id": artifact_id,
                        "first_accessed_at": row["accessed_at"],
                        "tool": row["tool"],
                    }
                )
        audit_rows: list[dict[str, Any]] = []
        for row in scenario_decisions:
            audit_rows.append(
                {
                    "event_id": row["event_id"],
                    "timestamp": row["decision_recorded_at"],
                    "actor": "manual_baseline_analyst",
                    "action": "record_psirt_posture",
                    "input_references": sorted(
                        {
                            access["artifact_id"]
                            for access in scenario_accesses
                            if access["event_id"] == row["event_id"]
                        }
                    ),
                    "output_state": row["recommended_state"],
                }
            )
        record["audit_log"] = audit_rows

        state_rows = [
            {
                "event_id": row["event_id"],
                "observed_state": row["recommended_state"],
                "expected_state": state_oracle[(scenario_id, row["event_id"])][
                    "expected_state"
                ],
            }
            for row in scenario_decisions
        ]
        detected = {
            (scenario_id, row["event_id"])
            for row in scenario_conflicts
            if row["classification"] == "CONFLICT"
        }
        all_detected_conflicts.update(detected)
        true_conflicts = sum(
            bool(row.get("expected_conflict"))
            for key, row in conflict_oracle.items()
            if key[0] == scenario_id
        )
        detected_true = sum(
            key in detected and bool(row.get("expected_conflict"))
            for key, row in conflict_oracle.items()
            if key[0] == scenario_id
        )
        opportunities = [
            {
                "observed_state": next(
                    decision["recommended_state"]
                    for decision in scenario_decisions
                    if decision["event_id"] == key[1]
                )
            }
            for key, row in clock_oracle.items()
            if key[0] == scenario_id
            and bool(row.get("eligible_prepare_to_escalate_opportunity"))
        ]
        ratios = traceability_ratios(claims)
        time_values = [
            float(row["elapsed_minutes"])
            for row in scenario_timing
            if row["elapsed_minutes"].strip()
        ]
        scenarios[scenario_id] = {
            "case_record": record,
            "state_rows": state_rows,
            "conflict_rows": scenario_conflicts,
            "source_access_rows": scenario_accesses,
            "timing_rows": scenario_timing,
            "metrics": {
                "EC": evidence_completeness(record),
                "TR": ratios["strict"],
                "CD": conflict_detection(detected_true, true_conflicts),
                "CA": clock_aware_escalation(opportunities),
                "AR": audit_reconstructability(audit_rows),
                "SC": state_correctness(state_rows),
                "EPG": 0,
                "supplemental": {
                    "common_field_completeness": common_field_completeness(
                        record, common_fields
                    ),
                    "partial_lineage_ratio": ratios["partial_lineage"],
                    "source_access": summarize_source_accesses(scenario_accesses),
                    "human_time_to_decision_minutes": round(sum(time_values), 6),
                    "equivalent_record_bundle_generation": 1,
                },
            },
        }

    overall_conflict = conflict_quality(all_detected_conflicts, conflict_oracle)
    return {
        "scenarios": scenarios,
        "overall_conflict_quality": {
            "true_positive": overall_conflict.true_positive,
            "false_positive": overall_conflict.false_positive,
            "false_negative": overall_conflict.false_negative,
            "true_negative": overall_conflict.true_negative,
            "precision": overall_conflict.precision,
            "recall": overall_conflict.recall,
        },
        "declaration": bundle["declaration.yaml"],
    }
