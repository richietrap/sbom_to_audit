"""Frozen EvidencePack v0.2 evaluation metrics."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

MANDATORY_FIELDS: tuple[str, ...] = (
    "case_metadata.case_id",
    "case_metadata.generated_at",
    "case_metadata.clock_start_time",
    "case_metadata.delta_t_hours",
    "product_context.product_id",
    "product_context.product_version",
    "product_context.purl",
    "product_context.sbom_reference",
    "identity_resolution.primary_identifier",
    "identity_resolution.matching_method",
    "identity_resolution.gamma_id",
    "vulnerability_intelligence.cve_id",
    "vulnerability_intelligence.cisa_kev_status",
    "vulnerability_intelligence.epss_percentile",
    "supplier_assertions.csaf_vex_status",
    "supplier_assertions.csaf_reference",
    "local_evidence.execution_observed",
    "local_evidence.reachability_confirmed",
    "local_evidence.telemetry_reference",
    "asset_context.asset_criticality",
    "asset_context.deployment_scope",
    "mitigation_context.mitigation_status",
    "orchestration_metrics.E_t",
    "orchestration_metrics.A_t",
    "orchestration_metrics.I_t",
    "orchestration_metrics.M_t",
    "orchestration_metrics.U_t",
    "orchestration_metrics.C_t",
    "decision_state.recommended_state",
    "decision_state.human_authorization_required",
    "decision_state.rationale",
    "claims[]",
    "source_artifacts[]",
    "audit_log[]",
)
TRACEABILITY_FIELDS = (
    "source_artifact_id",
    "source_uri",
    "source_hash",
    "timestamp",
    "confidence",
)


def _populated(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True  # zero and Boolean false are populated


def _path_value(document: dict[str, Any], path: str) -> Any:
    if path.endswith("[]"):
        return document.get(path[:-2])
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def evidence_completeness(pack: dict[str, Any]) -> float:
    populated = sum(_populated(_path_value(pack, path)) for path in MANDATORY_FIELDS)
    return round(populated / len(MANDATORY_FIELDS), 6)


def claim_traceable(claim: dict[str, Any]) -> bool:
    return all(_populated(claim.get(field)) for field in TRACEABILITY_FIELDS)


def traceability_ratio(claims: list[dict[str, Any]]) -> float:
    if not claims:
        return 0.0
    return round(sum(claim_traceable(claim) for claim in claims) / len(claims), 6)


def conflict_detection(detected: int, seeded: int) -> float | None:
    if seeded < 0 or detected < 0:
        raise ValueError("conflict counts must be non-negative")
    if seeded == 0:
        return None
    return round(detected / seeded, 6)


def clock_aware_escalation(opportunities: Iterable[dict[str, Any]]) -> float | None:
    rows = list(opportunities)
    if not rows:
        return None
    escalated = sum(row.get("observed_state") == "Escalate" for row in rows)
    return round(escalated / len(rows), 6)


def audit_reconstructability(entries: list[dict[str, Any]]) -> float:
    if not entries:
        return 0.0
    required = ("event_id", "timestamp", "actor", "action", "input_references", "output_state")
    reconstructable = sum(all(_populated(entry.get(key)) for key in required) for entry in entries)
    return round(reconstructable / len(entries), 6)


def state_correctness(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    correct = sum(row.get("observed_state") == row.get("expected_state") for row in rows)
    return round(correct / len(rows), 6)


def evidence_pack_generation(paths: Iterable[str | Path]) -> int:
    return int(all(Path(path).is_file() for path in paths))
