"""Scenario replay and EvidencePack v0.2 construction."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from sbom_to_audit.model.scoring import compute_scores
from sbom_to_audit.model.state_machine import recommend_state
from sbom_to_audit.utils.hashing import sha256_json
from sbom_to_audit.utils.time import delta_hours

EVIDENCE_BLOCKS = (
    "product_context",
    "identity_resolution",
    "vulnerability_intelligence",
    "supplier_assertions",
    "local_evidence",
    "asset_context",
    "mitigation_context",
)


def _deep_update(target: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = deepcopy(value)
    return target


def detect_conflicts(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_proposition: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        by_proposition.setdefault(str(claim.get("proposition")), []).append(claim)

    conflicts: list[dict[str, Any]] = []
    for proposition, proposition_claims in sorted(by_proposition.items()):
        normalized = {repr(claim.get("value")) for claim in proposition_claims}
        if len(normalized) > 1:
            conflicts.append(
                {
                    "conflict_id": f"CONFLICT-{len(conflicts) + 1:03d}",
                    "proposition": proposition,
                    "claim_ids": [claim["claim_id"] for claim in proposition_claims],
                    "values": [claim.get("value") for claim in proposition_claims],
                    "sources": [claim.get("source_artifact_id") for claim in proposition_claims],
                }
            )
    return conflicts


def replay_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    required = ["case_metadata", *EVIDENCE_BLOCKS, "claims", "source_artifacts", "replay_events"]
    missing = [key for key in required if key not in scenario]
    if missing:
        raise ValueError(f"scenario missing required blocks: {', '.join(missing)}")

    snapshot = {block: deepcopy(scenario[block]) for block in EVIDENCE_BLOCKS}
    claim_index = {claim["claim_id"]: deepcopy(claim) for claim in scenario["claims"]}
    t0 = scenario["case_metadata"]["clock_start_time"]
    state_rows: list[dict[str, Any]] = []
    audit_log: list[dict[str, Any]] = []
    all_conflicts: list[dict[str, Any]] = []
    previous_state: str | None = None
    active_claims: list[dict[str, Any]] = []
    final_scores: dict[str, Any] | None = None
    final_rationale = ""
    final_timestamp = t0

    for event in scenario["replay_events"]:
        _deep_update(snapshot, event.get("evidence_overrides") or {})
        active_claims = [claim_index[claim_id] for claim_id in event.get("active_claim_ids") or []]
        event_conflicts = detect_conflicts(active_claims)
        for conflict in event_conflicts:
            if conflict not in all_conflicts:
                all_conflicts.append(conflict)

        event_delta = delta_hours(t0, event["timestamp"])
        score_obj = compute_scores(snapshot, conflict=bool(event_conflicts), claims=active_claims)
        final_scores = score_obj.to_dict()
        observed_state, rationale = recommend_state(final_scores, event_delta, previous_state)
        final_rationale = rationale
        final_timestamp = event["timestamp"]

        state_rows.append(
            {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "delta_t_hours": event_delta,
                **final_scores,
                "previous_state": previous_state or "",
                "observed_state": observed_state,
                "expected_state": event["expected_state"],
                "state_match": observed_state == event["expected_state"],
                "rationale": rationale,
            }
        )
        audit_log.append(
            {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "actor": "sbom_to_audit.state_machine",
                "action": "evaluate_temporal_state",
                "input_references": event.get("active_claim_ids") or [],
                "input_hash": sha256_json(
                    {
                        "snapshot": snapshot,
                        "active_claim_ids": event.get("active_claim_ids") or [],
                        "delta_t_hours": event_delta,
                    }
                ),
                "output_state": observed_state,
                "expected_state": event["expected_state"],
                "rationale": rationale,
            }
        )
        previous_state = observed_state

    if final_scores is None:
        raise ValueError("scenario must contain at least one replay event")

    final_delta = delta_hours(t0, final_timestamp)
    pack = {
        "schema_version": "0.2",
        "case_metadata": {
            "case_id": scenario["case_metadata"]["case_id"],
            "generated_at": final_timestamp,
            "clock_start_time": t0,
            "delta_t_hours": final_delta,
        },
        "product_context": deepcopy(snapshot["product_context"]),
        "identity_resolution": deepcopy(snapshot["identity_resolution"]),
        "vulnerability_intelligence": deepcopy(snapshot["vulnerability_intelligence"]),
        "supplier_assertions": deepcopy(snapshot["supplier_assertions"]),
        "local_evidence": deepcopy(snapshot["local_evidence"]),
        "asset_context": deepcopy(snapshot["asset_context"]),
        "mitigation_context": deepcopy(snapshot["mitigation_context"]),
        "orchestration_metrics": final_scores,
        "decision_state": {
            "recommended_state": previous_state,
            "authorized_state": None,
            "human_authorization_required": True,
            "rationale": final_rationale,
        },
        "claims": active_claims,
        "source_artifacts": deepcopy(scenario["source_artifacts"]),
        "audit_log": audit_log,
    }
    return {
        "pack": pack,
        "state_rows": state_rows,
        "conflicts": all_conflicts,
        "final_active_claims": active_claims,
    }
