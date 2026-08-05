"""Deterministic Stage 6.2 robustness and sensitivity calculations."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict
from typing import Any

from sbom_to_audit.model.scoring import compute_scores
from sbom_to_audit.model.state_machine import Thresholds, recommend_state

THRESHOLD_NAMES = ("theta_A", "theta_E", "theta_I", "theta_U", "theta_N", "theta_L")
SUPPORTED_FACTORS = {
    "gamma_id",
    "cisa_kev_status",
    "epss_percentile",
    "csaf_vex_status",
    "execution_observed",
    "reachability_confirmed",
    "asset_criticality",
    "deployment_scope",
    "mitigation_status",
    "conflict",
    "malicious_exploitation_observed",
    "missing_telemetry_reference",
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def threshold_profile(profile_id: str, offset: float) -> dict[str, Any]:
    """Build one uniformly offset prototype-threshold profile."""

    base = Thresholds()
    values = asdict(base)
    for name in THRESHOLD_NAMES:
        values[name] = round(_clamp(float(values[name]) + float(offset)), 6)
    return {"profile_id": profile_id, "offset": float(offset), "thresholds": values}


def replay_threshold_profile(
    state_rows: list[dict[str, Any]],
    *,
    profile_id: str,
    offset: float,
) -> list[dict[str, Any]]:
    """Re-evaluate a frozen score trajectory under one threshold profile."""

    profile = threshold_profile(profile_id, offset)
    thresholds = Thresholds(**profile["thresholds"])
    previous_state: str | None = None
    results: list[dict[str, Any]] = []
    for row in state_rows:
        scores = {
            "E_t": float(row["E_t"]),
            "A_t": float(row["A_t"]),
            "I_t": float(row["I_t"]),
            "M_t": float(row["M_t"]),
            "U_t": float(row["U_t"]),
            "C_t": bool(row["C_t"]),
        }
        variant_state, rationale = recommend_state(
            scores,
            float(row["delta_t_hours"]),
            previous_state,
            thresholds,
        )
        baseline_state = str(row["observed_state"])
        results.append(
            {
                "event_id": str(row["event_id"]),
                "timestamp": str(row["timestamp"]),
                "profile_id": profile_id,
                "threshold_offset": float(offset),
                "baseline_state": baseline_state,
                "variant_state": variant_state,
                "state_changed": variant_state != baseline_state,
                "previous_variant_state": previous_state,
                "E_t": scores["E_t"],
                "A_t": scores["A_t"],
                "I_t": scores["I_t"],
                "M_t": scores["M_t"],
                "U_t": scores["U_t"],
                "C_t": scores["C_t"],
                "theta_A": thresholds.theta_A,
                "theta_E": thresholds.theta_E,
                "theta_I": thresholds.theta_I,
                "theta_U": thresholds.theta_U,
                "theta_N": thresholds.theta_N,
                "theta_L": thresholds.theta_L,
                "tau_E_hours": thresholds.tau_E_hours,
                "rationale": rationale,
            }
        )
        previous_state = variant_state
    return results


def replay_clock_profile(
    state_rows: list[dict[str, Any]],
    *,
    profile_id: str,
    tau_e_hours: float,
) -> list[dict[str, Any]]:
    """Re-evaluate a frozen score trajectory under one clock-safeguard value."""

    base = Thresholds()
    thresholds = Thresholds(
        theta_A=base.theta_A,
        theta_E=base.theta_E,
        theta_I=base.theta_I,
        theta_U=base.theta_U,
        theta_N=base.theta_N,
        theta_L=base.theta_L,
        tau_E_hours=float(tau_e_hours),
    )
    previous_state: str | None = None
    results: list[dict[str, Any]] = []
    for row in state_rows:
        scores = {
            "E_t": float(row["E_t"]),
            "A_t": float(row["A_t"]),
            "I_t": float(row["I_t"]),
            "M_t": float(row["M_t"]),
            "U_t": float(row["U_t"]),
            "C_t": bool(row["C_t"]),
        }
        variant_state, rationale = recommend_state(
            scores,
            float(row["delta_t_hours"]),
            previous_state,
            thresholds,
        )
        baseline_state = str(row["observed_state"])
        clock_triggered = bool(
            previous_state == "Prepare"
            and float(row["delta_t_hours"]) >= thresholds.tau_E_hours
            and variant_state == "Escalate"
            and not scores["C_t"]
        )
        results.append(
            {
                "event_id": str(row["event_id"]),
                "timestamp": str(row["timestamp"]),
                "profile_id": profile_id,
                "tau_E_hours": float(tau_e_hours),
                "baseline_state": baseline_state,
                "variant_state": variant_state,
                "state_changed": variant_state != baseline_state,
                "previous_variant_state": previous_state,
                "clock_safeguard_triggered": clock_triggered,
                "rationale": rationale,
            }
        )
        previous_state = variant_state
    return results


def _evaluation_claim(pack: dict[str, Any], enabled: bool) -> dict[str, Any]:
    identity = pack["identity_resolution"]
    vulnerability = pack["vulnerability_intelligence"]
    product = pack["product_context"]
    payload = {
        "proposition": "malicious_exploitation_observed",
        "value": enabled,
        "product_purl": product.get("purl"),
        "component_identifier": identity.get("primary_identifier"),
        "cve_id": vulnerability.get("cve_id"),
        "evaluation_scope": "stage6_2_controlled_single_factor_perturbation",
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "claim_id": f"CLAIM-STAGE62-MALICIOUS-{str(enabled).upper()}",
        "proposition": "malicious_exploitation_observed",
        "value": enabled,
        "scope": {
            "product_purl": product.get("purl"),
            "component_purl": identity.get("primary_identifier"),
            "cve_id": vulnerability.get("cve_id"),
        },
        "source_artifact_id": "ART-STAGE62-CONTROLLED-PERTURBATION",
        "source_uri": "evaluation:stage6_2/controlled_perturbation",
        "source_hash": digest,
        "timestamp": pack["case_metadata"]["generated_at"],
        "confidence": 1.0,
        "status": "active",
        "source_artifact_type": "evaluation_only_controlled_perturbation",
        "derivation": {
            "parser": "stage6_2_robustness_harness",
            "rule": "single_factor_malicious_exploitation_toggle",
        },
    }


def perturb_pack(pack: dict[str, Any], factor: str, value: Any) -> tuple[dict[str, Any], bool]:
    """Return an evaluation-only single-factor perturbation of one final pack."""

    if factor not in SUPPORTED_FACTORS:
        raise ValueError(f"unsupported Stage 6.2 factor: {factor}")
    mutated = deepcopy(pack)
    conflict = bool(mutated["orchestration_metrics"]["C_t"])

    if factor == "gamma_id":
        mutated["identity_resolution"]["gamma_id"] = float(value)
    elif factor == "cisa_kev_status":
        mutated["vulnerability_intelligence"]["cisa_kev_status"] = bool(value)
    elif factor == "epss_percentile":
        mutated["vulnerability_intelligence"]["epss_percentile"] = float(value)
    elif factor == "csaf_vex_status":
        mutated["supplier_assertions"]["csaf_vex_status"] = value
    elif factor == "execution_observed":
        mutated["local_evidence"]["execution_observed"] = bool(value)
    elif factor == "reachability_confirmed":
        mutated["local_evidence"]["reachability_confirmed"] = bool(value)
    elif factor == "asset_criticality":
        mutated["asset_context"]["asset_criticality"] = str(value)
    elif factor == "deployment_scope":
        mutated["asset_context"]["deployment_scope"] = str(value)
    elif factor == "mitigation_status":
        mutated["mitigation_context"]["mitigation_status"] = str(value)
    elif factor == "conflict":
        conflict = bool(value)
    elif factor == "malicious_exploitation_observed":
        claims = [
            claim
            for claim in mutated["claims"]
            if claim.get("proposition") != "malicious_exploitation_observed"
        ]
        claims.append(_evaluation_claim(mutated, bool(value)))
        mutated["claims"] = claims
    elif factor == "missing_telemetry_reference":
        mutated["local_evidence"]["telemetry_reference"] = (
            None if bool(value) else pack["local_evidence"].get("telemetry_reference")
        )

    return mutated, conflict


def evaluate_factor_variant(
    pack: dict[str, Any],
    *,
    factor: str,
    value: Any,
    delta_t_hours: float,
    previous_state: str | None,
) -> dict[str, Any]:
    """Evaluate one controlled single-factor perturbation at a frozen event boundary."""

    mutated, conflict = perturb_pack(pack, factor, value)
    scores = compute_scores(mutated, conflict=conflict, claims=mutated["claims"]).to_dict()
    variant_state, rationale = recommend_state(scores, delta_t_hours, previous_state)
    return {
        "factor": factor,
        "variant_value": value,
        "variant_state": variant_state,
        "E_t": scores["E_t"],
        "A_t": scores["A_t"],
        "I_t": scores["I_t"],
        "M_t": scores["M_t"],
        "U_t": scores["U_t"],
        "C_t": scores["C_t"],
        "rationale": rationale,
    }


def summarize_scenario_stability(
    scenario_id: str,
    threshold_rows: list[dict[str, Any]],
    factor_rows: list[dict[str, Any]],
    clock_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise observed sensitivity without claiming threshold validation."""

    non_baseline_thresholds = [
        row for row in threshold_rows if float(row["threshold_offset"]) != 0.0
    ]
    threshold_changes = sum(bool(row["state_changed"]) for row in non_baseline_thresholds)
    factor_changes = sum(bool(row["state_changed"]) for row in factor_rows)
    clock_changes = sum(bool(row["state_changed"]) for row in clock_rows)
    total_changes = threshold_changes + factor_changes + clock_changes
    if total_changes == 0:
        classification = "stable_across_registered_perturbations"
    elif threshold_changes > 0 and factor_changes == 0 and clock_changes == 0:
        classification = "threshold_boundary_sensitive"
    elif clock_changes > 0 and factor_changes == 0:
        classification = "clock_sensitive"
    else:
        classification = "multi_parameter_sensitive"
    return {
        "scenario_id": scenario_id,
        "threshold_variant_event_rows": len(non_baseline_thresholds),
        "threshold_state_changes": threshold_changes,
        "factor_variants": len(factor_rows),
        "factor_state_changes": factor_changes,
        "clock_variant_event_rows": len(clock_rows),
        "clock_state_changes": clock_changes,
        "total_state_changes": total_changes,
        "classification": classification,
    }
