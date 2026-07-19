"""Transparent EvidencePack v0.2 prototype scoring functions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from sbom_to_audit.model.identity import apply_identity_uncertainty, clamp

CRITICALITY_SCORES = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00}
SCOPE_SCORES = {"isolated": 0.25, "limited": 0.50, "broad": 0.75, "widespread": 1.00}
MITIGATION_SCORES = {
    "none": 0.00,
    "planned": 0.25,
    "partial": 0.50,
    "workaround": 0.50,
    "deployed": 0.75,
    "verified": 1.00,
}
AFFECTED_STATUSES = {"known_affected", "affected"}
NOT_AFFECTED_STATUSES = {"known_not_affected", "not_affected"}
UNCERTAINTY_FIELDS = (
    ("vulnerability_intelligence", "cisa_kev_status"),
    ("vulnerability_intelligence", "epss_percentile"),
    ("supplier_assertions", "csaf_vex_status"),
    ("local_evidence", "execution_observed"),
    ("local_evidence", "reachability_confirmed"),
    ("local_evidence", "telemetry_reference"),
    ("asset_context", "asset_criticality"),
    ("asset_context", "deployment_scope"),
    ("mitigation_context", "mitigation_status"),
)


@dataclass(frozen=True)
class Scores:
    E_t: float
    A_t: float
    I_t: float
    M_t: float
    U_t: float
    C_t: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "E_t": self.E_t,
            "A_t": self.A_t,
            "I_t": self.I_t,
            "M_t": self.M_t,
            "U_t": self.U_t,
            "C_t": self.C_t,
        }


TRACEABILITY_FIELDS = (
    "source_artifact_id",
    "source_uri",
    "source_hash",
    "timestamp",
    "confidence",
)


def _claim_traceable(claim: Mapping[str, Any]) -> bool:
    return all(claim.get(field) is not None and claim.get(field) != "" for field in TRACEABILITY_FIELDS)


def _active_malicious_exploitation_claim(claims: Iterable[Mapping[str, Any]]) -> bool:
    for claim in claims:
        status = str(claim.get("status") or "active").strip().lower()
        if status not in {"active", "confirmed"}:
            continue
        if (
            str(claim.get("proposition") or "").strip().lower()
            == "malicious_exploitation_observed"
            and claim.get("value") is True
            and _claim_traceable(claim)
        ):
            return True
    return False


def exploitation_score(
    vulnerability: dict[str, Any],
    local: dict[str, Any] | None = None,
    claims: Iterable[Mapping[str, Any]] = (),
) -> float:
    """Compute graded exploitation evidence without conflating execution.

    ``local`` remains in the signature for backward compatibility, but
    vulnerable-function execution and reachability do not contribute to
    ``E_t``. They are applicability evidence evaluated by
    :func:`applicability_score`.
    """

    del local
    candidates = [0.0]
    if _active_malicious_exploitation_claim(claims):
        candidates.append(1.0)
    if vulnerability.get("cisa_kev_status") is True:
        candidates.append(0.85)
    percentile = vulnerability.get("epss_percentile")
    if percentile is not None:
        candidates.append(0.60 * clamp(float(percentile)))
    return round(max(candidates), 6)


def applicability_score(
    supplier: dict[str, Any], local: dict[str, Any], gamma_id: float
) -> float:
    if local.get("execution_observed") is True or local.get("reachability_confirmed") is True:
        return 1.0
    status = str(supplier.get("csaf_vex_status") or "").strip().lower()
    candidates = [0.60 * clamp(gamma_id)]
    if status in AFFECTED_STATUSES:
        candidates.append(0.80)
    elif status in NOT_AFFECTED_STATUSES:
        candidates.append(0.10)
        # A supplier not-affected assertion is the strongest active applicability
        # statement when no local reachability or execution evidence exists.
        return 0.10
    return round(max(candidates), 6)


def impact_score(asset: dict[str, Any]) -> float:
    criticality = str(asset.get("asset_criticality") or "").lower()
    scope = str(asset.get("deployment_scope") or "").lower()
    if criticality not in CRITICALITY_SCORES:
        raise ValueError(f"unsupported asset criticality: {criticality!r}")
    if scope not in SCOPE_SCORES:
        raise ValueError(f"unsupported deployment scope: {scope!r}")
    return round((CRITICALITY_SCORES[criticality] + SCOPE_SCORES[scope]) / 2, 6)


def mitigation_score(mitigation: dict[str, Any]) -> float:
    status = str(mitigation.get("mitigation_status") or "").lower()
    if status not in MITIGATION_SCORES:
        raise ValueError(f"unsupported mitigation status: {status!r}")
    return MITIGATION_SCORES[status]


def uncertainty_score(snapshot: dict[str, Any], gamma_id: float, lambda_id: float = 0.5) -> float:
    missing = 0
    for block, field in UNCERTAINTY_FIELDS:
        value = (snapshot.get(block) or {}).get(field)
        if value is None or value == "":
            missing += 1
    base = 0.4 * (missing / len(UNCERTAINTY_FIELDS))
    return apply_identity_uncertainty(base, gamma_id, lambda_id)


def compute_scores(
    snapshot: dict[str, Any],
    conflict: bool,
    claims: Iterable[Mapping[str, Any]] = (),
) -> Scores:
    identity = snapshot.get("identity_resolution") or {}
    gamma_value = identity.get("gamma_id")
    if gamma_value is None:
        raise ValueError("identity_resolution.gamma_id is required for scoring")
    gamma_id = float(gamma_value)
    return Scores(
        E_t=exploitation_score(
            snapshot["vulnerability_intelligence"],
            snapshot["local_evidence"],
            claims,
        ),
        A_t=applicability_score(snapshot["supplier_assertions"], snapshot["local_evidence"], gamma_id),
        I_t=impact_score(snapshot["asset_context"]),
        M_t=mitigation_score(snapshot["mitigation_context"]),
        U_t=uncertainty_score(snapshot, gamma_id),
        C_t=bool(conflict),
    )
