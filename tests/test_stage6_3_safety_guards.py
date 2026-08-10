from pathlib import Path

import pytest

from sbom_to_audit.model.authorization import (
    HumanAuthorizationEvent,
    MilestoneSatisfactionEvidence,
    authorization_audit_event,
)
from sbom_to_audit.model.conflict_engine import detect_conflicts
from sbom_to_audit.model.identity import apply_identity_uncertainty
from sbom_to_audit.model.metrics import audit_reconstructability, evidence_pack_generation
from sbom_to_audit.model.state_machine import recommend_state


def _scores(**overrides):
    values = {"E_t": 0.0, "A_t": 0.0, "I_t": 0.0, "M_t": 0.0, "U_t": 0.0, "C_t": False}
    values.update(overrides)
    return values


def _authorization() -> HumanAuthorizationEvent:
    return HumanAuthorizationEvent(
        event_id="auth-stage63",
        timestamp="2026-08-05T12:00:00Z",
        actor_id="analyst-stage63",
        actor_role="psirt_reviewer",
        actor_type="human",
        authorized_state="Report",
        rationale="Registered Stage 6.3 authorization test.",
    )


def test_report_ready_requires_each_individual_threshold() -> None:
    state, _ = recommend_state(_scores(E_t=0.2, A_t=0.2, I_t=0.9), 1.0)
    assert state != "Report-Ready"


def test_negative_delta_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        recommend_state(_scores(), -0.5)


def test_blank_proposition_is_not_a_conflict() -> None:
    common = {
        "scope": {
            "product_purl": "pkg:generic/test@1.0",
            "component_purl": "pkg:generic/component@1.0",
            "cve_id": "CVE-2026-63001",
        },
        "status": "active",
    }
    claims = [
        {**common, "claim_id": "blank-a", "proposition": "", "value": False},
        {**common, "claim_id": "blank-b", "proposition": "", "value": True},
    ]
    assert detect_conflicts(claims) == []


def test_authorization_audit_rejects_blank_recommendation() -> None:
    with pytest.raises(ValueError, match="recommended_state"):
        authorization_audit_event(_authorization(), recommended_state=" ")


def test_milestone_satisfaction_requires_reference() -> None:
    with pytest.raises(ValueError, match="reference"):
        MilestoneSatisfactionEvidence(
            evidence_id="evidence-stage63",
            milestone_id="early_warning",
            timestamp="2026-08-05T12:00:00Z",
            reference="",
            actor="reporting_portal",
        )


def test_identity_uncertainty_rejects_gamma_above_one() -> None:
    with pytest.raises(ValueError, match="gamma_id"):
        apply_identity_uncertainty(0.1, gamma_id=1.1)


def test_audit_reconstructability_requires_every_registered_field() -> None:
    complete = {
        "event_id": "event-stage63",
        "timestamp": "2026-08-05T12:00:00Z",
        "actor": "stage63",
        "action": "validated",
        "input_references": ["source-stage63"],
        "output_state": "Monitor",
    }
    incomplete = {**complete, "input_references": []}
    assert audit_reconstructability([complete, incomplete]) == 0.5


def test_evidence_pack_generation_requires_every_output(tmp_path: Path) -> None:
    present = tmp_path / "present.json"
    missing = tmp_path / "missing.json"
    present.write_text("{}\n", encoding="utf-8")
    assert evidence_pack_generation([present, missing]) == 0
