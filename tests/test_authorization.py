import pytest

from sbom_to_audit.model.authorization import (
    HumanAuthorizationEvent,
    MilestoneSatisfactionEvidence,
    apply_human_authorization,
    authorization_audit_event,
    authorization_from_mapping,
    milestone_satisfaction_audit_event,
    satisfaction_evidence_from_mapping,
)


def valid_authorization(**overrides):
    values = {
        "event_id": "auth-001",
        "timestamp": "2026-09-13T04:00:00Z",
        "actor_id": "reviewer-001",
        "actor_role": "psirt_legal_reviewer",
        "actor_type": "human",
        "authorized_state": "Report",
        "rationale": "The evidence and reporting criteria were reviewed.",
    }
    values.update(overrides)
    return HumanAuthorizationEvent(**values)


def test_explicit_human_event_can_authorize_report():
    event = valid_authorization()
    assert apply_human_authorization(None, event) == "Report"


def test_explicit_human_event_can_authorize_document_no_report():
    event = valid_authorization(authorized_state="Document No-Report")
    assert apply_human_authorization(None, event) == "Document No-Report"


def test_system_actor_cannot_authorize():
    with pytest.raises(ValueError, match="explicit human"):
        valid_authorization(actor_type="system")


def test_malformed_human_event_is_rejected():
    with pytest.raises(ValueError, match="actor_role"):
        authorization_from_mapping(
            {
                "event_id": "auth-002",
                "timestamp": "2026-09-13T04:00:00Z",
                "actor_id": "reviewer-002",
                "actor_type": "human",
                "authorized_state": "Report",
                "rationale": "Reviewed.",
            }
        )


def test_recommendation_and_authorization_remain_distinct_in_audit_event():
    event = valid_authorization(authorized_state="Report")
    audit = authorization_audit_event(event, recommended_state="Escalate")
    assert audit["output_state"] == "Escalate"
    assert audit["authorized_state"] == "Report"


def test_milestone_satisfaction_is_a_separate_validated_record():
    evidence = satisfaction_evidence_from_mapping(
        {
            "submission_reference": "portal-confirmation-123",
            "milestone_id": "early_warning",
            "timestamp": "2026-09-13T04:20:00Z",
            "actor": "reporting_portal",
        }
    )
    assert isinstance(evidence, MilestoneSatisfactionEvidence)
    audit = milestone_satisfaction_audit_event(evidence, output_state="Report-Ready")
    assert audit["action"] == "milestone_satisfaction_recorded"
    assert audit["output_state"] == "Report-Ready"
    assert audit["submission_reference"] == "portal-confirmation-123"
