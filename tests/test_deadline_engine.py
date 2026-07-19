import pytest

from sbom_to_audit.model.deadline_engine import (
    DeadlineMilestone,
    DeadlineStatus,
    deadline_status_audit_event,
    evaluate_deadline,
    evaluate_deadline_profile,
)


MILESTONE = DeadlineMilestone(
    milestone_id="early_warning",
    deadline_hours=24,
    due_soon_lead_hours=6,
    breach_imminent_lead_hours=2,
)


def test_not_applicable_has_precedence():
    result = evaluate_deadline(MILESTONE, delta_t_hours=30, applicable=False)
    assert result.status == DeadlineStatus.NOT_APPLICABLE.value


def test_on_track_before_warning_window():
    result = evaluate_deadline(MILESTONE, delta_t_hours=17.9, applicable=True)
    assert result.status == DeadlineStatus.ON_TRACK.value


def test_due_soon_at_warning_threshold():
    result = evaluate_deadline(MILESTONE, delta_t_hours=18, applicable=True)
    assert result.status == DeadlineStatus.DUE_SOON.value


def test_breach_imminent_at_final_warning_threshold():
    result = evaluate_deadline(MILESTONE, delta_t_hours=22, applicable=True)
    assert result.status == DeadlineStatus.BREACH_IMMINENT.value


def test_overdue_at_due_time_without_completion_evidence():
    result = evaluate_deadline(MILESTONE, delta_t_hours=24, applicable=True)
    assert result.status == DeadlineStatus.OVERDUE.value


def test_valid_completion_evidence_marks_satisfied_and_records_lateness():
    on_time = evaluate_deadline(
        MILESTONE,
        delta_t_hours=20,
        applicable=True,
        satisfaction_evidence={"evidence_id": "submission-001"},
    )
    late = evaluate_deadline(
        MILESTONE,
        delta_t_hours=25,
        applicable=True,
        satisfaction_evidence={"submission_reference": "portal-ack-002"},
    )
    assert on_time.status == DeadlineStatus.SATISFIED.value
    assert on_time.satisfied_late is False
    assert late.status == DeadlineStatus.SATISFIED.value
    assert late.satisfied_late is True


def test_authorization_like_mapping_without_completion_identifier_is_rejected():
    with pytest.raises(ValueError, match="satisfaction_evidence"):
        evaluate_deadline(
            MILESTONE,
            delta_t_hours=20,
            applicable=True,
            satisfaction_evidence={"authorized_state": "Report"},
        )


def test_profile_evaluation_rejects_duplicate_milestones():
    with pytest.raises(ValueError, match="duplicate milestone_id"):
        evaluate_deadline_profile(
            [MILESTONE, MILESTONE],
            delta_t_hours=1,
            applicability={"early_warning": True},
        )


def test_deadline_audit_event_preserves_recommended_state():
    result = evaluate_deadline(MILESTONE, delta_t_hours=22, applicable=True)
    event = deadline_status_audit_event(
        result,
        event_id="evt-deadline-001",
        timestamp="2026-09-13T06:00:00Z",
        previous_status="Due Soon",
        output_state="Report-Ready",
        input_references=["clock-start-event", "profile-cra"],
    )
    assert event["action"] == "deadline_status_changed"
    assert event["new_status"] == "Breach Imminent"
    assert event["output_state"] == "Report-Ready"
