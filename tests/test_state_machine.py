from sbom_to_audit.model.state_machine import recommend_state


def scores(**overrides):
    base = {"E_t": 0.0, "A_t": 0.0, "I_t": 0.0, "M_t": 0.0, "U_t": 0.0, "C_t": False}
    base.update(overrides)
    return base


def test_conflict_has_precedence():
    state, _ = recommend_state(scores(E_t=1, A_t=1, I_t=1, C_t=True), 2)
    assert state == "Escalate"


def test_prepare_escalates_at_18_hours():
    state, _ = recommend_state(scores(), 18, previous_state="Prepare")
    assert state == "Escalate"


def test_report_ready_requires_all_three_thresholds():
    state, _ = recommend_state(scores(E_t=0.8, A_t=0.8, I_t=0.8), 4)
    assert state == "Report-Ready"


def test_document_no_report_for_low_applicability_and_uncertainty():
    state, _ = recommend_state(scores(A_t=0.1, U_t=0.1), 2)
    assert state == "Document No-Report"
