from hypothesis import given
from hypothesis import strategies as st

from sbom_to_audit.model.identity import apply_identity_uncertainty
from sbom_to_audit.model.state_machine import recommend_state


@given(
    base=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    lower_gamma=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    higher_gamma=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)
def test_lower_identity_confidence_cannot_reduce_uncertainty(
    base: float, lower_gamma: float, higher_gamma: float
) -> None:
    low, high = sorted((lower_gamma, higher_gamma))
    uncertainty_low_confidence = apply_identity_uncertainty(base, low)
    uncertainty_high_confidence = apply_identity_uncertainty(base, high)
    assert uncertainty_low_confidence >= uncertainty_high_confidence


@given(
    e=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    a=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    i=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    u=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    delta=st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
)
def test_conflict_precedence_always_forces_escalate(
    e: float, a: float, i: float, u: float, delta: float
) -> None:
    state, _ = recommend_state(
        {"E_t": e, "A_t": a, "I_t": i, "M_t": 0.0, "U_t": u, "C_t": True},
        delta,
    )
    assert state == "Escalate"
