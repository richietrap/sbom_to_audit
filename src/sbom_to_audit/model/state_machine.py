"""Frozen temporal state-transition logic for EvidencePack v0.2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ALLOWED_RECOMMENDED_STATES = (
    "Monitor",
    "Prepare",
    "Escalate",
    "Report-Ready",
    "Report",
    "Document No-Report",
)
ALLOWED_AUTHORIZED_STATES = ("Report", "Document No-Report", None)


@dataclass(frozen=True)
class Thresholds:
    theta_A: float = 0.70
    theta_E: float = 0.70
    theta_I: float = 0.70
    theta_U: float = 0.50
    theta_N: float = 0.20
    theta_L: float = 0.20
    tau_E_hours: float = 18.0


def recommend_state(
    scores: dict[str, Any],
    delta_t_hours: float,
    previous_state: str | None = None,
    thresholds: Thresholds | None = None,
) -> tuple[str, str]:
    t = thresholds or Thresholds()
    if delta_t_hours < 0:
        raise ValueError("delta_t_hours must be non-negative")

    E_t = float(scores["E_t"])
    A_t = float(scores["A_t"])
    I_t = float(scores["I_t"])
    U_t = float(scores["U_t"])
    C_t = bool(scores["C_t"])

    if C_t:
        return (
            "Escalate",
            "Active evidence claims conflict; conflict precedence forces internal escalation.",
        )
    if previous_state == "Prepare" and delta_t_hours >= t.tau_E_hours:
        return (
            "Escalate",
            f"The case remained in Prepare until delta_t={delta_t_hours:g}h, "
            f"meeting the internal {t.tau_E_hours:g}h safeguard.",
        )
    if A_t >= t.theta_A and E_t >= t.theta_E and I_t >= t.theta_I:
        return (
            "Report-Ready",
            "Applicability, exploitation evidence, and impact meet the prototype "
            "thresholds; human review is required.",
        )
    if U_t >= t.theta_U and (E_t >= t.theta_E or I_t >= t.theta_I):
        return (
            "Prepare",
            "Uncertainty is high while exploitation evidence or impact meets its threshold.",
        )
    if A_t <= t.theta_N and U_t <= t.theta_L:
        return (
            "Document No-Report",
            "Applicability and uncertainty are both low under the prototype thresholds; "
            "preserve the rationale for review.",
        )
    return "Monitor", "No higher-precedence transition rule is satisfied."


def validate_authorized_state(value: str | None) -> None:
    if value not in ALLOWED_AUTHORIZED_STATES:
        raise ValueError("authorized_state must be Report, Document No-Report, or null")
