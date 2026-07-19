"""Configured reporting-deadline posture for Prototype semantics v0.2.1.

The deadline engine monitors internal workflow milestones. It does not decide
whether a statutory obligation applies or determine the legally operative time
of awareness.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


class DeadlineStatus(str, Enum):
    """Allowed configured deadline-posture values."""

    NOT_APPLICABLE = "Not Applicable"
    ON_TRACK = "On Track"
    DUE_SOON = "Due Soon"
    BREACH_IMMINENT = "Breach Imminent"
    SATISFIED = "Satisfied"
    OVERDUE = "Overdue"


ALLOWED_DEADLINE_STATUSES: tuple[str, ...] = tuple(status.value for status in DeadlineStatus)


@dataclass(frozen=True)
class DeadlineMilestone:
    """A configured internal workflow milestone.

    ``breach_imminent_lead_hours`` must be smaller than
    ``due_soon_lead_hours`` so that Breach Imminent is the later and more
    urgent pre-deadline posture.
    """

    milestone_id: str
    deadline_hours: float
    due_soon_lead_hours: float
    breach_imminent_lead_hours: float

    def __post_init__(self) -> None:
        if not self.milestone_id.strip():
            raise ValueError("milestone_id must be non-empty")
        if self.deadline_hours <= 0:
            raise ValueError("deadline_hours must be greater than zero")
        if not (
            0
            < self.breach_imminent_lead_hours
            < self.due_soon_lead_hours
            < self.deadline_hours
        ):
            raise ValueError(
                "deadline leads must satisfy 0 < breach_imminent_lead_hours "
                "< due_soon_lead_hours < deadline_hours"
            )


@dataclass(frozen=True)
class DeadlineResult:
    """Deterministic evaluation result for one configured milestone."""

    milestone_id: str
    status: str
    delta_t_hours: float
    deadline_hours: float
    applicable: bool
    satisfaction_evidence_id: str | None
    satisfied_late: bool | None
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _evidence_identifier(evidence: Mapping[str, Any] | None) -> str | None:
    if evidence is None:
        return None
    for field in ("evidence_id", "submission_reference", "event_id"):
        value = evidence.get(field)
        if value is not None and str(value).strip():
            return str(value)
    return None


def evaluate_deadline(
    milestone: DeadlineMilestone,
    *,
    delta_t_hours: float,
    applicable: bool,
    satisfaction_evidence: Mapping[str, Any] | None = None,
) -> DeadlineResult:
    """Evaluate ``D_(k,t)`` for one configured milestone.

    Status precedence follows the approved v0.2.1 semantics:

    1. Not Applicable;
    2. Satisfied;
    3. Overdue;
    4. Breach Imminent;
    5. Due Soon;
    6. On Track.

    Satisfaction requires a non-empty evidence identifier. A human
    authorization event alone is not completion or submission evidence.
    """

    if delta_t_hours < 0:
        raise ValueError("delta_t_hours must be non-negative")

    evidence_id = _evidence_identifier(satisfaction_evidence)

    if not applicable:
        return DeadlineResult(
            milestone_id=milestone.milestone_id,
            status=DeadlineStatus.NOT_APPLICABLE.value,
            delta_t_hours=float(delta_t_hours),
            deadline_hours=float(milestone.deadline_hours),
            applicable=False,
            satisfaction_evidence_id=None,
            satisfied_late=None,
            rationale="The configured milestone is not enabled for this workflow profile.",
        )

    if satisfaction_evidence is not None and evidence_id is None:
        raise ValueError(
            "satisfaction_evidence must contain evidence_id, submission_reference, or event_id"
        )

    if evidence_id is not None:
        late = delta_t_hours >= milestone.deadline_hours
        timing = "after" if late else "before"
        return DeadlineResult(
            milestone_id=milestone.milestone_id,
            status=DeadlineStatus.SATISFIED.value,
            delta_t_hours=float(delta_t_hours),
            deadline_hours=float(milestone.deadline_hours),
            applicable=True,
            satisfaction_evidence_id=evidence_id,
            satisfied_late=late,
            rationale=(
                f"Milestone-completion evidence {evidence_id!r} was recorded {timing} "
                "the configured due time. Historical warning or overdue events remain auditable."
            ),
        )

    if delta_t_hours >= milestone.deadline_hours:
        status = DeadlineStatus.OVERDUE
        rationale = "The configured due time has passed without milestone-completion evidence."
    elif delta_t_hours >= milestone.deadline_hours - milestone.breach_imminent_lead_hours:
        status = DeadlineStatus.BREACH_IMMINENT
        rationale = "The milestone is within the configured breach-imminent lead window."
    elif delta_t_hours >= milestone.deadline_hours - milestone.due_soon_lead_hours:
        status = DeadlineStatus.DUE_SOON
        rationale = "The milestone is within the configured due-soon lead window."
    else:
        status = DeadlineStatus.ON_TRACK
        rationale = "The milestone remains outside the configured warning windows."

    return DeadlineResult(
        milestone_id=milestone.milestone_id,
        status=status.value,
        delta_t_hours=float(delta_t_hours),
        deadline_hours=float(milestone.deadline_hours),
        applicable=True,
        satisfaction_evidence_id=None,
        satisfied_late=None,
        rationale=rationale,
    )


def evaluate_deadline_profile(
    milestones: Iterable[DeadlineMilestone],
    *,
    delta_t_hours: float,
    applicability: Mapping[str, bool] | None = None,
    satisfaction_evidence: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, DeadlineResult]:
    """Evaluate a collection of milestones without altering evidential state."""

    applicability = applicability or {}
    satisfaction_evidence = satisfaction_evidence or {}
    results: dict[str, DeadlineResult] = {}
    for milestone in milestones:
        if milestone.milestone_id in results:
            raise ValueError(f"duplicate milestone_id: {milestone.milestone_id}")
        results[milestone.milestone_id] = evaluate_deadline(
            milestone,
            delta_t_hours=delta_t_hours,
            applicable=bool(applicability.get(milestone.milestone_id, False)),
            satisfaction_evidence=satisfaction_evidence.get(milestone.milestone_id),
        )
    return results


def deadline_status_audit_event(
    result: DeadlineResult,
    *,
    event_id: str,
    timestamp: str,
    previous_status: str | None,
    output_state: str,
    input_references: Iterable[str] = (),
) -> dict[str, Any]:
    """Create an EvidencePack v0.2-compatible deadline audit entry."""

    if not event_id.strip():
        raise ValueError("event_id must be non-empty")
    if not timestamp.strip():
        raise ValueError("timestamp must be non-empty")
    if not output_state.strip():
        raise ValueError("output_state must be non-empty")
    if previous_status is not None and previous_status not in ALLOWED_DEADLINE_STATUSES:
        raise ValueError(f"unsupported previous deadline status: {previous_status!r}")

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "actor": "sbom_to_audit.deadline_engine",
        "action": "deadline_status_changed",
        "input_references": list(input_references),
        "output_state": output_state,
        "milestone_id": result.milestone_id,
        "previous_status": previous_status,
        "new_status": result.status,
        "delta_t_hours": result.delta_t_hours,
        "deadline_hours": result.deadline_hours,
        "clock_basis": "internal_awareness_proxy",
        "satisfaction_evidence_id": result.satisfaction_evidence_id,
        "satisfied_late": result.satisfied_late,
        "rationale": result.rationale,
    }
