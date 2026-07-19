"""Human authorization and milestone-satisfaction boundaries.

Prototype v0.2.1 separates a human decision to authorize a state from evidence
that a configured reporting milestone was completed or submitted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from sbom_to_audit.model.state_machine import validate_authorized_state


@dataclass(frozen=True)
class HumanAuthorizationEvent:
    """Explicit human authorization that may set ``authorized_state``."""

    event_id: str
    timestamp: str
    actor_id: str
    actor_role: str
    actor_type: str
    authorized_state: str
    rationale: str

    def __post_init__(self) -> None:
        for field_name in ("event_id", "timestamp", "actor_id", "actor_role", "rationale"):
            value = getattr(self, field_name)
            if not str(value).strip():
                raise ValueError(f"{field_name} must be non-empty")
        if self.actor_type.strip().lower() != "human":
            raise ValueError("only an explicit human event may set authorized_state")
        validate_authorized_state(self.authorized_state)
        if self.authorized_state is None:  # defensive despite the dataclass annotation
            raise ValueError("an authorization event must authorize a non-null state")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MilestoneSatisfactionEvidence:
    """Evidence that a configured milestone was completed or submitted."""

    evidence_id: str
    milestone_id: str
    timestamp: str
    reference: str
    actor: str

    def __post_init__(self) -> None:
        for field_name in ("evidence_id", "milestone_id", "timestamp", "reference", "actor"):
            value = getattr(self, field_name)
            if not str(value).strip():
                raise ValueError(f"{field_name} must be non-empty")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def authorization_from_mapping(event: Mapping[str, Any]) -> HumanAuthorizationEvent:
    """Validate and construct a human authorization event from input data."""

    return HumanAuthorizationEvent(
        event_id=str(event.get("event_id") or ""),
        timestamp=str(event.get("timestamp") or ""),
        actor_id=str(event.get("actor_id") or ""),
        actor_role=str(event.get("actor_role") or ""),
        actor_type=str(event.get("actor_type") or ""),
        authorized_state=str(event.get("authorized_state") or ""),
        rationale=str(event.get("rationale") or ""),
    )


def satisfaction_evidence_from_mapping(
    evidence: Mapping[str, Any],
) -> MilestoneSatisfactionEvidence:
    """Validate and construct milestone-completion or submission evidence."""

    return MilestoneSatisfactionEvidence(
        evidence_id=str(evidence.get("evidence_id") or evidence.get("submission_reference") or ""),
        milestone_id=str(evidence.get("milestone_id") or ""),
        timestamp=str(evidence.get("timestamp") or ""),
        reference=str(evidence.get("reference") or evidence.get("submission_reference") or ""),
        actor=str(evidence.get("actor") or ""),
    )


def apply_human_authorization(
    current_authorized_state: str | None,
    event: HumanAuthorizationEvent,
) -> str:
    """Apply an already validated human event without changing recommendation."""

    validate_authorized_state(current_authorized_state)
    return event.authorized_state


def authorization_audit_event(
    event: HumanAuthorizationEvent,
    *,
    recommended_state: str,
) -> dict[str, Any]:
    """Create an EvidencePack v0.2-compatible authorization audit entry."""

    if not recommended_state.strip():
        raise ValueError("recommended_state must be non-empty")
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "actor": f"human:{event.actor_id}",
        "action": "human_authorization_recorded",
        "input_references": [],
        "output_state": recommended_state,
        "authorized_state": event.authorized_state,
        "actor_role": event.actor_role,
        "rationale": event.rationale,
    }


def milestone_satisfaction_audit_event(
    evidence: MilestoneSatisfactionEvidence,
    *,
    output_state: str,
) -> dict[str, Any]:
    """Create an EvidencePack v0.2-compatible milestone evidence event."""

    if not output_state.strip():
        raise ValueError("output_state must be non-empty")
    return {
        "event_id": evidence.evidence_id,
        "timestamp": evidence.timestamp,
        "actor": evidence.actor,
        "action": "milestone_satisfaction_recorded",
        "input_references": [evidence.reference],
        "output_state": output_state,
        "milestone_id": evidence.milestone_id,
        "satisfaction_evidence_id": evidence.evidence_id,
        "submission_reference": evidence.reference,
    }
