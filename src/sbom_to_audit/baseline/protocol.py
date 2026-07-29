"""Frozen protocols for the Stage 6 pilot and Stage 6.1 manual baseline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_yaml


@dataclass(frozen=True)
class BaselineProtocol:
    """Validated deterministic proxy definition retained for the Stage 6 pilot."""

    protocol_version: str
    protocol_id: str
    classification: str
    scenario_ids: tuple[str, ...]
    high_impact_criticalities: tuple[str, ...]
    broad_deployment_scopes: tuple[str, ...]
    not_affected_statuses: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.protocol_version != "0.1":
            raise ValueError("baseline protocol_version must be 0.1")
        if self.protocol_id != "matched_unorchestrated_psirt_worksheet":
            raise ValueError("unsupported baseline protocol_id")
        _validate_scenario_ids(self.scenario_ids)
        if not self.high_impact_criticalities or not self.broad_deployment_scopes:
            raise ValueError("baseline impact categories must be non-empty")
        if not self.not_affected_statuses:
            raise ValueError("baseline not-affected statuses must be non-empty")


@dataclass(frozen=True)
class ManualBaselineProtocol:
    """Pre-registered manual-assisted baseline definition for Stage 6.1."""

    protocol_version: str
    protocol_id: str
    classification: str
    evaluation_status: str
    scenario_ids: tuple[str, ...]
    shared_conditions: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    prohibited_tools: tuple[str, ...]
    required_records: tuple[str, ...]
    blinding_required: bool
    record_prior_exposure: bool
    confidence_required: bool
    confidence_minimum: float
    confidence_maximum: float
    locked_metrics: tuple[str, ...]
    supplemental_controls: tuple[str, ...]
    freeze_requirements: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.protocol_version != "0.2":
            raise ValueError("manual baseline protocol_version must be 0.2")
        if self.protocol_id != "matched_manual_assisted_psirt_baseline":
            raise ValueError("unsupported manual baseline protocol_id")
        if self.evaluation_status != "PRE_EXECUTION_PROTOCOL_FROZEN":
            raise ValueError("manual baseline protocol must be pre-execution frozen")
        _validate_scenario_ids(self.scenario_ids)
        if not self.allowed_tools or not self.prohibited_tools:
            raise ValueError("manual baseline tool policies must be non-empty")
        if not self.required_records:
            raise ValueError("manual baseline required_records must be non-empty")
        if self.confidence_minimum != 0.0 or self.confidence_maximum != 1.0:
            raise ValueError("manual confidence range must remain 0.0 to 1.0")
        if self.locked_metrics != ("EC", "TR", "CD", "CA", "AR", "SC", "EPG"):
            raise ValueError("locked Stage 6.1 metric set drifted")
        if not self.freeze_requirements or not self.limitations:
            raise ValueError("manual protocol requires freeze requirements and limitations")


def _validate_scenario_ids(values: tuple[str, ...]) -> None:
    if not values:
        raise ValueError("baseline protocol requires scenario_ids")
    if len(set(values)) != len(values):
        raise ValueError("baseline scenario_ids must be unique")


def _strings(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    values = payload.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"baseline protocol field {key!r} must be a non-empty list")
    result = tuple(str(value).strip() for value in values)
    if any(not value for value in result):
        raise ValueError(f"baseline protocol field {key!r} contains an empty value")
    return result


def load_protocol(path: str | Path) -> BaselineProtocol:
    """Load and validate the retained Stage 6 deterministic proxy protocol."""

    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError("baseline protocol must contain an object")
    decision = payload.get("decision_categories") or {}
    if not isinstance(decision, dict):
        raise ValueError("decision_categories must contain an object")
    limitations = payload.get("limitations") or []
    if not isinstance(limitations, list) or not limitations:
        raise ValueError("baseline protocol must declare limitations")
    return BaselineProtocol(
        protocol_version=str(payload.get("protocol_version") or ""),
        protocol_id=str(payload.get("protocol_id") or ""),
        classification=str(payload.get("classification") or ""),
        scenario_ids=_strings(payload, "scenario_ids"),
        high_impact_criticalities=_strings(decision, "high_impact_criticalities"),
        broad_deployment_scopes=_strings(decision, "broad_deployment_scopes"),
        not_affected_statuses=_strings(decision, "not_affected_statuses"),
        limitations=tuple(str(item).strip() for item in limitations if str(item).strip()),
    )


def load_manual_protocol(path: str | Path) -> ManualBaselineProtocol:
    """Load and validate the Stage 6.1 manual-assisted protocol."""

    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError("manual baseline protocol must contain an object")
    blinding = payload.get("blinding") or {}
    confidence = payload.get("confidence_recording") or {}
    controls = payload.get("metric_controls") or {}
    if not all(isinstance(item, dict) for item in (blinding, confidence, controls)):
        raise ValueError("manual baseline protocol nested controls must be objects")
    confidence_range = confidence.get("range") or []
    if not isinstance(confidence_range, list) or len(confidence_range) != 2:
        raise ValueError("manual confidence range must contain two values")
    limitations = payload.get("limitations") or []
    freeze_requirements = payload.get("freeze_requirements") or []
    if not isinstance(limitations, list) or not isinstance(freeze_requirements, list):
        raise ValueError("manual limitations and freeze requirements must be lists")
    return ManualBaselineProtocol(
        protocol_version=str(payload.get("protocol_version") or ""),
        protocol_id=str(payload.get("protocol_id") or ""),
        classification=str(payload.get("classification") or ""),
        evaluation_status=str(payload.get("evaluation_status") or ""),
        scenario_ids=_strings(payload, "scenario_ids"),
        shared_conditions=_strings(payload, "shared_conditions"),
        allowed_tools=_strings(payload, "allowed_tools"),
        prohibited_tools=_strings(payload, "prohibited_tools"),
        required_records=_strings(payload, "required_records"),
        blinding_required=bool(blinding.get("required")),
        record_prior_exposure=bool(blinding.get("record_prior_exposure")),
        confidence_required=bool(confidence.get("required_for_traceable_observations")),
        confidence_minimum=float(confidence_range[0]),
        confidence_maximum=float(confidence_range[1]),
        locked_metrics=_strings(controls, "locked_metrics_unchanged"),
        supplemental_controls=_strings(controls, "supplemental_controls"),
        freeze_requirements=tuple(
            str(item).strip() for item in freeze_requirements if str(item).strip()
        ),
        limitations=tuple(str(item).strip() for item in limitations if str(item).strip()),
    )
