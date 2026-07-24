"""Frozen protocol for the matched un-orchestrated PSIRT worksheet baseline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_yaml


@dataclass(frozen=True)
class BaselineProtocol:
    """Validated baseline definition used by the Stage 6 comparison."""

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
        if not self.scenario_ids:
            raise ValueError("baseline protocol requires scenario_ids")
        if len(set(self.scenario_ids)) != len(self.scenario_ids):
            raise ValueError("baseline scenario_ids must be unique")
        if not self.high_impact_criticalities or not self.broad_deployment_scopes:
            raise ValueError("baseline impact categories must be non-empty")
        if not self.not_affected_statuses:
            raise ValueError("baseline not-affected statuses must be non-empty")


def _strings(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    values = payload.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"baseline protocol field {key!r} must be a non-empty list")
    result = tuple(str(value).strip() for value in values)
    if any(not value for value in result):
        raise ValueError(f"baseline protocol field {key!r} contains an empty value")
    return result


def load_protocol(path: str | Path) -> BaselineProtocol:
    """Load and validate the frozen baseline protocol YAML."""

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
