"""Independent event-level evaluation oracles for Stage 6.1."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_yaml


@dataclass(frozen=True)
class ConflictQuality:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None


def _load_object(path: str | Path) -> dict[str, Any]:
    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError(f"oracle must contain an object: {path}")
    if payload.get("status") != "FROZEN_BEFORE_FINAL_EXECUTION":
        raise ValueError(f"oracle is not frozen: {path}")
    return payload


def load_state_oracle(path: str | Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Load the state oracle keyed by scenario and event."""

    payload = _load_object(path)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for scenario in payload.get("scenarios") or []:
        scenario_id = str(scenario.get("scenario_id") or "")
        for event in scenario.get("events") or []:
            key = (scenario_id, str(event.get("event_id") or ""))
            if not all(key) or key in result:
                raise ValueError("state oracle contains an empty or duplicate event key")
            result[key] = dict(event)
    if not result:
        raise ValueError("state oracle contains no events")
    return result


def load_conflict_oracle(path: str | Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Load exhaustive event-level conflict ground truth."""

    payload = _load_object(path)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for event in payload.get("events") or []:
        key = (str(event.get("scenario_id") or ""), str(event.get("event_id") or ""))
        if not all(key) or key in result:
            raise ValueError("conflict oracle contains an empty or duplicate event key")
        result[key] = dict(event)
    if not result:
        raise ValueError("conflict oracle contains no events")
    return result


def load_clock_oracle(path: str | Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Load exhaustive automatic clock-opportunity ground truth."""

    payload = _load_object(path)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for event in payload.get("events") or []:
        key = (str(event.get("scenario_id") or ""), str(event.get("event_id") or ""))
        if not all(key) or key in result:
            raise ValueError("clock oracle contains an empty or duplicate event key")
        result[key] = dict(event)
    if not result:
        raise ValueError("clock oracle contains no events")
    return result


def validate_oracle_coverage(
    state_oracle: dict[tuple[str, str], dict[str, Any]],
    conflict_oracle: dict[tuple[str, str], dict[str, Any]],
    clock_oracle: dict[tuple[str, str], dict[str, Any]],
) -> None:
    """Require all independent oracles to cover the same event universe."""

    if set(state_oracle) != set(conflict_oracle) or set(state_oracle) != set(clock_oracle):
        raise ValueError("Stage 6.1 oracle event universes do not match")


def conflict_quality(
    detected_event_keys: set[tuple[str, str]],
    oracle: dict[tuple[str, str], dict[str, Any]],
) -> ConflictQuality:
    """Calculate precision and recall against workflow-independent event ground truth."""

    unknown = detected_event_keys - set(oracle)
    if unknown:
        raise ValueError(f"detected conflicts reference unknown oracle events: {sorted(unknown)}")
    truth = {key for key, row in oracle.items() if bool(row.get("expected_conflict"))}
    false_truth = set(oracle) - truth
    tp = len(detected_event_keys & truth)
    fp = len(detected_event_keys & false_truth)
    fn = len(truth - detected_event_keys)
    tn = len(false_truth - detected_event_keys)
    precision = round(tp / (tp + fp), 6) if tp + fp else None
    recall = round(tp / (tp + fn), 6) if tp + fn else None
    return ConflictQuality(tp, fp, fn, tn, precision, recall)
