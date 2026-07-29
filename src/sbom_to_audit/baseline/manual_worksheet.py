"""Canonical Stage 6.1 manual worksheet bundle definitions."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_yaml

CASE_DECISION_FIELDS: tuple[str, ...] = (
    "decision_id",
    "scenario_id",
    "event_id",
    "event_timestamp",
    "review_started_at",
    "decision_recorded_at",
    "recommended_state",
    "authorized_state",
    "human_authorization_required",
    "identity_matching_method",
    "identity_confidence",
    "conflict_identified",
    "conflict_ids",
    "clock_safeguard_noted",
    "rationale",
    "analyst_confidence",
    "completion_status",
    "notes",
)
EVIDENCE_OBSERVATION_FIELDS: tuple[str, ...] = (
    "observation_id",
    "scenario_id",
    "event_id",
    "proposition",
    "value",
    "source_artifact_id",
    "source_uri",
    "source_hash",
    "source_timestamp",
    "confidence",
    "observation_status",
    "notes",
)
SOURCE_ACCESS_FIELDS: tuple[str, ...] = (
    "access_id",
    "scenario_id",
    "event_id",
    "accessed_at",
    "artifact_id",
    "tool",
    "command_or_method",
    "purpose",
    "notes",
)
CONFLICT_FIELDS: tuple[str, ...] = (
    "record_id",
    "scenario_id",
    "event_id",
    "conflict_id",
    "proposition",
    "scope_summary",
    "observation_a",
    "source_a",
    "observation_b",
    "source_b",
    "classification",
    "confidence",
    "resolution_status",
    "notes",
)
TIMING_FIELDS: tuple[str, ...] = (
    "scenario_id",
    "event_id",
    "evidence_released_at",
    "review_started_at",
    "decision_recorded_at",
    "elapsed_minutes",
    "notes",
)

BUNDLE_SCHEMAS: dict[str, tuple[str, ...]] = {
    "case_decisions.csv": CASE_DECISION_FIELDS,
    "evidence_observations.csv": EVIDENCE_OBSERVATION_FIELDS,
    "source_access_log.csv": SOURCE_ACCESS_FIELDS,
    "conflict_log.csv": CONFLICT_FIELDS,
    "timing_log.csv": TIMING_FIELDS,
}
DECLARATION_FILE = "declaration.yaml"


def read_csv_rows(path: str | Path, expected_fields: tuple[str, ...]) -> list[dict[str, str]]:
    """Read a worksheet CSV and reject column drift."""

    csv_path = Path(path)
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != expected_fields:
            raise ValueError(
                f"{csv_path.name} columns drifted; expected {list(expected_fields)} "
                f"but found {reader.fieldnames}"
            )
        return [dict(row) for row in reader]


def load_manual_bundle(root: str | Path) -> dict[str, Any]:
    """Load the canonical CSV/YAML exchange bundle."""

    bundle_root = Path(root)
    payload: dict[str, Any] = {}
    for filename, fields in BUNDLE_SCHEMAS.items():
        payload[filename] = read_csv_rows(bundle_root / filename, fields)
    declaration = read_yaml(bundle_root / DECLARATION_FILE)
    if not isinstance(declaration, dict):
        raise ValueError("declaration.yaml must contain an object")
    payload[DECLARATION_FILE] = declaration
    return payload
