"""Supplemental fairness controls for the Stage 6.1 matched evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

TRACEABILITY_ELEMENTS: tuple[str, ...] = (
    "source_artifact_id",
    "source_uri",
    "source_hash",
    "timestamp",
    "confidence",
)
PARTIAL_LINEAGE_ELEMENTS: tuple[str, ...] = TRACEABILITY_ELEMENTS[:-1]


def populated(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def path_value(document: dict[str, Any], path: str) -> Any:
    if path.endswith("[]"):
        return document.get(path[:-2])
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def common_field_completeness(document: dict[str, Any], field_paths: list[str]) -> float:
    if not field_paths:
        raise ValueError("common field set must not be empty")
    present = sum(populated(path_value(document, path)) for path in field_paths)
    return round(present / len(field_paths), 6)


def traceability_ratios(observations: list[dict[str, Any]]) -> dict[str, float]:
    if not observations:
        return {"strict": 0.0, "partial_lineage": 0.0}
    strict = sum(
        all(populated(row.get(field)) for field in TRACEABILITY_ELEMENTS)
        for row in observations
    )
    partial = sum(
        all(populated(row.get(field)) for field in PARTIAL_LINEAGE_ELEMENTS)
        for row in observations
    )
    count = len(observations)
    return {
        "strict": round(strict / count, 6),
        "partial_lineage": round(partial / count, 6),
    }


def equivalent_record_bundle_generation(paths: dict[str, str | Path]) -> int:
    required = {"case_record", "decision_history", "conflict_history", "source_register"}
    if set(paths) != required:
        raise ValueError(f"equivalent record bundle requires {sorted(required)}")
    return int(all(Path(path).is_file() for path in paths.values()))
