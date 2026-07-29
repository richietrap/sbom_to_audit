"""Validated mapping for equivalent manual and orchestrated record classes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sbom_to_audit.utils.io import read_yaml


@dataclass(frozen=True)
class RecordEquivalenceMapping:
    mapping_version: str
    record_classes: dict[str, dict[str, tuple[str, ...]]]
    interpretation: str

    def __post_init__(self) -> None:
        required = {"case_record", "decision_history", "conflict_history", "source_register"}
        if self.mapping_version != "0.1" or set(self.record_classes) != required:
            raise ValueError("equivalent record mapping drifted")
        for workflows in self.record_classes.values():
            if set(workflows) != {"orchestrated", "manual_baseline"}:
                raise ValueError("record-equivalence workflow mapping drifted")
            if any(not values for values in workflows.values()):
                raise ValueError("record-equivalence entries must be non-empty")


def load_record_equivalence(path: str | Path) -> RecordEquivalenceMapping:
    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError("record-equivalence mapping must contain an object")
    classes = payload.get("record_classes") or {}
    if not isinstance(classes, dict):
        raise ValueError("record_classes must contain an object")
    normalized: dict[str, dict[str, tuple[str, ...]]] = {}
    for record_class, workflows in classes.items():
        if not isinstance(workflows, dict):
            raise ValueError("record-class workflows must contain an object")
        normalized[str(record_class)] = {
            str(workflow): tuple(str(value) for value in values)
            for workflow, values in workflows.items()
            if isinstance(values, list)
        }
    return RecordEquivalenceMapping(
        mapping_version=str(payload.get("mapping_version") or ""),
        record_classes=normalized,
        interpretation=str(payload.get("interpretation") or ""),
    )
