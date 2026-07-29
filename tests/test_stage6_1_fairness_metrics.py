from pathlib import Path

import pytest

from sbom_to_audit.baseline.fairness_metrics import (
    common_field_completeness,
    equivalent_record_bundle_generation,
    traceability_ratios,
)
from sbom_to_audit.baseline.record_equivalence import load_record_equivalence

ROOT = Path(__file__).resolve().parents[1]


def test_common_field_completeness_keeps_false_and_zero_populated() -> None:
    record = {"a": {"value": False}, "b": {"value": 0}, "c": {"value": None}}
    assert common_field_completeness(record, ["a.value", "b.value", "c.value"]) == 0.666667


def test_traceability_confidence_is_not_forced_to_zero_or_imputed() -> None:
    rows = [
        {
            "source_artifact_id": "A",
            "source_uri": "a.json",
            "source_hash": "f" * 64,
            "timestamp": "2026-01-01T00:00:00Z",
            "confidence": 0.8,
        },
        {
            "source_artifact_id": "B",
            "source_uri": "b.json",
            "source_hash": "e" * 64,
            "timestamp": "2026-01-01T00:00:00Z",
            "confidence": None,
        },
    ]
    assert traceability_ratios(rows) == {"strict": 0.5, "partial_lineage": 1.0}


def test_equivalent_record_bundle_has_a_distinct_supplemental_contract(tmp_path: Path) -> None:
    mapping = load_record_equivalence(
        ROOT / "evaluation" / "mappings" / "equivalent_record_bundle_v0.1.yaml"
    )
    assert set(mapping.record_classes) == {
        "case_record",
        "decision_history",
        "conflict_history",
        "source_register",
    }
    paths = {}
    for name in mapping.record_classes:
        path = tmp_path / f"{name}.json"
        path.write_text("{}\n", encoding="utf-8")
        paths[name] = path
    assert equivalent_record_bundle_generation(paths) == 1
    with pytest.raises(ValueError):
        equivalent_record_bundle_generation({"case_record": tmp_path / "x"})
