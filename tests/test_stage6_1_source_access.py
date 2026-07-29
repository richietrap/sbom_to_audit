import pytest

from sbom_to_audit.baseline.source_access_accounting import summarize_source_accesses


def test_source_access_accounting_uses_the_same_units() -> None:
    rows = [
        {"scenario_id": "s", "event_id": "e1", "artifact_id": "a"},
        {"scenario_id": "s", "event_id": "e2", "artifact_id": "a"},
        {"scenario_id": "s", "event_id": "e2", "artifact_id": "b"},
    ]
    assert summarize_source_accesses(rows) == {
        "total_access_rows": 3,
        "distinct_source_artifacts_accessed": 2,
        "event_source_accesses": 3,
        "repeat_accesses": 1,
    }


def test_source_access_accounting_rejects_missing_artifact_ids() -> None:
    with pytest.raises(ValueError, match="artifact_id"):
        summarize_source_accesses([{"scenario_id": "s", "event_id": "e", "artifact_id": ""}])
