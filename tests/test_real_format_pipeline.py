import json
import shutil
from copy import deepcopy
from pathlib import Path

import pytest

from sbom_to_audit.ingestion import pipeline as ingestion_pipeline
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "ghost_logger.yaml"


def _scenario() -> dict:
    value = read_yaml(SCENARIO)
    assert isinstance(value, dict)
    return value


def test_scenario_contains_no_precomputed_claims_or_hashes() -> None:
    scenario = _scenario()
    assert "claims" not in scenario
    assert "source_artifacts" not in scenario
    assert "product_context" not in scenario
    serialized = json.dumps(scenario)
    assert "source_hash" not in serialized
    assert "E_t" not in serialized
    assert "A_t" not in serialized
    assert "C_t" not in serialized


def test_full_trajectory_is_derived_from_source_files() -> None:
    result = replay_scenario(_scenario(), repository_root=ROOT)
    rows = result["state_rows"]
    assert [row["observed_state"] for row in rows] == [
        "Document No-Report",
        "Escalate",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert all(row["state_match"] for row in rows)
    assert all(row["deadline_match"] for row in rows)
    assert all(row["authorization_match"] for row in rows)
    assert result["pack"]["source_artifacts"][0]["validation_status"] == "valid"


def test_historical_conflict_is_resolved_without_erasing_detection() -> None:
    result = replay_scenario(_scenario(), repository_root=ROOT)

    assert result["pack"]["orchestration_metrics"]["C_t"] is False
    assert len(result["conflicts"]) == 1

    conflict = result["conflicts"][0]
    assert conflict["status"] == "resolved"
    assert conflict["detected_at_event_id"] == "EVT-GL-010H"
    assert conflict["resolved_at_event_id"] == "EVT-GL-014H"
    assert conflict["resolution_artifact_ids"] == ["ART-DEC-RESOLVE-001"]
    assert conflict["resolution_event_ids"] == ["DEC-GL-CONFLICT-001"]
    assert [entry["status"] for entry in conflict["lifecycle"]] == ["active", "resolved"]

    actions = [entry["action"] for entry in result["audit_ledger"]]
    assert "evidence_conflict_detected" in actions
    assert "evidence_conflict_resolved" in actions


def test_final_conflict_flag_matches_active_history_records() -> None:
    result = replay_scenario(_scenario(), repository_root=ROOT)
    active = [item for item in result["conflicts"] if item["status"] == "active"]
    assert result["pack"]["orchestration_metrics"]["C_t"] == bool(active)


def test_conflict_cannot_disappear_without_registered_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ingestion_pipeline,
        "_matching_conflict_resolutions",
        lambda _conflict, _records: [],
    )
    with pytest.raises(
        AssertionError,
        match="active conflict disappeared without an explicit registered resolution artefact",
    ):
        replay_scenario(_scenario(), repository_root=ROOT)


def test_removing_execution_release_prevents_seeded_conflict() -> None:
    scenario = _scenario()
    mutated = deepcopy(scenario)
    mutated["replay_events"] = [mutated["replay_events"][0]]
    result = replay_scenario(mutated, repository_root=ROOT)
    assert result["conflicts"] == []
    assert result["pack"]["decision_state"]["recommended_state"] == "Document No-Report"


def test_vex_status_change_changes_derived_supplier_claim(tmp_path: Path) -> None:
    scenario = _scenario()
    original = ROOT / "data" / "csaf" / "ghost_logger_vex.json"
    document = json.loads(original.read_text(encoding="utf-8"))
    status = document["vulnerabilities"][0]["product_status"]
    status["known_affected"] = status.pop("known_not_affected")
    temp_root = tmp_path / "repository"
    shutil.copytree(ROOT / "data", temp_root / "data")
    shutil.copytree(ROOT / "schemas", temp_root / "schemas")
    shutil.copy2(ROOT / "pyproject.toml", temp_root / "pyproject.toml")
    replacement = temp_root / "data" / "csaf" / "ghost_logger_vex.json"
    replacement.write_text(json.dumps(document), encoding="utf-8")

    mutated = deepcopy(scenario)
    result = replay_scenario(mutated, repository_root=temp_root)
    supplier = result["pack"]["supplier_assertions"]
    assert supplier["csaf_vex_status"] == "known_affected"
