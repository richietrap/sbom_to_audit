import csv
import json
from pathlib import Path

import pytest

from sbom_to_audit.cli import run
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "rapid_pivot.yaml"
CONTROL = ROOT / "data" / "scenarios" / "rapid_pivot_control.yaml"


def _load(path: Path) -> dict:
    value = read_yaml(path)
    assert isinstance(value, dict)
    return value


def test_unresolved_uncertainty_triggers_clock_aware_escalation() -> None:
    result = replay_scenario(_load(SCENARIO), repository_root=ROOT)
    rows = result["state_rows"]

    assert [row["observed_state"] for row in rows] == [
        "Prepare",
        "Prepare",
        "Escalate",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert all(row["state_match"] for row in rows)

    initial = rows[0]
    safeguard = rows[2]
    resolved = rows[3]
    assert initial["E_t"] == 0.85
    assert initial["A_t"] == 0.24
    assert initial["I_t"] == 0.75
    assert initial["U_t"] == pytest.approx(0.522222)
    assert initial["clock_safeguard_triggered"] is False

    assert safeguard["previous_state"] == "Prepare"
    assert safeguard["delta_t_hours"] == 18.0
    assert safeguard["C_t"] is False
    assert safeguard["clock_safeguard_triggered"] is True
    assert "18h safeguard" in safeguard["rationale"]

    assert resolved["A_t"] == 1.0
    assert resolved["U_t"] == 0.15
    assert resolved["observed_state"] == "Report-Ready"


def test_early_resolution_control_holds_inputs_constant_and_avoids_timeout() -> None:
    main_spec = _load(SCENARIO)
    control_spec = _load(CONTROL)
    main = replay_scenario(main_spec, repository_root=ROOT)
    control = replay_scenario(control_spec, repository_root=ROOT)

    assert main_spec["source_catalog"] == control_spec["source_catalog"]
    assert main_spec["deadline_profile"] == control_spec["deadline_profile"]
    assert main_spec["target"] == control_spec["target"]
    assert [event["timestamp"] for event in main_spec["replay_events"]] == [
        event["timestamp"] for event in control_spec["replay_events"]
    ]

    resolving_ids = {
        "ART-RP-ID-001",
        "ART-RP-EPSS-001",
        "ART-RP-VEX-001",
        "ART-RP-TELEM-001",
    }
    assert resolving_ids.issubset(main_spec["replay_events"][3]["release_artifact_ids"])
    assert resolving_ids.issubset(control_spec["replay_events"][1]["release_artifact_ids"])

    control_rows = control["state_rows"]
    assert [row["observed_state"] for row in control_rows] == [
        "Prepare",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert not any(row["clock_safeguard_triggered"] for row in control_rows)
    assert main["state_rows"][2]["deadline_posture"] == control_rows[2]["deadline_posture"]


def test_identity_evidence_changes_confidence_without_scenario_supplied_gamma() -> None:
    result = replay_scenario(_load(SCENARIO), repository_root=ROOT)
    rows = result["state_rows"]
    pack = result["pack"]

    assert "gamma_id" not in _load(SCENARIO)["target"]
    assert rows[0]["U_t"] > rows[3]["U_t"]
    assert pack["identity_resolution"]["matching_method"] == "exact_cpe_confirmed"
    assert pack["identity_resolution"]["gamma_id"] == 0.7
    assert pack["identity_resolution"]["resolution_artifact_id"] == "ART-RP-ID-001"

    identity_claims = [
        claim
        for claim in pack["claims"]
        if claim["proposition"] == "component_identity_confirmed" and claim["status"] == "active"
    ]
    assert len(identity_claims) == 1
    assert identity_claims[0]["source_artifact_id"] == "ART-RP-ID-001"
    assert identity_claims[0]["confidence"] == 0.7


def test_invalid_identity_confirmation_fails_closed() -> None:
    scenario = _load(SCENARIO)
    identity_path = ROOT / "data" / "decision_records" / "rapid_pivot_identity_resolution.yaml"
    original = identity_path.read_text(encoding="utf-8")
    try:
        identity_path.write_text(
            original.replace(
                "pkg:npm/session-router@3.1.4",
                "pkg:npm/different-component@9.9.9",
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="does not resolve the target component PURL"):
            replay_scenario(scenario, repository_root=ROOT)
    finally:
        identity_path.write_text(original, encoding="utf-8")


def test_rapid_pivot_metrics_and_outputs_are_deterministic(tmp_path: Path) -> None:
    first = run(SCENARIO, tmp_path / "first")
    second = run(SCENARIO, tmp_path / "second")
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()

    metrics = json.loads(first["metrics"].read_text(encoding="utf-8"))
    assert metrics["CA"] == 1.0
    assert metrics["CA_status"] == "applicable"
    assert metrics["SC"] == 1.0
    assert metrics["TR"] == 1.0
    assert metrics["supplemental"]["clock_safeguard_opportunities"] == 1
    assert metrics["supplemental"]["clock_safeguard_triggers"] == 1

    with first["state_log"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[2]["clock_safeguard_triggered"] == "True"

    control_paths = run(CONTROL, tmp_path / "control")
    control_metrics = json.loads(control_paths["metrics"].read_text(encoding="utf-8"))
    assert control_metrics["CA"] is None
    assert control_metrics["supplemental"]["clock_safeguard_triggers"] == 0


def test_application_source_contains_no_rapid_pivot_identifiers() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "sbom_to_audit").rglob("*.py"))
    ).lower()
    for forbidden in (
        "rapid_pivot",
        "remote-operations-console",
        "session-router",
        "cve-2026-44007",
    ):
        assert forbidden not in source
