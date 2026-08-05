import csv
import json
from pathlib import Path

from sbom_to_audit.evaluation.robustness import (
    evaluate_factor_variant,
    replay_clock_profile,
    replay_threshold_profile,
    threshold_profile,
)
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml
from scripts.run_stage6_2_robustness import run

ROOT = Path(__file__).resolve().parents[1]
RAPID_PIVOT = ROOT / "data" / "scenarios" / "rapid_pivot.yaml"


def _rapid_pivot_result() -> dict:
    scenario = read_yaml(RAPID_PIVOT)
    assert isinstance(scenario, dict)
    return replay_scenario(scenario, repository_root=ROOT)


def test_threshold_profile_offsets_and_clamps() -> None:
    low = threshold_profile("low", -0.10)["thresholds"]
    high = threshold_profile("high", 0.10)["thresholds"]
    assert low["theta_A"] == 0.60
    assert low["theta_N"] == 0.10
    assert high["theta_A"] == 0.80
    assert high["theta_N"] == 0.30
    assert low["tau_E_hours"] == high["tau_E_hours"] == 18.0


def test_clock_sweep_moves_rapid_pivot_safeguard_explainably() -> None:
    rows = _rapid_pivot_result()["state_rows"]
    early = replay_clock_profile(rows, profile_id="clock_14h", tau_e_hours=14.0)
    baseline = replay_clock_profile(rows, profile_id="clock_18h", tau_e_hours=18.0)
    early_triggers = [row["event_id"] for row in early if row["clock_safeguard_triggered"]]
    baseline_triggers = [row["event_id"] for row in baseline if row["clock_safeguard_triggered"]]
    assert early_triggers == ["EVT-RP-018H"]
    assert baseline_triggers == ["EVT-RP-018H"]
    assert (
        next(row for row in early if row["event_id"] == "EVT-RP-018H")["variant_state"]
        == "Escalate"
    )


def test_conflict_single_factor_variant_forces_escalate() -> None:
    result = _rapid_pivot_result()
    final = result["state_rows"][-1]
    previous_state = result["state_rows"][-2]["observed_state"]
    variant = evaluate_factor_variant(
        result["pack"],
        factor="conflict",
        value=True,
        delta_t_hours=float(final["delta_t_hours"]),
        previous_state=str(previous_state),
    )
    assert variant["C_t"] is True
    assert variant["variant_state"] == "Escalate"


def test_baseline_threshold_profile_reproduces_registered_states() -> None:
    rows = _rapid_pivot_result()["state_rows"]
    replayed = replay_threshold_profile(
        rows,
        profile_id="threshold_baseline",
        offset=0.0,
    )
    assert all(not row["state_changed"] for row in replayed)


def test_stage6_2_run_is_deterministic_and_complete(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_outputs = run(first)
    second_outputs = run(second)
    assert sorted(first_outputs) == sorted(second_outputs)
    for key in first_outputs:
        assert first_outputs[key].read_bytes() == second_outputs[key].read_bytes()

    report = json.loads(first_outputs["report"].read_text(encoding="utf-8"))
    assert report["scenario_count"] == 7
    assert report["event_count"] == 28
    assert report["threshold_event_rows"] == 140
    assert report["clock_event_rows"] == 60
    assert report["factor_variant_rows"] == 266
    assert report["negative_cases_rejected"] == 8
    assert report["manuscript_eligible"] is False

    with first_outputs["negative_cases"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 8
    assert all(row["rejected_as_expected"] == "True" for row in rows)
