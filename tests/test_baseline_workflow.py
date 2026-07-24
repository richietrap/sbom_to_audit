from pathlib import Path

from sbom_to_audit.baseline.protocol import load_protocol
from sbom_to_audit.baseline.workflow import run_baseline_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = load_protocol(ROOT / "evaluation" / "baseline_protocol_v0.1.yaml")


def _run(scenario_id: str) -> dict:
    scenario = read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
    assert isinstance(scenario, dict)
    return run_baseline_scenario(scenario, repository_root=ROOT, protocol=PROTOCOL)


def test_baseline_matches_ghost_logger_conflict_recall_but_not_claim_traceability() -> None:
    result = _run("ghost_logger")
    states = [row["observed_state"] for row in result["decision_rows"]]
    assert states == [
        "Document No-Report",
        "Escalate",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert result["metrics"]["CD"] == 1.0
    assert result["metrics"]["TR"] == 0.0
    assert result["metrics"]["supplemental"]["partial_traceability_ratio"] == 0.8
    assert result["metrics"]["AR"] == 1.0
    assert result["metrics"]["EPG"] == 0


def test_baseline_false_comfort_exposes_scope_blind_false_conflict() -> None:
    result = _run("false_comfort")
    states = [row["observed_state"] for row in result["decision_rows"]]
    assert states == ["Document No-Report", "Escalate", "Escalate", "Escalate"]
    assert result["metrics"]["SC"] == 0.0
    assert result["metrics"]["supplemental"]["conflict_episode_count"] == 1
    assert result["metrics"]["supplemental"]["false_positive_conflict_count"] == 1


def test_baseline_preserves_matched_controls_and_operational_outlier() -> None:
    false_comfort_control = _run("false_comfort_control")
    operational = _run("operational_outlier")
    operational_control = _run("operational_outlier_control")
    assert false_comfort_control["metrics"]["SC"] == 1.0
    assert operational["metrics"]["SC"] == 1.0
    assert operational_control["metrics"]["SC"] == 1.0
    assert operational["decision_rows"][-1]["observed_state"] == "Report-Ready"
    assert operational_control["decision_rows"][-1]["observed_state"] == "Monitor"


def test_baseline_has_no_automatic_rapid_pivot_clock_escalation() -> None:
    result = _run("rapid_pivot")
    event = next(row for row in result["decision_rows"] if row["event_id"] == "EVT-RP-018H")
    assert event["previous_state"] == "Prepare"
    assert event["observed_state"] == "Prepare"
    assert result["metrics"]["CA"] == 0.0
    assert result["metrics"]["SC"] == 0.833333


def test_baseline_case_record_completeness_is_stable() -> None:
    result = _run("ghost_logger")
    assert result["metrics"]["EC"] == 0.764706
    assert result["metrics"]["supplemental"]["mandatory_field_denominator"] == 34
    assert result["case_record"]["claims"] == []
    assert all(value is None for value in result["case_record"]["orchestration_metrics"].values())
