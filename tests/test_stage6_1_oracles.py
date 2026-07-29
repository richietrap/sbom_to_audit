from pathlib import Path

from sbom_to_audit.baseline.evaluation_oracles import (
    conflict_quality,
    load_clock_oracle,
    load_conflict_oracle,
    load_state_oracle,
    validate_oracle_coverage,
)

ROOT = Path(__file__).resolve().parents[1]
ORACLES = ROOT / "evaluation" / "oracles"


def test_stage6_1_oracles_cover_the_same_event_universe() -> None:
    state = load_state_oracle(ORACLES / "state_oracle_v0.1.yaml")
    conflicts = load_conflict_oracle(ORACLES / "conflict_oracle_v0.1.yaml")
    clock = load_clock_oracle(ORACLES / "clock_opportunity_oracle_v0.1.yaml")
    validate_oracle_coverage(state, conflicts, clock)
    assert len(state) == 28
    assert conflicts[("ghost_logger", "EVT-GL-010H")]["expected_conflict"] is True
    assert conflicts[("false_comfort", "EVT-FC-008H")]["expected_conflict"] is False
    assert clock[("rapid_pivot", "EVT-RP-018H")]["eligible_prepare_to_escalate_opportunity"] is True


def test_conflict_precision_uses_event_ground_truth_not_detected_counts() -> None:
    oracle = load_conflict_oracle(ORACLES / "conflict_oracle_v0.1.yaml")
    correct = conflict_quality({("ghost_logger", "EVT-GL-010H")}, oracle)
    wrong_event_same_count = conflict_quality({("false_comfort", "EVT-FC-008H")}, oracle)
    assert correct.precision == 1.0 and correct.recall == 1.0
    assert wrong_event_same_count.precision == 0.0 and wrong_event_same_count.recall == 0.0
