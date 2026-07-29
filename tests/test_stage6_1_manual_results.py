from pathlib import Path

from sbom_to_audit.baseline.evaluation_oracles import (
    load_clock_oracle,
    load_conflict_oracle,
    load_state_oracle,
)
from sbom_to_audit.baseline.manual_results import normalize_manual_results
from sbom_to_audit.utils.io import read_yaml
from stage6_1_helpers import build_completed_manual_bundle

ROOT = Path(__file__).resolve().parents[1]


def test_manual_results_use_recorded_confidence_and_independent_conflict_oracle(
    tmp_path: Path,
) -> None:
    bundle = build_completed_manual_bundle(tmp_path / "bundle")
    state = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    conflicts = load_conflict_oracle(
        ROOT / "evaluation" / "oracles" / "conflict_oracle_v0.1.yaml"
    )
    clock = load_clock_oracle(
        ROOT / "evaluation" / "oracles" / "clock_opportunity_oracle_v0.1.yaml"
    )
    mapping = read_yaml(ROOT / "evaluation" / "mappings" / "common_field_set_v0.1.yaml")
    result = normalize_manual_results(
        bundle, ROOT, state, conflicts, clock, mapping["field_paths"]
    )
    assert result["overall_conflict_quality"]["precision"] == 1.0
    assert result["overall_conflict_quality"]["recall"] == 1.0
    ghost = result["scenarios"]["ghost_logger"]["metrics"]
    assert ghost["TR"] == 1.0
    assert ghost["supplemental"]["partial_lineage_ratio"] == 1.0
    assert ghost["EPG"] == 0
    assert ghost["supplemental"]["equivalent_record_bundle_generation"] == 1
