from pathlib import Path

from stage6_1_helpers import build_completed_manual_bundle

from sbom_to_audit.baseline.evaluation_oracles import load_state_oracle
from sbom_to_audit.baseline.protocol import load_manual_protocol
from sbom_to_audit.baseline.worksheet_validation import validate_manual_bundle
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]


def _known(protocol_scenarios: tuple[str, ...]) -> dict[str, set[str]]:
    result = {}
    for scenario_id in protocol_scenarios:
        scenario = read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
        result[scenario_id] = {row["artifact_id"] for row in scenario["source_catalog"]}
    return result


def test_blank_manual_template_is_structurally_valid_but_not_complete() -> None:
    protocol = load_manual_protocol(ROOT / "evaluation" / "baseline_protocol_v0.2.yaml")
    oracle = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    template = ROOT / "data" / "baseline_templates"
    structural = validate_manual_bundle(
        template, protocol, oracle, _known(protocol.scenario_ids), require_complete=False
    )
    complete = validate_manual_bundle(
        template, protocol, oracle, _known(protocol.scenario_ids), require_complete=True
    )
    assert structural.valid
    assert not complete.valid
    assert any("incomplete decision" in error for error in complete.errors)


def test_completed_manual_bundle_passes_fail_closed_validation(tmp_path: Path) -> None:
    protocol = load_manual_protocol(ROOT / "evaluation" / "baseline_protocol_v0.2.yaml")
    oracle = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    bundle = build_completed_manual_bundle(tmp_path / "bundle")
    report = validate_manual_bundle(
        bundle, protocol, oracle, _known(protocol.scenario_ids), require_complete=True
    )
    assert report.valid, report.errors
    assert report.checks["complete_decisions"] == 28
