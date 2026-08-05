from pathlib import Path

from scripts.run_stage6_2_robustness import run
from scripts.validate_stage6_2_evaluation import validate_protocol, validate_results


def test_stage6_2_protocol_and_generated_results_validate(tmp_path: Path) -> None:
    errors, protocol = validate_protocol()
    assert errors == []
    destination = tmp_path / "results"
    run(destination)
    assert validate_results(destination, protocol) == []


def test_stage6_2_result_validator_detects_tampering(tmp_path: Path) -> None:
    errors, protocol = validate_protocol()
    assert errors == []
    destination = tmp_path / "results"
    outputs = run(destination)
    outputs["scenario_stability"].write_text("tampered\n", encoding="utf-8")
    result_errors = validate_results(destination, protocol)
    assert any("output hash mismatch" in error for error in result_errors)
