import json
from pathlib import Path

from jsonschema import Draft202012Validator

from sbom_to_audit.cli import run

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "ghost_logger.yaml"
SCHEMA = ROOT / "schemas" / "evidencepack_v0.2.schema.json"


def test_cli_generates_schema_valid_deterministic_outputs(tmp_path: Path) -> None:
    first = run(SCENARIO, tmp_path / "first")
    second = run(SCENARIO, tmp_path / "second")

    assert set(first) == {"evidence_pack", "state_log", "conflict_report", "metrics"}
    for key in first:
        assert first[key].is_file()
        assert second[key].is_file()
        assert first[key].read_bytes() == second[key].read_bytes()

    pack = json.loads(first["evidence_pack"].read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(pack)
    assert pack["schema_version"] == "0.2"
    assert pack["decision_state"]["recommended_state"] == "Escalate"
    assert pack["decision_state"]["authorized_state"] is None
    assert pack["orchestration_metrics"]["E_t"] < 1.0
    assert pack["orchestration_metrics"]["A_t"] == 1.0
    assert pack["orchestration_metrics"]["C_t"] is True
