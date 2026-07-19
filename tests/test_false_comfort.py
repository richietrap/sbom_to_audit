import json
from pathlib import Path

from sbom_to_audit.cli import run
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "false_comfort.yaml"
CONTROL = ROOT / "data" / "scenarios" / "false_comfort_control.yaml"


def _load(path: Path) -> dict:
    value = read_yaml(path)
    assert isinstance(value, dict)
    return value


def test_wrongly_scoped_supplier_assurance_is_retained_but_not_applied() -> None:
    result = replay_scenario(_load(SCENARIO), repository_root=ROOT)
    rows = result["state_rows"]
    assert [row["observed_state"] for row in rows] == [
        "Monitor",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert all(row["state_match"] for row in rows)
    supplier = result["pack"]["supplier_assertions"]
    assert supplier["asserted_csaf_vex_status"] == "known_not_affected"
    assert supplier["csaf_vex_status"] == "not_applicable_scope_mismatch"
    assert supplier["scope_applicability"] == "scope_mismatch"
    assert supplier["assertion_scope"]["product_variant"] == "standard-profile"
    assert supplier["target_scope"]["product_variant"] == "legacy-plugin-profile"
    assert result["conflicts"] == []


def test_scope_matched_negative_control_applies_supplier_assurance() -> None:
    result = replay_scenario(_load(CONTROL), repository_root=ROOT)
    assert result["pack"]["decision_state"]["recommended_state"] == "Document No-Report"
    supplier = result["pack"]["supplier_assertions"]
    assert supplier["csaf_vex_status"] == "known_not_affected"
    assert supplier["scope_applicability"] == "applicable"
    assert result["pack"]["orchestration_metrics"]["A_t"] == 0.1
    assert result["conflicts"] == []


def test_false_comfort_cli_outputs_are_deterministic_and_traceable(tmp_path: Path) -> None:
    first = run(SCENARIO, tmp_path / "first")
    second = run(SCENARIO, tmp_path / "second")
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()
    pack = json.loads(first["evidence_pack"].read_text(encoding="utf-8"))
    metrics = json.loads(first["metrics"].read_text(encoding="utf-8"))
    assert pack["decision_state"]["authorized_state"] == "Report"
    assert metrics["EC"] == 1.0
    assert metrics["TR"] == 1.0
    assert metrics["SC"] == 1.0
    assert metrics["CD"] is None
    assert metrics["CA"] is None


def test_application_source_contains_no_scenario_specific_identifiers() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "sbom_to_audit").rglob("*.py"))
    ).lower()
    for forbidden in ("ghost_logger", "false_comfort", "claims-hub", "industrial-smart-gateway"):
        assert forbidden not in source
