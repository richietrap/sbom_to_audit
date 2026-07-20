import json
from pathlib import Path

from sbom_to_audit.cli import run
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "operational_outlier.yaml"
CONTROL = ROOT / "data" / "scenarios" / "operational_outlier_control.yaml"


def _load(path: Path) -> dict:
    value = read_yaml(path)
    assert isinstance(value, dict)
    return value


def test_operational_impact_changes_state_with_matched_technical_evidence() -> None:
    main = replay_scenario(_load(SCENARIO), repository_root=ROOT)
    control = replay_scenario(_load(CONTROL), repository_root=ROOT)

    assert [row["observed_state"] for row in main["state_rows"]] == [
        "Monitor",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    assert [row["observed_state"] for row in control["state_rows"]] == [
        "Monitor",
        "Monitor",
    ]
    assert all(row["state_match"] for row in main["state_rows"])
    assert all(row["state_match"] for row in control["state_rows"])

    main_reach = main["state_rows"][1]
    control_reach = control["state_rows"][1]
    for field in ("E_t", "A_t", "U_t", "C_t"):
        assert main_reach[field] == control_reach[field]
    assert main_reach["I_t"] == 1.0
    assert control_reach["I_t"] == 0.5

    main_vuln = main["pack"]["vulnerability_intelligence"]
    control_vuln = control["pack"]["vulnerability_intelligence"]
    assert main_vuln["cvss_base_score"] == control_vuln["cvss_base_score"] == 6.5
    assert main_vuln["cvss_base_severity"] == control_vuln["cvss_base_severity"] == "MEDIUM"
    assert main["pack"]["asset_context"]["asset_criticality"] == "critical"
    assert control["pack"]["asset_context"]["asset_criticality"] == "medium"

    # The counterfactual control must hold workflow timing and all non-asset source
    # bytes constant. This prevents a hidden second treatment from explaining the
    # state difference.
    assert main_reach["deadline_posture"] == control_reach["deadline_posture"]
    main_spec = _load(SCENARIO)
    control_spec = _load(CONTROL)
    assert main_spec["deadline_profile"] == control_spec["deadline_profile"]

    def matched_released_sources(spec: dict) -> list[tuple[str, str, str]]:
        released = {
            artifact_id
            for event in spec["replay_events"][:2]
            for artifact_id in event["release_artifact_ids"]
        }
        return sorted(
            (item["artifact_type"], item["path"], item["timestamp"])
            for item in spec["source_catalog"]
            if item["artifact_id"] in released and item["artifact_type"] != "asset_context"
        )

    assert matched_released_sources(main_spec) == matched_released_sources(control_spec)

    main_asset = dict(main["pack"]["asset_context"])
    control_asset = dict(control["pack"]["asset_context"])
    for field in ("asset_criticality", "deployment_scope"):
        main_asset.pop(field)
        control_asset.pop(field)
    assert main_asset == control_asset


def test_under_investigation_is_not_misrepresented_as_not_affected() -> None:
    result = replay_scenario(_load(SCENARIO), repository_root=ROOT)
    active = [claim for claim in result["pack"]["claims"] if claim.get("status") == "active"]
    supplier_claims = [claim for claim in active if claim["source_artifact_id"] == "ART-OO-VEX-001"]
    assert any(
        claim["proposition"] == "supplier_assessment_status"
        and claim["value"] == "under_investigation"
        for claim in supplier_claims
    )
    assert not any(claim["proposition"] == "product_affectedness" for claim in supplier_claims)
    assert result["conflicts"] == []


def test_operational_outlier_cli_outputs_are_deterministic_and_traceable(
    tmp_path: Path,
) -> None:
    first = run(SCENARIO, tmp_path / "first")
    second = run(SCENARIO, tmp_path / "second")
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()

    pack = json.loads(first["evidence_pack"].read_text(encoding="utf-8"))
    metrics = json.loads(first["metrics"].read_text(encoding="utf-8"))
    assert pack["decision_state"]["recommended_state"] == "Report-Ready"
    assert pack["decision_state"]["authorized_state"] == "Report"
    assert pack["orchestration_metrics"]["I_t"] == 1.0
    assert metrics["EC"] == 1.0
    assert metrics["TR"] == 1.0
    assert metrics["SC"] == 1.0
    assert metrics["CD"] is None
    assert metrics["CA"] is None


def test_application_source_contains_no_operational_outlier_identifiers() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src" / "sbom_to_audit").rglob("*.py"))
    ).lower()
    for forbidden in (
        "operational_outlier",
        "municipal-water-controller",
        "flow-parser",
        "cve-2026-43003",
    ):
        assert forbidden not in source
