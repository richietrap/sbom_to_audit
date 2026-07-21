from __future__ import annotations

from pathlib import Path

from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data/scenarios/historical_cve_2024_3400_reference.yaml"


def _result() -> dict:
    scenario = read_yaml(SCENARIO)
    assert isinstance(scenario, dict)
    return replay_scenario(scenario, repository_root=ROOT)


def test_reference_replay_preserves_historical_classification_and_expected_states() -> None:
    result = _result()
    states = [row["observed_state"] for row in result["state_rows"]]
    assert states == [
        "Monitor",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
        "Report-Ready",
    ]
    pack = result["pack"]
    assert pack["decision_state"]["authorized_state"] == "Report"
    assert pack["orchestration_metrics"]["E_t"] == 1.0
    assert pack["orchestration_metrics"]["A_t"] == 0.8


def test_public_exploitation_increases_E_without_becoming_local_telemetry() -> None:
    result = _result()
    pack = result["pack"]
    claims = [
        claim
        for claim in pack["claims"]
        if claim["source_artifact_type"] == "public_exploitation_report"
    ]
    assert len(claims) == 1
    assert claims[0]["proposition"] == "malicious_exploitation_observed"
    assert claims[0]["value"] is True
    assert pack["vulnerability_intelligence"]["public_exploitation_observed"] is True
    assert pack["local_evidence"]["malicious_exploitation_observed"] is False
    assert pack["local_evidence"]["telemetry_reference"].endswith("local_observation.jsonl")


def test_reference_inputs_are_explicitly_synthetic_and_epss_has_verification_contract() -> None:
    result = _result()
    pack = result["pack"]
    assert pack["asset_context"]["evidence_classification"] == "synthetic_reference_deployment"
    scenario = read_yaml(SCENARIO)
    assert scenario["scenario"]["classification"] == "historical_reference_deployment"
    assert scenario["scenario"]["primary_controlled_family"] is False
    epss = next(
        source
        for source in result["source_manifest"]["sources"]
        if source["artifact_type"] == "epss_snapshot"
    )
    assert "epss_snapshot.json" in epss["relative_path"]
    snapshot = __import__("json").loads((ROOT / epss["relative_path"]).read_text())
    assert snapshot["verification_status"] == ("authoritative_dual_source_verification_contract")
