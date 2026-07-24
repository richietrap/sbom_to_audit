from pathlib import Path

import pytest

from sbom_to_audit.baseline.protocol import load_protocol

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "evaluation" / "baseline_protocol_v0.1.yaml"


def test_baseline_protocol_is_frozen_and_covers_only_controlled_replays() -> None:
    protocol = load_protocol(PROTOCOL)
    assert protocol.protocol_version == "0.1"
    assert protocol.protocol_id == "matched_unorchestrated_psirt_worksheet"
    assert protocol.scenario_ids == (
        "ghost_logger",
        "false_comfort",
        "false_comfort_control",
        "operational_outlier",
        "operational_outlier_control",
        "rapid_pivot",
        "rapid_pivot_control",
    )
    assert "historical_cve_2024_3400_reference" not in protocol.scenario_ids
    assert protocol.limitations


def test_baseline_protocol_rejects_an_unsupported_version(tmp_path: Path) -> None:
    path = tmp_path / "protocol.yaml"
    path.write_text(
        """
protocol_version: "9.9"
protocol_id: matched_unorchestrated_psirt_worksheet
classification: test
scenario_ids: [ghost_logger]
decision_categories:
  high_impact_criticalities: [critical]
  broad_deployment_scopes: [widespread]
  not_affected_statuses: [known_not_affected]
limitations: [test limitation]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="protocol_version"):
        load_protocol(path)
