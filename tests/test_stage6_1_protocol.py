from pathlib import Path

import pytest

from sbom_to_audit.baseline.protocol import load_manual_protocol

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "evaluation" / "baseline_protocol_v0.2.yaml"


def test_stage6_1_manual_protocol_is_frozen_and_preserves_locked_metrics() -> None:
    protocol = load_manual_protocol(PROTOCOL)
    assert protocol.protocol_version == "0.2"
    assert protocol.evaluation_status == "PRE_EXECUTION_PROTOCOL_FROZEN"
    assert protocol.locked_metrics == ("EC", "TR", "CD", "CA", "AR", "SC", "EPG")
    assert protocol.blinding_required is True
    assert "confidence" not in protocol.prohibited_tools


def test_stage6_1_protocol_rejects_mutable_status(tmp_path: Path) -> None:
    text = PROTOCOL.read_text(encoding="utf-8").replace("PRE_EXECUTION_PROTOCOL_FROZEN", "DRAFT")
    path = tmp_path / "protocol.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="pre-execution frozen"):
        load_manual_protocol(path)
