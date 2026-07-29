from pathlib import Path

from sbom_to_audit.baseline.evaluation_freeze import verify_freeze, write_freeze


def test_stage6_1_freeze_detects_post_freeze_drift(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "protocol.yaml"
    target.write_text("version: 0.2\n", encoding="utf-8")
    freeze = tmp_path / "freeze.json"
    write_freeze(root, ("protocol.yaml",), freeze)
    assert verify_freeze(root, freeze) == []
    target.write_text("version: 0.3\n", encoding="utf-8")
    assert verify_freeze(root, freeze) == ["hash_mismatch:protocol.yaml"]
