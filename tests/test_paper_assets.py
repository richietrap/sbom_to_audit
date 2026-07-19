import json
from pathlib import Path

from paper_assets.scripts.build_stage2_assets import build
from sbom_to_audit.cli import run

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "ghost_logger.yaml"


def test_pilot_paper_assets_are_generated_from_outputs(tmp_path: Path) -> None:
    output_root = tmp_path / "outputs"
    destination = tmp_path / "paper_assets"
    run(SCENARIO, output_root)
    generated = build(output_root, destination)
    for path in generated.values():
        assert Path(path).is_file()
    metadata = json.loads(
        (destination / "data" / "stage2_ghost_logger_asset_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert metadata["asset_status"] == "PILOT"
    assert metadata["manuscript_eligible"] is False
    assert metadata["source_run_id"] == "GL-STAGE2-0-1-PILOT-001"
    assert len(metadata["generated_asset_hashes"]) == 5
    assert len(metadata["source_data_hashes"]) == 4
    assert len(metadata["generation_script_hash"]) == 64
    assert all(len(value) == 64 for value in metadata["generated_asset_hashes"].values())

    lifecycle = destination / "tables" / "ghost_logger_conflict_lifecycle.csv"
    text = lifecycle.read_text(encoding="utf-8")
    assert "resolved" in text
    assert "EVT-GL-010H" in text
    assert "EVT-GL-014H" in text
