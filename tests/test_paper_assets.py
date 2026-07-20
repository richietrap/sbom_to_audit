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


def test_stage3_assets_compare_scope_mismatch_and_negative_control(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage3_assets import build as build_stage3

    output_root = tmp_path / "outputs"
    for scenario_name in ("ghost_logger", "false_comfort", "false_comfort_control"):
        run(ROOT / "data" / "scenarios" / f"{scenario_name}.yaml", output_root)
    destination = tmp_path / "stage3_assets"
    generated = build_stage3(output_root, destination)
    assert all(Path(path).is_file() for path in generated.values())
    metadata = json.loads(
        (destination / "data" / "stage3_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT"
    assert metadata["manuscript_eligible"] is False
    assert len(metadata["generated_asset_hashes"]) == 4
    scope_table = (destination / "tables" / "false_comfort_scope_applicability.csv").read_text(
        encoding="utf-8"
    )
    assert "scope_mismatch" in scope_table
    assert "applicable" in scope_table
    assert "legacy-plugin-profile" in scope_table
    assert "standard-profile" in scope_table


def test_stage4_assets_compare_operational_impact_with_matched_evidence(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage4_assets import build as build_stage4

    output_root = tmp_path / "outputs"
    for scenario_name in (
        "ghost_logger",
        "false_comfort",
        "false_comfort_control",
        "operational_outlier",
        "operational_outlier_control",
    ):
        run(ROOT / "data" / "scenarios" / f"{scenario_name}.yaml", output_root)
    destination = tmp_path / "stage4_assets"
    generated = build_stage4(output_root, destination)
    assert all(Path(path).is_file() for path in generated.values())
    metadata = json.loads(
        (destination / "data" / "stage4_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT"
    assert metadata["manuscript_eligible"] is False
    assert len(metadata["generated_asset_hashes"]) == 4

    comparison = (destination / "tables" / "operational_impact_comparison.csv").read_text(
        encoding="utf-8"
    )
    assert "6.5" in comparison
    assert "MEDIUM" in comparison
    assert "Report-Ready" in comparison
    assert "Monitor" in comparison
    assert "critical" in comparison
    assert "medium" in comparison
