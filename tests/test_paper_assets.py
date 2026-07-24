import csv
import json
import xml.etree.ElementTree as ET
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


def test_stage5_assets_compare_clock_aware_escalation_with_temporal_control(
    tmp_path: Path,
) -> None:
    from paper_assets.scripts.build_stage5_assets import build as build_stage5

    output_root = tmp_path / "outputs"
    for scenario_name in (
        "ghost_logger",
        "false_comfort",
        "false_comfort_control",
        "operational_outlier",
        "operational_outlier_control",
        "rapid_pivot",
        "rapid_pivot_control",
    ):
        run(ROOT / "data" / "scenarios" / f"{scenario_name}.yaml", output_root)
    destination = tmp_path / "stage5_assets"
    generated = build_stage5(output_root, destination)
    assert all(Path(path).is_file() for path in generated.values())

    metadata = json.loads(
        (destination / "data" / "stage5_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT"
    assert metadata["manuscript_eligible"] is False
    assert len(metadata["generated_asset_hashes"]) == 4
    assert len(metadata["source_run_ids"]) == 7

    comparison = (destination / "tables" / "rapid_pivot_clock_comparison.csv").read_text(
        encoding="utf-8"
    )
    assert "Escalate" in comparison
    assert "Report-Ready" in comparison
    assert "True" in comparison
    assert "False" in comparison

    figure = (destination / "figures" / "rapid_pivot_clock_comparison.svg").read_text(
        encoding="utf-8"
    )
    assert "τE = 18h" in figure
    assert "Early-resolution control" in figure
    assert "{y}" not in figure
    ET.fromstring(figure)


def test_stage55_historical_assets_are_generated_from_registered_outputs(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage55_assets import build
    from scripts.run_historical_replay import run as run_historical

    output_root = tmp_path / "outputs"
    destination = tmp_path / "assets"
    run(
        ROOT / "data" / "scenarios" / "historical_cve_2024_3400_reference.yaml",
        output_root,
    )
    run_historical(output_root)
    hashes = build(output_root, destination)
    assert len(hashes) == 5
    figure = destination / "figures" / "cve_2024_3400_public_timeline.svg"
    assert figure.is_file()
    import xml.etree.ElementTree as ET

    ET.parse(figure)
    metadata = json.loads(
        (destination / "data" / "stage55_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT_VERIFICATION_CANDIDATE"
    assert metadata["manuscript_eligible"] is False
    assert metadata["eligibility_blockers"]


def test_stage551_epss_assets_are_generated_from_verified_outputs(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage551_assets import build
    from scripts.run_historical_replay import run as run_historical

    output_root = tmp_path / "outputs"
    destination = tmp_path / "assets"
    run(
        ROOT / "data" / "scenarios" / "historical_cve_2024_3400_reference.yaml",
        output_root,
    )
    run_historical(output_root)
    hashes = build(output_root, destination)
    assert len(hashes) == 4
    figure = destination / "figures" / "cve_2024_3400_epss_verification.svg"
    assert figure.is_file()
    import xml.etree.ElementTree as ET

    ET.parse(figure)
    metadata = json.loads(
        (destination / "data" / "stage551_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT_VERIFICATION_CANDIDATE"
    assert metadata["manuscript_eligible"] is False
    ablation_rows = list(
        csv.DictReader(
            (destination / "tables" / "cve_2024_3400_epss_ablation.csv").open(
                encoding="utf-8", newline=""
            )
        )
    )
    assert ablation_rows
    assert not any(row["state_changed"] == "True" for row in ablation_rows)


def test_stage552_corrected_epss_assets_use_corrected_run_lineage(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage552_assets import build as build_stage552
    from scripts.run_historical_replay import run as run_historical

    output_root = tmp_path / "outputs"
    destination = tmp_path / "assets"
    run(
        ROOT / "data" / "scenarios" / "historical_cve_2024_3400_reference.yaml",
        output_root,
    )
    run_historical(output_root)
    hashes = build_stage552(output_root, destination)
    assert len(hashes) == 4
    figure = destination / "figures" / "cve_2024_3400_epss_verification.svg"
    ET.parse(figure)
    assert "EPSS 0.00371; percentile 0.72343" in figure.read_text(encoding="utf-8")
    table = list(
        csv.DictReader(
            (destination / "tables" / "cve_2024_3400_epss_verification.csv").open(
                encoding="utf-8", newline=""
            )
        )
    )
    assert table[0]["epss"] == "0.00371"
    assert table[0]["percentile"] == "0.72343"
    metadata = json.loads(
        (destination / "data" / "stage552_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT_VERIFICATION_CANDIDATE"
    assert metadata["manuscript_eligible"] is False
    assert metadata["source_run_ids"] == [
        "HIST-CVE-2024-3400-PUBLIC-STAGE552-CORRECTED-CANDIDATE-001",
        "HIST-CVE-2024-3400-REF-STAGE552-CORRECTED-CANDIDATE-001",
    ]
    assert metadata["generation_script"] == ("paper_assets/scripts/build_stage552_assets.py")


def test_stage6_assets_compare_orchestrated_and_structured_baseline(tmp_path: Path) -> None:
    from paper_assets.scripts.build_stage6_assets import build as build_stage6
    from scripts.run_baseline_comparison import run as run_baseline

    output_root = tmp_path / "stage6_outputs"
    destination = tmp_path / "stage6_assets"
    run_baseline(output_root)
    generated = build_stage6(output_root, destination)
    assert all(Path(path).is_file() for path in generated.values())

    metadata = json.loads(
        (destination / "data" / "stage6_asset_manifest.json").read_text(encoding="utf-8")
    )
    assert metadata["asset_status"] == "PILOT_BASELINE_NOT_FROZEN"
    assert metadata["manuscript_eligible"] is False
    assert metadata["source_run_ids"] == ["STAGE6-MATCHED-BASELINE-PILOT-001"]
    assert len(metadata["generated_asset_hashes"]) == 6

    figure = destination / "figures" / "stage6_metric_comparison.svg"
    ET.parse(figure)
    figure_text = figure.read_text(encoding="utf-8")
    assert "Orchestrated artefact" in figure_text
    assert "Structured un-orchestrated baseline" in figure_text

    metrics = list(
        csv.DictReader(
            (destination / "tables" / "stage6_primary_metric_comparison.csv").open(
                encoding="utf-8", newline=""
            )
        )
    )
    by_metric = {row["metric"]: row for row in metrics}
    assert by_metric["AR"]["difference"] == "0.0"
    assert by_metric["CD"]["difference"] == "0.0"
    assert by_metric["SC"]["difference"] == "0.291667"
