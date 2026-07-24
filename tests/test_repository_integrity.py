from pathlib import Path

from scripts.validate_repository import (
    ValidationReport,
    run_validation,
    validate_generated_artifact_placement,
)

ROOT = Path(__file__).resolve().parents[1]


def test_repository_validator_passes_with_all_strict_sources() -> None:
    report = run_validation(strict_sources=True)
    assert report.status == "PASS"
    assert not report.errors
    counts = {
        Path(item["file"]).stem: item["registered_sources"] for item in report.checks["scenarios"]
    }
    assert counts == {
        "false_comfort": 13,
        "false_comfort_control": 8,
        "ghost_logger": 15,
        "historical_cve_2024_3400_reference": 14,
        "operational_outlier": 14,
        "operational_outlier_control": 10,
        "rapid_pivot": 13,
        "rapid_pivot_control": 13,
    }
    assert report.checks["evaluation_registry"] == {
        "scenarios": 10,
        "runs": 29,
        "environments": 9,
    }
    assert report.checks["baseline_protocol"] == {
        "protocol_id": "matched_unorchestrated_psirt_worksheet",
        "protocol_version": "0.1",
        "scenario_count": 7,
        "limitations": 5,
    }


def test_gitignore_excludes_generated_outputs_and_local_quality_caches() -> None:
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for required in (
        ".mypy_cache/",
        ".ruff_cache/",
        ".hypothesis/",
        ".qa-venv/",
        "outputs/evidence_packs/*",
        "outputs/state_logs/*",
        "outputs/conflict_reports/*",
        "outputs/metrics/*",
        "outputs/source_manifests/*",
        "outputs/audit_ledgers/*",
        "outputs/validation/*",
        "outputs/stage6_baseline/*",
        "/cve_2024_3400_epss_2024-04-15_api.json",
        "/cve_2024_3400_epss_2024-04-15_row.csv",
        "/epss_scores-2024-04-15.csv.gz",
        "/historical_epss_verification.json",
    ):
        assert required in text


def test_root_historical_epss_downloads_are_rejected(tmp_path: Path) -> None:
    stray = tmp_path / "cve_2024_3400_epss_2024-04-15_api.json"
    stray.write_text("{}", encoding="utf-8")
    report = ValidationReport()
    validate_generated_artifact_placement(report, tmp_path)
    assert report.status == "FAIL"
    assert report.checks["root_verification_artifacts"] == [stray.name]
    assert "not repository root" in report.errors[0]
