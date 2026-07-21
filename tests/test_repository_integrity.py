from pathlib import Path

from scripts.validate_repository import run_validation

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
        "scenarios": 9,
        "runs": 10,
        "environments": 6,
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
    ):
        assert required in text
