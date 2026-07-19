from pathlib import Path

from scripts.validate_repository import run_validation

ROOT = Path(__file__).resolve().parents[1]


def test_repository_validator_passes_with_strict_stage2_sources() -> None:
    report = run_validation(strict_sources=True)
    assert report.status == "PASS"
    assert not report.errors
    assert report.checks["scenarios"][0]["registered_sources"] == 15


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
