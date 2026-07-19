from pathlib import Path

from scripts.validate_repository import run_validation

ROOT = Path(__file__).resolve().parents[1]


def test_repository_validator_passes_with_stage2_source_warnings() -> None:
    report = run_validation(strict_sources=False)
    assert report.status == "PASS"
    assert not report.errors
    assert any("expected before Stage 2" in warning for warning in report.warnings)


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
    ):
        assert required in text
