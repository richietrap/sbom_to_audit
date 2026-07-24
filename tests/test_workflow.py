"""Regression checks for the GitHub Actions workflow configuration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGRESSION_WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
QUALITY_WORKFLOW = ROOT / ".github" / "workflows" / "quality.yml"


def test_workflows_use_supported_official_action_major_tags() -> None:
    for path in (REGRESSION_WORKFLOW, QUALITY_WORKFLOW):
        text = path.read_text(encoding="utf-8")
        assert "actions/checkout@v6" in text
        assert "actions/setup-python@v6" in text
        assert "actions/checkout@v7" not in text
        assert "actions/setup-python@v7" not in text


def test_regression_workflow_does_not_require_committed_generated_outputs() -> None:
    text = REGRESSION_WORKFLOW.read_text(encoding="utf-8")
    assert 'output-root "$first"' in text
    assert 'output-root "$second"' in text
    assert 'diff -ru "$first" "$second"' in text


def test_quality_workflow_runs_independent_quality_gates() -> None:
    text = QUALITY_WORKFLOW.read_text(encoding="utf-8")
    for required in (
        "actionlint",
        "ruff check .",
        "ruff format --check .",
        "python -m mypy src",
        "codespell",
        "yamllint",
        "scripts/validate_repository.py",
        "scripts/verify_historical_epss.py",
        "--online",
        "--epss-verification-report",
        "scripts/assert_verified_historical_replay.py",
        "--cov=sbom_to_audit",
    ):
        assert required in text


def test_regression_workflow_runs_deterministic_stage6_baseline() -> None:
    text = REGRESSION_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/run_baseline_comparison.py" in text
    assert "stage6-baseline-first" in text
    assert "stage6-baseline-second" in text
