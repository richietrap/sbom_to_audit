"""Regression checks for the GitHub Actions workflow configuration."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def test_workflow_uses_resolvable_official_action_major_tags() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/checkout@v6" in text
    assert "actions/setup-python@v6" in text
    assert "actions/checkout@v7" not in text
    assert "actions/setup-python@v7" not in text
