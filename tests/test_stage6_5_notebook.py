"""Stage 6.5 Colab checkpoint contract tests."""

from pathlib import Path

from scripts.validate_stage6_5_colab_notebook import validate_notebook

ROOT = Path(__file__).resolve().parents[1]


def test_stage6_5_notebook_contract() -> None:
    notebook = ROOT / "notebooks/stage6_5_colab_checkpoint.ipynb"
    assert validate_notebook(notebook) == []
