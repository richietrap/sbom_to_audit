import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE3_NOTEBOOK = ROOT / "notebooks" / "stage3_colab_checkpoint.ipynb"


def test_stage3_colab_notebook_code_cells_compile() -> None:
    notebook = json.loads(STAGE3_NOTEBOOK.read_text(encoding="utf-8"))
    assert notebook["nbformat"] == 4
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    for index, cell in enumerate(code_cells, 1):
        source = "".join(cell["source"])
        ast.parse(source, filename=f"stage3_colab_cell_{index}.py")


def test_stage3_colab_notebook_uses_isolated_environment_and_release_gate() -> None:
    text = STAGE3_NOTEBOOK.read_text(encoding="utf-8")
    for required in (
        "sbom_to_audit_stage3_venv",
        "scripts/release_check.py",
        "false_comfort_control",
        "scope_mismatch",
        "stage3_colab_checkpoint_evidence.zip",
    ):
        assert required in text
    assert ("<YOUR-" + "GITHUB-USERNAME>") not in text


STAGE4_NOTEBOOK = ROOT / "notebooks" / "stage4_colab_checkpoint.ipynb"


def test_stage4_colab_notebook_code_cells_compile() -> None:
    notebook = json.loads(STAGE4_NOTEBOOK.read_text(encoding="utf-8"))
    assert notebook["nbformat"] == 4
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    for index, cell in enumerate(code_cells, 1):
        source = "".join(cell["source"])
        ast.parse(source, filename=f"stage4_colab_cell_{index}.py")


def test_stage4_colab_notebook_preserves_checkpoint_lineage() -> None:
    text = STAGE4_NOTEBOOK.read_text(encoding="utf-8")
    for required in (
        "sbom_to_audit_stage4_venv",
        "scripts/release_check.py",
        "operational_outlier_control",
        "under_investigation",
        "stage4_colab_checkpoint_evidence.zip",
        "Tested Git commit",
        "Colab evidence bundle SHA-256",
    ):
        assert required in text
    assert ("<YOUR-" + "GITHUB-USERNAME>") not in text
