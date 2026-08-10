import json
from pathlib import Path

from scripts.validate_stage6_3_colab_notebook import validate_notebook

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "stage6_3_colab_checkpoint.ipynb"


def test_stage6_3_notebook_contract_passes() -> None:
    assert validate_notebook(NOTEBOOK) == []


def test_stage6_3_notebook_is_output_free() -> None:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    code_cells = [cell for cell in notebook["cells"] if cell.get("cell_type") == "code"]
    assert code_cells
    assert all(cell.get("execution_count") is None for cell in code_cells)
    assert all(cell.get("outputs") == [] for cell in code_cells)
