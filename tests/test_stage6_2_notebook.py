import json
from copy import deepcopy
from pathlib import Path

from scripts.validate_stage6_2_colab_notebook import validate_notebook

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "stage6_2_colab_checkpoint.ipynb"


def test_stage6_2_notebook_contract_passes() -> None:
    assert validate_notebook(NOTEBOOK) == []


def test_stage6_2_notebook_has_no_retained_outputs() -> None:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    for cell in notebook["cells"]:
        if cell.get("cell_type") == "code":
            assert cell.get("execution_count") is None
            assert cell.get("outputs") == []


def test_stage6_2_notebook_validator_rejects_shared_pip_check(tmp_path: Path) -> None:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    mutated = deepcopy(notebook)
    source = "".join(mutated["cells"][3]["source"])
    source += '\nsubprocess.run([sys.executable, "-m", "pip", "check"])\n'
    mutated["cells"][3]["source"] = source
    target = tmp_path / "bad.ipynb"
    target.write_text(json.dumps(mutated), encoding="utf-8")
    errors = validate_notebook(target)
    assert any("shared-kernel dependency check" in error for error in errors)


def test_stage6_2_notebook_validator_rejects_invalid_syntax(tmp_path: Path) -> None:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    mutated = deepcopy(notebook)
    mutated["cells"][1]["source"] = "def broken(:\n"
    target = tmp_path / "bad.ipynb"
    target.write_text(json.dumps(mutated), encoding="utf-8")
    errors = validate_notebook(target)
    assert any("does not compile" in error for error in errors)
