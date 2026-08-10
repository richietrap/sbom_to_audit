import json
from pathlib import Path

from scripts.validate_stage6_4_colab_notebook import validate_notebook

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks/stage6_4_colab_checkpoint.ipynb"


def test_stage6_4_notebook_contract_is_valid() -> None:
    assert validate_notebook(NOTEBOOK) == []


def test_stage6_4_notebook_rejects_mutable_ref(tmp_path: Path) -> None:
    payload = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    source = "".join(payload["cells"][1]["source"])
    payload["cells"][1]["source"] = source.replace('REF = ""', 'REF = "main"').splitlines(
        keepends=True
    )
    path = tmp_path / "bad.ipynb"
    path.write_text(json.dumps(payload), encoding="utf-8")
    errors = validate_notebook(path)
    assert any("mutable main branch" in error for error in errors)
