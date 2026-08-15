"""Stage 6.5 Colab checkpoint contract tests."""

import json
from pathlib import Path

from scripts.validate_stage6_5_colab_notebook import validate_notebook

ROOT = Path(__file__).resolve().parents[1]


def test_stage6_5_notebook_contract() -> None:
    notebook = ROOT / "notebooks/stage6_5_colab_checkpoint.ipynb"
    assert validate_notebook(notebook) == []


def test_stage6_5_notebook_rejects_external_result_paths(tmp_path: Path) -> None:
    notebook = ROOT / "notebooks/stage6_5_colab_checkpoint.ipynb"
    payload = json.loads(notebook.read_text(encoding="utf-8"))
    replaced = False
    for cell in payload["cells"]:
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", [])
        text = "".join(source) if isinstance(source, list) else source
        updated = text.replace(
            'RESULT_FULL = WORKDIR / "outputs/validation/stage65_colab_results"',
            'RESULT_FULL = Path("/content/stage65_results")',
        )
        if updated != text:
            replaced = True
            cell["source"] = (
                updated.splitlines(keepends=True) if isinstance(source, list) else updated
            )
    assert replaced
    mutated = tmp_path / "stage6_5_colab_checkpoint.ipynb"
    mutated.write_text(json.dumps(payload), encoding="utf-8")
    errors = validate_notebook(mutated)
    assert any("repository-relative ignored results path" in error for error in errors)
