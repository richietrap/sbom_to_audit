import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_stage6_1_notebook_rejects_mutable_main_ref() -> None:
    notebook = json.loads(
        (ROOT / "notebooks" / "stage6_1_colab_checkpoint.ipynb").read_text(encoding="utf-8")
    )
    source = "\n".join(
        line
        for cell in notebook["cells"]
        for line in cell.get("source", [])
        if cell.get("cell_type") == "code"
    )
    assert 'REF = "STAGE61_REF_REQUIRED"' in source
    assert "REF in {\"main\", \"master\", \"STAGE61_REF_REQUIRED\"}" in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source
