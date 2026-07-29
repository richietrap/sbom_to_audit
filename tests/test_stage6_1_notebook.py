import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _code_source(path: Path) -> str:
    notebook = json.loads(path.read_text(encoding="utf-8"))
    return "\n".join(
        line
        for cell in notebook["cells"]
        for line in cell.get("source", [])
        if cell.get("cell_type") == "code"
    )


def test_stage6_1_notebook_rejects_mutable_main_ref() -> None:
    source = _code_source(ROOT / "notebooks" / "stage6_1_colab_checkpoint.ipynb")
    assert 'REF = "STAGE61_REF_REQUIRED"' in source
    assert 'REF in {"main", "master", "STAGE61_REF_REQUIRED"}' in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source


def test_stage6_1_1_notebook_rejects_mutable_ref_and_checks_version() -> None:
    source = _code_source(ROOT / "notebooks" / "stage6_1_1_colab_checkpoint.ipynb")
    assert 'REF = "STAGE611_REF_REQUIRED"' in source
    assert 'REF in {"main", "master", "STAGE611_REF_REQUIRED"}' in source
    assert 'sbom_to_audit.__version__ == "0.6.1.1"' in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source


def test_stage6_1_2_notebook_rejects_mutable_ref_and_checks_version() -> None:
    source = _code_source(ROOT / "notebooks" / "stage6_1_2_colab_checkpoint.ipynb")
    assert 'REF = "STAGE612_REF_REQUIRED"' in source
    assert 'REF in {"main", "master", "STAGE612_REF_REQUIRED"}' in source
    assert 'sbom_to_audit.__version__ == "0.6.1.2"' in source
    assert '"stage": "6.1.2"' in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source


def test_stage6_1_3_notebook_rejects_mutable_ref_and_checks_version() -> None:
    source = _code_source(ROOT / "notebooks" / "stage6_1_3_colab_checkpoint.ipynb")
    assert 'REF = "STAGE613_REF_REQUIRED"' in source
    assert 'REF in {"main", "master", "STAGE613_REF_REQUIRED"}' in source
    assert 'sbom_to_audit.__version__ == "0.6.1.3"' in source
    assert '"stage": "6.1.3"' in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source


def test_stage6_1_4_notebook_rejects_mutable_ref_and_checks_version() -> None:
    source = _code_source(ROOT / "notebooks" / "stage6_1_4_colab_checkpoint.ipynb")
    assert 'REF = "STAGE614_REF_REQUIRED"' in source
    assert 'REF in {"main", "master", "STAGE614_REF_REQUIRED"}' in source
    assert 'sbom_to_audit.__version__ == "0.6.1.4"' in source
    assert '"stage": "6.1.4"' in source
    assert "freeze_stage6_1_protocol.py" in source
    assert "--verify" in source
