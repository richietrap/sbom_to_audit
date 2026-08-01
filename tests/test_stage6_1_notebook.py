import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, list):
        return "".join(str(line) for line in source)
    return str(source)


def _code_source(path: Path) -> str:
    notebook = json.loads(path.read_text(encoding="utf-8"))
    return "\n".join(
        _cell_source(cell)
        for cell in notebook["cells"]
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


def test_stage6_1_5_notebook_uses_isolated_environment_and_full_preflight() -> None:
    path = ROOT / "notebooks" / "stage6_1_5_colab_checkpoint.ipynb"
    source = _code_source(path)
    notebook = json.loads(path.read_text(encoding="utf-8"))

    assert 'REF = ""' in source
    assert 're.fullmatch(r"[0-9a-fA-F]{40}", REF)' in source
    assert 'PACKAGE_VERSION = "0.6.1.5"' in source
    assert 'STAGE = "6.1.5"' in source
    assert '["git", "checkout", "--detach", REF]' in source
    assert '["git", "branch", "--show-current"]' in source
    assert 'VENV_PYTHON = VENV / "bin" / "python"' in source
    assert '[str(VENV_PYTHON), "-m", "pip", "check"]' in source
    assert "scripts/release_check.py" in source
    assert "scripts/verify_historical_epss.py" in source
    assert "def safe_extract_zip" in source
    assert "zipfile.is_zipfile(source)" in source
    assert "100 * 1024 * 1024" in source
    assert "archive.testzip()" in source
    assert "evidence_checksums.json" in source
    assert 'subprocess.run(["python"' not in source
    assert 'shutil.unpack_archive(' not in source

    for index, cell in enumerate(notebook["cells"], start=1):
        if cell.get("cell_type") != "code":
            continue
        compile(_cell_source(cell), f"notebook-cell-{index}", "exec")
        assert cell.get("execution_count") is None
        assert not cell.get("outputs")
