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


STAGE5_NOTEBOOK = ROOT / "notebooks" / "stage5_colab_checkpoint.ipynb"


def test_stage5_colab_notebook_code_cells_compile() -> None:
    notebook = json.loads(STAGE5_NOTEBOOK.read_text(encoding="utf-8"))
    assert notebook["nbformat"] == 4
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    for index, cell in enumerate(code_cells, 1):
        source = "".join(cell["source"])
        ast.parse(source, filename=f"stage5_colab_cell_{index}.py")


def test_stage5_colab_notebook_preserves_clock_checkpoint_lineage() -> None:
    text = STAGE5_NOTEBOOK.read_text(encoding="utf-8")
    for required in (
        "sbom_to_audit_stage5_venv",
        "scripts/release_check.py",
        "rapid_pivot_control",
        "clock_safeguard_triggered",
        "stage5_colab_checkpoint_evidence.zip",
        "Tested Git commit",
        "Colab evidence bundle SHA-256",
    ):
        assert required in text
    assert ("<YOUR-" + "GITHUB-USERNAME>") not in text


STAGE55_NOTEBOOK = ROOT / "notebooks" / "stage55_colab_checkpoint.ipynb"


def test_stage55_colab_notebook_code_cells_compile() -> None:
    notebook = json.loads(STAGE55_NOTEBOOK.read_text(encoding="utf-8"))
    assert notebook["nbformat"] == 4
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    for index, cell in enumerate(code_cells, 1):
        source = "".join(cell["source"])
        ast.parse(source, filename=f"stage55_colab_cell_{index}.py")


def test_stage55_colab_notebook_preserves_historical_boundaries_and_lineage() -> None:
    text = STAGE55_NOTEBOOK.read_text(encoding="utf-8")
    for required in (
        "sbom_to_audit_stage55_venv",
        "scripts/release_check.py",
        "run_historical_replay.py",
        "historical_cve_2024_3400_reference",
        "full_evidencepack_generated",
        "public_exploitation_observed",
        "stage55_colab_checkpoint_evidence.zip",
        "Tested Git commit",
        "Colab evidence bundle SHA-256",
    ):
        assert required in text
    assert ("<YOUR-" + "GITHUB-USERNAME>") not in text


STAGE551_NOTEBOOK = ROOT / "notebooks" / "stage551_colab_checkpoint.ipynb"


def test_stage551_colab_notebook_code_cells_compile() -> None:
    notebook = json.loads(STAGE551_NOTEBOOK.read_text(encoding="utf-8"))
    assert notebook["nbformat"] == 4
    code_cells = [cell for cell in notebook["cells"] if cell["cell_type"] == "code"]
    assert code_cells
    for index, cell in enumerate(code_cells, 1):
        ast.parse("".join(cell["source"]), filename=f"stage551_colab_cell_{index}.py")


def test_stage551_colab_notebook_preserves_authoritative_epss_evidence() -> None:
    text = STAGE551_NOTEBOOK.read_text(encoding="utf-8")
    for required in (
        "verify_historical_epss.py",
        "--online",
        "authoritative_dual_source_verified",
        "epss_scores-2024-04-15.csv.gz",
        "state_trajectory_changed",
        "stage551_colab_checkpoint_evidence.zip",
        "Tested Git commit",
        "Colab evidence-bundle SHA-256",
    ):
        assert required in text
    assert ("<YOUR-" + "GITHUB-USERNAME>") not in text
    assert "authoritative_dual_source_verified_by_required_online_gate" not in text
