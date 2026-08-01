import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_stage6_1_colab_notebook.py"
NOTEBOOK = ROOT / "notebooks" / "stage6_1_5_colab_checkpoint.ipynb"


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, list):
        return "".join(str(line) for line in source)
    return str(source)


def _set_cell_source(cell: dict[str, Any], source: str) -> None:
    cell["source"] = source.splitlines(keepends=True)


def _run_validator(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(path),
            "--expected-stage",
            "6.1.5",
            "--expected-version",
            "0.6.1.5",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _mutated_notebook(tmp_path: Path, name: str) -> tuple[dict[str, Any], Path]:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    return notebook, tmp_path / name


def test_stage6_1_5_notebook_contract_validator_passes() -> None:
    completed = _run_validator(NOTEBOOK)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_stage6_1_5_notebook_validator_rejects_global_pip_check(tmp_path: Path) -> None:
    notebook, path = _mutated_notebook(tmp_path, "global-pip-check.ipynb")
    source = _cell_source(notebook["cells"][3])
    _set_cell_source(
        notebook["cells"][3],
        source.replace(
            '[str(VENV_PYTHON), "-m", "pip", "check"]',
            '["python", "-m", "pip", "check"]',
        ),
    )
    path.write_text(json.dumps(notebook), encoding="utf-8")

    completed = _run_validator(path)
    assert completed.returncode == 1
    assert "global-environment pip check" in completed.stdout


def test_stage6_1_5_notebook_validator_rejects_invalid_code_cell(tmp_path: Path) -> None:
    notebook, path = _mutated_notebook(tmp_path, "invalid-code.ipynb")
    source = _cell_source(notebook["cells"][2])
    _set_cell_source(notebook["cells"][2], source + "\nif True print('invalid')\n")
    path.write_text(json.dumps(notebook), encoding="utf-8")

    completed = _run_validator(path)
    assert completed.returncode == 1
    assert "does not compile" in completed.stdout


def test_stage6_1_5_notebook_validator_rejects_system_site_packages(tmp_path: Path) -> None:
    notebook, path = _mutated_notebook(tmp_path, "system-site-packages.ipynb")
    source = _cell_source(notebook["cells"][3])
    source = source.replace(
        '[sys.executable, "-m", "venv", str(VENV)]',
        '[sys.executable, "-m", "venv", "--system-site-packages", str(VENV)]',
    )
    _set_cell_source(notebook["cells"][3], source)
    path.write_text(json.dumps(notebook), encoding="utf-8")

    completed = _run_validator(path)
    assert completed.returncode == 1
    assert "system site-packages exposure" in completed.stdout


def test_stage6_1_5_notebook_validator_rejects_kernel_project_install(tmp_path: Path) -> None:
    notebook, path = _mutated_notebook(tmp_path, "kernel-project-install.ipynb")
    source = _cell_source(notebook["cells"][3])
    source = source.replace(
        '[str(VENV_PYTHON), "-m", "pip", "install", "--no-cache-dir", "-e", ".[dev]"]',
        '[sys.executable, "-m", "pip", "install", "--no-cache-dir", "-e", ".[dev]"]',
    )
    _set_cell_source(notebook["cells"][3], source)
    path.write_text(json.dumps(notebook), encoding="utf-8")

    completed = _run_validator(path)
    assert completed.returncode == 1
    assert "kernel interpreter" in completed.stdout


def test_stage6_1_5_notebook_validator_rejects_unsafe_manual_extraction(
    tmp_path: Path,
) -> None:
    notebook, path = _mutated_notebook(tmp_path, "unsafe-extraction.ipynb")
    source = _cell_source(notebook["cells"][6])
    source = source.replace(
        "                    target_stream.write(chunk)",
        "                    target_stream.write(chunk)\n        archive.extractall(root)",
    )
    _set_cell_source(notebook["cells"][6], source)
    path.write_text(json.dumps(notebook), encoding="utf-8")

    completed = _run_validator(path)
    assert completed.returncode == 1
    assert "bulk archive extraction" in completed.stdout
