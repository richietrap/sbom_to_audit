import ast
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "stage6_1_5_colab_checkpoint.ipynb"


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, list):
        return "".join(str(line) for line in source)
    return str(source)


def _load_module(path: Path, source: str) -> ModuleType:
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_checked(tmp_path: Path, log_root: Path) -> Any:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    source = _cell_source(notebook["cells"][2])
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_checked"
    )
    module_source = (
        "import json\n"
        "import re\n"
        "import shlex\n"
        "import subprocess\n"
        "import time\n"
        "from collections.abc import Sequence\n"
        "from pathlib import Path\n\n" + ast.unparse(function) + "\n"
    )
    module = _load_module(tmp_path / "notebook_run_checked.py", module_source)
    module.LOG_ROOT = log_root
    return module.run_checked


def test_stage6_1_5_run_checked_preserves_each_retry(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    marker = tmp_path / "marker"
    script = tmp_path / "flaky.py"
    script.write_text(
        "from pathlib import Path\n"
        f"marker = Path({str(marker)!r})\n"
        "if marker.exists():\n"
        "    print('second attempt passes')\n"
        "else:\n"
        "    marker.write_text('seen')\n"
        "    print('first attempt fails')\n"
        "    raise SystemExit(7)\n",
        encoding="utf-8",
    )

    completed = _run_checked(tmp_path, logs)(
        "flaky command",
        [sys.executable, str(script)],
        attempts=2,
        retry_delay_seconds=0,
    )

    assert completed.returncode == 0
    assert (logs / "flaky_command.attempt-01.log").is_file()
    assert (logs / "flaky_command.attempt-02.log").is_file()
    summary = json.loads((logs / "flaky_command.summary.json").read_text(encoding="utf-8"))
    assert [row["returncode"] for row in summary["attempts"]] == [7, 0]
    assert summary["final_returncode"] == 0


def test_stage6_1_5_run_checked_preserves_all_failed_attempts(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()

    with pytest.raises(RuntimeError, match="Attempt logs"):
        _run_checked(tmp_path, logs)(
            "always fails",
            [sys.executable, "-c", "print('failure'); raise SystemExit(3)"],
            attempts=2,
            retry_delay_seconds=0,
        )

    assert (logs / "always_fails.attempt-01.log").is_file()
    assert (logs / "always_fails.attempt-02.log").is_file()
    summary = json.loads((logs / "always_fails.summary.json").read_text(encoding="utf-8"))
    assert [row["returncode"] for row in summary["attempts"]] == [3, 3]
    assert summary["final_returncode"] == 3


def test_stage6_1_5_run_checked_records_accepted_nonzero(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()

    completed = _run_checked(tmp_path, logs)(
        "expected strict validation failure",
        [sys.executable, "-c", "print('strict invalid'); raise SystemExit(1)"],
        accepted_returncodes=(0, 1),
    )

    assert completed.returncode == 1
    summary = json.loads(
        (logs / "expected_strict_validation_failure.summary.json").read_text(encoding="utf-8")
    )
    assert summary["final_returncode"] == 1
    assert summary["accepted_returncodes"] == [0, 1]
