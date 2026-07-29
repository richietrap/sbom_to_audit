#!/usr/bin/env python3
"""Create and verify the repository's declared static-quality environment."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VENV = ROOT / ".quality-venv"


def _run(command: list[str], *, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return (completed.stdout or completed.stderr).strip()


def _tool_report(python: Path) -> dict[str, Any]:
    bin_dir = python.parent
    commands = {
        "ruff": [str(bin_dir / "ruff"), "--version"],
        "mypy": [str(bin_dir / "mypy"), "--version"],
        "codespell": [str(bin_dir / "codespell"), "--version"],
        "yamllint": [str(bin_dir / "yamllint"), "--version"],
        "hypothesis": [
            str(python),
            "-c",
            "import hypothesis; print(hypothesis.__version__)",
        ],
    }
    return {name: _run(command) for name, command in commands.items()}


def bootstrap(venv: Path, python_executable: str) -> dict[str, Any]:
    _run([python_executable, "-m", "venv", "--clear", str(venv)])
    python = venv / "bin" / "python"
    _run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    _run([str(python), "-m", "pip", "install", "-e", ".[dev]"])
    _run([str(python), "-m", "pip", "check"])
    return {
        "status": "PASS",
        "venv": str(venv),
        "python": _run([str(python), "--version"]),
        "tools": _tool_report(python),
    }


def check_current() -> dict[str, Any]:
    python = Path(sys.executable)
    return {
        "status": "PASS",
        "venv": str(python.parent.parent),
        "python": _run([str(python), "--version"]),
        "tools": _tool_report(python),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", type=Path, default=DEFAULT_VENV)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--check-current", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    try:
        report = check_current() if args.check_current else bootstrap(args.venv, args.python)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        report = {
            "status": "TOOLCHAIN_NOT_PROVISIONED",
            "error": str(exc),
        }
        exit_code = 1
    else:
        exit_code = 0

    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(payload, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
