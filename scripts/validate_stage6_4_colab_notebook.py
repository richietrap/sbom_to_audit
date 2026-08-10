#!/usr/bin/env python3
"""Validate the Stage 6.4 Colab checkpoint execution contract."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, str):
        return source
    if isinstance(source, list) and all(isinstance(item, str) for item in source):
        return "".join(source)
    raise ValueError("notebook cell source must be a string or list of strings")


def validate_notebook(path: Path) -> list[str]:
    errors: list[str] = []
    notebook = json.loads(path.read_text(encoding="utf-8"))
    cells = notebook.get("cells") or []
    if not isinstance(cells, list):
        return ["notebook cells must be a list"]

    code_sources: list[str] = []
    for index, cell in enumerate(cells):
        if not isinstance(cell, dict):
            errors.append(f"cell {index} must be an object")
            continue
        if cell.get("cell_type") != "code":
            continue
        source = _cell_source(cell)
        code_sources.append(source)
        try:
            ast.parse(source)
        except SyntaxError as exc:
            errors.append(f"code cell {index} does not compile: {exc}")
        if cell.get("execution_count") is not None:
            errors.append(f"code cell {index} retains an execution count")
        if cell.get("outputs") not in (None, []):
            errors.append(f"code cell {index} retains outputs")

    source = "\n".join(code_sources)
    required = {
        'STAGE = "6.4"': "Stage identifier",
        'PACKAGE_VERSION = "0.6.4"': "package version",
        'CHECKPOINT_ID = "STAGE6-4-CHECKPOINT-001"': "checkpoint identifier",
        're.fullmatch(r"[0-9a-fA-F]{40}", REF)': "exact commit validation",
        '["git", "checkout", "--detach", REF]': "detached exact checkout",
        'VENV = Path("/content/sbom_to_audit_stage64_venv")': "isolated environment path",
        'VENV_ENV["PYTHONNOUSERSITE"] = "1"': "user-site isolation",
        '[str(VENV_PYTHON), "-m", "pip", "check"]': "isolated dependency check",
        '"canonical release check"': "canonical release gate",
        '"scripts/release_check.py"': "canonical release script",
        '"scripts/run_stage6_4_performance.py"': "Stage 6.4 performance runner",
        '"--profile",\n        "full"': "full performance profile",
        '"scripts/validate_stage6_4_evaluation.py"': "Stage 6.4 validator",
        '"scripts/build_stage6_4_paper_assets.py"': "paper-asset builder",
        'stage64_report.get("source_commit") != COMMIT': "exact-commit result check",
        'stage64_report.get("source_tree_dirty") is not False': "clean-tree result check",
        '"CANDIDATE_NOT_FROZEN"': "manuscript boundary",
        "stage64_colab_checkpoint_evidence.zip": "checkpoint archive",
        "archive.testzip()": "archive integrity validation",
        '"Checkpoint status: PASS"': "success sentinel",
    }
    for pattern, description in required.items():
        if pattern not in source:
            errors.append(f"missing notebook contract: {description}")

    forbidden = {
        'REF = "main"': "mutable main branch",
        'REF = "master"': "mutable master branch",
        'subprocess.run(["python"': "ambient Python command",
        '[sys.executable, "-m", "pip", "check"]': "shared-kernel dependency check",
        'manuscript_eligible": True': "premature manuscript eligibility",
        "tree_hashes(RESULT_FULL)": "invalid byte-determinism requirement for timing results",
    }
    for pattern, description in forbidden.items():
        if pattern in source:
            errors.append(f"forbidden notebook pattern: {description}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notebook", type=Path)
    args = parser.parse_args()
    errors = validate_notebook(args.notebook.resolve())
    payload = {
        "valid": not errors,
        "notebook": str(args.notebook),
        "expected_stage": "6.4",
        "expected_version": "0.6.4",
        "errors": errors,
    }
    print(json.dumps(payload, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
