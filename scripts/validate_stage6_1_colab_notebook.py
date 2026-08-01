#!/usr/bin/env python3
"""Validate the current Stage 6.1 Colab checkpoint execution contract."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any


def _cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source") or ""
    if isinstance(source, list):
        return "".join(str(line) for line in source)
    return str(source)


def _code_cells(notebook: dict[str, Any]) -> list[dict[str, Any]]:
    cells = notebook.get("cells") or []
    return [cell for cell in cells if cell.get("cell_type") == "code"]


def _source(notebook: dict[str, Any]) -> str:
    return "\n".join(_cell_source(cell) for cell in _code_cells(notebook))


def _literal_strings(node: ast.AST) -> list[str]:
    values: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            values.append(child.value)
    return values


def _validate_project_command_isolation(source: str, errors: list[str]) -> None:
    project_commands = {
        "scripts/release_check.py",
        "scripts/verify_historical_epss.py",
        "scripts/run_historical_replay.py",
        "scripts/assert_verified_historical_replay.py",
        "scripts/export_stage6_1_baseline_packets.py",
        "scripts/validate_manual_baseline_worksheet.py",
        "scripts/import_manual_baseline_results.py",
        "scripts/run_stage6_1_comparison.py",
        "scripts/validate_stage6_1_evaluation.py",
        "scripts/build_stage6_1_paper_assets.py",
    }
    observed: set[str] = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        strings = set(_literal_strings(node))
        matched = project_commands & strings
        if not matched:
            continue
        observed.update(matched)
        rendered = ast.unparse(node)
        if "VENV_PYTHON" not in rendered:
            for command in sorted(matched):
                errors.append(f"project command does not use isolated Python: {command}")

    for command in sorted(project_commands - observed):
        errors.append(f"project command missing: {command}")


def validate(path: Path, expected_stage: str, expected_version: str) -> list[str]:
    errors: list[str] = []
    try:
        notebook = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"notebook could not be read: {exc}"]

    if notebook.get("nbformat") != 4:
        errors.append("notebook must use nbformat 4")
    cells = notebook.get("cells")
    if not isinstance(cells, list) or not cells:
        return errors + ["notebook has no cells"]

    code_cells = _code_cells(notebook)
    if not code_cells:
        errors.append("notebook has no code cells")
    for index, cell in enumerate(code_cells, start=1):
        source = _cell_source(cell)
        try:
            compile(source, f"{path.name}:code-cell-{index}", "exec")
        except SyntaxError as exc:
            errors.append(f"code cell {index} does not compile: {exc}")
        if cell.get("execution_count") is not None:
            errors.append(f"code cell {index} retains an execution count")
        if cell.get("outputs"):
            errors.append(f"code cell {index} retains outputs")

    source = _source(notebook)
    required_fragments = {
        f'STAGE = "{expected_stage}"': "stage marker",
        f'PACKAGE_VERSION = "{expected_version}"': "package-version marker",
        'REF = ""': "blank exact-SHA configuration",
        're.fullmatch(r"[0-9a-fA-F]{40}", REF)': "full SHA validation",
        'input("Paste the exact 40-character': "interactive SHA prompt",
        '["git", "checkout", "--detach", REF]': "detached exact-commit checkout",
        '["git", "branch", "--show-current"]': "detached-head verification",
        'VENV = Path("/content/sbom_to_audit_stage615_venv")': "isolated environment",
        'VENV_PYTHON = VENV / "bin" / "python"': "isolated Python binding",
        '[str(VENV_PYTHON), "-m", "pip", "install", "--no-cache-dir", "-e", ".[dev]"]': (
            "isolated project development installation"
        ),
        '[str(VENV_PYTHON), "-m", "pip", "check"]': "isolated pip check",
        'VENV_ENV["PIP_REQUIRE_VIRTUALENV"] = "true"': "pip virtualenv enforcement",
        'VENV_ENV["PYTHONNOUSERSITE"] = "1"': "user-site isolation",
        'verify virtual environment isolation': "virtualenv prefix verification",
        'stdlib_venv_pip_probe.log': "stdlib venv pip probe",
        'attempt-{attempt:02d}.log': "per-attempt command logging",
        "scripts/release_check.py": "canonical release gate",
        "scripts/verify_historical_epss.py": "online historical EPSS gate",
        "scripts/export_stage6_1_baseline_packets.py": "packet export",
        "Packet manifest hash mismatch": "packet-manifest hash verification",
        "Released packet artifact hash mismatch": "packet-artifact hash verification",
        "Blinding boundary violation in packet manifest": "packet-content blinding validation",
        "def safe_extract_zip(": "safe manual ZIP extraction",
        "zipfile.is_zipfile(source)": "ZIP format validation",
        "file_type = stat.S_IFMT(mode)": "portable ZIP member-type handling",
        "MAX_MANUAL_ZIP_MEMBERS = 200": "ZIP member-count safety limit",
        "MAX_MANUAL_ZIP_UNCOMPRESSED_BYTES = 100 * 1024 * 1024": (
            "ZIP expansion safety limit"
        ),
        "Manual ZIP contains a corrupt member": "manual ZIP CRC validation",
        "duplicate normalized paths": "normalized ZIP-path collision rejection",
        'target.open("xb")': "exclusive controlled ZIP extraction",
        "while chunk := source_stream.read": "streamed extraction-size enforcement",
        "Manual result ZIP changed while the checkpoint was processing it": (
            "manual input immutability verification"
        ),
        "files outside the canonical bundle": "canonical manual-bundle boundary",
        "archive.testzip()": "checkpoint ZIP integrity test",
        "Archived evidence checksum mismatch": "archived-evidence checksum verification",
        "evidence_checksums.json": "evidence checksum inventory",
        "stage615_colab_checkpoint_evidence.zip": "checkpoint archive",
    }
    for fragment, label in required_fragments.items():
        if fragment not in source:
            errors.append(f"missing {label}: {fragment}")

    forbidden_fragments = {
        'REF = "main"': "mutable main reference",
        'REF = "master"': "mutable master reference",
        "STAGE615_REF_REQUIRED": "placeholder reference that fails before prompting",
        'subprocess.run(["python"': "global Python subprocess",
        'subprocess.check_output(["python"': "global Python check_output",
        '["python", "-m", "pip", "check"]': "global-environment pip check",
        '"--system-site-packages"': "system site-packages exposure",
        "shutil.unpack_archive(": "unvalidated archive extraction",
        "archive.extractall(": "bulk archive extraction",
    }
    for fragment, label in forbidden_fragments.items():
        if fragment in source:
            errors.append(f"forbidden {label}: {fragment}")

    project_install_fragments = (
        '[sys.executable, "-m", "pip", "install", "-e", ".[dev]"]',
        '[sys.executable, "-m", "pip", "install", "--no-cache-dir", "-e", ".[dev]"]',
    )
    if any(fragment in source for fragment in project_install_fragments):
        errors.append("project development dependencies are installed with the kernel interpreter")

    _validate_project_command_isolation(source, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notebook", type=Path)
    parser.add_argument("--expected-stage", required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    errors = validate(args.notebook, args.expected_stage, args.expected_version)
    payload = {
        "valid": not errors,
        "notebook": str(args.notebook),
        "expected_stage": args.expected_stage,
        "expected_version": args.expected_version,
        "errors": errors,
    }
    print(json.dumps(payload, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
