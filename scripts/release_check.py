#!/usr/bin/env python3
"""Run the complete local release-quality gate and deterministic replay check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class CheckResult:
    name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass
class ReleaseReport:
    status: str = "PASS"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    python: str = sys.version
    platform: str = platform.platform()
    checks: list[CheckResult] = field(default_factory=list)
    deterministic_hashes: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.status = "FAIL"
        self.errors.append(message)


def _run(report: ReleaseReport, name: str, command: list[str]) -> None:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONHASHSEED": "0"},
    )
    result = CheckResult(name, command, completed.returncode, completed.stdout, completed.stderr)
    report.checks.append(result)
    if completed.returncode != 0:
        report.fail(f"{name} failed with exit code {completed.returncode}")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _deterministic_replay(report: ReleaseReport) -> None:
    expected = (
        "evidence_packs/ghost_logger.json",
        "state_logs/ghost_logger.csv",
        "conflict_reports/ghost_logger.json",
        "metrics/ghost_logger_metrics.json",
    )
    with tempfile.TemporaryDirectory(prefix="sbom-audit-release-") as temp:
        base = Path(temp)
        first = base / "first"
        second = base / "second"
        command_base = [
            sys.executable,
            "-m",
            "sbom_to_audit.cli",
            "--scenario",
            "data/scenarios/ghost_logger.yaml",
        ]
        _run(report, "deterministic replay A", command_base + ["--output-root", str(first)])
        _run(report, "deterministic replay B", command_base + ["--output-root", str(second)])
        if report.status == "FAIL":
            return
        for relative in expected:
            left = first / relative
            right = second / relative
            if not left.is_file() or not right.is_file():
                report.fail(f"deterministic replay output missing: {relative}")
                continue
            left_hash = _sha256(left)
            right_hash = _sha256(right)
            if left_hash != right_hash:
                report.fail(f"non-deterministic output: {relative}")
            report.deterministic_hashes[relative] = left_hash


def run_release_check() -> ReleaseReport:
    report = ReleaseReport()
    commands = [
        ("dependency integrity", [sys.executable, "-m", "pip", "check"]),
        ("compile", [sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"]),
        ("ruff lint", [sys.executable, "-m", "ruff", "check", "."]),
        ("ruff format", [sys.executable, "-m", "ruff", "format", "--check", "."]),
        ("mypy", [sys.executable, "-m", "mypy", "src"]),
        ("codespell", [str(Path(sys.executable).with_name("codespell"))]),
        (
            "yamllint",
            [
                sys.executable,
                "-m",
                "yamllint",
                ".github",
                "data",
                ".pre-commit-config.yaml",
                ".yamllint.yml",
            ],
        ),
        (
            "repository validation",
            [sys.executable, "scripts/validate_repository.py"],
        ),
        (
            "tests and coverage",
            [
                sys.executable,
                "-m",
                "pytest",
                "--cov=sbom_to_audit",
                "--cov-branch",
                "--cov-report=term-missing",
            ],
        ),
    ]
    for name, command in commands:
        _run(report, name, command)
    if report.status == "PASS":
        _deterministic_replay(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional JSON report path.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = run_release_check()
    payload: dict[str, Any] = asdict(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
