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

import yaml

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


def _scenario_specs() -> list[tuple[Path, str]]:
    specs: list[tuple[Path, str]] = []
    for path in sorted((ROOT / "data" / "scenarios").glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"scenario must contain an object: {path}")
        scenario = payload.get("scenario") or {}
        scenario_id = str(scenario.get("scenario_id") or "").strip()
        if not scenario_id:
            raise ValueError(f"scenario_id is missing: {path}")
        specs.append((path, scenario_id))
    return specs


def _deterministic_replay(report: ReleaseReport) -> None:
    output_templates = (
        "evidence_packs/{scenario_id}.json",
        "state_logs/{scenario_id}.csv",
        "conflict_reports/{scenario_id}.json",
        "metrics/{scenario_id}_metrics.json",
        "source_manifests/{scenario_id}_sources.json",
        "audit_ledgers/{scenario_id}.jsonl",
    )
    with tempfile.TemporaryDirectory(prefix="sbom-audit-release-") as temp:
        base = Path(temp)
        for scenario_path, scenario_id in _scenario_specs():
            first = base / scenario_id / "first"
            second = base / scenario_id / "second"
            command_base = [
                sys.executable,
                "-m",
                "sbom_to_audit.cli",
                "--scenario",
                str(scenario_path.relative_to(ROOT)),
            ]
            _run(
                report,
                f"{scenario_id} deterministic replay A",
                command_base + ["--output-root", str(first)],
            )
            _run(
                report,
                f"{scenario_id} deterministic replay B",
                command_base + ["--output-root", str(second)],
            )
            if report.status == "FAIL":
                return
            for template in output_templates:
                relative = template.format(scenario_id=scenario_id)
                left = first / relative
                right = second / relative
                if not left.is_file() or not right.is_file():
                    report.fail(f"deterministic replay output missing: {relative}")
                    continue
                left_hash = _sha256(left)
                right_hash = _sha256(right)
                if left_hash != right_hash:
                    report.fail(f"non-deterministic output: {relative}")
                report.deterministic_hashes[f"{scenario_id}/{relative}"] = left_hash


def _deterministic_historical_public_replay(report: ReleaseReport) -> None:
    output_files = (
        "historical_public/cve_2024_3400_public_bundle.json",
        "historical_public/cve_2024_3400_public_timeline.csv",
        "historical_public/cve_2024_3400_public_sources.json",
        "historical_public/cve_2024_3400_epss_ablation.json",
        "historical_public/cve_2024_3400_epss_ablation.csv",
    )
    with tempfile.TemporaryDirectory(prefix="sbom-audit-historical-") as temp:
        base = Path(temp)
        first = base / "first"
        second = base / "second"
        command = [sys.executable, "scripts/run_historical_replay.py", "--output-root"]
        _run(report, "historical public replay A", command + [str(first)])
        _run(report, "historical public replay B", command + [str(second)])
        if report.status == "FAIL":
            return
        for relative in output_files:
            left = first / relative
            right = second / relative
            if not left.is_file() or not right.is_file():
                report.fail(f"historical deterministic output missing: {relative}")
                continue
            left_hash = _sha256(left)
            right_hash = _sha256(right)
            if left_hash != right_hash:
                report.fail(f"non-deterministic historical output: {relative}")
            report.deterministic_hashes[f"historical_public/{relative}"] = left_hash


def _deterministic_stage6_baseline(report: ReleaseReport) -> None:
    with tempfile.TemporaryDirectory(prefix="sbom-audit-stage6-baseline-") as temp:
        base = Path(temp)
        first = base / "first"
        second = base / "second"
        command = [sys.executable, "scripts/run_baseline_comparison.py", "--output-root"]
        _run(report, "Stage 6 matched baseline A", command + [str(first)])
        _run(report, "Stage 6 matched baseline B", command + [str(second)])
        if report.status == "FAIL":
            return
        first_files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
        second_files = sorted(
            path.relative_to(second) for path in second.rglob("*") if path.is_file()
        )
        if first_files != second_files:
            report.fail("Stage 6 baseline output inventories differ")
            return
        for relative in first_files:
            left = first / relative
            right = second / relative
            left_hash = _sha256(left)
            right_hash = _sha256(right)
            if left_hash != right_hash:
                report.fail(f"non-deterministic Stage 6 baseline output: {relative}")
            report.deterministic_hashes[f"stage6_baseline/{relative.as_posix()}"] = left_hash


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
                "evaluation/baseline_protocol_v0.1.yaml",
                ".pre-commit-config.yaml",
                ".yamllint.yml",
            ],
        ),
        (
            "historical EPSS offline contract",
            [sys.executable, "scripts/verify_historical_epss.py"],
        ),
        (
            "repository validation",
            [sys.executable, "scripts/validate_repository.py", "--strict-sources"],
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
    if report.status == "PASS":
        _deterministic_historical_public_replay(report)
    if report.status == "PASS":
        _deterministic_stage6_baseline(report)
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
