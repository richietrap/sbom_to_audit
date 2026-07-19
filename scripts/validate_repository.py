#!/usr/bin/env python3
"""Validate repository structure, locked definitions, and scenario integrity."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sbom_to_audit.model.metrics import MANDATORY_FIELDS

ROOT = Path(__file__).resolve().parents[1]
GENERATED_OUTPUT_DIRS = {
    Path("outputs/evidence_packs"),
    Path("outputs/state_logs"),
    Path("outputs/conflict_reports"),
    Path("outputs/metrics"),
}
IGNORED_NAMES = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".qa-venv",
    "__pycache__",
    "build",
    "dist",
}
SOURCE_REFERENCE_PREFIX = "file:"
LOCKED_REQUIRED_TOP_LEVEL = {
    "schema_version",
    "case_metadata",
    "product_context",
    "identity_resolution",
    "vulnerability_intelligence",
    "supplier_assertions",
    "local_evidence",
    "asset_context",
    "mitigation_context",
    "orchestration_metrics",
    "decision_state",
    "claims",
    "source_artifacts",
    "audit_log",
}
LOCKED_RECOMMENDED_STATES = {
    "Monitor",
    "Prepare",
    "Escalate",
    "Report-Ready",
    "Report",
    "Document No-Report",
}


@dataclass
class ValidationReport:
    status: str = "PASS"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)

    def error(self, message: str) -> None:
        self.status = "FAIL"
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)


def _manifest_paths(text: str) -> set[str]:
    table = text.split("## v0.2.1", maxsplit=1)[0]
    return set(re.findall(r"^\| `([^`]+)` \|", table, flags=re.MULTILINE))


def _repository_files() -> set[str]:
    files: set[str] = set()
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_NAMES or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.suffix == ".pyc" or relative.name.startswith(".coverage"):
            continue
        if relative.parent in GENERATED_OUTPUT_DIRS and relative.name != ".gitkeep":
            continue
        files.add(relative.as_posix())
    return files


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a YAML object")
    return data


def validate_manifest(report: ValidationReport) -> None:
    manifest_path = ROOT / "MANIFEST.md"
    if not manifest_path.is_file():
        report.error("MANIFEST.md is missing")
        return
    text = manifest_path.read_text(encoding="utf-8")
    declared = _manifest_paths(text)
    actual = _repository_files()
    expected_match = re.search(r"\*\*Expected files:\*\* (\d+)", text)
    created_match = re.search(r"\*\*Created files:\*\* (\d+)", text)
    missing_match = re.search(r"\*\*Missing files:\*\* (\d+)", text)
    if not all((expected_match, created_match, missing_match)):
        report.error("MANIFEST.md count fields are missing")
        return
    expected = int(expected_match.group(1))
    created = int(created_match.group(1))
    missing = int(missing_match.group(1))
    report.checks["manifest"] = {
        "declared": len(declared),
        "actual": len(actual),
        "expected": expected,
        "created": created,
        "missing": missing,
    }
    if declared != actual:
        undeclared = sorted(actual - declared)
        absent = sorted(declared - actual)
        if undeclared:
            report.error(f"files absent from MANIFEST.md: {undeclared}")
        if absent:
            report.error(f"manifest-declared files missing from repository: {absent}")
    if len(declared) != expected or created != expected or missing != 0:
        report.error("MANIFEST.md counts do not match the declared inventory")


def validate_schema(report: ValidationReport) -> None:
    schema_path = ROOT / "schemas" / "evidencepack_v0.2.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.error(f"EvidencePack schema cannot be loaded: {exc}")
        return
    properties = schema.get("properties") or {}
    report.checks["schema_version"] = (properties.get("schema_version") or {}).get("const")
    if report.checks["schema_version"] != "0.2":
        report.error("EvidencePack schema version drifted from 0.2")
    if set(properties) != LOCKED_REQUIRED_TOP_LEVEL:
        report.error("EvidencePack top-level block set drifted from v0.2")
    states = (
        ((properties.get("decision_state") or {}).get("properties") or {})
        .get("recommended_state", {})
        .get("enum", [])
    )
    if set(states) != LOCKED_RECOMMENDED_STATES:
        report.error("recommended_state enumeration drifted from the locked set")
    mandatory_count = len(MANDATORY_FIELDS)
    report.checks["mandatory_fields"] = mandatory_count
    if mandatory_count != 34:
        report.error(f"EC mandatory-field count drifted from 34 to {mandatory_count}")


def validate_scenarios(report: ValidationReport, strict_sources: bool) -> None:
    scenario_files = sorted((ROOT / "data" / "scenarios").glob("*.yaml"))
    if not scenario_files:
        report.error("no scenario YAML files were found")
        return
    summaries: list[dict[str, Any]] = []
    for path in scenario_files:
        try:
            scenario = _load_yaml(path)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            report.error(str(exc))
            continue
        if scenario.get("schema_version") != "0.2":
            report.error(f"{path.name}: scenario schema_version must remain 0.2")
        claims = scenario.get("claims") or []
        artifacts = scenario.get("source_artifacts") or []
        events = scenario.get("replay_events") or []
        claim_ids = [str(item.get("claim_id")) for item in claims]
        artifact_ids = [str(item.get("artifact_id")) for item in artifacts]
        event_ids = [str(item.get("event_id")) for item in events]
        for label, values in (
            ("claim", claim_ids),
            ("source artifact", artifact_ids),
            ("event", event_ids),
        ):
            duplicate_values = _duplicates(values)
            if duplicate_values:
                report.error(f"{path.name}: duplicate {label} IDs: {duplicate_values}")
        unknown_claims = sorted(
            {
                str(claim_id)
                for event in events
                for claim_id in (event.get("active_claim_ids") or [])
                if str(claim_id) not in set(claim_ids)
            }
        )
        if unknown_claims:
            report.error(f"{path.name}: events reference unknown claims: {unknown_claims}")
        unknown_artifacts = sorted(
            {
                str(claim.get("source_artifact_id"))
                for claim in claims
                if str(claim.get("source_artifact_id")) not in set(artifact_ids)
            }
        )
        if unknown_artifacts:
            report.error(
                f"{path.name}: claims reference unknown source artifacts: {unknown_artifacts}"
            )
        missing_sources: list[str] = []
        for artifact in artifacts:
            uri = str(artifact.get("source_uri") or "")
            if not uri.startswith(SOURCE_REFERENCE_PREFIX):
                continue
            relative = uri.removeprefix(SOURCE_REFERENCE_PREFIX)
            if not (ROOT / relative).is_file():
                missing_sources.append(relative)
        if missing_sources:
            message = (
                f"{path.name}: referenced source files not yet present: {sorted(missing_sources)}"
            )
            if strict_sources:
                report.error(message)
            else:
                report.warning(message + " (expected before Stage 2)")
        summaries.append(
            {
                "file": path.relative_to(ROOT).as_posix(),
                "claims": len(claims),
                "source_artifacts": len(artifacts),
                "events": len(events),
            }
        )
    report.checks["scenarios"] = summaries


def validate_text_integrity(report: ValidationReport) -> None:
    markers = ("<" * 7, "=" * 7, ">" * 7)
    bad_files: list[str] = []
    placeholder_files: list[str] = []
    scan_roots = [
        ROOT / "src",
        ROOT / "tests",
        ROOT / "scripts",
        ROOT / "schemas",
        ROOT / ".github",
    ]
    for scan_root in scan_roots:
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file() or path.suffix in {".pyc"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if any(marker in text for marker in markers):
                bad_files.append(path.relative_to(ROOT).as_posix())
            if ("<YOUR-" + "GITHUB") in text or ("TODO_" + "REPLACE") in text:
                placeholder_files.append(path.relative_to(ROOT).as_posix())
    if bad_files:
        report.error(f"merge-conflict markers detected in: {sorted(bad_files)}")
    if placeholder_files:
        report.error(f"release-blocking placeholders detected in: {sorted(placeholder_files)}")


def run_validation(strict_sources: bool = False) -> ValidationReport:
    report = ValidationReport()
    validate_manifest(report)
    validate_schema(report)
    validate_scenarios(report, strict_sources)
    validate_text_integrity(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-sources",
        action="store_true",
        help="Fail when scenario source files are absent; becomes mandatory in Stage 2.",
    )
    parser.add_argument("--report", type=Path, help="Optional JSON report path.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = run_validation(strict_sources=args.strict_sources)
    payload = asdict(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
