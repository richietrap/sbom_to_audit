#!/usr/bin/env python3
"""Validate repository structure, locked definitions, and source-catalog scenarios."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sbom_to_audit.baseline.evaluation_freeze import verify_freeze
from sbom_to_audit.baseline.evaluation_oracles import (
    load_clock_oracle,
    load_conflict_oracle,
    load_state_oracle,
    validate_oracle_coverage,
)
from sbom_to_audit.baseline.manual_worksheet import BUNDLE_SCHEMAS, DECLARATION_FILE
from sbom_to_audit.baseline.protocol import load_manual_protocol, load_protocol
from sbom_to_audit.historical.epss_verification import verify_offline_contract
from sbom_to_audit.historical.public_replay import run_public_historical_replay
from sbom_to_audit.ingestion.source_registry import SourceRegistry
from sbom_to_audit.model.metrics import MANDATORY_FIELDS
from sbom_to_audit.utils.hashing import sha256_file

ROOT = Path(__file__).resolve().parents[1]
GENERATED_OUTPUT_DIRS = {
    Path("outputs/evidence_packs"),
    Path("outputs/state_logs"),
    Path("outputs/conflict_reports"),
    Path("outputs/metrics"),
    Path("outputs/source_manifests"),
    Path("outputs/audit_ledgers"),
    Path("outputs/validation"),
    Path("outputs/stage6_baseline"),
    Path("outputs/stage6_1_manual_baseline"),
    Path("outputs/stage6_1_comparison"),
    Path("outputs/stage6_1_validation"),
}
IGNORED_NAMES = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".qa-venv",
    ".quality-venv",
    "__pycache__",
    "build",
    "dist",
}
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

FORBIDDEN_ROOT_VERIFICATION_ARTIFACTS = {
    "cve_2024_3400_epss_2024-04-15_api.json",
    "cve_2024_3400_epss_2024-04-15_row.csv",
    "epss_scores-2024-04-15.csv.gz",
    "historical_epss_verification.json",
}
LOCKED_RECOMMENDED_STATES = {
    "Monitor",
    "Prepare",
    "Escalate",
    "Report-Ready",
    "Report",
    "Document No-Report",
}


def _sha256(path: Path) -> str:
    return sha256_file(path)


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
        if (
            any(relative.is_relative_to(directory) for directory in GENERATED_OUTPUT_DIRS)
            and relative.name != ".gitkeep"
        ):
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


def validate_generated_artifact_placement(report: ValidationReport, root: Path = ROOT) -> None:
    """Reject mutable online verification downloads at repository root."""

    found = sorted(name for name in FORBIDDEN_ROOT_VERIFICATION_ARTIFACTS if (root / name).exists())
    report.checks["root_verification_artifacts"] = found
    if found:
        report.error(
            "historical EPSS verification downloads must be stored under "
            f"outputs/validation or a checkpoint bundle, not repository root: {found}"
        )


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
    report.checks["mandatory_fields"] = len(MANDATORY_FIELDS)
    if len(MANDATORY_FIELDS) != 34:
        report.error(f"EC mandatory-field count drifted from 34 to {len(MANDATORY_FIELDS)}")


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
        for forbidden in ("claims", "source_artifacts", "product_context", "identity_resolution"):
            if forbidden in scenario:
                report.error(
                    f"{path.name}: normalized block {forbidden!r} must not be "
                    "embedded in Stage 2 YAML"
                )

        target = scenario.get("target") or {}
        required_target = {"product_purl", "component_purl", "cve_id", "csaf_product_id"}
        if not required_target.issubset(target):
            report.error(f"{path.name}: target must define {sorted(required_target)}")
            continue
        catalog = scenario.get("source_catalog") or []
        events = scenario.get("replay_events") or []
        artifact_ids = [str(item.get("artifact_id")) for item in catalog]
        event_ids = [str(item.get("event_id")) for item in events]
        for label, values in (("source artifact", artifact_ids), ("event", event_ids)):
            duplicates = _duplicates(values)
            if duplicates:
                report.error(f"{path.name}: duplicate {label} IDs: {duplicates}")
        known_artifacts = set(artifact_ids)
        released = {
            str(artifact_id)
            for event in events
            for artifact_id in (event.get("release_artifact_ids") or [])
        }
        unknown = sorted(released - known_artifacts)
        if unknown:
            report.error(f"{path.name}: events release unknown source artifacts: {unknown}")
        never_released = sorted(known_artifacts - released)
        if never_released:
            report.warning(f"{path.name}: catalog sources never released: {never_released}")

        try:
            registry = SourceRegistry(ROOT, target_cve=str(target["cve_id"]))
            registry.register_catalog(catalog)
        except (FileNotFoundError, KeyError, TypeError, ValueError) as exc:
            if strict_sources:
                report.error(f"{path.name}: source validation failed: {exc}")
            else:
                report.warning(f"{path.name}: source validation warning: {exc}")
            continue
        summaries.append(
            {
                "file": path.relative_to(ROOT).as_posix(),
                "source_catalog": len(catalog),
                "events": len(events),
                "registered_sources": registry.manifest()["source_count"],
            }
        )
    report.checks["scenarios"] = summaries


def validate_historical_replay(report: ValidationReport, strict_sources: bool) -> None:
    try:
        result = run_public_historical_replay(ROOT)
    except (FileNotFoundError, KeyError, TypeError, ValueError) as exc:
        if strict_sources:
            report.error(f"historical public replay validation failed: {exc}")
        else:
            report.warning(f"historical public replay validation warning: {exc}")
        return
    bundle = result["bundle"]
    boundaries = bundle["evidence_boundaries"]
    if boundaries.get("full_evidencepack_generated") is not False:
        report.error("public historical replay must not generate a full EvidencePack")
    try:
        offline = verify_offline_contract(
            ROOT / "data/historical_replays/cve_2024_3400/epss/verification_manifest.json"
        )
    except (OSError, TypeError, ValueError) as exc:
        report.error(f"historical EPSS offline contract validation failed: {exc}")
        return
    if bundle.get("provisional_source_ids"):
        report.error("historical replay must not contain provisional EPSS sources")
    if bundle.get("manuscript_eligibility") is not False:
        report.error("offline validation must not imply that the online EPSS gate has passed")
    verification = bundle.get("historical_epss_verification") or {}
    if verification.get("status") != "verification_contract_valid_online_gate_required":
        report.error("historical replay does not retain the required online EPSS gate")
    report.checks["historical_public_replay"] = {
        "replay_id": bundle["replay_id"],
        "source_count": bundle["source_manifest"]["source_count"],
        "timeline_events": len(bundle["timeline"]),
        "provisional_source_ids": bundle["provisional_source_ids"],
        "manuscript_eligibility": bundle["manuscript_eligibility"],
        "epss_offline_contract_status": offline.status,
        "online_gate_required": True,
    }


def validate_evaluation_registry(report: ValidationReport) -> None:
    scenario_registry_path = ROOT / "evaluation" / "scenario_registry.csv"
    run_registry_path = ROOT / "evaluation" / "run_registry.csv"
    environment_dir = ROOT / "evaluation" / "environments"
    try:
        with scenario_registry_path.open(encoding="utf-8", newline="") as handle:
            scenario_rows = list(csv.DictReader(handle))
        with run_registry_path.open(encoding="utf-8", newline="") as handle:
            run_rows = list(csv.DictReader(handle))
    except OSError as exc:
        report.error(f"evaluation registry cannot be loaded: {exc}")
        return

    scenario_ids = [str(row.get("scenario_id", "")) for row in scenario_rows]
    duplicate_scenarios = _duplicates(scenario_ids)
    if duplicate_scenarios:
        report.error(f"duplicate evaluation scenario IDs: {duplicate_scenarios}")

    environments: dict[str, str] = {}
    for path in sorted(environment_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.error(f"evaluation environment cannot be loaded ({path.name}): {exc}")
            continue
        environment_id = str(payload.get("environment_id", ""))
        if not environment_id:
            report.error(f"{path.name}: environment_id is required")
        elif environment_id in environments:
            report.error(
                f"duplicate evaluation environment ID {environment_id!r}: "
                f"{environments[environment_id]} and {path.name}"
            )
        else:
            environments[environment_id] = path.name

    run_ids = [str(row.get("run_id", "")) for row in run_rows]
    duplicate_runs = _duplicates(run_ids)
    if duplicate_runs:
        report.error(f"duplicate evaluation run IDs: {duplicate_runs}")

    hash_pattern = re.compile(r"^[0-9a-f]{64}$")
    commit_pattern = re.compile(r"^[0-9a-f]{40}$")
    known_scenarios = set(scenario_ids)
    for row in run_rows:
        run_id = str(row.get("run_id", "<missing>"))
        scenario_id = str(row.get("scenario_id", ""))
        environment_id = str(row.get("environment_id", ""))
        if scenario_id not in known_scenarios:
            report.error(f"{run_id}: unknown scenario_id {scenario_id!r}")
        if environment_id not in environments:
            report.error(f"{run_id}: unknown environment_id {environment_id!r}")
        for field_name in ("input_manifest_hash", "output_manifest_hash"):
            value = str(row.get(field_name, ""))
            if not hash_pattern.fullmatch(value):
                report.error(f"{run_id}: {field_name} must be a lowercase SHA-256 digest")
        commit = str(row.get("git_commit", ""))
        if not (commit_pattern.fullmatch(commit) or commit.startswith("not_recorded_")):
            report.error(
                f"{run_id}: git_commit must be a 40-character digest or an explicit "
                "not_recorded_* pilot marker"
            )
        if scenario_id in {
            "cve_2024_3400_public",
            "historical_cve_2024_3400_reference",
        }:
            allowed = {
                "PILOT_PROVISIONAL",
                "PILOT_VERIFICATION_CANDIDATE",
                "PILOT_VERIFIED_NOT_FROZEN",
            }
            if str(row.get("evaluation_status", "")) not in allowed:
                report.error(
                    f"{run_id}: historical evaluation status must be one of {sorted(allowed)}"
                )

    report.checks["evaluation_registry"] = {
        "scenarios": len(scenario_rows),
        "runs": len(run_rows),
        "environments": len(environments),
    }


def validate_baseline_protocol(report: ValidationReport) -> None:
    protocol_path = ROOT / "evaluation" / "baseline_protocol_v0.1.yaml"
    try:
        protocol = load_protocol(protocol_path)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        report.error(f"Stage 6 baseline protocol validation failed: {exc}")
        return
    executable = {path.stem for path in (ROOT / "data" / "scenarios").glob("*.yaml")}
    missing = sorted(set(protocol.scenario_ids) - executable)
    if missing:
        report.error(f"baseline protocol references missing scenarios: {missing}")
    if "historical_cve_2024_3400_reference" in protocol.scenario_ids:
        report.error("historical reference replay must remain outside the primary baseline suite")
    report.checks["baseline_protocol"] = {
        "protocol_id": protocol.protocol_id,
        "protocol_version": protocol.protocol_version,
        "scenario_count": len(protocol.scenario_ids),
        "limitations": len(protocol.limitations),
    }


def validate_stage6_1_controls(report: ValidationReport) -> None:
    """Validate the pre-execution Stage 6.1 protocol, oracles, templates, and freeze."""

    protocol_path = ROOT / "evaluation" / "baseline_protocol_v0.2.yaml"
    try:
        protocol = load_manual_protocol(protocol_path)
        state_oracle = load_state_oracle(ROOT / "evaluation/oracles/state_oracle_v0.1.yaml")
        conflict_oracle = load_conflict_oracle(
            ROOT / "evaluation/oracles/conflict_oracle_v0.1.yaml"
        )
        clock_oracle = load_clock_oracle(
            ROOT / "evaluation/oracles/clock_opportunity_oracle_v0.1.yaml"
        )
        validate_oracle_coverage(state_oracle, conflict_oracle, clock_oracle)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        report.error(f"Stage 6.1 control validation failed: {exc}")
        return

    executable = {path.stem for path in (ROOT / "data/scenarios").glob("*.yaml")}
    missing_scenarios = sorted(set(protocol.scenario_ids) - executable)
    if missing_scenarios:
        report.error(f"Stage 6.1 protocol references missing scenarios: {missing_scenarios}")

    scenario_events: set[tuple[str, str]] = set()
    for scenario_id in protocol.scenario_ids:
        try:
            scenario = _load_yaml(ROOT / "data/scenarios" / f"{scenario_id}.yaml")
        except (OSError, ValueError, yaml.YAMLError) as exc:
            report.error(f"Stage 6.1 scenario cannot be loaded ({scenario_id}): {exc}")
            continue
        for event in scenario.get("replay_events") or []:
            scenario_events.add((scenario_id, str(event.get("event_id") or "")))
    if set(state_oracle) != scenario_events:
        report.error("Stage 6.1 oracle event universe drifted from the executable scenarios")

    required_templates = {
        *BUNDLE_SCHEMAS,
        DECLARATION_FILE,
        "manual_psirt_worksheet.xlsx",
        "manual_psirt_worksheet.schema.json",
    }
    missing_templates = sorted(
        name
        for name in required_templates
        if not (ROOT / "data/baseline_templates" / name).is_file()
    )
    if missing_templates:
        report.error(f"Stage 6.1 baseline templates are missing: {missing_templates}")

    missing_release_manifests = sorted(
        scenario_id
        for scenario_id in protocol.scenario_ids
        if not (
            ROOT / "data/baseline_release_packets" / scenario_id / "release_manifest.yaml"
        ).is_file()
    )
    if missing_release_manifests:
        report.error(f"Stage 6.1 release manifests are missing for: {missing_release_manifests}")

    freeze_errors = verify_freeze(ROOT, ROOT / "evaluation/freeze/stage6_1_protocol_freeze.json")
    if freeze_errors:
        report.error(f"Stage 6.1 pre-execution freeze failed: {freeze_errors}")

    true_conflicts = sum(bool(row.get("expected_conflict")) for row in conflict_oracle.values())
    clock_opportunities = sum(
        bool(row.get("eligible_prepare_to_escalate_opportunity")) for row in clock_oracle.values()
    )
    report.checks["stage6_1_controls"] = {
        "protocol_id": protocol.protocol_id,
        "protocol_version": protocol.protocol_version,
        "evaluation_status": protocol.evaluation_status,
        "scenario_count": len(protocol.scenario_ids),
        "event_count": len(state_oracle),
        "true_conflicts": true_conflicts,
        "automatic_clock_opportunities": clock_opportunities,
        "locked_metrics": list(protocol.locked_metrics),
        "freeze_verified": not freeze_errors,
    }


def validate_stage6_2_controls(report: ValidationReport) -> None:
    """Validate the registered Stage 6.2 protocol, candidate results, and asset boundary."""

    protocol_path = ROOT / "evaluation/stage6_2_robustness_protocol_v0.1.yaml"
    results_root = ROOT / "evaluation/stage6_2_candidate"
    try:
        protocol = _load_yaml(protocol_path)
        result = json.loads(
            (results_root / "stage6_2_robustness_report.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (results_root / "stage6_2_output_manifest.json").read_text(encoding="utf-8")
        )
        asset_manifest = json.loads(
            (ROOT / "paper_assets/data/stage6_2_asset_manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        report.error(f"Stage 6.2 control validation failed: {exc}")
        return

    expected_scenarios = {
        "ghost_logger",
        "false_comfort",
        "false_comfort_control",
        "operational_outlier",
        "operational_outlier_control",
        "rapid_pivot",
        "rapid_pivot_control",
    }
    expected_metrics = ["EC", "TR", "CD", "CA", "AR", "SC", "EPG"]
    if set(protocol.get("scenario_ids") or []) != expected_scenarios:
        report.error("Stage 6.2 scenario registry differs from the seven controlled scenarios")
    locked = protocol.get("locked_controls") or {}
    if str(locked.get("evidencepack_schema_version")) != "0.2":
        report.error("Stage 6.2 EvidencePack schema boundary changed")
    if int(locked.get("evidence_completeness_denominator", -1)) != 34:
        report.error("Stage 6.2 EC denominator changed")
    if list(locked.get("metrics") or []) != expected_metrics:
        report.error("Stage 6.2 locked metric list changed")
    if protocol.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        report.error("Stage 6.2 protocol must remain CANDIDATE_NOT_FROZEN")
    if result.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        report.error("Stage 6.2 candidate report status changed")
    if result.get("manuscript_eligible") is not False:
        report.error("Stage 6.2 candidate report became prematurely manuscript-eligible")
    if result.get("locked_controls") != locked:
        report.error("Stage 6.2 candidate report changed the locked controls")
    if int(result.get("negative_cases_rejected", -1)) != 8:
        report.error("Stage 6.2 did not preserve all eight fail-closed negative cases")

    output_hashes = manifest.get("output_files") or {}
    for name, expected_hash in output_hashes.items():
        path = results_root / str(name)
        if not path.is_file() or _sha256(path) != expected_hash:
            report.error(f"Stage 6.2 candidate output hash mismatch: {name}")

    if asset_manifest.get("asset_status") != "CANDIDATE_NOT_FROZEN":
        report.error("Stage 6.2 asset status changed")
    if asset_manifest.get("manuscript_eligible") is not False:
        report.error("Stage 6.2 assets became prematurely manuscript-eligible")
    for relative, expected_hash in (asset_manifest.get("generated_asset_hashes") or {}).items():
        path = ROOT / "paper_assets" / str(relative)
        if not path.is_file() or _sha256(path) != expected_hash:
            report.error(f"Stage 6.2 paper-asset hash mismatch: {relative}")

    report.checks["stage6_2_controls"] = {
        "protocol_id": protocol.get("protocol_id"),
        "protocol_version": protocol.get("protocol_version"),
        "evaluation_status": protocol.get("evaluation_status"),
        "scenario_count": len(protocol.get("scenario_ids") or []),
        "event_count": result.get("event_count"),
        "threshold_event_rows": result.get("threshold_event_rows"),
        "clock_event_rows": result.get("clock_event_rows"),
        "factor_variant_rows": result.get("factor_variant_rows"),
        "negative_cases_rejected": result.get("negative_cases_rejected"),
        "manuscript_eligible": result.get("manuscript_eligible"),
    }


def validate_text_integrity(report: ValidationReport) -> None:
    markers = ("<" * 7, "=" * 7, ">" * 7)
    bad_files: list[str] = []
    placeholder_files: list[str] = []
    for scan_root in (
        ROOT / "src",
        ROOT / "tests",
        ROOT / "scripts",
        ROOT / "schemas",
        ROOT / ".github",
        ROOT / "paper_assets" / "scripts",
    ):
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file() or path.suffix == ".pyc":
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
    validate_generated_artifact_placement(report)
    validate_manifest(report)
    validate_schema(report)
    validate_scenarios(report, strict_sources)
    validate_historical_replay(report, strict_sources)
    validate_evaluation_registry(report)
    validate_baseline_protocol(report)
    validate_stage6_1_controls(report)
    validate_stage6_2_controls(report)
    validate_text_integrity(report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-sources",
        action="store_true",
        help="Fail when any source-catalog artefact is missing or invalid.",
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
