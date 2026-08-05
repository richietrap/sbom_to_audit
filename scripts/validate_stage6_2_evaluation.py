#!/usr/bin/env python3
"""Validate the Stage 6.2 protocol and an optional generated result directory."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.robustness import SUPPORTED_FACTORS
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "stage6_2_robustness_protocol_v0.1.yaml"
EXPECTED_SCENARIOS = {
    "ghost_logger",
    "false_comfort",
    "false_comfort_control",
    "operational_outlier",
    "operational_outlier_control",
    "rapid_pivot",
    "rapid_pivot_control",
}
EXPECTED_METRICS = ["EC", "TR", "CD", "CA", "AR", "SC", "EPG"]
EXPECTED_OUTPUTS = {
    "stage6_2_threshold_sensitivity.csv",
    "stage6_2_clock_sensitivity.csv",
    "stage6_2_factor_sensitivity.csv",
    "stage6_2_negative_cases.csv",
    "stage6_2_scenario_stability.csv",
    "stage6_2_robustness_report.json",
    "stage6_2_output_manifest.json",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_protocol() -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    protocol = read_yaml(PROTOCOL_PATH)
    if not isinstance(protocol, dict):
        return ["Stage 6.2 protocol must contain an object"], {}
    if protocol.get("protocol_id") != "stage6_2_robustness_and_sensitivity":
        errors.append("unexpected Stage 6.2 protocol_id")
    if str(protocol.get("protocol_version")) != "0.1":
        errors.append("unexpected Stage 6.2 protocol_version")
    if protocol.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        errors.append("Stage 6.2 protocol must remain CANDIDATE_NOT_FROZEN")
    if protocol.get("manuscript_eligible") is not False:
        errors.append("Stage 6.2 protocol must remain manuscript-ineligible")
    if set(protocol.get("scenario_ids") or []) != EXPECTED_SCENARIOS:
        errors.append("Stage 6.2 scenario registry differs from the seven controlled scenarios")

    locked = protocol.get("locked_controls") or {}
    if str(locked.get("evidencepack_schema_version")) != "0.2":
        errors.append("EvidencePack schema version must remain 0.2")
    if int(locked.get("evidence_completeness_denominator", -1)) != 34:
        errors.append("Stage 6.2 EC denominator must remain 34")
    if list(locked.get("metrics") or []) != EXPECTED_METRICS:
        errors.append("Stage 6.2 locked metric list changed")
    if float(locked.get("baseline_tau_E_hours", -1.0)) != 18.0:
        errors.append("Stage 6.2 baseline tau_E must remain 18 hours")

    threshold_profiles = protocol.get("threshold_profiles") or []
    offsets = [float(item.get("offset")) for item in threshold_profiles]
    if offsets != [-0.10, -0.05, 0.0, 0.05, 0.10]:
        errors.append("threshold profile offsets must be -0.10, -0.05, 0, +0.05, +0.10")

    clock_profiles = (protocol.get("clock_sensitivity") or {}).get("profiles") or []
    clock_values = [float(item.get("tau_E_hours")) for item in clock_profiles]
    if clock_values != [14.0, 16.0, 18.0, 20.0, 22.0]:
        errors.append("clock profiles must be 14, 16, 18, 20, and 22 hours")

    factors = [str(item.get("factor")) for item in protocol.get("single_factor_profiles") or []]
    if set(factors) != SUPPORTED_FACTORS:
        errors.append("Stage 6.2 factor registry differs from the supported implementation")

    negative_cases = protocol.get("negative_cases") or []
    if len(negative_cases) != 8:
        errors.append("Stage 6.2 protocol must register eight negative cases")
    if set(protocol.get("outputs") or []) != EXPECTED_OUTPUTS:
        errors.append("Stage 6.2 output registry is incomplete or contains unexpected files")
    return errors, protocol


def validate_results(destination: Path, protocol: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(name for name in EXPECTED_OUTPUTS if not (destination / name).is_file())
    if missing:
        return [f"Stage 6.2 output files are missing: {missing}"]

    threshold_rows = _read_csv(destination / "stage6_2_threshold_sensitivity.csv")
    clock_rows = _read_csv(destination / "stage6_2_clock_sensitivity.csv")
    factor_rows = _read_csv(destination / "stage6_2_factor_sensitivity.csv")
    negative_rows = _read_csv(destination / "stage6_2_negative_cases.csv")
    stability_rows = _read_csv(destination / "stage6_2_scenario_stability.csv")
    report = json.loads(
        (destination / "stage6_2_robustness_report.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (destination / "stage6_2_output_manifest.json").read_text(encoding="utf-8")
    )

    expected_events = 28
    expected_threshold_rows = expected_events * len(protocol["threshold_profiles"])
    if len(threshold_rows) != expected_threshold_rows:
        errors.append(
            f"threshold sensitivity contains {len(threshold_rows)} rows, expected "
            f"{expected_threshold_rows}"
        )
    expected_clock_events = 12
    expected_clock_rows = expected_clock_events * len(protocol["clock_sensitivity"]["profiles"])
    if len(clock_rows) != expected_clock_rows:
        errors.append(
            f"clock sensitivity contains {len(clock_rows)} rows, expected {expected_clock_rows}"
        )
    factor_value_count = sum(
        len(item.get("values") or []) for item in protocol["single_factor_profiles"]
    )
    expected_factor_rows = len(EXPECTED_SCENARIOS) * factor_value_count
    if len(factor_rows) != expected_factor_rows:
        errors.append(
            f"factor sensitivity contains {len(factor_rows)} rows, expected {expected_factor_rows}"
        )
    if len(negative_rows) != len(protocol["negative_cases"]):
        errors.append("negative-case row count differs from the protocol")
    if any(row.get("rejected_as_expected") != "True" for row in negative_rows):
        errors.append("one or more Stage 6.2 negative cases did not fail closed")
    if len(stability_rows) != len(EXPECTED_SCENARIOS):
        errors.append("scenario-stability summary must contain seven rows")

    if report.get("run_id") != "STAGE6-2-ROBUSTNESS-CANDIDATE-001":
        errors.append("unexpected Stage 6.2 run_id")
    if report.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        errors.append("Stage 6.2 report must remain CANDIDATE_NOT_FROZEN")
    if report.get("manuscript_eligible") is not False:
        errors.append("Stage 6.2 report must remain manuscript-ineligible")
    if int(report.get("scenario_count", -1)) != 7:
        errors.append("Stage 6.2 report scenario_count must be seven")
    if int(report.get("event_count", -1)) != 28:
        errors.append("Stage 6.2 report event_count must be 28")
    if int(report.get("negative_cases_rejected", -1)) != 8:
        errors.append("Stage 6.2 report must record eight rejected negative cases")
    if report.get("locked_controls") != protocol.get("locked_controls"):
        errors.append("Stage 6.2 report changed the locked controls")

    output_hashes = manifest.get("output_files") or {}
    for name in EXPECTED_OUTPUTS - {"stage6_2_output_manifest.json"}:
        expected_hash = output_hashes.get(name)
        if expected_hash != _sha256(destination / name):
            errors.append(f"Stage 6.2 output hash mismatch: {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, help="Optional generated Stage 6.2 directory.")
    args = parser.parse_args()

    errors, protocol = validate_protocol()
    if args.results and not errors:
        errors.extend(validate_results(args.results.resolve(), protocol))
    payload = {
        "valid": not errors,
        "errors": errors,
        "checks": {
            "protocol_version": protocol.get("protocol_version") if protocol else None,
            "scenario_count": len(protocol.get("scenario_ids") or []) if protocol else 0,
            "threshold_profiles": len(protocol.get("threshold_profiles") or []) if protocol else 0,
            "clock_profiles": len((protocol.get("clock_sensitivity") or {}).get("profiles") or [])
            if protocol
            else 0,
            "single_factor_profiles": len(protocol.get("single_factor_profiles") or [])
            if protocol
            else 0,
            "negative_cases": len(protocol.get("negative_cases") or []) if protocol else 0,
            "results_validated": bool(args.results),
        },
    }
    print(json.dumps(payload, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
