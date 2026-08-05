#!/usr/bin/env python3
"""Run the deterministic Stage 6.2 robustness and sensitivity evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from sbom_to_audit.evaluation.robustness import (
    evaluate_factor_variant,
    replay_clock_profile,
    replay_threshold_profile,
    summarize_scenario_stability,
)
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml, write_csv, write_json

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation" / "stage6_2_robustness_protocol_v0.1.yaml"
RUN_ID = "STAGE6-2-ROBUSTNESS-CANDIDATE-001"

THRESHOLD_FIELDS = [
    "scenario_id",
    "event_id",
    "timestamp",
    "profile_id",
    "threshold_offset",
    "baseline_state",
    "variant_state",
    "state_changed",
    "previous_variant_state",
    "E_t",
    "A_t",
    "I_t",
    "M_t",
    "U_t",
    "C_t",
    "theta_A",
    "theta_E",
    "theta_I",
    "theta_U",
    "theta_N",
    "theta_L",
    "tau_E_hours",
    "rationale",
]
CLOCK_FIELDS = [
    "scenario_id",
    "event_id",
    "timestamp",
    "profile_id",
    "tau_E_hours",
    "baseline_state",
    "variant_state",
    "state_changed",
    "previous_variant_state",
    "clock_safeguard_triggered",
    "rationale",
]
FACTOR_FIELDS = [
    "scenario_id",
    "event_id",
    "factor",
    "variant_value",
    "baseline_value",
    "baseline_state",
    "variant_state",
    "state_changed",
    "delta_t_hours",
    "previous_state",
    "E_t",
    "A_t",
    "I_t",
    "M_t",
    "U_t",
    "C_t",
    "rationale",
]
NEGATIVE_FIELDS = [
    "case_id",
    "expected_exception",
    "expected_message",
    "observed_exception",
    "observed_message",
    "rejected_as_expected",
]
STABILITY_FIELDS = [
    "scenario_id",
    "threshold_variant_event_rows",
    "threshold_state_changes",
    "factor_variants",
    "factor_state_changes",
    "clock_variant_event_rows",
    "clock_state_changes",
    "total_state_changes",
    "classification",
]


def _load_protocol() -> dict[str, Any]:
    protocol = read_yaml(PROTOCOL_PATH)
    if not isinstance(protocol, dict):
        raise ValueError("Stage 6.2 protocol must contain an object")
    if protocol.get("protocol_id") != "stage6_2_robustness_and_sensitivity":
        raise ValueError("unexpected Stage 6.2 protocol_id")
    if str(protocol.get("protocol_version")) != "0.1":
        raise ValueError("unexpected Stage 6.2 protocol_version")
    return protocol


def _scenario_path(scenario_id: str) -> Path:
    path = ROOT / "data" / "scenarios" / f"{scenario_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"registered Stage 6.2 scenario is missing: {path}")
    return path


def _factor_value(pack: dict[str, Any], factor: str) -> Any:
    if factor == "gamma_id":
        return pack["identity_resolution"].get("gamma_id")
    if factor == "cisa_kev_status":
        return pack["vulnerability_intelligence"].get("cisa_kev_status")
    if factor == "epss_percentile":
        return pack["vulnerability_intelligence"].get("epss_percentile")
    if factor == "csaf_vex_status":
        return pack["supplier_assertions"].get("csaf_vex_status")
    if factor == "execution_observed":
        return pack["local_evidence"].get("execution_observed")
    if factor == "reachability_confirmed":
        return pack["local_evidence"].get("reachability_confirmed")
    if factor == "asset_criticality":
        return pack["asset_context"].get("asset_criticality")
    if factor == "deployment_scope":
        return pack["asset_context"].get("deployment_scope")
    if factor == "mitigation_status":
        return pack["mitigation_context"].get("mitigation_status")
    if factor == "conflict":
        return pack["orchestration_metrics"].get("C_t")
    if factor == "malicious_exploitation_observed":
        return any(
            claim.get("proposition") == "malicious_exploitation_observed"
            and claim.get("value") is True
            for claim in pack["claims"]
        )
    if factor == "missing_telemetry_reference":
        return pack["local_evidence"].get("telemetry_reference") is None
    raise ValueError(f"unsupported factor in protocol: {factor}")


def _copy_repository_inputs(destination: Path) -> None:
    shutil.copytree(ROOT / "data", destination / "data")
    shutil.copytree(ROOT / "schemas", destination / "schemas")
    shutil.copy2(ROOT / "pyproject.toml", destination / "pyproject.toml")


def _write_malformed_json(path: Path) -> None:
    path.write_text('{"bomFormat": "CycloneDX", broken', encoding="utf-8")


def _run_negative_case(case_id: str, scenario: dict[str, Any], temp_root: Path) -> None:
    mutated = deepcopy(scenario)
    catalog = mutated["source_catalog"]
    events = mutated["replay_events"]

    if case_id == "missing_required_source":
        catalog[0]["path"] = "data/sbom/stage6_2_missing.cdx.json"
    elif case_id == "malformed_sbom_json":
        source_path = temp_root / str(catalog[0]["path"])
        _write_malformed_json(source_path)
    elif case_id == "duplicate_artifact_id":
        catalog.append(deepcopy(catalog[0]))
    elif case_id == "path_traversal":
        catalog[0]["path"] = "../stage6_2_escape.json"
    elif case_id == "out_of_order_events":
        events[0], events[1] = events[1], events[0]
    elif case_id == "duplicate_event_id":
        events[1]["event_id"] = events[0]["event_id"]
    elif case_id == "future_dated_release":
        catalog[0]["timestamp"] = "2026-09-12T11:00:00Z"
    elif case_id == "unsupported_asset_criticality":
        asset_spec = next(item for item in catalog if item.get("artifact_type") == "asset_context")
        asset_path = temp_root / str(asset_spec["path"])
        asset = yaml.safe_load(asset_path.read_text(encoding="utf-8"))
        if not isinstance(asset, dict):
            raise ValueError("asset context fixture must contain an object")
        asset["asset_criticality"] = "mission_supreme"
        asset_path.write_text(yaml.safe_dump(asset, sort_keys=False), encoding="utf-8")
    else:
        raise ValueError(f"unsupported Stage 6.2 negative case: {case_id}")

    replay_scenario(mutated, repository_root=temp_root)


def _negative_rows(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    base = read_yaml(_scenario_path("ghost_logger"))
    if not isinstance(base, dict):
        raise ValueError("Ghost-Logger scenario must contain an object")
    rows: list[dict[str, Any]] = []
    for spec in protocol["negative_cases"]:
        case_id = str(spec["case_id"])
        expected_exception = str(spec["expected_exception"])
        expected_message = str(spec["expected_message"])
        observed_exception = "NO_EXCEPTION"
        observed_message = ""
        with tempfile.TemporaryDirectory(prefix=f"stage62-{case_id}-") as temp:
            temp_root = Path(temp) / "repository"
            _copy_repository_inputs(temp_root)
            try:
                _run_negative_case(case_id, base, temp_root)
            except Exception as exc:  # noqa: BLE001 - the protocol records the exact class.
                observed_exception = type(exc).__name__
                observed_message = str(exc)
        rows.append(
            {
                "case_id": case_id,
                "expected_exception": expected_exception,
                "expected_message": expected_message,
                "observed_exception": observed_exception,
                "observed_message": observed_message,
                "rejected_as_expected": observed_exception == expected_exception
                and expected_message in observed_message,
            }
        )
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(destination: Path) -> dict[str, Path]:
    protocol = _load_protocol()
    destination.mkdir(parents=True, exist_ok=True)

    threshold_rows: list[dict[str, Any]] = []
    clock_rows: list[dict[str, Any]] = []
    factor_rows: list[dict[str, Any]] = []
    stability_rows: list[dict[str, Any]] = []
    scenario_hashes: dict[str, str] = {}
    scenario_results: dict[str, dict[str, Any]] = {}

    for scenario_id in protocol["scenario_ids"]:
        scenario_file = _scenario_path(str(scenario_id))
        scenario = read_yaml(scenario_file)
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario must contain an object: {scenario_file}")
        scenario_results[str(scenario_id)] = replay_scenario(scenario, repository_root=ROOT)
        scenario_hashes[str(scenario_id)] = sha256_file(scenario_file)

    for scenario_id, result in scenario_results.items():
        state_rows = result["state_rows"]
        scenario_threshold_rows: list[dict[str, Any]] = []
        for profile in protocol["threshold_profiles"]:
            rows = replay_threshold_profile(
                state_rows,
                profile_id=str(profile["profile_id"]),
                offset=float(profile["offset"]),
            )
            for row in rows:
                row["scenario_id"] = scenario_id
            threshold_rows.extend(rows)
            scenario_threshold_rows.extend(rows)

        scenario_clock_rows: list[dict[str, Any]] = []
        if scenario_id in protocol["clock_sensitivity"]["scenario_ids"]:
            for profile in protocol["clock_sensitivity"]["profiles"]:
                rows = replay_clock_profile(
                    state_rows,
                    profile_id=str(profile["profile_id"]),
                    tau_e_hours=float(profile["tau_E_hours"]),
                )
                for row in rows:
                    row["scenario_id"] = scenario_id
                clock_rows.extend(rows)
                scenario_clock_rows.extend(rows)

        final_row = state_rows[-1]
        previous_state = str(state_rows[-2]["observed_state"]) if len(state_rows) > 1 else None
        pack = result["pack"]
        scenario_factor_rows: list[dict[str, Any]] = []
        for factor_spec in protocol["single_factor_profiles"]:
            factor = str(factor_spec["factor"])
            baseline_value = _factor_value(pack, factor)
            for value in factor_spec["values"]:
                evaluated = evaluate_factor_variant(
                    pack,
                    factor=factor,
                    value=value,
                    delta_t_hours=float(final_row["delta_t_hours"]),
                    previous_state=previous_state,
                )
                row = {
                    "scenario_id": scenario_id,
                    "event_id": str(final_row["event_id"]),
                    "factor": factor,
                    "variant_value": json.dumps(value, sort_keys=True),
                    "baseline_value": json.dumps(baseline_value, sort_keys=True),
                    "baseline_state": str(final_row["observed_state"]),
                    "variant_state": evaluated["variant_state"],
                    "state_changed": evaluated["variant_state"] != str(final_row["observed_state"]),
                    "delta_t_hours": float(final_row["delta_t_hours"]),
                    "previous_state": previous_state,
                    "E_t": evaluated["E_t"],
                    "A_t": evaluated["A_t"],
                    "I_t": evaluated["I_t"],
                    "M_t": evaluated["M_t"],
                    "U_t": evaluated["U_t"],
                    "C_t": evaluated["C_t"],
                    "rationale": evaluated["rationale"],
                }
                factor_rows.append(row)
                scenario_factor_rows.append(row)

        stability_rows.append(
            summarize_scenario_stability(
                scenario_id,
                scenario_threshold_rows,
                scenario_factor_rows,
                scenario_clock_rows,
            )
        )

    negative_rows = _negative_rows(protocol)
    if not all(bool(row["rejected_as_expected"]) for row in negative_rows):
        failures = [row["case_id"] for row in negative_rows if not row["rejected_as_expected"]]
        raise RuntimeError(f"Stage 6.2 negative cases did not fail closed: {failures}")

    threshold_path = write_csv(
        destination / "stage6_2_threshold_sensitivity.csv",
        threshold_rows,
        THRESHOLD_FIELDS,
    )
    clock_path = write_csv(
        destination / "stage6_2_clock_sensitivity.csv",
        clock_rows,
        CLOCK_FIELDS,
    )
    factor_path = write_csv(
        destination / "stage6_2_factor_sensitivity.csv",
        factor_rows,
        FACTOR_FIELDS,
    )
    negative_path = write_csv(
        destination / "stage6_2_negative_cases.csv",
        negative_rows,
        NEGATIVE_FIELDS,
    )
    stability_path = write_csv(
        destination / "stage6_2_scenario_stability.csv",
        stability_rows,
        STABILITY_FIELDS,
    )

    non_baseline_threshold_rows = [
        row for row in threshold_rows if float(row["threshold_offset"]) != 0.0
    ]
    report = {
        "run_id": RUN_ID,
        "stage": "6.2",
        "protocol_id": protocol["protocol_id"],
        "protocol_version": protocol["protocol_version"],
        "evaluation_status": protocol["evaluation_status"],
        "manuscript_eligible": False,
        "scenario_count": len(scenario_results),
        "event_count": sum(len(result["state_rows"]) for result in scenario_results.values()),
        "threshold_profile_count": len(protocol["threshold_profiles"]),
        "threshold_event_rows": len(threshold_rows),
        "non_baseline_threshold_event_rows": len(non_baseline_threshold_rows),
        "threshold_state_changes": sum(
            bool(row["state_changed"]) for row in non_baseline_threshold_rows
        ),
        "clock_profile_count": len(protocol["clock_sensitivity"]["profiles"]),
        "clock_event_rows": len(clock_rows),
        "clock_state_changes": sum(bool(row["state_changed"]) for row in clock_rows),
        "factor_variant_rows": len(factor_rows),
        "factor_state_changes": sum(bool(row["state_changed"]) for row in factor_rows),
        "negative_case_count": len(negative_rows),
        "negative_cases_rejected": sum(bool(row["rejected_as_expected"]) for row in negative_rows),
        "scenario_stability": stability_rows,
        "scenario_definition_hashes": scenario_hashes,
        "locked_controls": protocol["locked_controls"],
        "interpretation_boundary": [
            (
                "The registered perturbations test deterministic prototype behaviour, "
                "not legal correctness."
            ),
            (
                "Threshold and clock sweeps are sensitivity analyses and do not validate "
                "or optimise parameters."
            ),
            (
                "Controlled evidence toggles are evaluation-only counterfactuals, not "
                "observed incidents."
            ),
            "Candidate outputs remain ineligible until exact-commit reproduction and final freeze.",
        ],
        "limitations": [
            (
                "Single-factor evidence analysis evaluates the final registered event "
                "boundary rather than every possible multivariate trajectory."
            ),
            "The controlled scenario families do not establish industrial generalisability.",
            (
                "The registered grid is finite and cannot establish global stability "
                "outside tested values."
            ),
            "Manual-assisted baseline execution remains deferred and is not part of Stage 6.2.",
        ],
    }
    report_path = write_json(destination / "stage6_2_robustness_report.json", report)

    source_files = [
        PROTOCOL_PATH,
        *[_scenario_path(str(item)) for item in protocol["scenario_ids"]],
    ]
    output_files = [
        threshold_path,
        clock_path,
        factor_path,
        negative_path,
        stability_path,
        report_path,
    ]
    manifest = {
        "run_id": RUN_ID,
        "algorithm": "sha256",
        "source_files": {path.relative_to(ROOT).as_posix(): _sha256(path) for path in source_files},
        "output_files": {path.name: _sha256(path) for path in output_files},
    }
    manifest_path = write_json(destination / "stage6_2_output_manifest.json", manifest)
    return {
        "threshold_sensitivity": threshold_path,
        "clock_sensitivity": clock_path,
        "factor_sensitivity": factor_path,
        "negative_cases": negative_path,
        "scenario_stability": stability_path,
        "report": report_path,
        "manifest": manifest_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    outputs = run(args.destination.resolve())
    print("Stage 6.2 robustness and sensitivity evaluation completed:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
