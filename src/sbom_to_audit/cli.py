"""Command-line entry point for deterministic controlled scenario replay."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.model.metrics import (
    audit_reconstructability,
    clock_aware_escalation,
    conflict_detection,
    evidence_completeness,
    evidence_pack_generation,
    state_correctness,
    traceability_ratio,
)
from sbom_to_audit.utils.io import read_json, read_yaml, write_csv, write_json

STATE_FIELDS = [
    "event_id",
    "timestamp",
    "delta_t_hours",
    "E_t",
    "A_t",
    "I_t",
    "M_t",
    "U_t",
    "C_t",
    "previous_state",
    "observed_state",
    "expected_state",
    "state_match",
    "rationale",
]


def _find_repository_root(scenario_path: Path) -> Path:
    for candidate in [
        Path.cwd().resolve(),
        *Path.cwd().resolve().parents,
        scenario_path.resolve().parent,
        *scenario_path.resolve().parents,
    ]:
        if (candidate / "pyproject.toml").exists() and (candidate / "schemas").is_dir():
            return candidate
    raise FileNotFoundError(
        "could not locate repository root containing pyproject.toml and schemas/"
    )


def _validate_pack(pack: dict[str, Any], schema_path: Path) -> None:
    schema = read_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(pack), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"generated EvidencePack failed schema validation: {details}")


def run(scenario_path: str | Path, output_root: str | Path | None = None) -> dict[str, Path]:
    scenario_file = Path(scenario_path).resolve()
    scenario = read_yaml(scenario_file)
    if not isinstance(scenario, dict):
        raise ValueError("scenario YAML must contain an object")
    if scenario.get("schema_version") != "0.2":
        raise ValueError("scenario schema_version must be 0.2")

    repository_root = _find_repository_root(scenario_file)
    outputs_root = Path(output_root).resolve() if output_root else repository_root / "outputs"
    scenario_id = scenario["scenario"]["scenario_id"]
    result = replay_scenario(scenario)

    evidence_pack_path = outputs_root / "evidence_packs" / f"{scenario_id}.json"
    state_log_path = outputs_root / "state_logs" / f"{scenario_id}.csv"
    conflict_report_path = outputs_root / "conflict_reports" / f"{scenario_id}.json"
    metrics_path = outputs_root / "metrics" / f"{scenario_id}_metrics.json"

    _validate_pack(result["pack"], repository_root / "schemas" / "evidencepack_v0.2.schema.json")
    write_json(evidence_pack_path, result["pack"])
    write_csv(state_log_path, result["state_rows"], STATE_FIELDS)
    write_json(
        conflict_report_path,
        {
            "scenario_id": scenario_id,
            "seeded_conflicts": int(scenario["scenario"].get("seeded_conflicts", 0)),
            "detected_conflicts": len(result["conflicts"]),
            "C_t": bool(result["pack"]["orchestration_metrics"]["C_t"]),
            "conflicts": result["conflicts"],
        },
    )

    near_clock_events = [
        row
        for row in result["state_rows"]
        if row.get("previous_state") == "Prepare" and float(row["delta_t_hours"]) >= 18.0
    ]
    primary_outputs = [evidence_pack_path, state_log_path, conflict_report_path]
    ca_value = clock_aware_escalation(near_clock_events)
    metrics = {
        "scenario_id": scenario_id,
        "schema_version": "0.2",
        "EC": evidence_completeness(result["pack"]),
        "TR": traceability_ratio(result["pack"]["claims"]),
        "CD": conflict_detection(
            len(result["conflicts"]), int(scenario["scenario"].get("seeded_conflicts", 0))
        ),
        "CA": ca_value,
        "CA_status": "not_applicable" if ca_value is None else "applicable",
        "AR": audit_reconstructability(result["pack"]["audit_log"]),
        "SC": state_correctness(result["state_rows"]),
        "EPG": evidence_pack_generation(primary_outputs),
        "identity_uncertainty_context": {
            "gamma_id": result["pack"]["identity_resolution"]["gamma_id"],
            "U_t": result["pack"]["orchestration_metrics"]["U_t"],
        },
        "baseline_comparison_status": "pending_matched_baseline_replay",
    }
    write_json(metrics_path, metrics)

    return {
        "evidence_pack": evidence_pack_path,
        "state_log": state_log_path,
        "conflict_report": conflict_report_path,
        "metrics": metrics_path,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario", required=True, help="Path to a controlled scenario YAML file."
    )
    parser.add_argument(
        "--output-root", help="Optional output directory; defaults to repository outputs/."
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    paths = run(args.scenario, args.output_root)
    print("EvidencePack v0.2 replay completed:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
