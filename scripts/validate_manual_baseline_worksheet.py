#!/usr/bin/env python3
"""Validate a Stage 6.1 manual baseline CSV/YAML bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbom_to_audit.baseline.evaluation_oracles import load_state_oracle
from sbom_to_audit.baseline.protocol import load_manual_protocol
from sbom_to_audit.baseline.worksheet_validation import validate_manual_bundle
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]


def _known_artifacts(protocol_scenarios: tuple[str, ...]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for scenario_id in protocol_scenarios:
        scenario = read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario must contain an object: {scenario_id}")
        result[scenario_id] = {
            str(row["artifact_id"]) for row in scenario.get("source_catalog") or []
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    protocol = load_manual_protocol(ROOT / "evaluation" / "baseline_protocol_v0.2.yaml")
    oracle = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    report = validate_manual_bundle(
        args.bundle,
        protocol,
        oracle,
        _known_artifacts(protocol.scenario_ids),
        require_complete=args.require_complete,
    )
    payload = {
        "valid": report.valid,
        "errors": report.errors,
        "warnings": report.warnings,
        "checks": report.checks,
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
