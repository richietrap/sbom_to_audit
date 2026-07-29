#!/usr/bin/env python3
"""Validate Stage 6.1 protocol, oracles, freeze, and optional comparison outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbom_to_audit.baseline.evaluation_freeze import verify_freeze
from sbom_to_audit.baseline.evaluation_oracles import (
    load_clock_oracle,
    load_conflict_oracle,
    load_state_oracle,
    validate_oracle_coverage,
)
from sbom_to_audit.baseline.protocol import load_manual_protocol
from sbom_to_audit.model.metrics import MANDATORY_FIELDS
from sbom_to_audit.utils.io import read_json

ROOT = Path(__file__).resolve().parents[1]


def validate(comparison_report: Path | None = None) -> dict[str, object]:
    protocol = load_manual_protocol(ROOT / "evaluation" / "baseline_protocol_v0.2.yaml")
    state = load_state_oracle(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    conflicts = load_conflict_oracle(ROOT / "evaluation" / "oracles" / "conflict_oracle_v0.1.yaml")
    clock = load_clock_oracle(
        ROOT / "evaluation" / "oracles" / "clock_opportunity_oracle_v0.1.yaml"
    )
    errors = verify_freeze(ROOT, ROOT / "evaluation" / "freeze" / "stage6_1_protocol_freeze.json")
    try:
        validate_oracle_coverage(state, conflicts, clock)
    except ValueError as exc:
        errors.append(str(exc))
    if len(MANDATORY_FIELDS) != 34:
        errors.append("locked EC denominator drifted from 34")
    checks: dict[str, object] = {
        "protocol_version": protocol.protocol_version,
        "scenario_count": len(protocol.scenario_ids),
        "oracle_event_count": len(state),
        "mandatory_field_count": len(MANDATORY_FIELDS),
        "locked_metrics": list(protocol.locked_metrics),
        "freeze_verified": not errors,
    }
    if comparison_report is not None:
        report = read_json(comparison_report)
        if report.get("manuscript_eligible") is not False:
            errors.append("Stage 6.1 candidate must remain manuscript-ineligible before final tag")
        checks["comparison_id"] = report.get("comparison_id")
    return {"valid": not errors, "errors": errors, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison-report", type=Path)
    args = parser.parse_args()
    report = validate(args.comparison_report)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
