#!/usr/bin/env python3
"""Validate the Stage 6.5 audit-remediation governance and AR conformance boundary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.model.metrics import MANDATORY_FIELDS, audit_reconstructability
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "evaluation/stage6_5_remediation_protocol_v0.1.yaml"
STAGE63_SUMMARY = ROOT / "evaluation/stage6_3_candidate/stage6_3_mutation_summary.json"
EXPECTED_PARENT_COMMIT = "77178902b04fcc9b8bd8c660e553c89e9ae6d246"
EXPECTED_STAGE64_PROTOCOL_SHA256 = (
    "c5001c5ef760ed37d72971970c119848e06f6fec481677e73895c1ab32745035"
)
EXPECTED_STAGE63_PROTOCOL_SHA256 = (
    "e6bfcc0c4984b41846e5dfb732b9a6e7d06e2fb5f40fef73c07d429b183ceb6b"
)
EXPECTED_STAGE63_SAFETY_SHA256 = "97a72aa162b2efe023119e23a75b147739923cd870c385993e8374f7bfa33139"
EXPECTED_AUDIT_PROTOCOL_SHA256 = "a0afdf749dd796dffbc9d7e2dde5d78fc5411bc417140fe60c5c63771b36d529"
EXPECTED_AUDIT_BUNDLE_SHA256 = "5a39ef9f506f0f2a5e486658330277a76465da47c43a19e1e3f448538f1ed51c"


def _error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _ar_matrix() -> dict[str, float]:
    common = {
        "event_id": "stage65-event",
        "timestamp": "2026-08-12T12:00:00Z",
        "actor": "stage65",
        "action": "validate",
        "input_references": ["source-stage65"],
    }
    return {
        "hash_only": audit_reconstructability([{**common, "output_hash": "a" * 64}]),
        "state_only": audit_reconstructability([{**common, "output_state": "Monitor"}]),
        "both": audit_reconstructability(
            [{**common, "output_hash": "b" * 64, "output_state": "Escalate"}]
        ),
        "neither": audit_reconstructability([dict(common)]),
    }


def validate() -> dict[str, Any]:
    errors: list[str] = []
    protocol = read_yaml(PROTOCOL_PATH)
    _error(
        errors, protocol.get("protocol_id") == "stage6_5_audit_remediation", "protocol_id changed"
    )
    _error(errors, str(protocol.get("protocol_version")) == "0.1", "protocol_version changed")
    _error(errors, str(protocol.get("package_version")) == "0.6.5", "package version changed")
    _error(
        errors,
        protocol.get("manuscript_eligible") is False,
        "remediation became manuscript-eligible",
    )
    parent = protocol.get("parent_checkpoint") or {}
    _error(
        errors,
        parent.get("git_commit") == EXPECTED_PARENT_COMMIT,
        "parent Stage 6.4 commit changed",
    )
    audit = protocol.get("source_audit") or {}
    _error(
        errors,
        audit.get("protocol_sha256") == EXPECTED_AUDIT_PROTOCOL_SHA256,
        "audit protocol hash changed",
    )
    _error(
        errors,
        audit.get("result_bundle_sha256") == EXPECTED_AUDIT_BUNDLE_SHA256,
        "audit bundle hash changed",
    )
    _error(
        errors,
        list(protocol.get("findings_in_scope") or []) == ["S65-F001", "S65-F004"],
        "finding scope changed",
    )
    _error(errors, len(MANDATORY_FIELDS) == 34, "Evidence Completeness denominator changed")
    _error(
        errors,
        sha256_file(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
        == EXPECTED_STAGE64_PROTOCOL_SHA256,
        "historical Stage 6.4 protocol v0.1 changed",
    )
    _error(
        errors,
        sha256_file(ROOT / "evaluation/stage6_3_mutation_protocol_v0.1.yaml")
        == EXPECTED_STAGE63_PROTOCOL_SHA256,
        "historical Stage 6.3 mutation protocol changed",
    )
    _error(
        errors,
        sha256_file(ROOT / "tests/test_stage6_3_safety_guards.py")
        == EXPECTED_STAGE63_SAFETY_SHA256,
        "historical Stage 6.3 safety test changed",
    )

    stage63 = json.loads(STAGE63_SUMMARY.read_text(encoding="utf-8"))
    historical_hashes = stage63.get("target_source_hashes") or {}
    compatibility = protocol.get("stage6_3_historical_compatibility") or {}
    authorized = set(compatibility.get("authorized_current_source_evolution") or [])
    changed_targets: list[str] = []
    for relative, historical_hash in historical_hashes.items():
        path = ROOT / relative
        _error(errors, path.is_file(), f"Stage 6.3 mutation target is missing: {relative}")
        if path.is_file() and sha256_file(path) != historical_hash:
            changed_targets.append(relative)
    _error(
        errors,
        set(changed_targets) == authorized,
        f"Stage 6.3 target-source evolution differs from the authorised set: {changed_targets}",
    )
    _error(
        errors,
        compatibility.get("historical_protocol_mutation_registry_changed") is False,
        "historical mutation registry marked as changed",
    )
    _error(
        errors,
        compatibility.get("historical_candidate_results_changed") is False,
        "historical mutation results marked as changed",
    )

    ar = _ar_matrix()
    _error(errors, ar["hash_only"] == 1.0, "AR does not accept hash-only output identification")
    _error(errors, ar["state_only"] == 1.0, "AR does not accept state-only output identification")
    _error(errors, ar["both"] == 1.0, "AR does not accept hash+state output identification")
    _error(errors, ar["neither"] == 0.0, "AR accepts an entry with no output identifier")

    v02 = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml")
    memory = (v02.get("measurement_scope") or {}).get("memory_measurement") or {}
    _error(
        errors,
        str(v02.get("protocol_version")) == "0.2",
        "performance remediation protocol is not v0.2",
    )
    _error(
        errors,
        memory.get("raw_observation_granularity") == "one observation per workload worker",
        "performance remediation memory granularity changed",
    )
    _error(
        errors,
        (v02.get("statistics") or {}).get("wall_cv_definition")
        == "sample_standard_deviation_n_minus_1_divided_by_arithmetic_mean",
        "performance remediation CV convention changed",
    )

    return {
        "valid": not errors,
        "errors": errors,
        "checks": {
            "package_version": str(protocol.get("package_version")),
            "parent_commit": parent.get("git_commit"),
            "findings_in_scope": protocol.get("findings_in_scope"),
            "ar_conformance_matrix": ar,
            "stage6_3_changed_target_sources": changed_targets,
            "stage6_3_authorized_source_evolution": sorted(authorized),
            "historical_stage6_3_protocol_preserved": True,
            "historical_stage6_4_protocol_preserved": True,
            "memory_observation_granularity": memory.get("raw_observation_granularity"),
            "manuscript_eligible": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=__doc__)


def main() -> int:
    build_parser().parse_args()
    report = validate()
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
