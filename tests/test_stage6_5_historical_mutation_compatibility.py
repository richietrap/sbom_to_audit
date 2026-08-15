"""Stage 6.5 controls for preserving historical Stage 6.3 mutation evidence."""

import json
from pathlib import Path

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]


def test_only_authorized_stage6_3_target_source_evolved() -> None:
    summary = json.loads(
        (ROOT / "evaluation/stage6_3_candidate/stage6_3_mutation_summary.json").read_text(
            encoding="utf-8"
        )
    )
    protocol = read_yaml(ROOT / "evaluation/stage6_5_remediation_protocol_v0.1.yaml")
    authorized = set(
        (protocol.get("stage6_3_historical_compatibility") or {}).get(
            "authorized_current_source_evolution"
        )
        or []
    )
    changed = {
        relative
        for relative, historical_hash in (summary.get("target_source_hashes") or {}).items()
        if sha256_file(ROOT / relative) != historical_hash
    }
    assert changed == authorized == {"src/sbom_to_audit/model/metrics.py"}


def test_historical_stage6_3_protocol_and_safety_test_remain_byte_stable() -> None:
    assert (
        sha256_file(ROOT / "evaluation/stage6_3_mutation_protocol_v0.1.yaml")
        == "e6bfcc0c4984b41846e5dfb732b9a6e7d06e2fb5f40fef73c07d429b183ceb6b"
    )
    assert (
        sha256_file(ROOT / "tests/test_stage6_3_safety_guards.py")
        == "97a72aa162b2efe023119e23a75b147739923cd870c385993e8374f7bfa33139"
    )
