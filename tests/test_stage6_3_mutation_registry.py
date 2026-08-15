import json
import py_compile
from pathlib import Path

import pytest

from sbom_to_audit.evaluation.mutation import (
    apply_mutant,
    mutation_score,
    summarize_outcomes,
    validate_mutant_registry,
)
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "evaluation" / "stage6_3_mutation_protocol_v0.1.yaml"
SUMMARY = ROOT / "evaluation" / "stage6_3_candidate" / "stage6_3_mutation_summary.json"
AUTHORIZED_SOURCE_EVOLUTION = {"src/sbom_to_audit/model/metrics.py"}


def _mutants():
    protocol = read_yaml(PROTOCOL)
    assert isinstance(protocol, dict)
    values = protocol["mutants"]
    assert isinstance(values, list)
    return validate_mutant_registry(values)


def test_registered_mutants_compile_against_unchanged_historical_targets(tmp_path: Path) -> None:
    mutants = _mutants()
    assert len(mutants) == 26
    assert len({mutant.family for mutant in mutants}) == 7
    assert [mutant.mutant_id for mutant in mutants] == sorted(
        mutant.mutant_id for mutant in mutants
    )

    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    historical_hashes = summary["target_source_hashes"]

    evolved_targets: set[str] = set()
    for mutant in mutants:
        source = ROOT / mutant.target_file
        historical_hash = historical_hashes[mutant.target_file]
        if sha256_file(source) != historical_hash:
            evolved_targets.add(mutant.target_file)
            continue

        repository = tmp_path / mutant.mutant_id
        target = repository / mutant.target_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        mutated = apply_mutant(repository, mutant)
        py_compile.compile(str(mutated), doraise=True)

    # Stage 6.5 deliberately changes AR semantics in metrics.py. Historical Stage 6.3
    # exact-text mutants remain evidence against their recorded source hashes rather than
    # being mechanically re-applied to a later source version. No other target may drift.
    assert evolved_targets == AUTHORIZED_SOURCE_EVOLUTION


def test_registry_rejects_duplicate_identifiers() -> None:
    mutant = {
        "mutant_id": "S63-TEST-001",
        "family": "metrics",
        "target_file": "src/example.py",
        "target_symbol": "example",
        "description": "Example mutant.",
        "rationale": "Exercises duplicate detection.",
        "replacements": [{"original": "a = 1", "mutated": "a = 2"}],
        "baseline_tests": ["tests/test_example.py"],
        "strengthened_tests": [],
    }
    with pytest.raises(ValueError, match="duplicate mutant_id"):
        validate_mutant_registry([mutant, mutant])


def test_mutation_application_fails_when_source_match_drifted(tmp_path: Path) -> None:
    mutant = _mutants()[0]
    target = tmp_path / mutant.target_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("source no longer contains the registered expression\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected one source match"):
        apply_mutant(tmp_path, mutant)


def test_mutation_scores_exclude_invalid_and_timeout_rows() -> None:
    rows = [
        {"outcome": "KILLED"},
        {"outcome": "SURVIVED"},
        {"outcome": "INVALID"},
        {"outcome": "TIMEOUT"},
    ]
    assert mutation_score(rows, "outcome") == 0.5
    assert summarize_outcomes(rows, "outcome") == {
        "INVALID": 1,
        "KILLED": 1,
        "SURVIVED": 1,
        "TIMEOUT": 1,
    }
