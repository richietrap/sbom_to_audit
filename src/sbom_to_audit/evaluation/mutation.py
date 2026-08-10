"""Controlled source-mutation primitives for Stage 6.3 evaluation.

The module applies registered exact-text replacements only inside temporary
repository copies. It never mutates the accepted source tree in place.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

ALLOWED_FAMILIES = {
    "authorization",
    "conflict",
    "evidence_semantics",
    "identity_uncertainty",
    "metrics",
    "temporal_decision",
    "traceability_integrity",
}
ALLOWED_OUTCOMES = {"KILLED", "SURVIVED", "INVALID", "TIMEOUT"}


@dataclass(frozen=True)
class Replacement:
    """One exact source replacement registered for a mutant."""

    original: str
    mutated: str


@dataclass(frozen=True)
class Mutant:
    """Validated mutation specification."""

    mutant_id: str
    family: str
    target_file: str
    target_symbol: str
    description: str
    rationale: str
    replacements: tuple[Replacement, ...]
    baseline_tests: tuple[str, ...]
    strengthened_tests: tuple[str, ...]


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"mutation field {field!r} must be non-empty")
    return text


def mutant_from_mapping(value: dict[str, Any]) -> Mutant:
    """Validate and construct a mutant from one protocol mapping."""

    mutant_id = _required_text(value.get("mutant_id"), "mutant_id")
    family = _required_text(value.get("family"), "family")
    if family not in ALLOWED_FAMILIES:
        raise ValueError(f"unsupported mutation family: {family}")

    raw_replacements = value.get("replacements")
    if not isinstance(raw_replacements, list) or not raw_replacements:
        raise ValueError(f"{mutant_id}: replacements must be a non-empty list")
    replacements: list[Replacement] = []
    for index, item in enumerate(raw_replacements):
        if not isinstance(item, dict):
            raise ValueError(f"{mutant_id}: replacement {index} must be an object")
        original = str(item.get("original") or "")
        mutated = str(item.get("mutated") or "")
        if not original:
            raise ValueError(f"{mutant_id}: replacement {index} original must be non-empty")
        if original == mutated:
            raise ValueError(f"{mutant_id}: replacement {index} does not change the source")
        replacements.append(Replacement(original=original, mutated=mutated))

    baseline_tests = tuple(str(item).strip() for item in value.get("baseline_tests") or [])
    strengthened_tests = tuple(str(item).strip() for item in value.get("strengthened_tests") or [])
    if not baseline_tests or any(not item for item in baseline_tests):
        raise ValueError(f"{mutant_id}: baseline_tests must contain test node IDs")
    if any(not item for item in strengthened_tests):
        raise ValueError(f"{mutant_id}: strengthened_tests contains a blank node ID")

    return Mutant(
        mutant_id=mutant_id,
        family=family,
        target_file=_required_text(value.get("target_file"), "target_file"),
        target_symbol=_required_text(value.get("target_symbol"), "target_symbol"),
        description=_required_text(value.get("description"), "description"),
        rationale=_required_text(value.get("rationale"), "rationale"),
        replacements=tuple(replacements),
        baseline_tests=baseline_tests,
        strengthened_tests=strengthened_tests,
    )


def validate_mutant_registry(values: list[dict[str, Any]]) -> list[Mutant]:
    """Validate registry uniqueness and deterministic ordering."""

    mutants = [mutant_from_mapping(value) for value in values]
    identifiers = [mutant.mutant_id for mutant in mutants]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("mutation registry contains duplicate mutant_id values")
    if identifiers != sorted(identifiers):
        raise ValueError("mutation registry must be ordered by mutant_id")
    return mutants


def apply_mutant(repository_root: Path, mutant: Mutant) -> Path:
    """Apply one mutant to a temporary repository and return its target path."""

    root = repository_root.resolve()
    target = (root / mutant.target_file).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{mutant.mutant_id}: target escapes repository root") from exc
    if not target.is_file():
        raise FileNotFoundError(f"{mutant.mutant_id}: target file is missing: {target}")

    source = target.read_text(encoding="utf-8")
    for index, replacement in enumerate(mutant.replacements):
        count = source.count(replacement.original)
        if count != 1:
            raise ValueError(
                f"{mutant.mutant_id}: replacement {index} expected one source match, found {count}"
            )
        source = source.replace(replacement.original, replacement.mutated, 1)
    target.write_text(source, encoding="utf-8", newline="\n")
    return target


def mutation_score(rows: list[dict[str, Any]], outcome_field: str) -> float | None:
    """Compute killed/(killed+survived), excluding invalid and timeout rows."""

    killed = sum(1 for row in rows if row.get(outcome_field) == "KILLED")
    survived = sum(1 for row in rows if row.get(outcome_field) == "SURVIVED")
    denominator = killed + survived
    if denominator == 0:
        return None
    return round(killed / denominator, 6)


def summarize_outcomes(rows: list[dict[str, Any]], outcome_field: str) -> dict[str, int]:
    """Count explicit mutation outcomes for one test-suite phase."""

    counts = {outcome: 0 for outcome in sorted(ALLOWED_OUTCOMES)}
    for row in rows:
        outcome = str(row.get(outcome_field) or "")
        if outcome not in counts:
            raise ValueError(f"unexpected mutation outcome: {outcome}")
        counts[outcome] += 1
    return counts
