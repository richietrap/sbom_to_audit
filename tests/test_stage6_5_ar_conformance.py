"""Specification-derived Stage 6.5 AR conformance controls."""

from sbom_to_audit.model.metrics import audit_reconstructability

COMMON = {
    "event_id": "event-stage65",
    "timestamp": "2026-08-12T12:00:00Z",
    "actor": "stage65",
    "action": "validated",
    "input_references": ["source-stage65"],
}


def _entry(*, output_hash: object = None, output_state: object = None) -> dict[str, object]:
    entry: dict[str, object] = dict(COMMON)
    if output_hash is not None:
        entry["output_hash"] = output_hash
    if output_state is not None:
        entry["output_state"] = output_state
    return entry


def test_ar_accepts_hash_without_state() -> None:
    entry = _entry(output_hash="a" * 64)
    assert audit_reconstructability([entry]) == 1.0


def test_ar_accepts_state_without_hash() -> None:
    entry = _entry(output_state="Monitor")
    assert audit_reconstructability([entry]) == 1.0


def test_ar_accepts_hash_and_state() -> None:
    entry = _entry(output_hash="b" * 64, output_state="Escalate")
    assert audit_reconstructability([entry]) == 1.0


def test_ar_rejects_missing_hash_and_state() -> None:
    assert audit_reconstructability([dict(COMMON)]) == 0.0


def test_ar_requires_every_common_reconstruction_field() -> None:
    entry = _entry(output_hash="c" * 64)
    entry["input_references"] = []
    assert audit_reconstructability([entry]) == 0.0


def test_ar_preserves_existing_state_only_historical_semantics() -> None:
    complete = _entry(output_state="Report-Ready")
    incomplete = dict(complete)
    incomplete["actor"] = ""
    assert audit_reconstructability([complete, incomplete]) == 0.5


def test_ar_uses_existing_population_rules_for_blank_output_identifiers() -> None:
    assert audit_reconstructability([_entry(output_hash="   ")]) == 0.0
    assert audit_reconstructability([_entry(output_state="")]) == 0.0
