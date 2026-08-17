"""Controlled admission for explicitly documented baseline exceptions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_json


def admit_controlled_exception(
    errors: list[str],
    adjudication_path: str | Path,
    *,
    expected_errors: list[str],
    expected_adjudication: dict[str, Any],
    basis: str,
) -> dict[str, Any]:
    """Admit only an explicitly specified and adjudicated validation exception."""
    if errors != expected_errors:
        raise ValueError("validation errors do not match the controlled exception")

    path = Path(adjudication_path)
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("controlled-exception adjudication must be a JSON object")

    mismatches = [
        key for key, expected in expected_adjudication.items() if payload.get(key) != expected
    ]
    if mismatches:
        raise ValueError(f"controlled-exception adjudication mismatch: {sorted(mismatches)}")

    return {
        "admitted": True,
        "basis": basis,
        "strict_validation_valid": False,
        "strict_validation_errors": list(errors),
        "adjudication_filename": path.name,
        "adjudication_sha256": sha256_file(path),
        "adjudication_status": payload.get("status"),
        "analyst_clarification_received": payload.get("analyst_clarification_received"),
        "canonical_log_amendment_required": payload.get("canonical_log_amendment_required"),
    }
