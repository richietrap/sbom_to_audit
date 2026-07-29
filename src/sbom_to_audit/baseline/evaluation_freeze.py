"""Pre-execution hashing and verification for Stage 6.1 evaluation controls."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_json, read_yaml, write_json


def load_freeze_targets(path: str | Path) -> tuple[str, ...]:
    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError("freeze-target configuration must contain an object")
    targets = payload.get("paths") or []
    if not isinstance(targets, list) or not targets:
        raise ValueError("freeze-target configuration requires paths")
    values = tuple(str(value).strip() for value in targets)
    if any(not value for value in values) or len(set(values)) != len(values):
        raise ValueError("freeze-target paths must be non-empty and unique")
    return values


def build_freeze_payload(repository_root: str | Path, paths: tuple[str, ...]) -> dict[str, Any]:
    root = Path(repository_root)
    records: list[dict[str, str]] = []
    for relative in paths:
        target = root / relative
        if not target.is_file():
            raise FileNotFoundError(f"freeze target does not exist: {relative}")
        records.append({"path": relative, "sha256": sha256_file(target)})
    return {
        "freeze_id": "STAGE6-1-PRE-EXECUTION-FREEZE-002",
        "freeze_status": "PRE_EXECUTION_FROZEN",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "records": records,
    }


def write_freeze(
    repository_root: str | Path,
    paths: tuple[str, ...],
    output_path: str | Path,
) -> Path:
    return write_json(output_path, build_freeze_payload(repository_root, paths))


def verify_freeze(repository_root: str | Path, freeze_path: str | Path) -> list[str]:
    root = Path(repository_root)
    payload = read_json(freeze_path)
    if not isinstance(payload, dict) or payload.get("freeze_status") != "PRE_EXECUTION_FROZEN":
        raise ValueError("Stage 6.1 freeze record is invalid")
    errors: list[str] = []
    for row in payload.get("records") or []:
        relative = str(row.get("path") or "")
        expected = str(row.get("sha256") or "")
        target = root / relative
        if not target.is_file():
            errors.append(f"missing:{relative}")
        elif sha256_file(target) != expected:
            errors.append(f"hash_mismatch:{relative}")
    return errors
