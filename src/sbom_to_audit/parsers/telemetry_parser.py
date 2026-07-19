"""Parsers and reducers for controlled JSON, JSONL, and CSV telemetry."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def parse_telemetry(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix == ".json":
        with source.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        records = data if isinstance(data, list) else [data]
    elif suffix == ".jsonl":
        records = []
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"invalid JSONL at line {line_number}") from exc
    elif suffix == ".csv":
        with source.open("r", encoding="utf-8", newline="") as handle:
            records = list(csv.DictReader(handle))
    else:
        raise ValueError(f"unsupported telemetry format: {suffix}")

    if not all(isinstance(record, dict) for record in records):
        raise ValueError("telemetry records must be objects")
    return records


def _truthy(value: Any) -> bool:
    return value in {True, "1", "true", "True", "yes", "observed", "executed", "confirmed"}


def execution_observed(records: list[dict[str, Any]]) -> bool:
    return any(_truthy(record.get("execution_observed")) for record in records)


def reachability_confirmed(records: list[dict[str, Any]]) -> bool:
    return any(_truthy(record.get("reachability_confirmed")) for record in records)


def malicious_exploitation_observed(records: list[dict[str, Any]]) -> bool:
    return any(_truthy(record.get("malicious_exploitation_observed")) for record in records)
