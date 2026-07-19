"""Parsers for controlled JSON, JSONL, and CSV telemetry evidence."""

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
        return data if isinstance(data, list) else [data]
    if suffix == ".jsonl":
        records = []
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"invalid JSONL at line {line_number}") from exc
        return records
    if suffix == ".csv":
        with source.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    raise ValueError(f"unsupported telemetry format: {suffix}")


def execution_observed(records: list[dict[str, Any]]) -> bool:
    truthy = {True, 1, "1", "true", "True", "yes", "observed", "executed"}
    return any(record.get("execution_observed") in truthy for record in records)
