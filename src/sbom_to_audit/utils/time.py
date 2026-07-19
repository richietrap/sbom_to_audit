"""UTC timestamp parsing and reporting-clock calculations."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def isoformat_z(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("datetime must include a timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def delta_hours(start: str | datetime, end: str | datetime) -> float:
    start_dt = parse_timestamp(start) if isinstance(start, str) else start.astimezone(timezone.utc)
    end_dt = parse_timestamp(end) if isinstance(end, str) else end.astimezone(timezone.utc)
    result = (end_dt - start_dt).total_seconds() / 3600.0
    if result < 0:
        raise ValueError("end timestamp precedes the reporting-clock start")
    return round(result, 6)
