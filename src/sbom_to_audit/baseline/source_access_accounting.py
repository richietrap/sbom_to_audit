"""Like-for-like source-access accounting for Stage 6.1."""

from __future__ import annotations

from typing import Any


def summarize_source_accesses(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize distinct, event-level, and repeated artifact accesses."""

    artifact_ids = [str(row.get("artifact_id") or "").strip() for row in rows]
    if any(not artifact_id for artifact_id in artifact_ids):
        raise ValueError("source-access rows require artifact_id")
    event_keys = {
        (
            str(row.get("scenario_id") or "").strip(),
            str(row.get("event_id") or "").strip(),
            str(row.get("artifact_id") or "").strip(),
        )
        for row in rows
    }
    if any(not all(key) for key in event_keys):
        raise ValueError("source-access rows require scenario_id and event_id")
    distinct = len(set(artifact_ids))
    return {
        "total_access_rows": len(rows),
        "distinct_source_artifacts_accessed": distinct,
        "event_source_accesses": len(event_keys),
        "repeat_accesses": len(rows) - distinct,
    }
