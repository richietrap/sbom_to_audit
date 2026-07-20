"""Offline NVD API 2.0 snapshot helpers for technical-severity context."""

from __future__ import annotations

from typing import Any

_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def extract_cvss_metrics(snapshot: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Return normalized CVSS context for ``cve_id`` from an NVD-shaped snapshot.

    The function prefers CVSS v3.1, then v3.0, then v2.0. It does not use the
    score for orchestration state transitions; the value is retained as
    contextual evidence for the Operational Outlier evaluation.
    """

    for wrapper in snapshot.get("vulnerabilities") or []:
        if not isinstance(wrapper, dict):
            continue
        cve = wrapper.get("cve") or {}
        if not isinstance(cve, dict) or cve.get("id") != cve_id:
            continue
        metrics = cve.get("metrics") or {}
        if not isinstance(metrics, dict):
            return None
        for key in _METRIC_KEYS:
            entries = metrics.get(key) or []
            if not isinstance(entries, list) or not entries:
                continue
            primary = next(
                (
                    item
                    for item in entries
                    if isinstance(item, dict) and item.get("type") == "Primary"
                ),
                None,
            )
            selected = primary or next((item for item in entries if isinstance(item, dict)), None)
            if selected is None:
                continue
            cvss_data = selected.get("cvssData") or {}
            if not isinstance(cvss_data, dict):
                continue
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or selected.get("baseSeverity")
            vector = cvss_data.get("vectorString")
            if score is None or severity is None:
                continue
            numeric_score = float(score)
            if not 0.0 <= numeric_score <= 10.0:
                raise ValueError("NVD CVSS base score must be between 0 and 10")
            return {
                "cve_id": cve_id,
                "metric_version": key,
                "base_score": numeric_score,
                "base_severity": str(severity).upper(),
                "vector_string": str(vector or ""),
                "source": selected.get("source"),
                "type": selected.get("type"),
            }
    return None
