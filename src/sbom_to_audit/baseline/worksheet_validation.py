"""Fail-closed validation for Stage 6.1 manual baseline bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.manual_worksheet import (
    BUNDLE_SCHEMAS,
    DECLARATION_FILE,
    load_manual_bundle,
)
from sbom_to_audit.baseline.protocol import ManualBaselineProtocol

RECOMMENDED_STATES = {
    "Monitor",
    "Prepare",
    "Escalate",
    "Report-Ready",
    "Report",
    "Document No-Report",
}
AUTHORIZED_STATES = {"", "Report", "Document No-Report"}
TRUE_VALUES = {"true", "yes", "1"}
FALSE_VALUES = {"false", "no", "0"}


@dataclass
class WorksheetValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return not self.errors


def _timestamp(value: str, label: str, report: WorksheetValidationReport) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        report.errors.append(f"invalid timestamp for {label}: {value!r}")
        return None


def _timestamps_equal(
    observed: str,
    expected: str,
    label: str,
    report: WorksheetValidationReport,
) -> bool:
    observed_value = _timestamp(observed, f"{label}/observed", report)
    expected_value = _timestamp(expected, f"{label}/expected", report)
    return (
        observed_value is not None
        and expected_value is not None
        and observed_value == expected_value
    )


def _confidence(value: str, label: str, report: WorksheetValidationReport) -> float | None:
    text = value.strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        report.errors.append(f"invalid confidence for {label}: {value!r}")
        return None
    if not 0.0 <= number <= 1.0:
        report.errors.append(f"confidence outside 0.0-1.0 for {label}: {number}")
    return number


def _boolean(value: str, label: str, report: WorksheetValidationReport) -> bool | None:
    text = value.strip().lower()
    if not text:
        return None
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    report.errors.append(f"invalid Boolean for {label}: {value!r}")
    return None


def validate_manual_bundle(
    bundle_root: str | Path,
    protocol: ManualBaselineProtocol,
    state_oracle: dict[tuple[str, str], dict[str, Any]],
    known_artifacts: dict[str, set[str]],
    *,
    require_complete: bool,
) -> WorksheetValidationReport:
    """Validate worksheet structure, event coverage, provenance, timing, and declarations."""

    report = WorksheetValidationReport()
    root = Path(bundle_root)
    missing = [name for name in (*BUNDLE_SCHEMAS, DECLARATION_FILE) if not (root / name).is_file()]
    if missing:
        report.errors.append(f"manual baseline bundle is missing files: {missing}")
        return report
    try:
        bundle = load_manual_bundle(root)
    except (OSError, ValueError) as exc:
        report.errors.append(str(exc))
        return report

    decisions = bundle["case_decisions.csv"]
    decision_keys = [(row["scenario_id"].strip(), row["event_id"].strip()) for row in decisions]
    if len(set(decision_keys)) != len(decision_keys):
        report.errors.append("case_decisions.csv contains duplicate scenario/event rows")
    expected_keys = set(state_oracle)
    if set(decision_keys) != expected_keys:
        missing_keys = sorted(expected_keys - set(decision_keys))
        extra_keys = sorted(set(decision_keys) - expected_keys)
        report.errors.append(
            f"case decision event coverage drifted; missing={missing_keys}, extra={extra_keys}"
        )

    complete_count = 0
    for row in decisions:
        key = (row["scenario_id"].strip(), row["event_id"].strip())
        label = "/".join(key)
        if key not in state_oracle:
            continue
        if not _timestamps_equal(
            row["event_timestamp"],
            str(state_oracle[key]["timestamp"]),
            f"{label}/event_timestamp",
            report,
        ):
            report.errors.append(f"event timestamp drift for {label}")
        status = row["completion_status"].strip()
        if status == "COMPLETE":
            complete_count += 1
        elif require_complete:
            report.errors.append(f"incomplete decision row: {label}")
        if status == "COMPLETE" or any(
            row[field].strip()
            for field in ("recommended_state", "rationale", "decision_recorded_at")
        ):
            if row["recommended_state"].strip() not in RECOMMENDED_STATES:
                report.errors.append(f"invalid recommended_state for {label}")
            if row["authorized_state"].strip() not in AUTHORIZED_STATES:
                report.errors.append(f"invalid authorized_state for {label}")
            _boolean(row["human_authorization_required"], f"{label}/authorization", report)
            _boolean(row["conflict_identified"], f"{label}/conflict", report)
            _boolean(row["clock_safeguard_noted"], f"{label}/clock", report)
            _confidence(row["identity_confidence"], f"{label}/identity", report)
            _confidence(row["analyst_confidence"], f"{label}/analyst", report)
            start = _timestamp(row["review_started_at"], f"{label}/review_started", report)
            decision = _timestamp(
                row["decision_recorded_at"], f"{label}/decision_recorded", report
            )
            if start is not None and decision is not None and decision < start:
                report.errors.append(f"decision precedes review start for {label}")
            if not row["rationale"].strip():
                report.errors.append(f"decision rationale is missing for {label}")

    observations = bundle["evidence_observations.csv"]
    observation_ids: set[str] = set()
    completed_observation_events: set[tuple[str, str]] = set()
    for row in observations:
        observation_id = row["observation_id"].strip()
        if not observation_id or observation_id in observation_ids:
            report.errors.append(f"blank or duplicate observation_id: {observation_id!r}")
        observation_ids.add(observation_id)
        key = (row["scenario_id"].strip(), row["event_id"].strip())
        if key not in expected_keys:
            report.errors.append(f"observation references unknown event: {key}")
            continue
        status = row["observation_status"].strip()
        if status in {"OBSERVED", "MISSING", "NOT_APPLICABLE"}:
            completed_observation_events.add(key)
        elif require_complete:
            report.errors.append(f"observation not reviewed: {observation_id}")
        if status == "OBSERVED":
            if not row["value"].strip():
                report.errors.append(f"observed value is blank: {observation_id}")
            artifact_id = row["source_artifact_id"].strip()
            scenario_id = key[0]
            if artifact_id not in known_artifacts.get(scenario_id, set()):
                report.errors.append(
                    "observation references unknown source artifact: "
                    f"{observation_id}/{artifact_id}"
                )
            for field_name in ("source_uri", "source_hash", "source_timestamp"):
                if not row[field_name].strip():
                    report.errors.append(f"{field_name} missing for {observation_id}")
            _timestamp(row["source_timestamp"], f"{observation_id}/source_timestamp", report)
            confidence = _confidence(row["confidence"], f"{observation_id}/confidence", report)
            if protocol.confidence_required and confidence is None:
                report.errors.append(f"confidence missing for observed row: {observation_id}")
        elif status in {"MISSING", "NOT_APPLICABLE"} and row["value"].strip():
            report.errors.append(f"non-observed row contains a value: {observation_id}")

    access_rows = bundle["source_access_log.csv"]
    access_ids: set[str] = set()
    accessed_events: set[tuple[str, str]] = set()
    for row in access_rows:
        access_id = row["access_id"].strip()
        if not access_id or access_id in access_ids:
            report.errors.append(f"blank or duplicate access_id: {access_id!r}")
        access_ids.add(access_id)
        key = (row["scenario_id"].strip(), row["event_id"].strip())
        if key not in expected_keys:
            report.errors.append(f"source access references unknown event: {key}")
            continue
        accessed_events.add(key)
        artifact_id = row["artifact_id"].strip()
        if artifact_id not in known_artifacts.get(key[0], set()):
            report.errors.append(f"source access references unknown artifact: {key}/{artifact_id}")
        if row["tool"].strip() not in protocol.allowed_tools:
            report.errors.append(
                "source access uses a tool outside the allowlist: "
                f"{row['tool']!r}"
            )
        _timestamp(row["accessed_at"], f"{access_id}/accessed_at", report)

    conflict_rows = bundle["conflict_log.csv"]
    conflict_record_ids: set[str] = set()
    for row in conflict_rows:
        record_id = row["record_id"].strip()
        if not record_id or record_id in conflict_record_ids:
            report.errors.append(f"blank or duplicate conflict record_id: {record_id!r}")
        conflict_record_ids.add(record_id)
        key = (row["scenario_id"].strip(), row["event_id"].strip())
        if key not in expected_keys:
            report.errors.append(f"conflict row references unknown event: {key}")
        if row["classification"].strip() not in {"CONFLICT", "NO_CONFLICT"}:
            report.errors.append(f"invalid conflict classification: {record_id}")
        _confidence(row["confidence"], f"{record_id}/confidence", report)

    timing_rows = bundle["timing_log.csv"]
    timing_keys = [(row["scenario_id"].strip(), row["event_id"].strip()) for row in timing_rows]
    if len(set(timing_keys)) != len(timing_keys) or set(timing_keys) != expected_keys:
        report.errors.append("timing_log.csv event coverage drifted")
    for row in timing_rows:
        key = (row["scenario_id"].strip(), row["event_id"].strip())
        label = "/".join(key)
        if key not in state_oracle:
            continue
        if not _timestamps_equal(
            row["evidence_released_at"],
            str(state_oracle[key]["timestamp"]),
            f"{label}/evidence_released_at",
            report,
        ):
            report.errors.append(f"timing release timestamp drift for {label}")
        start = _timestamp(row["review_started_at"], f"{label}/timing_start", report)
        end = _timestamp(row["decision_recorded_at"], f"{label}/timing_decision", report)
        if require_complete and (start is None or end is None):
            report.errors.append(f"timing record incomplete for {label}")
        if start is not None and end is not None:
            expected_minutes = round((end - start).total_seconds() / 60.0, 6)
            try:
                recorded = float(row["elapsed_minutes"])
            except ValueError:
                report.errors.append(f"elapsed_minutes invalid for {label}")
            else:
                if abs(recorded - expected_minutes) > 0.01:
                    report.errors.append(f"elapsed_minutes mismatch for {label}")

    declaration = bundle[DECLARATION_FILE]
    if declaration.get("protocol_id") != protocol.protocol_id:
        report.errors.append("declaration protocol_id mismatch")
    if str(declaration.get("protocol_version")) != protocol.protocol_version:
        report.errors.append("declaration protocol_version mismatch")
    if require_complete:
        for field_name in (
            "analyst_id_or_pseudonym",
            "execution_role",
            "baseline_execution_started_at",
            "baseline_execution_completed_at",
            "signed_name_or_pseudonym",
        ):
            if not str(declaration.get(field_name) or "").strip():
                report.errors.append(f"declaration field is missing: {field_name}")
        if declaration.get("automated_outputs_seen_before_execution") is None:
            report.errors.append("declaration must record prior automated-output exposure")
    if declaration.get("automated_outputs_seen_before_execution") is True:
        report.warnings.append(
            "baseline execution is non-blinded and requires limitation disclosure"
        )

    if require_complete:
        missing_observation_events = expected_keys - completed_observation_events
        if missing_observation_events:
            report.errors.append(
                f"events without reviewed observations: {sorted(missing_observation_events)}"
            )
        missing_access_events = expected_keys - accessed_events
        if missing_access_events:
            report.errors.append(
                "events without source-access records: "
                f"{sorted(missing_access_events)}"
            )

    report.checks = {
        "expected_events": len(expected_keys),
        "decision_rows": len(decisions),
        "complete_decisions": complete_count,
        "observation_rows": len(observations),
        "source_access_rows": len(access_rows),
        "conflict_rows": len(conflict_rows),
        "timing_rows": len(timing_rows),
        "require_complete": require_complete,
    }
    return report
