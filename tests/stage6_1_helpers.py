from __future__ import annotations

import csv
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_completed_manual_bundle(destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    template_root = ROOT / "data" / "baseline_templates"
    for name in (
        "case_decisions.csv",
        "evidence_observations.csv",
        "source_access_log.csv",
        "conflict_log.csv",
        "timing_log.csv",
        "declaration.yaml",
    ):
        shutil.copy2(template_root / name, destination / name)

    state_payload = read_yaml(ROOT / "evaluation" / "oracles" / "state_oracle_v0.1.yaml")
    assert isinstance(state_payload, dict)
    state = {
        (scenario["scenario_id"], event["event_id"]): event
        for scenario in state_payload["scenarios"]
        for event in scenario["events"]
    }
    scenarios = {
        scenario_id: read_yaml(ROOT / "data" / "scenarios" / f"{scenario_id}.yaml")
        for scenario_id in {key[0] for key in state}
    }
    catalogs = {
        scenario_id: {row["artifact_id"]: row for row in payload["source_catalog"]}
        for scenario_id, payload in scenarios.items()
    }
    cumulative: dict[tuple[str, str], list[str]] = {}
    for scenario_id, payload in scenarios.items():
        available: list[str] = []
        for event in payload["replay_events"]:
            for artifact_id in event.get("release_artifact_ids") or []:
                if artifact_id not in available:
                    available.append(artifact_id)
            cumulative[(scenario_id, event["event_id"])] = list(available)

    decision_path = destination / "case_decisions.csv"
    with decision_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fields = list(reader.fieldnames or [])
    for index, row in enumerate(rows):
        key = (row["scenario_id"], row["event_id"])
        expected = state[key]
        start = datetime.fromisoformat(row["event_timestamp"].replace("Z", "+00:00"))
        row.update(
            {
                "review_started_at": _iso(start + timedelta(minutes=index + 1)),
                "decision_recorded_at": _iso(start + timedelta(minutes=index + 6)),
                "recommended_state": expected["expected_state"],
                "authorized_state": expected.get("expected_authorized_state") or "",
                "human_authorization_required": "true",
                "identity_matching_method": "analyst_recorded_match",
                "identity_confidence": "0.8",
                "conflict_identified": (
                    "true" if key == ("ghost_logger", "EVT-GL-010H") else "false"
                ),
                "conflict_ids": "GL-CONFLICT-001" if key == ("ghost_logger", "EVT-GL-010H") else "",
                "clock_safeguard_noted": (
                    "true" if key == ("rapid_pivot", "EVT-RP-018H") else "false"
                ),
                "rationale": "Synthetic completed test fixture based on the frozen oracle.",
                "analyst_confidence": "0.75",
                "completion_status": "COMPLETE",
            }
        )
    with decision_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    observation_path = destination / "evidence_observations.csv"
    with observation_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        observations = list(reader)
        fields = list(reader.fieldnames or [])
    values = {
        "product_id": "test-product",
        "product_version": "1.0",
        "product_purl": "pkg:generic/test-product@1.0",
        "sbom_reference": "data/sbom/test.cdx.json",
        "primary_identifier": "pkg:generic/test-component@1.0",
        "matching_method": "analyst_recorded_match",
        "identity_confidence": "0.8",
        "cve_id": "CVE-TEST-0001",
        "cisa_kev_status": "true",
        "epss_percentile": "0.9",
        "csaf_vex_status": "under_investigation",
        "csaf_reference": "data/csaf/test.json",
        "execution_observed": "false",
        "reachability_confirmed": "true",
        "telemetry_reference": "data/telemetry/test.jsonl",
        "asset_criticality": "high",
        "deployment_scope": "broad",
        "mitigation_status": "planned",
    }
    for row in observations:
        key = (row["scenario_id"], row["event_id"])
        artifact_id = cumulative[key][0]
        source = catalogs[row["scenario_id"]][artifact_id]
        source_path = ROOT / source["path"]
        row.update(
            {
                "value": values[row["proposition"]],
                "source_artifact_id": artifact_id,
                "source_uri": source["path"],
                "source_hash": sha256_file(source_path),
                "source_timestamp": source["timestamp"],
                "confidence": "0.75",
                "observation_status": "OBSERVED",
            }
        )
    with observation_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(observations)

    access_path = destination / "source_access_log.csv"
    with access_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
    access_rows = []
    access_index = 0
    for key, available in cumulative.items():
        scenario_id, event_id = key
        event_time = state[key]["timestamp"]
        for artifact_id in available:
            access_index += 1
            access_rows.append(
                {
                    "access_id": f"ACCESS-{access_index:04d}",
                    "scenario_id": scenario_id,
                    "event_id": event_id,
                    "accessed_at": event_time,
                    "artifact_id": artifact_id,
                    "tool": "json_viewer",
                    "command_or_method": "manual inspection",
                    "purpose": "evidence review",
                    "notes": "synthetic completed test fixture",
                }
            )
    with access_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(access_rows)

    conflict_path = destination / "conflict_log.csv"
    with conflict_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
    conflict_rows = []
    for index, key in enumerate(sorted(state), start=1):
        is_conflict = key == ("ghost_logger", "EVT-GL-010H")
        conflict_rows.append(
            {
                "record_id": f"CONFLICT-RECORD-{index:03d}",
                "scenario_id": key[0],
                "event_id": key[1],
                "conflict_id": "GL-CONFLICT-001" if is_conflict else "",
                "proposition": "product_affectedness" if is_conflict else "none",
                "scope_summary": "overlapping deployment scope" if is_conflict else "none",
                "observation_a": "supplier assertion" if is_conflict else "none",
                "source_a": cumulative[key][0],
                "observation_b": "local execution" if is_conflict else "none",
                "source_b": cumulative[key][-1],
                "classification": "CONFLICT" if is_conflict else "NO_CONFLICT",
                "confidence": "0.8",
                "resolution_status": "ACTIVE" if is_conflict else "NOT_APPLICABLE",
                "notes": "synthetic completed test fixture",
            }
        )
    with conflict_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(conflict_rows)

    timing_path = destination / "timing_log.csv"
    with timing_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        timing_rows = list(reader)
        fields = list(reader.fieldnames or [])
    for index, row in enumerate(timing_rows):
        released = datetime.fromisoformat(row["evidence_released_at"].replace("Z", "+00:00"))
        start = released + timedelta(minutes=index + 1)
        decision = start + timedelta(minutes=5)
        row.update(
            {
                "review_started_at": _iso(start),
                "decision_recorded_at": _iso(decision),
                "elapsed_minutes": "5.0",
                "notes": "synthetic completed test fixture",
            }
        )
    with timing_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(timing_rows)

    declaration_path = destination / "declaration.yaml"
    declaration = yaml.safe_load(declaration_path.read_text(encoding="utf-8"))
    declaration.update(
        {
            "analyst_id_or_pseudonym": "TEST-ANALYST",
            "execution_role": "test_fixture",
            "automated_outputs_seen_before_execution": False,
            "baseline_execution_started_at": "2026-07-24T10:00:00Z",
            "baseline_execution_completed_at": "2026-07-24T12:00:00Z",
            "signed_name_or_pseudonym": "TEST-ANALYST",
        }
    )
    declaration_path.write_text(yaml.safe_dump(declaration, sort_keys=False), encoding="utf-8")
    return destination
