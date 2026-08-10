"""Controlled performance and scale helpers for Stage 6.4 evaluation."""

from __future__ import annotations

import json
import math
import os
import platform
import random
import shutil
import statistics
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.hashing import sha256_file, sha256_json
from sbom_to_audit.utils.io import read_json, write_json

AXES = ("sbom_components", "telemetry_records", "source_artifacts", "replay_events")


@dataclass(frozen=True)
class Workload:
    """One registered scale workload."""

    workload_id: str
    axis: str
    scale_value: int


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    """Return a deterministic nearest-rank percentile for non-empty observations."""

    if not values:
        raise ValueError("percentile requires at least one observation")
    if not 0 < percentile <= 1:
        raise ValueError("percentile must be in (0, 1]")
    ordered = sorted(float(value) for value in values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def summarize_trials(rows: list[dict[str, Any]]) -> dict[str, float]:
    """Summarize measured worker trials without imposing a performance threshold."""

    if not rows:
        raise ValueError("at least one measured trial is required")
    wall = [float(row["wall_ms"]) for row in rows]
    cpu = [float(row["cpu_ms"]) for row in rows]
    mean_wall = statistics.fmean(wall)
    stdev_wall = statistics.stdev(wall) if len(wall) > 1 else 0.0
    return {
        "median_wall_ms": round(statistics.median(wall), 6),
        "p95_wall_ms": round(nearest_rank_percentile(wall, 0.95), 6),
        "mean_wall_ms": round(mean_wall, 6),
        "wall_cv": round(stdev_wall / mean_wall, 6) if mean_wall else 0.0,
        "median_cpu_ms": round(statistics.median(cpu), 6),
        "p95_cpu_ms": round(nearest_rank_percentile(cpu, 0.95), 6),
    }


def registered_workloads(protocol: dict[str, Any]) -> list[Workload]:
    """Build and validate the ordered workload registry from the protocol."""

    axes = protocol.get("scale_axes") or {}
    workloads: list[Workload] = []
    for axis in AXES:
        values = axes.get(axis)
        if not isinstance(values, list) or not values:
            raise ValueError(f"missing scale axis: {axis}")
        normalized = [int(value) for value in values]
        if normalized != sorted(set(normalized)):
            raise ValueError(f"scale values must be unique ascending integers: {axis}")
        if any(value <= 0 for value in normalized):
            raise ValueError(f"scale values must be positive: {axis}")
        for value in normalized:
            workloads.append(
                Workload(
                    workload_id=f"S64-{axis.upper().replace('_', '-')}-{value:05d}",
                    axis=axis,
                    scale_value=value,
                )
            )
    return workloads


def execution_order(workloads: list[Workload], seed: int) -> list[Workload]:
    """Return a reproducibly shuffled execution order to reduce monotonic order bias."""

    ordered = list(workloads)
    random.Random(seed).shuffle(ordered)
    return ordered


def _copy_catalog_sources(
    base_root: Path, destination_root: Path, scenario: dict[str, Any]
) -> None:
    for item in scenario.get("source_catalog") or []:
        relative = Path(str(item["path"]))
        source = base_root / relative
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _scale_sbom(path: Path, component_count: int) -> None:
    document = read_json(path)
    if not isinstance(document, dict):
        raise ValueError("scale fixture SBOM must be a JSON object")
    components = list(document.get("components") or [])
    if len(components) < 2:
        raise ValueError("scale fixture requires the two canonical Ghost Logger components")
    logger = deepcopy(components[0])
    target = deepcopy(components[1])
    if component_count < 2:
        raise ValueError("SBOM component scale must be at least two")
    decoy_count = component_count - 2
    decoys: list[dict[str, Any]] = []
    decoy_refs: list[str] = []
    dependencies: list[dict[str, Any]] = []
    for index in range(decoy_count):
        ref = f"pkg:generic/stage64-decoy-{index:06d}@1.0.0"
        decoys.append(
            {
                "type": "library",
                "bom-ref": ref,
                "group": "stage64.synthetic",
                "name": f"stage64-decoy-{index:06d}",
                "version": "1.0.0",
                "purl": ref,
            }
        )
        decoy_refs.append(ref)
        dependencies.append({"ref": ref, "dependsOn": []})
    root_ref = str((document.get("metadata") or {}).get("component", {}).get("bom-ref") or "")
    logger_ref = str(logger.get("bom-ref") or "")
    target_ref = str(target.get("bom-ref") or "")
    document["components"] = [logger, *decoys, target]
    document["dependencies"] = [
        {"ref": root_ref, "dependsOn": [logger_ref, *decoy_refs]},
        {"ref": logger_ref, "dependsOn": [target_ref]},
        *dependencies,
        {"ref": target_ref, "dependsOn": []},
    ]
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def _scale_initial_telemetry(path: Path, record_count: int) -> None:
    original = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    if record_count < 1:
        raise ValueError("telemetry record scale must be positive")
    rows = [original]
    for index in range(1, record_count):
        rows.append(
            {
                **original,
                "event_id": f"TEL-S64-DECOY-{index:06d}",
                "deployment_id": f"stage64-decoy-{index:06d}",
                "execution_observed": False,
                "reachability_confirmed": False,
                "malicious_exploitation_observed": False,
                "observation_type": "stage64_non_target_scale_observation",
            }
        )
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )


def _add_source_artifacts(root: Path, scenario: dict[str, Any], total_sources: int) -> None:
    catalog = list(scenario.get("source_catalog") or [])
    base_count = len(catalog)
    if total_sources < base_count:
        raise ValueError(f"source_artifacts scale cannot be less than base count {base_count}")
    first_event = scenario["replay_events"][0]
    for index in range(total_sources - base_count):
        artifact_id = f"ART-S64-DECOY-{index:06d}"
        relative = Path("data/telemetry") / f"stage64_source_decoy_{index:06d}.jsonl"
        record = {
            "event_id": f"TEL-S64-SOURCE-{index:06d}",
            "timestamp": "2026-09-12T08:20:00Z",
            "deployment_id": f"stage64-source-decoy-{index:06d}",
            "component_purl": scenario["target"]["component_purl"],
            "execution_observed": False,
            "reachability_confirmed": False,
            "malicious_exploitation_observed": False,
            "observation_type": "stage64_non_target_source_scale_observation",
        }
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        catalog.append(
            {
                "artifact_id": artifact_id,
                "artifact_type": "runtime_telemetry",
                "path": relative.as_posix(),
                "timestamp": "2026-09-12T08:20:00Z",
            }
        )
        first_event["release_artifact_ids"].append(artifact_id)
    scenario["source_catalog"] = catalog


def _scale_replay_events(scenario: dict[str, Any], event_count: int) -> None:
    events = list(scenario.get("replay_events") or [])
    if event_count < len(events):
        raise ValueError(f"replay_events scale cannot be less than base count {len(events)}")
    final_timestamp = datetime.fromisoformat(
        str(events[-1]["timestamp"]).replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    for index in range(event_count - len(events)):
        timestamp = (
            (final_timestamp + timedelta(hours=index + 1)).isoformat().replace("+00:00", "Z")
        )
        events.append(
            {
                "event_id": f"EVT-S64-NOOP-{index:06d}",
                "timestamp": timestamp,
                "description": "Stage 6.4 no-op temporal scale event after satisfied milestones.",
                "release_artifact_ids": [],
                "expected_state": "Report-Ready",
                "expected_authorized_state": "Report",
                "expected_deadline_posture": {
                    "early_warning": "Satisfied",
                    "full_notification": "Satisfied",
                },
            }
        )
    scenario["replay_events"] = events


def build_workload_fixture(
    base_root: Path,
    destination_root: Path,
    base_scenario: dict[str, Any],
    workload: Workload,
) -> dict[str, Any]:
    """Create one deterministic isolated scale fixture from Ghost Logger."""

    root = destination_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    scenario = deepcopy(base_scenario)
    _copy_catalog_sources(base_root.resolve(), root, scenario)

    if workload.axis == "sbom_components":
        sbom_items = [
            item
            for item in scenario["source_catalog"]
            if item.get("artifact_type") == "cyclonedx_sbom"
        ]
        if len(sbom_items) != 1:
            raise ValueError("performance fixture requires exactly one CycloneDX SBOM")
        _scale_sbom(root / str(sbom_items[0]["path"]), workload.scale_value)
    elif workload.axis == "telemetry_records":
        first_release_ids = set(scenario["replay_events"][0]["release_artifact_ids"])
        telemetry_items = [
            item
            for item in scenario["source_catalog"]
            if item.get("artifact_type") == "runtime_telemetry"
            and item.get("artifact_id") in first_release_ids
        ]
        if len(telemetry_items) != 1:
            raise ValueError(
                "performance fixture requires exactly one initially released telemetry source"
            )
        _scale_initial_telemetry(root / str(telemetry_items[0]["path"]), workload.scale_value)
    elif workload.axis == "source_artifacts":
        _add_source_artifacts(root, scenario, workload.scale_value)
    elif workload.axis == "replay_events":
        _scale_replay_events(scenario, workload.scale_value)
    else:
        raise ValueError(f"unsupported performance scale axis: {workload.axis}")

    metadata: dict[str, Any] = {
        "workload_id": workload.workload_id,
        "axis": workload.axis,
        "scale_value": workload.scale_value,
        "source_artifact_count": len(scenario["source_catalog"]),
        "replay_event_count": len(scenario["replay_events"]),
        "fixture_files": {},
    }
    for item in scenario["source_catalog"]:
        relative = str(item["path"])
        path = root / relative
        metadata["fixture_files"][relative] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    metadata["input_bytes"] = sum(
        int(item["size_bytes"]) for item in metadata["fixture_files"].values()
    )
    metadata["scenario_sha256"] = sha256_json(scenario)
    write_json(root / "stage6_4_fixture_metadata.json", metadata)
    return scenario


def core_decision_fingerprint(result: dict[str, Any]) -> dict[str, Any]:
    """Return decision-relevant outputs that scale-only fixtures must preserve."""

    pack = result["pack"]
    return {
        "recommended_state": pack["decision_state"]["recommended_state"],
        "authorized_state": pack["decision_state"].get("authorized_state"),
        "scores": pack["orchestration_metrics"],
        "original_event_states": [
            {
                "event_id": row["event_id"],
                "observed_state": row["observed_state"],
                "authorized_state": row["authorized_state"],
                "state_match": row["state_match"],
                "authorization_match": row["authorization_match"],
            }
            for row in result["state_rows"]
            if not str(row["event_id"]).startswith("EVT-S64-NOOP-")
        ],
    }


def environment_metadata() -> dict[str, Any]:
    """Capture benchmark environment metadata without claiming hardware equivalence."""

    memory_bytes: int | None = None
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        physical_pages = os.sysconf("SC_PHYS_PAGES")
        memory_bytes = int(page_size) * int(physical_pages)
    except (AttributeError, OSError, ValueError):
        pass
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "physical_memory_bytes": memory_bytes,
    }
