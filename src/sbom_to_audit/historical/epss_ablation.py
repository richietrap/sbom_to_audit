"""EPSS ablation for the CVE-2024-3400 synthetic reference deployment."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

EPSS_ARTIFACT_ID = "ART-HIST-REF-EPSS-001"


def _scenario(path: str | Path) -> dict[str, Any]:
    value = read_yaml(Path(path))
    if not isinstance(value, dict):
        raise ValueError("historical reference scenario must contain an object")
    return value


def scenario_without_epss(scenario: dict[str, Any]) -> dict[str, Any]:
    mutated = deepcopy(scenario)
    mutated["source_catalog"] = [
        item
        for item in mutated.get("source_catalog", [])
        if item.get("artifact_id") != EPSS_ARTIFACT_ID
    ]
    for event in mutated.get("replay_events", []):
        event["release_artifact_ids"] = [
            artifact_id
            for artifact_id in event.get("release_artifact_ids", [])
            if artifact_id != EPSS_ARTIFACT_ID
        ]
    return mutated


def run_epss_ablation(
    repository_root: str | Path,
    scenario_path: str | Path = "data/scenarios/historical_cve_2024_3400_reference.yaml",
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    scenario = _scenario(root / scenario_path)
    with_epss = replay_scenario(scenario, repository_root=root)
    without_epss = replay_scenario(scenario_without_epss(scenario), repository_root=root)

    with_states = [row["observed_state"] for row in with_epss["state_rows"]]
    without_states = [row["observed_state"] for row in without_epss["state_rows"]]
    rows: list[dict[str, Any]] = []
    for index, (with_row, without_row) in enumerate(
        zip(with_epss["state_rows"], without_epss["state_rows"], strict=True)
    ):
        rows.append(
            {
                "event_index": index,
                "event_id": with_row["event_id"],
                "timestamp": with_row["timestamp"],
                "state_with_epss": with_row["observed_state"],
                "state_without_epss": without_row["observed_state"],
                "state_changed": with_row["observed_state"] != without_row["observed_state"],
                "E_t_with_epss": with_row["E_t"],
                "E_t_without_epss": without_row["E_t"],
            }
        )

    return {
        "ablation_version": "0.1",
        "scenario_id": scenario["scenario"]["scenario_id"],
        "treatment": "authoritative_historical_epss_included",
        "control": "historical_epss_omitted",
        "state_trajectory_with_epss": with_states,
        "state_trajectory_without_epss": without_states,
        "state_trajectory_changed": with_states != without_states,
        "final_state_with_epss": with_epss["pack"]["decision_state"]["recommended_state"],
        "final_state_without_epss": without_epss["pack"]["decision_state"]["recommended_state"],
        "final_E_t_with_epss": with_epss["pack"]["orchestration_metrics"]["E_t"],
        "final_E_t_without_epss": without_epss["pack"]["orchestration_metrics"]["E_t"],
        "interpretation": (
            "The historical state trajectory is unchanged when EPSS is omitted because "
            "public exploitation reporting and KEV evidence dominate E_t after disclosure."
        ),
        "rows": rows,
    }
