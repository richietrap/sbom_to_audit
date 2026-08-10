import json
from pathlib import Path

import pytest

from sbom_to_audit.evaluation.performance import (
    Workload,
    build_workload_fixture,
    core_decision_fingerprint,
    nearest_rank_percentile,
    registered_workloads,
    summarize_trials,
)
from sbom_to_audit.model.evidence_pack import replay_scenario
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
BASE_SCENARIO = read_yaml(ROOT / "data/scenarios/ghost_logger.yaml")


def test_registered_stage6_4_workloads_are_complete_and_ordered() -> None:
    workloads = registered_workloads(PROTOCOL)
    assert len(workloads) == 20
    assert {workload.axis for workload in workloads} == {
        "sbom_components",
        "telemetry_records",
        "source_artifacts",
        "replay_events",
    }
    assert len({workload.workload_id for workload in workloads}) == 20


def test_nearest_rank_and_trial_statistics_are_explicit() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    assert nearest_rank_percentile(values, 0.95) == 100.0
    summary = summarize_trials(
        [
            {"wall_ms": 1.0, "cpu_ms": 0.5},
            {"wall_ms": 2.0, "cpu_ms": 1.5},
            {"wall_ms": 3.0, "cpu_ms": 2.5},
        ]
    )
    assert summary["median_wall_ms"] == 2.0
    assert summary["p95_wall_ms"] == 3.0
    assert summary["median_cpu_ms"] == 1.5


@pytest.mark.parametrize(
    ("axis", "scale_value"),
    [
        ("sbom_components", 100),
        ("telemetry_records", 10),
        ("source_artifacts", 20),
        ("replay_events", 10),
    ],
)
def test_scale_fixtures_preserve_ghost_logger_decision(
    tmp_path: Path, axis: str, scale_value: int
) -> None:
    canonical = replay_scenario(BASE_SCENARIO, repository_root=ROOT)
    workload = Workload(f"TEST-{axis}", axis, scale_value)
    fixture_root = tmp_path / axis
    scenario = build_workload_fixture(ROOT, fixture_root, BASE_SCENARIO, workload)
    result = replay_scenario(scenario, repository_root=fixture_root)
    assert core_decision_fingerprint(result) == core_decision_fingerprint(canonical)
    metadata = json.loads((fixture_root / "stage6_4_fixture_metadata.json").read_text())
    assert metadata["axis"] == axis
    assert metadata["scale_value"] == scale_value
    assert metadata["input_bytes"] > 0
