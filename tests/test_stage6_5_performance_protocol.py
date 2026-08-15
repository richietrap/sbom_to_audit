"""Stage 6.5 protocol controls for raw worker-level memory evidence."""

from pathlib import Path

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml

ROOT = Path(__file__).resolve().parents[1]


def test_performance_v02_preserves_v01_scale_axes() -> None:
    v01 = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
    v02 = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml")
    assert v02["scale_axes"] == v01["scale_axes"]
    assert v02["execution"]["warmup_runs"] == v01["execution"]["warmup_runs"] == 3
    assert v02["execution"]["measured_runs"] == v01["execution"]["measured_runs"] == 10


def test_performance_v02_records_real_memory_granularity() -> None:
    protocol = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml")
    memory = protocol["measurement_scope"]["memory_measurement"]
    assert memory["api"] == "resource.getrusage(resource.RUSAGE_SELF).ru_maxrss"
    assert memory["measured_process"] == "workload_worker"
    assert memory["raw_observation_granularity"] == "one observation per workload worker"
    assert memory["normalized_unit"] == "bytes"


def test_performance_v02_explicitly_uses_sample_cv() -> None:
    protocol = read_yaml(ROOT / "evaluation/stage6_4_performance_protocol_v0.2.yaml")
    assert (
        protocol["statistics"]["wall_cv_definition"]
        == "sample_standard_deviation_n_minus_1_divided_by_arithmetic_mean"
    )


def test_historical_stage6_4_protocol_is_unchanged() -> None:
    assert (
        sha256_file(ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml")
        == "c5001c5ef760ed37d72971970c119848e06f6fec481677e73895c1ab32745035"
    )
