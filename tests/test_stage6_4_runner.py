import csv
import json
from pathlib import Path

from scripts.run_stage6_4_performance import run

ROOT = Path(__file__).resolve().parents[1]


def test_stage6_4_smoke_runner_records_semantics_and_measurements(tmp_path: Path) -> None:
    outputs = run(tmp_path, profile="smoke")
    report = json.loads(outputs["report"].read_text(encoding="utf-8"))
    assert report["profile"] == "smoke"
    assert report["workload_count"] == 4
    assert report["axis_count"] == 4
    assert report["measured_runs"] == 1
    assert report["all_decision_equivalent"] is True
    assert report["manuscript_eligible"] is False

    with outputs["scale_summary"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 4
    assert all(float(row["median_wall_ms"]) > 0 for row in rows)
    assert all(row["decision_equivalent"] == "True" for row in rows)


def test_stage6_4_protocol_defines_no_latency_acceptance_threshold() -> None:
    text = (ROOT / "evaluation/stage6_4_performance_protocol_v0.1.yaml").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "service-level objective" in lowered
    assert "no absolute latency" in lowered
    assert "pass_latency" not in lowered
    assert "maximum_allowed_latency" not in lowered
