import csv
import json
from pathlib import Path

from scripts.run_baseline_comparison import run


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_matched_baseline_comparison_is_deterministic_and_fairly_bounded(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    run(first)
    run(second)

    first_files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    second_files = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    assert first_files == second_files
    for relative in first_files:
        assert (first / relative).read_bytes() == (second / relative).read_bytes()

    report = json.loads(
        (first / "comparison" / "stage6_baseline_report.json").read_text(encoding="utf-8")
    )
    assert report["scenario_count"] == 7
    assert report["primary_scenario_count"] == 4
    assert report["control_count"] == 3
    assert report["conflict_precision"]["orchestrated"] == 1.0
    assert report["conflict_precision"]["baseline"] == 0.5
    assert report["manuscript_eligible"] is False
    assert "not a human analyst study" in " ".join(report["limitations"])


def test_stage6_primary_metric_differences_are_reported_without_hiding_ties(tmp_path: Path) -> None:
    run(tmp_path)
    rows = _read_csv(tmp_path / "comparison" / "stage6_metric_summary.csv")
    by_metric = {row["metric"]: row for row in rows}
    assert by_metric["EC"]["orchestrated_primary_mean"] == "1.0"
    assert by_metric["EC"]["baseline_primary_mean"] == "0.764706"
    assert by_metric["TR"]["baseline_primary_mean"] == "0.0"
    assert by_metric["CA"]["baseline_primary_mean"] == "0.0"
    assert by_metric["AR"]["difference"] == "0.0"
    assert by_metric["CD"]["difference"] == "0.0"
    assert by_metric["SC"]["baseline_primary_mean"] == "0.708333"
    assert by_metric["EPG"]["baseline_primary_mean"] == "0.0"


def test_stage6_divergences_are_limited_to_scope_and_clock_mechanisms(tmp_path: Path) -> None:
    run(tmp_path)
    rows = _read_csv(tmp_path / "comparison" / "stage6_decision_divergence.csv")
    assert len(rows) == 5
    assert {row["scenario_id"] for row in rows} == {"false_comfort", "rapid_pivot"}
    assert sum(row["scenario_id"] == "false_comfort" for row in rows) == 4
    assert sum(row["scenario_id"] == "rapid_pivot" for row in rows) == 1
