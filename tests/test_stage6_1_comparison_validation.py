import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest
from stage6_1_helpers import build_completed_manual_bundle

from scripts.validate_stage6_1_evaluation import validate

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> None:
    subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def evidence(tmp_path):
    run = tmp_path / "run"
    completed = build_completed_manual_bundle(run / "completed")
    imported = run / "imported"

    _run(
        "scripts/import_manual_baseline_results.py",
        str(completed),
        "--destination",
        str(imported),
    )

    normalized = imported / "normalized" / "stage6_1_manual_baseline_normalized.json"

    comparison = run / "comparison"

    _run(
        "scripts/run_stage6_1_comparison.py",
        str(normalized),
        "--destination",
        str(comparison),
    )

    return {
        "report": (comparison / "comparison" / "stage6_1_comparison_report.json"),
        "scenario_csv": (comparison / "comparison" / "stage6_1_scenario_comparison.csv"),
        "normalized": normalized,
        "conflicts": comparison / "orchestrated" / "conflict_reports",
    }


def test_pristine_comparison_evidence_passes(evidence):
    result = validate(evidence["report"])

    assert result["valid"] is True
    assert result["errors"] == []

    checks = result["checks"]
    assert checks["comparison_integrity_verified"] is True
    assert checks["conflict_quality_verified"] is True

    counts = checks["applicable_primary_counts"]
    assert counts["CD"] == {"orchestrated": 1, "manual": 1}
    assert counts["CA"] == {"orchestrated": 1, "manual": 1}
    assert counts["SC"] == {"orchestrated": 4, "manual": 4}


def test_tampered_report_metric_is_rejected(evidence):
    path = evidence["report"]
    payload = json.loads(path.read_text())

    for row in payload["locked_metrics"]:
        if row["metric"] == "SC":
            row["manual_primary_mean"] = 0.9

    path.write_text(json.dumps(payload, indent=2) + "\n")

    result = validate(path)

    assert result["valid"] is False
    assert "comparison report locked metrics do not match recomputed means" in result["errors"]


def test_tampered_scenario_csv_is_rejected(evidence):
    path = evidence["scenario_csv"]

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fields = list(rows[0])

    for row in rows:
        if row["scenario_id"] == "ghost_logger":
            row["manual_SC"] = "0.9"

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    result = validate(evidence["report"])

    assert result["valid"] is False
    assert "metric summary CSV does not match recomputed means" in result["errors"]
    assert "scenario comparison semantic SHA-256 mismatch" in result["errors"]


def test_tampered_manual_baseline_is_rejected(evidence):
    path = evidence["normalized"]
    payload = json.loads(path.read_text())
    payload["tamper_marker"] = True
    path.write_text(json.dumps(payload, indent=2) + "\n")

    result = validate(evidence["report"])

    assert result["valid"] is False
    assert "normalized manual baseline SHA-256 mismatch" in result["errors"]


def test_tampered_conflict_evidence_is_rejected(evidence):
    path = evidence["conflicts"] / "ghost_logger.json"
    payload = json.loads(path.read_text())
    payload["conflicts"] = []
    path.write_text(json.dumps(payload, indent=2) + "\n")

    result = validate(evidence["report"])

    assert result["valid"] is False
    assert "comparison report conflict quality does not match frozen oracle" in result["errors"]
