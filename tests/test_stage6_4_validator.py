import shutil
from pathlib import Path

from scripts.validate_stage6_4_evaluation import validate

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/stage6_4_candidate"


def test_stage6_4_candidate_results_validate() -> None:
    report = validate(RESULTS)
    assert report["valid"] is True
    assert report["errors"] == []
    assert report["checks"]["workload_count"] == 20
    assert report["checks"]["raw_trial_count"] == 200
    assert report["checks"]["all_decision_equivalent"] is True


def test_stage6_4_validator_rejects_tampered_summary(tmp_path: Path) -> None:
    copied = tmp_path / "results"
    shutil.copytree(RESULTS, copied)
    summary = copied / "stage6_4_scale_summary.csv"
    text = summary.read_text(encoding="utf-8")
    summary.write_text(text.replace(",True,", ",False,", 1), encoding="utf-8", newline="\n")
    report = validate(copied)
    assert report["valid"] is False
    assert report["errors"]
