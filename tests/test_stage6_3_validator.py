import json
import shutil
from pathlib import Path

from scripts.validate_stage6_3_evaluation import validate

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation" / "stage6_3_candidate"


def test_stage6_3_candidate_results_validate() -> None:
    report = validate(RESULTS, historical_source_mode=True)
    assert report["valid"] is True
    assert report["errors"] == []
    assert report["checks"]["mutant_count"] == 26
    assert report["checks"]["family_count"] == 7


def test_stage6_3_strict_current_source_validation_detects_stage6_5_drift() -> None:
    report = validate(RESULTS)
    assert report["valid"] is False
    assert any("S63-MT-002" in error for error in report["errors"])


def test_stage6_3_validator_rejects_tampered_summary(tmp_path: Path) -> None:
    copied = tmp_path / "results"
    shutil.copytree(RESULTS, copied)
    summary_path = copied / "stage6_3_mutation_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["manuscript_eligible"] = True
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    report = validate(copied, historical_source_mode=True)
    assert report["valid"] is False
    assert any("manuscript" in error for error in report["errors"])
