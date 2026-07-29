from pathlib import Path

from scripts.release_check import ReleaseReport, _run


def test_release_check_records_missing_quality_tool_instead_of_crashing(tmp_path: Path) -> None:
    report = ReleaseReport()
    missing = tmp_path / "tool-that-does-not-exist"
    _run(report, "missing tool", [str(missing)])
    assert report.status == "FAIL"
    assert report.checks[-1].returncode == 127
    assert "could not start" in report.errors[-1]
