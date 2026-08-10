from pathlib import Path

from scripts.run_stage6_3_mutation_testing import _classify_test_run


def test_mutation_runner_classifies_surviving_and_killed_tests(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    sample = tests / "test_sample.py"
    sample.write_text(
        "def test_passes():\n    assert True\n\ndef test_fails():\n    assert False\n",
        encoding="utf-8",
    )

    survived, survived_code = _classify_test_run(
        tmp_path,
        ("tests/test_sample.py::test_passes",),
        timeout_seconds=5,
    )
    killed, killed_code = _classify_test_run(
        tmp_path,
        ("tests/test_sample.py::test_fails",),
        timeout_seconds=5,
    )

    assert (survived, survived_code) == ("SURVIVED", 0)
    assert (killed, killed_code) == ("KILLED", 1)
