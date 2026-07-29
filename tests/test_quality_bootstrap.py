from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_quality_bootstrap_installs_declared_dev_extra_and_checks_tools() -> None:
    source = (ROOT / "scripts" / "bootstrap_quality_env.py").read_text(encoding="utf-8")
    assert '"-e", ".[dev]"' in source
    for tool in ("ruff", "mypy", "codespell", "yamllint", "hypothesis"):
        assert f'"{tool}"' in source
    assert "TOOLCHAIN_NOT_PROVISIONED" in source
