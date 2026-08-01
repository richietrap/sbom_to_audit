import re
from pathlib import Path

from sbom_to_audit import __version__

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.6.1.5"
EXPECTED_STAGE = "Stage 6.1.5"


def test_release_version_markers_are_consistent() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    manifest = (ROOT / "MANIFEST.md").read_text(encoding="utf-8")

    assert __version__ == EXPECTED_VERSION
    assert f'version = "{EXPECTED_VERSION}"' in pyproject
    assert f"version: {EXPECTED_VERSION}" in citation
    assert EXPECTED_STAGE in readme
    assert f"## {EXPECTED_VERSION} — {EXPECTED_STAGE}" in changelog
    assert f"package v{EXPECTED_VERSION}" in manifest


def test_corrective_bugs_are_assigned_to_their_releases() -> None:
    register = (ROOT / "docs/bug_register.csv").read_text(encoding="utf-8")
    assert re.search(r"^BUG-017,2026-07-29,0\.6\.1\.1,", register, re.MULTILINE)
    assert re.search(r"^BUG-018,2026-07-29,0\.6\.1\.2,", register, re.MULTILINE)
    assert re.search(r"^BUG-019,2026-07-29,0\.6\.1\.3,", register, re.MULTILINE)
    assert re.search(r"^BUG-020,2026-07-29,0\.6\.1\.3,", register, re.MULTILINE)
    assert re.search(r"^BUG-021,2026-07-29,0\.6\.1\.4,", register, re.MULTILINE)
    assert re.search(r"^BUG-022,2026-07-30,0\.6\.1\.4,", register, re.MULTILINE)
    assert re.search(r"^BUG-023,2026-07-30,0\.6\.1\.5-pre-release,", register, re.MULTILINE)
    assert re.search(r"^BUG-024,2026-07-30,0\.6\.1\.5-pre-release,", register, re.MULTILINE)
    assert re.search(r"^BUG-025,2026-07-30,0\.6\.1\.5-pre-release,", register, re.MULTILINE)
    assert re.search(r"^BUG-026,2026-07-30,0\.6\.1\.5-pre-release,", register, re.MULTILINE)
