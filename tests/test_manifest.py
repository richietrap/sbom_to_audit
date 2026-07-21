import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.md"
GENERATED_OUTPUT_DIRS = {
    Path("outputs/evidence_packs"),
    Path("outputs/state_logs"),
    Path("outputs/conflict_reports"),
    Path("outputs/metrics"),
    Path("outputs/source_manifests"),
    Path("outputs/audit_ledgers"),
    Path("outputs/validation"),
}
IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".qa-venv",
    "__pycache__",
    "build",
    "dist",
}


def _declared_paths(text: str) -> list[str]:
    table = text.split("## v0.2.1", maxsplit=1)[0]
    return re.findall(r"^\| `([^`]+)` \|", table, flags=re.MULTILINE)


def _repository_files_requiring_manifest_entry() -> set[str]:
    files: set[str] = set()
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(
            part in IGNORED_DIRECTORY_NAMES or part.endswith(".egg-info") for part in relative.parts
        ):
            continue
        if path.suffix == ".pyc" or relative.name.startswith(".coverage"):
            continue
        if (
            any(relative.is_relative_to(directory) for directory in GENERATED_OUTPUT_DIRS)
            and relative.name != ".gitkeep"
        ):
            continue
        files.add(relative.as_posix())
    return files


def test_manifest_declared_files_exist_and_counts_match() -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    declared = set(_declared_paths(text))
    expected_match = re.search(r"\*\*Expected files:\*\* (\d+)", text)
    created_match = re.search(r"\*\*Created files:\*\* (\d+)", text)
    missing_match = re.search(r"\*\*Missing files:\*\* (\d+)", text)
    assert expected_match and created_match and missing_match
    expected = int(expected_match.group(1))
    created = int(created_match.group(1))
    missing = int(missing_match.group(1))
    actual = _repository_files_requiring_manifest_entry()

    assert len(declared) == expected
    assert created == expected
    assert missing == 0
    assert declared == actual
