"""EvidencePack v0.2 construction entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.ingestion.pipeline import replay_real_format_scenario


def _repository_root() -> Path:
    current = Path.cwd().resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "schemas").is_dir():
            return candidate
    raise FileNotFoundError("could not locate repository root")


def replay_scenario(
    scenario: dict[str, Any],
    *,
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Replay a source-catalog scenario and derive the EvidencePack from files."""

    if "source_catalog" not in scenario:
        raise ValueError(
            "Stage 2 scenarios must define source_catalog; normalized claims and source hashes "
            "may not be embedded in the scenario YAML"
        )
    root = Path(repository_root).resolve() if repository_root else _repository_root()
    return replay_real_format_scenario(scenario, repository_root=str(root))
