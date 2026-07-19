"""Typed results produced by source registration and parsing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RegisteredSource:
    """A source artefact verified against the repository filesystem."""

    artifact_id: str
    artifact_type: str
    relative_path: str
    absolute_path: Path
    source_uri: str
    source_hash: str
    timestamp: str
    media_type: str
    parser: str
    validation_status: str
    size_bytes: int
    validation_details: dict[str, Any] = field(default_factory=dict)

    def to_pack_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("absolute_path")
        payload.pop("relative_path")
        return payload

    def to_manifest_dict(self) -> dict[str, Any]:
        payload = self.to_pack_dict()
        payload["relative_path"] = self.relative_path
        return payload


@dataclass(frozen=True)
class ParsedSource:
    """Registered source plus parser-derived normalized content."""

    source: RegisteredSource
    data: dict[str, Any] | list[dict[str, Any]]
