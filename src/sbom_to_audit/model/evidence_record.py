"""Typed evidence claims and source artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SourceArtifact:
    artifact_id: str
    artifact_type: str
    source_uri: str
    source_hash: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceClaim:
    claim_id: str
    proposition: str
    value: Any
    source_artifact_id: str
    source_uri: str
    source_hash: str
    timestamp: str
    confidence: float

    def is_traceable(self) -> bool:
        required = (
            self.source_artifact_id,
            self.source_uri,
            self.source_hash,
            self.timestamp,
            self.confidence,
        )
        return all(value is not None and value != "" for value in required)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
