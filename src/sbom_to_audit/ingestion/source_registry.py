"""Source registry with path confinement, validation, and computed hashes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sbom_to_audit.ingestion.artifact_validator import validate_and_parse
from sbom_to_audit.ingestion.ingestion_result import ParsedSource, RegisteredSource
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.time import parse_timestamp


class SourceRegistry:
    """Register scenario artefacts without trusting scenario-supplied hashes."""

    def __init__(self, repository_root: str | Path, *, target_cve: str | None = None) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.target_cve = target_cve
        self._sources: dict[str, RegisteredSource] = {}
        self._parsed: dict[str, ParsedSource] = {}

    def register_catalog(self, catalog: list[dict[str, Any]]) -> None:
        for item in catalog:
            self.register(item)

    def register(self, spec: dict[str, Any]) -> RegisteredSource:
        artifact_id = str(spec.get("artifact_id") or "").strip()
        artifact_type = str(spec.get("artifact_type") or "").strip()
        relative_path = str(spec.get("path") or "").strip()
        timestamp = str(spec.get("timestamp") or "").strip()
        if not all((artifact_id, artifact_type, relative_path, timestamp)):
            raise ValueError(
                "source catalog entries require artifact_id, artifact_type, path, and timestamp"
            )
        if artifact_id in self._sources:
            raise ValueError(f"duplicate artifact_id: {artifact_id}")

        candidate = (self.repository_root / relative_path).resolve()
        try:
            candidate.relative_to(self.repository_root)
        except ValueError as exc:
            raise ValueError(f"source path escapes repository root: {relative_path}") from exc
        if not candidate.is_file():
            raise FileNotFoundError(f"source artefact not found: {relative_path}")

        media_type, parser, data, details = validate_and_parse(
            candidate,
            artifact_type,
            target_cve=self.target_cve,
        )
        if artifact_type == "public_exploitation_report":
            assert isinstance(data, dict)
            if parse_timestamp(timestamp) < parse_timestamp(str(data["published_at"])):
                raise ValueError(
                    "public exploitation report catalog timestamp must not precede published_at"
                )
        registered = RegisteredSource(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            relative_path=relative_path,
            absolute_path=candidate,
            source_uri=f"file:{relative_path}",
            source_hash=sha256_file(candidate),
            timestamp=timestamp,
            media_type=media_type,
            parser=parser,
            validation_status="valid",
            size_bytes=candidate.stat().st_size,
            validation_details=details,
        )
        self._sources[artifact_id] = registered
        self._parsed[artifact_id] = ParsedSource(source=registered, data=data)
        return registered

    def source(self, artifact_id: str) -> RegisteredSource:
        try:
            return self._sources[artifact_id]
        except KeyError as exc:
            raise KeyError(f"unknown artifact_id: {artifact_id}") from exc

    def parsed(self, artifact_id: str) -> ParsedSource:
        try:
            return self._parsed[artifact_id]
        except KeyError as exc:
            raise KeyError(f"unknown artifact_id: {artifact_id}") from exc

    def released(self, artifact_ids: set[str]) -> list[RegisteredSource]:
        return [self.source(artifact_id) for artifact_id in sorted(artifact_ids)]

    def manifest(self) -> dict[str, Any]:
        sources = [self._sources[key].to_manifest_dict() for key in sorted(self._sources)]
        return {
            "registry_version": "0.1",
            "source_count": len(sources),
            "sources": sources,
        }
