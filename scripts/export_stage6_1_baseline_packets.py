#!/usr/bin/env python3
"""Export blinded event-release packets for the Stage 6.1 manual baseline."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.protocol import load_manual_protocol
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import read_yaml, write_json

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "evaluation" / "baseline_protocol_v0.2.yaml"


def _manifest(scenario_id: str) -> dict[str, Any]:
    path = ROOT / "data" / "baseline_release_packets" / scenario_id / "release_manifest.yaml"
    payload = read_yaml(path)
    if not isinstance(payload, dict):
        raise ValueError(f"release manifest must contain an object: {path}")
    return payload


def export(destination: Path) -> Path:
    protocol = load_manual_protocol(PROTOCOL)
    destination.mkdir(parents=True, exist_ok=True)
    registry: list[dict[str, Any]] = []
    for scenario_id in protocol.scenario_ids:
        manifest = _manifest(scenario_id)
        scenario_root = destination / scenario_id
        for index, release in enumerate(manifest.get("releases") or [], start=1):
            event_id = str(release["event_id"])
            event_root = scenario_root / f"{index:02d}_{event_id}"
            event_root.mkdir(parents=True, exist_ok=True)
            copied: list[dict[str, str]] = []
            for artifact in release.get("release_artifacts") or []:
                source = ROOT / str(artifact["path"])
                if not source.is_file():
                    raise FileNotFoundError(source)
                target = event_root / source.name
                shutil.copy2(source, target)
                copied.append(
                    {
                        "artifact_id": str(artifact["artifact_id"]),
                        "artifact_type": str(artifact["artifact_type"]),
                        "filename": target.name,
                        "source_repository_path": str(artifact["path"]),
                        "sha256": sha256_file(target),
                        "source_timestamp": str(artifact["source_timestamp"]),
                    }
                )
            event_manifest = {
                "scenario_id": scenario_id,
                "event_id": event_id,
                "event_timestamp": release["timestamp"],
                "released_artifacts": copied,
                "cumulative_available_artifact_ids": release["cumulative_available_artifact_ids"],
                "blinding_boundary": (
                    "No expected state, conflict oracle, automated score, or "
                    "generated claim is included."
                ),
            }
            manifest_path = event_root / "event_manifest.json"
            write_json(manifest_path, event_manifest)
            registry.append(
                {
                    "scenario_id": scenario_id,
                    "event_id": event_id,
                    "manifest_path": manifest_path.relative_to(destination).as_posix(),
                    "manifest_sha256": sha256_file(manifest_path),
                }
            )
    registry_path = destination / "packet_registry.json"
    write_json(
        registry_path,
        {
            "protocol_id": protocol.protocol_id,
            "protocol_version": protocol.protocol_version,
            "packets": registry,
        },
    )
    return registry_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    path = export(args.destination)
    print(f"Stage 6.1 baseline packets exported: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
