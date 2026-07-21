#!/usr/bin/env python3
"""Generate the public-evidence-only CVE-2024-3400 historical replay."""

from __future__ import annotations

import argparse
from pathlib import Path

from sbom_to_audit.historical.public_replay import run_public_historical_replay
from sbom_to_audit.utils.io import write_csv, write_json

ROOT = Path(__file__).resolve().parents[1]
FIELDS = [
    "event_id",
    "timestamp",
    "event_class",
    "description",
    "new_source_ids",
    "available_source_ids",
    "available_source_count",
    "public_exploitation_known",
    "kev_known",
    "hotfix_known",
    "epss_known",
    "provisional_source_ids",
]


def run(output_root: str | Path) -> dict[str, Path]:
    root = Path(output_root).resolve()
    result = run_public_historical_replay(ROOT)
    bundle = write_json(
        root / "historical_public" / "cve_2024_3400_public_bundle.json", result["bundle"]
    )
    timeline = write_csv(
        root / "historical_public" / "cve_2024_3400_public_timeline.csv",
        result["timeline_rows"],
        FIELDS,
    )
    manifest = write_json(
        root / "historical_public" / "cve_2024_3400_public_sources.json", result["source_manifest"]
    )
    return {"bundle": bundle, "timeline": timeline, "source_manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    paths = run(args.output_root)
    print("Public historical replay completed without generating an EvidencePack:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
