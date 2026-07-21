#!/usr/bin/env python3
"""Verify the historical CVE-2024-3400 EPSS record offline or online."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbom_to_audit.historical.epss_verification import (
    verify_offline_contract,
    verify_online,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data/historical_replays/cve_2024_3400/epss/verification_manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/validation/epss"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    result = (
        verify_online(args.output_dir) if args.online else verify_offline_contract(args.manifest)
    )
    payload = result.to_dict()
    report = args.report
    if report is None and args.online:
        report = args.output_dir / "historical_epss_verification.json"
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
