#!/usr/bin/env python3
"""Verify the historical CVE-2024-3400 EPSS record offline or online."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.historical.epss_verification import (
    HistoricalEpssVerificationError,
    verify_offline_contract,
    verify_online,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data/historical_replays/cve_2024_3400/epss/verification_manifest.json"


def _write_report(report: Path | None, payload: dict[str, Any]) -> None:
    if report is None:
        return
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/validation/epss"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = args.report
    if report is None and args.online:
        report = args.output_dir / "historical_epss_verification.json"

    try:
        result = (
            verify_online(args.output_dir)
            if args.online
            else verify_offline_contract(args.manifest)
        )
        payload = result.to_dict()
        _write_report(report, payload)
        print(json.dumps(payload, indent=2))
        return 0
    except HistoricalEpssVerificationError as exc:
        payload = exc.result.to_dict()
        payload["error"] = str(exc)
        _write_report(report, payload)
        print(json.dumps(payload, indent=2))
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI must preserve a diagnostic report on failure.
        payload = {
            "status": "verification_error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        _write_report(report, payload)
        print(json.dumps(payload, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
