#!/usr/bin/env python3
"""Fail unless a historical public replay used verified authoritative EPSS evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

EXPECTED_STATUS = "authoritative_dual_source_verified"


def validate_bundle(path: str | Path) -> dict[str, Any]:
    bundle_path = Path(path)
    try:
        value = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load historical replay bundle {bundle_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("historical replay bundle must contain a JSON object")
    if value.get("manuscript_eligibility") is not True:
        raise ValueError("historical replay is not manuscript eligible")
    verification = value.get("historical_epss_verification")
    if not isinstance(verification, dict):
        raise ValueError("historical replay lacks historical_epss_verification")
    if verification.get("status") != EXPECTED_STATUS:
        raise ValueError("historical replay EPSS status is not authoritative_dual_source_verified")
    report_sha = verification.get("online_report_hash")
    if not isinstance(report_sha, str) or len(report_sha) != 64:
        raise ValueError("historical replay lacks a valid online-report SHA-256")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Historical public replay bundle JSON.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    validate_bundle(args.bundle)
    print("PASS: historical replay uses authoritative dual-source EPSS verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
