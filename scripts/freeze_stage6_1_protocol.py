#!/usr/bin/env python3
"""Create or verify the Stage 6.1 pre-execution protocol freeze."""

from __future__ import annotations

import argparse
from pathlib import Path

from sbom_to_audit.baseline.evaluation_freeze import (
    load_freeze_targets,
    verify_freeze,
    write_freeze,
)

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "evaluation" / "freeze" / "stage6_1_freeze_targets.yaml"
DEFAULT_OUTPUT = ROOT / "evaluation" / "freeze" / "stage6_1_protocol_freeze.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Verify the existing freeze record.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.verify:
        errors = verify_freeze(ROOT, args.output)
        if errors:
            print("Stage 6.1 freeze verification failed:")
            for error in errors:
                print(f"- {error}")
            return 1
        print("PASS: Stage 6.1 pre-execution freeze verified")
        return 0
    paths = load_freeze_targets(TARGETS)
    output = write_freeze(ROOT, paths, args.output)
    print(f"Stage 6.1 pre-execution freeze written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
