#!/usr/bin/env python3
"""Generate Stage 5.5 pilot assets for the CVE-2024-3400 historical replay."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _timeline_svg(path: Path, rows: list[dict[str, str]], manuscript_eligible: bool) -> None:
    width, height = 1220, 520
    left, right = 80, 1140
    count = len(rows)
    step = (right - left) / max(count - 1, 1)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="45" y="38" font-family="sans-serif" font-size="23" font-weight="bold">CVE-2024-3400: occurrence versus public availability</text>',
        (
            '<text x="1170" y="62" text-anchor="end" font-family="sans-serif" font-size="12">'
            + (
                "PILOT — authoritative EPSS verified; evaluation not yet frozen"
                if manuscript_eligible
                else "PILOT — online EPSS verification gate still required"
            )
            + "</text>"
        ),
        '<line x1="80" y1="245" x2="1140" y2="245" stroke="#222" stroke-width="2"/>',
    ]
    for index, row in enumerate(rows):
        x = left + index * step
        is_public = int(row["available_source_count"]) > 0
        y = 245
        parts.append(f'<circle cx="{x:.1f}" cy="{y}" r="8" fill="white" stroke="#111"/>')
        date = html.escape(row["timestamp"][:10])
        event_class = html.escape(row["event_class"].replace("_", " "))
        anchor_y = 155 if index % 2 == 0 else 335
        line_end = anchor_y + 15 if anchor_y < y else anchor_y - 20
        parts.append(f'<line x1="{x:.1f}" y1="{y}" x2="{x:.1f}" y2="{line_end}" stroke="#777"/>')
        parts.append(
            f'<text x="{x:.1f}" y="{anchor_y}" text-anchor="middle" font-family="sans-serif" font-size="12" font-weight="bold">{date}</text>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{anchor_y + 18}" text-anchor="middle" font-family="sans-serif" font-size="10">{event_class}</text>'
        )
        label = (
            "public sources: " + row["available_source_count"] if is_public else "not public yet"
        )
        parts.append(
            f'<text x="{x:.1f}" y="{anchor_y + 34}" text-anchor="middle" font-family="sans-serif" font-size="10">{html.escape(label)}</text>'
        )
    parts.extend(
        [
            '<text x="610" y="470" text-anchor="middle" font-family="sans-serif" font-size="12">Retrospective occurrence dates are preserved but do not release evidence before publication.</text>',
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    public_dir = output_root / "historical_public"
    timeline_path = public_dir / "cve_2024_3400_public_timeline.csv"
    bundle_path = public_dir / "cve_2024_3400_public_bundle.json"
    reference_state_path = output_root / "state_logs" / "historical_cve_2024_3400_reference.csv"
    rows = _read_csv(timeline_path)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    reference_rows = _read_csv(reference_state_path)

    chronology_out = destination / "tables" / "cve_2024_3400_public_chronology.csv"
    chronology_fields = [
        "event_id",
        "timestamp",
        "event_class",
        "new_source_ids",
        "available_source_count",
        "public_exploitation_known",
        "kev_known",
        "hotfix_known",
        "epss_known",
        "provisional_source_ids",
    ]
    _write_csv(
        chronology_out,
        [{field: row[field] for field in chronology_fields} for row in rows],
        chronology_fields,
    )

    boundaries = bundle["evidence_boundaries"]
    boundary_rows = [
        {
            "evidence_dimension": key,
            "public_only_value": value,
            "reference_deployment_addition": (
                "synthetic only"
                if key
                in {
                    "organisation_local_reachability",
                    "organisation_local_execution",
                    "organisation_local_impact",
                    "organisation_local_mitigation",
                    "human_authorization",
                    "submission_evidence",
                }
                else "not changed"
            ),
        }
        for key, value in boundaries.items()
        if key != "reason"
    ]
    boundary_out = destination / "tables" / "historical_evidence_boundary.csv"
    _write_csv(
        boundary_out,
        boundary_rows,
        ["evidence_dimension", "public_only_value", "reference_deployment_addition"],
    )

    reference_fields = [
        "event_id",
        "timestamp",
        "delta_t_hours",
        "E_t",
        "A_t",
        "I_t",
        "M_t",
        "U_t",
        "C_t",
        "observed_state",
        "authorized_state",
        "deadline_posture",
    ]
    reference_out = destination / "tables" / "historical_reference_event_replay.csv"
    _write_csv(
        reference_out,
        [{field: row[field] for field in reference_fields} for row in reference_rows],
        reference_fields,
    )

    figure_out = destination / "figures" / "cve_2024_3400_public_timeline.svg"
    _timeline_svg(figure_out, rows, bool(bundle["manuscript_eligibility"]))

    generated = (chronology_out, boundary_out, reference_out, figure_out)
    sources = (timeline_path, bundle_path, reference_state_path)
    metadata = {
        "asset_status": (
            "PILOT_VERIFIED_NOT_FROZEN"
            if bundle["manuscript_eligibility"]
            else "PILOT_VERIFICATION_CANDIDATE"
        ),
        "manuscript_eligible": bool(bundle["manuscript_eligibility"]),
        "eligibility_blockers": bundle["eligibility_blockers"],
        "source_run_ids": [
            "HIST-CVE-2024-3400-PUBLIC-PILOT-001",
            "HIST-CVE-2024-3400-REF-PILOT-001",
        ],
        "generation_script": "paper_assets/scripts/build_stage55_assets.py",
        "generation_script_hash": _sha256(Path(__file__).resolve()),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in sources
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
    }
    manifest = destination / "data" / "stage55_asset_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        path.relative_to(destination).as_posix(): _sha256(path) for path in (*generated, manifest)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output_root.resolve(), args.destination.resolve()), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
