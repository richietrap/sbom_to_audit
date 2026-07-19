#!/usr/bin/env python3
"""Generate pilot Stage 2 paper assets from replay outputs."""

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


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _architecture_svg(path: Path) -> None:
    labels = [
        "Real-format\nsource artefacts",
        "Source registry\n+ hashes",
        "Format-specific\nparsers",
        "Identity +\nnormalized claims",
        "Conflict, scoring\n+ deadline engines",
        "EvidencePack +\naudit outputs",
    ]
    width, height = 1200, 240
    box_w, box_h, gap = 160, 92, 34
    start_x, y = 35, 72
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="35" y="35" font-family="sans-serif" font-size="20" font-weight="bold">Stage 2.0.1 corrective pilot architecture</text>',
        '<text x="1160" y="35" text-anchor="end" font-family="sans-serif" font-size="12">PILOT — not final paper evidence</text>',
    ]
    for index, label in enumerate(labels):
        x = start_x + index * (box_w + gap)
        parts.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="8" fill="#f2f2f2" stroke="#222" stroke-width="1.5"/>'
        )
        lines = label.split("\n")
        for line_index, line in enumerate(lines):
            parts.append(
                f'<text x="{x + box_w / 2}" y="{y + 38 + 22 * line_index}" text-anchor="middle" font-family="sans-serif" font-size="14">{html.escape(line)}</text>'
            )
        if index < len(labels) - 1:
            x1 = x + box_w
            x2 = x + box_w + gap - 8
            mid = y + box_h / 2
            parts.append(
                f'<line x1="{x1}" y1="{mid}" x2="{x2}" y2="{mid}" stroke="#222" stroke-width="2"/>'
            )
            parts.append(
                f'<polygon points="{x2},{mid} {x2 - 10},{mid - 6} {x2 - 10},{mid + 6}" fill="#222"/>'
            )
    parts.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def _trajectory_svg(path: Path, rows: list[dict[str, str]]) -> None:
    width, height = 1100, 520
    left, right, top, bottom = 90, 40, 80, 100
    plot_w, plot_h = width - left - right, height - top - bottom
    max_t = max(float(row["delta_t_hours"]) for row in rows)
    series = [("E_t", "#111"), ("A_t", "#555"), ("I_t", "#888"), ("U_t", "#bbb")]

    def x(value: float) -> float:
        return left + plot_w * value / max_t

    def y(value: float) -> float:
        return top + plot_h * (1 - value)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="90" y="35" font-family="sans-serif" font-size="20" font-weight="bold">Ghost-Logger temporal trajectory</text>',
        '<text x="1060" y="35" text-anchor="end" font-family="sans-serif" font-size="12">PILOT — derived from GL-STAGE2-0-1-PILOT-001</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#222"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#222"/>',
    ]
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        yy = y(tick)
        parts.append(
            f'<line x1="{left - 5}" y1="{yy}" x2="{left + plot_w}" y2="{yy}" stroke="#ddd"/>'
        )
        parts.append(
            f'<text x="{left - 12}" y="{yy + 4}" text-anchor="end" font-family="sans-serif" font-size="11">{tick:.2f}</text>'
        )
    for key, colour in series:
        points = " ".join(
            f"{x(float(row['delta_t_hours'])):.1f},{y(float(row[key])):.1f}" for row in rows
        )
        parts.append(
            f'<polyline points="{points}" fill="none" stroke="{colour}" stroke-width="2.5"/>'
        )
        for row in rows:
            parts.append(
                f'<circle cx="{x(float(row["delta_t_hours"])):.1f}" cy="{y(float(row[key])):.1f}" r="4" fill="{colour}"/>'
            )
    for row in rows:
        xx = x(float(row["delta_t_hours"]))
        parts.append(
            f'<line x1="{xx}" y1="{top + plot_h}" x2="{xx}" y2="{top + plot_h + 8}" stroke="#222"/>'
        )
        parts.append(
            f'<text x="{xx}" y="{top + plot_h + 24}" text-anchor="middle" font-family="sans-serif" font-size="11">T+{float(row["delta_t_hours"]):g}h</text>'
        )
        parts.append(
            f'<text x="{xx}" y="{top + plot_h + 44}" text-anchor="middle" font-family="sans-serif" font-size="10">{html.escape(row["observed_state"])}</text>'
        )
        if row["C_t"].lower() == "true":
            parts.append(
                f'<text x="{xx}" y="{top + 14}" text-anchor="middle" font-family="sans-serif" font-size="11" font-weight="bold">conflict</text>'
            )
    legend_x = left
    for index, (key, colour) in enumerate(series):
        lx = legend_x + index * 100
        parts.append(
            f'<line x1="{lx}" y1="{height - 30}" x2="{lx + 22}" y2="{height - 30}" stroke="{colour}" stroke-width="3"/>'
        )
        parts.append(
            f'<text x="{lx + 28}" y="{height - 26}" font-family="sans-serif" font-size="12">{key}</text>'
        )
    parts.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    source_manifest = json.loads(
        (output_root / "source_manifests" / "ghost_logger_sources.json").read_text(encoding="utf-8")
    )
    state_rows = _read_csv(output_root / "state_logs" / "ghost_logger.csv")
    metrics = json.loads(
        (output_root / "metrics" / "ghost_logger_metrics.json").read_text(encoding="utf-8")
    )
    conflict_report = json.loads(
        (output_root / "conflict_reports" / "ghost_logger.json").read_text(encoding="utf-8")
    )

    source_table = destination / "tables" / "ghost_logger_source_inventory.csv"
    source_rows = [
        {
            "artifact_id": item["artifact_id"],
            "artifact_type": item["artifact_type"],
            "relative_path": item["relative_path"],
            "parser": item["parser"],
            "validation_status": item["validation_status"],
            "size_bytes": item["size_bytes"],
            "source_hash": item["source_hash"],
        }
        for item in source_manifest["sources"]
    ]
    _write_csv(
        source_table,
        source_rows,
        [
            "artifact_id",
            "artifact_type",
            "relative_path",
            "parser",
            "validation_status",
            "size_bytes",
            "source_hash",
        ],
    )

    event_table = destination / "tables" / "ghost_logger_event_replay.csv"
    event_fields = [
        "event_id",
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
        "state_match",
        "authorization_match",
        "deadline_match",
    ]
    _write_csv(
        event_table, [{key: row[key] for key in event_fields} for row in state_rows], event_fields
    )

    conflict_table = destination / "tables" / "ghost_logger_conflict_lifecycle.csv"
    conflict_fields = [
        "conflict_id",
        "proposition",
        "status",
        "detected_at_event_id",
        "detected_at",
        "resolved_at_event_id",
        "resolved_at",
        "claim_ids",
        "sources",
        "resolution_artifact_ids",
        "resolution_event_ids",
        "resolution_rationale",
    ]
    conflict_rows = []
    for conflict in conflict_report["conflicts"]:
        conflict_rows.append(
            {
                **{key: conflict.get(key) for key in conflict_fields},
                "claim_ids": json.dumps(conflict.get("claim_ids") or []),
                "sources": json.dumps(conflict.get("sources") or []),
                "resolution_artifact_ids": json.dumps(
                    conflict.get("resolution_artifact_ids") or []
                ),
                "resolution_event_ids": json.dumps(conflict.get("resolution_event_ids") or []),
            }
        )
    _write_csv(conflict_table, conflict_rows, conflict_fields)

    architecture = destination / "figures" / "prototype_architecture.svg"
    trajectory = destination / "figures" / "ghost_logger_trajectory.svg"
    _architecture_svg(architecture)
    _trajectory_svg(trajectory, state_rows)

    generated_paths = (architecture, trajectory, source_table, event_table, conflict_table)
    source_paths = (
        output_root / "state_logs" / "ghost_logger.csv",
        output_root / "metrics" / "ghost_logger_metrics.json",
        output_root / "source_manifests" / "ghost_logger_sources.json",
        output_root / "conflict_reports" / "ghost_logger.json",
    )
    script_path = Path(__file__).resolve()
    metadata = {
        "asset_status": "PILOT",
        "manuscript_eligible": False,
        "source_run_id": "GL-STAGE2-0-1-PILOT-001",
        "scenario_id": "ghost_logger",
        "source_manifest_hash": metrics["supplemental"]["source_manifest_hash"],
        "generation_script": script_path.relative_to(script_path.parents[2]).as_posix(),
        "generation_script_hash": _sha256(script_path),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in source_paths
        },
        "metrics": metrics,
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated_paths
        },
    }
    metadata_path = destination / "data" / "stage2_ghost_logger_asset_manifest.json"
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        "metadata": str(metadata_path),
        **{
            path.stem: str(path)
            for path in (architecture, trajectory, source_table, event_table, conflict_table)
        },
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
