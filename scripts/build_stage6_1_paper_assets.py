#!/usr/bin/env python3
"""Build candidate Stage 6.1 paper tables and a deterministic SVG figure."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import write_json

METRICS = ("EC", "TR", "CD", "CA", "AR", "SC", "EPG")


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _figure(path: Path, rows: list[dict[str, str]]) -> None:
    width, height = 1120, 590
    left, top, plot_height = 90, 100, 360
    group_width, bar_width = 140, 34
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="40" y="42" font-family="sans-serif" font-size="23" font-weight="bold">'
        'Stage 6.1 matched manual-assisted baseline candidate</text>',
        '<text x="1080" y="66" text-anchor="end" font-family="sans-serif" font-size="12">'
        'CANDIDATE — not manuscript-frozen</text>',
    ]
    for tick in range(6):
        value = tick / 5
        y = top + plot_height - value * plot_height
        parts.append(f'<line x1="{left}" y1="{y}" x2="1080" y2="{y}" stroke="#ddd"/>')
        parts.append(
            f'<text x="78" y="{y + 4}" text-anchor="end" font-family="sans-serif" '
            f'font-size="11">{value:.1f}</text>'
        )
    for index, metric in enumerate(METRICS):
        row = next(item for item in rows if item["metric"] == metric)
        x = left + 55 + index * group_width
        for offset, key, fill in (
            (0, "orchestrated_primary_mean", "#315c8a"),
            (bar_width + 9, "manual_primary_mean", "#777777"),
        ):
            value = float(row[key]) if row[key] else 0.0
            bar_height = value * plot_height
            y = top + plot_height - bar_height
            parts.append(
                f'<rect x="{x + offset}" y="{y}" width="{bar_width}" height="{bar_height}" '
                f'fill="{fill}"/>'
            )
        parts.append(
            f'<text x="{x + bar_width}" y="{top + plot_height + 28}" text-anchor="middle" '
            f'font-family="sans-serif" font-size="13">{metric}</text>'
        )
    parts.extend(
        [
            '<rect x="770" y="500" width="16" height="16" fill="#315c8a"/>',
            '<text x="794" y="513" font-family="sans-serif" font-size="12">Orchestrated</text>',
            '<rect x="895" y="500" width="16" height="16" fill="#777777"/>',
            '<text x="919" y="513" font-family="sans-serif" font-size="12">Manual baseline</text>',
            '</svg>',
        ]
    )
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(comparison_root: Path, destination: Path) -> dict[str, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    metric_source = comparison_root / "stage6_1_locked_metric_summary.csv"
    scenario_source = comparison_root / "stage6_1_scenario_comparison.csv"
    report_source = comparison_root / "stage6_1_comparison_report.json"
    rows = _read_csv(metric_source)
    table_metric = destination / "table_stage6_1_locked_metrics.csv"
    table_metric.write_bytes(metric_source.read_bytes())
    table_scenario = destination / "table_stage6_1_scenario_comparison.csv"
    table_scenario.write_bytes(scenario_source.read_bytes())
    figure = destination / "figure_stage6_1_metric_comparison.svg"
    _figure(figure, rows)
    registry: list[dict[str, Any]] = []
    for path in (table_metric, table_scenario, figure):
        registry.append({"path": path.name, "sha256": sha256_file(path)})
    report = json.loads(report_source.read_text(encoding="utf-8"))
    registry_path = write_json(
        destination / "paper_asset_registry.json",
        {
            "status": "CANDIDATE_NOT_FROZEN",
            "comparison_id": report["comparison_id"],
            "assets": registry,
        },
    )
    return {
        "metric_table": table_metric,
        "scenario_table": table_scenario,
        "figure": figure,
        "registry": registry_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("comparison_root", type=Path)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    paths = build(args.comparison_root, args.destination)
    print("Stage 6.1 candidate paper assets generated:")
    for label, path in paths.items():
        print(f"- {label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
