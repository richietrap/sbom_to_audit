#!/usr/bin/env python3
"""Build candidate paper assets from one observed Stage 6.4 performance run."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import Any

from sbom_to_audit.evaluation.performance import AXES
from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import write_json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / "evaluation/stage6_4_candidate"
DEFAULT_DESTINATION = ROOT / "paper_assets"


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _axis_endpoint_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for axis in AXES:
        axis_rows = sorted(
            (row for row in rows if row["axis"] == axis),
            key=lambda row: int(row["scale_value"]),
        )
        if not axis_rows:
            raise ValueError(f"Stage 6.4 summary has no rows for axis {axis}")
        first = axis_rows[0]
        last = axis_rows[-1]
        output.append(
            {
                "axis": axis,
                "minimum_scale": first["scale_value"],
                "minimum_median_wall_ms": first["median_wall_ms"],
                "maximum_scale": last["scale_value"],
                "maximum_median_wall_ms": last["median_wall_ms"],
                "maximum_p95_wall_ms": last["p95_wall_ms"],
                "maximum_peak_rss_mib": round(int(last["peak_rss_bytes"]) / (1024 * 1024), 3),
                "maximum_input_mib": round(int(last["input_bytes"]) / (1024 * 1024), 3),
                "slowdown_vs_axis_minimum": last["slowdown_vs_axis_minimum"],
                "decision_equivalent": last["decision_equivalent"],
            }
        )
    return output


def _write_scaling_figure(path: Path, rows: list[dict[str, str]]) -> None:
    width = 1000
    height = 650
    margin_x = 80
    margin_y = 75
    gap_x = 55
    gap_y = 70
    panel_width = (width - 2 * margin_x - gap_x) / 2
    panel_height = (height - 2 * margin_y - gap_y) / 2
    positions = {
        "sbom_components": (margin_x, margin_y),
        "telemetry_records": (margin_x + panel_width + gap_x, margin_y),
        "source_artifacts": (margin_x, margin_y + panel_height + gap_y),
        "replay_events": (margin_x + panel_width + gap_x, margin_y + panel_height + gap_y),
    }
    labels = {
        "sbom_components": "SBOM components",
        "telemetry_records": "Telemetry records",
        "source_artifacts": "Source artefacts",
        "replay_events": "Replay events",
    }
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="500" y="34" text-anchor="middle" font-family="sans-serif" '
        'font-size="20">Stage 6.4 observed latency across registered scale axes</text>',
        '<text x="500" y="54" text-anchor="middle" font-family="sans-serif" '
        'font-size="11">Candidate environment-specific measurements; median and p95 '
        "wall time</text>",
    ]
    for axis in AXES:
        axis_rows = sorted(
            (row for row in rows if row["axis"] == axis),
            key=lambda row: int(row["scale_value"]),
        )
        x0, y0 = positions[axis]
        plot_left = x0 + 48
        plot_top = y0 + 28
        plot_width = panel_width - 62
        plot_height = panel_height - 58
        max_y = max(float(row["p95_wall_ms"]) for row in axis_rows)
        max_y = max(max_y, 1.0)
        elements.extend(
            [
                f'<text x="{x0 + panel_width / 2:.1f}" y="{y0 + 14:.1f}" text-anchor="middle" '
                f'font-family="sans-serif" font-size="13">{labels[axis]}</text>',
                f'<line x1="{plot_left:.1f}" y1="{plot_top:.1f}" x2="{plot_left:.1f}" '
                f'y2="{plot_top + plot_height:.1f}" stroke="#222" stroke-width="1"/>',
                f'<line x1="{plot_left:.1f}" y1="{plot_top + plot_height:.1f}" '
                f'x2="{plot_left + plot_width:.1f}" y2="{plot_top + plot_height:.1f}" '
                'stroke="#222" stroke-width="1"/>',
            ]
        )
        for tick in range(5):
            value = max_y * tick / 4
            y = plot_top + plot_height - plot_height * tick / 4
            elements.append(
                f'<line x1="{plot_left:.1f}" y1="{y:.1f}" x2="{plot_left + plot_width:.1f}" '
                f'y2="{y:.1f}" stroke="#dedede" stroke-width="0.8"/>'
            )
            elements.append(
                f'<text x="{plot_left - 7:.1f}" y="{y + 4:.1f}" text-anchor="end" '
                f'font-family="sans-serif" font-size="9">{value:.1f}</text>'
            )
        median_points: list[str] = []
        p95_points: list[str] = []
        count = len(axis_rows)
        for index, row in enumerate(axis_rows):
            x = plot_left + (plot_width * index / max(1, count - 1))
            median = float(row["median_wall_ms"])
            p95 = float(row["p95_wall_ms"])
            median_y = plot_top + plot_height - (median / max_y) * plot_height
            p95_y = plot_top + plot_height - (p95 / max_y) * plot_height
            median_points.append(f"{x:.1f},{median_y:.1f}")
            p95_points.append(f"{x:.1f},{p95_y:.1f}")
            elements.extend(
                [
                    f'<circle cx="{x:.1f}" cy="{median_y:.1f}" r="2.8" fill="#222"/>',
                    f'<circle cx="{x:.1f}" cy="{p95_y:.1f}" r="2.5" fill="white" '
                    'stroke="#666" stroke-width="1.2"/>',
                    f'<text x="{x:.1f}" y="{plot_top + plot_height + 14:.1f}" text-anchor="middle" '
                    f'font-family="sans-serif" font-size="8">{row["scale_value"]}</text>',
                ]
            )
        elements.append(
            f'<polyline points="{" ".join(median_points)}" fill="none" stroke="#222" '
            'stroke-width="1.8"/>'
        )
        elements.append(
            f'<polyline points="{" ".join(p95_points)}" fill="none" stroke="#666" '
            'stroke-width="1.4" stroke-dasharray="5,4"/>'
        )
    elements.extend(
        [
            '<line x1="365" y1="627" x2="389" y2="627" stroke="#222" stroke-width="1.8"/>',
            '<text x="396" y="631" font-family="sans-serif" font-size="10">Median wall time</text>',
            '<line x1="515" y1="627" x2="539" y2="627" stroke="#666" stroke-width="1.4" '
            'stroke-dasharray="5,4"/>',
            '<text x="546" y="631" font-family="sans-serif" font-size="10">p95 wall time</text>',
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(elements) + "\n", encoding="utf-8", newline="\n")


def build(results: Path, destination: Path) -> dict[str, Path]:
    report_path = results / "stage6_4_performance_report.json"
    summary_path = results / "stage6_4_scale_summary.csv"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("profile") != "full":
        raise ValueError("paper assets require a full Stage 6.4 performance run")
    if report.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        raise ValueError("Stage 6.4 paper assets require candidate-only results")
    if report.get("manuscript_eligible") is not False:
        raise ValueError("Stage 6.4 results must not be manuscript-eligible")
    rows = _read_csv(summary_path)

    tables = destination / "tables"
    figures = destination / "figures"
    data = destination / "data"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    detailed_output = tables / "stage6_4_scale_summary.csv"
    endpoint_output = tables / "stage6_4_axis_endpoints.csv"
    figure_output = figures / "stage6_4_latency_scaling.svg"
    shutil.copy2(summary_path, detailed_output)
    endpoint_rows = _axis_endpoint_rows(rows)
    _write_csv(
        endpoint_output,
        [
            "axis",
            "minimum_scale",
            "minimum_median_wall_ms",
            "maximum_scale",
            "maximum_median_wall_ms",
            "maximum_p95_wall_ms",
            "maximum_peak_rss_mib",
            "maximum_input_mib",
            "slowdown_vs_axis_minimum",
            "decision_equivalent",
        ],
        endpoint_rows,
    )
    _write_scaling_figure(figure_output, rows)

    generated = [detailed_output, endpoint_output, figure_output]
    manifest = {
        "run_id": report["run_id"],
        "asset_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "source_environment": report["environment"],
        "source_commit": report["source_commit"],
        "source_results": {
            report_path.relative_to(ROOT).as_posix()
            if report_path.is_relative_to(ROOT)
            else report_path.name: sha256_file(report_path),
            summary_path.relative_to(ROOT).as_posix()
            if summary_path.is_relative_to(ROOT)
            else summary_path.name: sha256_file(summary_path),
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): sha256_file(path)
            for path in sorted(generated)
        },
        "interpretation_boundary": (
            "Stage 6.4 timing assets describe one observed environment-specific candidate run. "
            "They remain ineligible until exact-commit reproduction, independent audit, and the "
            "final evaluation freeze."
        ),
    }
    manifest_path = write_json(data / "stage6_4_asset_manifest.json", manifest)
    return {
        "detailed_table": detailed_output,
        "endpoint_table": endpoint_output,
        "figure": figure_output,
        "manifest": manifest_path,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    outputs = build(args.results.resolve(), args.destination.resolve())
    print("Stage 6.4 candidate paper assets generated:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
