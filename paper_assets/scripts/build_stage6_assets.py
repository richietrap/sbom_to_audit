#!/usr/bin/env python3
"""Generate Stage 6 pilot assets for the matched PSIRT baseline comparison."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

METRIC_ORDER = ("EC", "TR", "CD", "CA", "AR", "SC", "EPG")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _metric_svg(path: Path, rows: list[dict[str, str]]) -> None:
    width, height = 1160, 610
    left, top, plot_height = 105, 105, 390
    group_width = 135
    bar_width = 34
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<defs><pattern id="baselineHatch" width="6" height="6" '
        'patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
        '<line x1="0" y1="0" x2="0" y2="6" stroke="#555" stroke-width="2"/>'
        "</pattern></defs>",
        '<text x="45" y="42" font-family="sans-serif" font-size="23" '
        'font-weight="bold">Matched baseline comparison across four primary '
        "scenario families</text>",
        '<text x="1115" y="66" text-anchor="end" font-family="sans-serif" '
        'font-size="12">PILOT — controlled computational proxy</text>',
    ]
    for tick in range(0, 6):
        value = tick / 5
        y = top + plot_height - value * plot_height
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="1085" y2="{y:.1f}" stroke="#ddd"/>')
        parts.append(
            f'<text x="92" y="{y + 4:.1f}" text-anchor="end" font-family="sans-serif" '
            f'font-size="11">{value:.1f}</text>'
        )
    for index, metric in enumerate(METRIC_ORDER):
        row = next(item for item in rows if item["metric"] == metric)
        orchestrated_raw = row["orchestrated_primary_mean"]
        baseline_raw = row["baseline_primary_mean"]
        orchestrated = float(orchestrated_raw) if orchestrated_raw else 0.0
        baseline = float(baseline_raw) if baseline_raw else 0.0
        center = left + 75 + index * group_width
        orch_height = orchestrated * plot_height
        base_height = baseline * plot_height
        parts.extend(
            [
                f'<rect x="{center - 42}" y="{top + plot_height - orch_height:.1f}" '
                f'width="{bar_width}" height="{orch_height:.1f}" fill="#333"/>',
                f'<rect x="{center + 8}" y="{top + plot_height - base_height:.1f}" '
                f'width="{bar_width}" height="{base_height:.1f}" fill="url(#baselineHatch)" '
                'stroke="#555"/>',
                f'<text x="{center - 25}" y="{top + plot_height - orch_height - 7:.1f}" '
                'text-anchor="middle" font-family="sans-serif" font-size="10">'
                f"{orchestrated:.2f}</text>",
                f'<text x="{center + 25}" y="{top + plot_height - base_height - 7:.1f}" '
                'text-anchor="middle" font-family="sans-serif" font-size="10">'
                f"{baseline:.2f}</text>",
                f'<text x="{center}" y="{top + plot_height + 28}" text-anchor="middle" '
                f'font-family="sans-serif" font-size="13" font-weight="bold">{metric}</text>',
            ]
        )
    parts.extend(
        [
            '<rect x="405" y="552" width="18" height="18" fill="#333"/>',
            '<text x="432" y="566" font-family="sans-serif" font-size="12">'
            "Orchestrated artefact</text>",
            '<rect x="610" y="552" width="18" height="18" fill="url(#baselineHatch)" '
            'stroke="#555"/>',
            '<text x="637" y="566" font-family="sans-serif" font-size="12">'
            "Structured un-orchestrated baseline</text>",
            '<text x="580" y="594" text-anchor="middle" font-family="sans-serif" '
            'font-size="11">CD and CA means use only primary scenarios where the metric '
            "is applicable. "
            "AR equality is retained rather than hidden.</text>",
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    comparison_root = output_root / "comparison"
    metric_source = comparison_root / "stage6_metric_summary.csv"
    scenario_source = comparison_root / "stage6_scenario_comparison.csv"
    divergence_source = comparison_root / "stage6_decision_divergence.csv"
    report_source = comparison_root / "stage6_baseline_report.json"

    metrics = _read_csv(metric_source)
    scenarios = _read_csv(scenario_source)
    divergences = _read_csv(divergence_source)
    report = json.loads(report_source.read_text(encoding="utf-8"))

    primary_table = destination / "tables" / "stage6_primary_metric_comparison.csv"
    _write_csv(primary_table, metrics, list(metrics[0]))

    divergence_table = destination / "tables" / "stage6_decision_divergence.csv"
    _write_csv(
        divergence_table,
        divergences,
        list(divergences[0])
        if divergences
        else [
            "scenario_id",
            "event_id",
            "timestamp",
            "expected_state",
            "orchestrated_state",
            "baseline_state",
            "orchestrated_match",
            "baseline_match",
            "baseline_conflict_flag",
            "baseline_rationale",
        ],
    )

    conflict_rows = [
        {
            "workflow": "orchestrated_artefact",
            "true_conflict_episodes": report["conflict_precision"]["true_conflict_episodes"],
            "total_detected_episodes": report["conflict_precision"]["orchestrated_total_detected"],
            "precision": report["conflict_precision"]["orchestrated"],
        },
        {
            "workflow": "structured_unorchestrated_baseline",
            "true_conflict_episodes": report["conflict_precision"]["true_conflict_episodes"],
            "total_detected_episodes": report["conflict_precision"]["baseline_total_detected"],
            "precision": report["conflict_precision"]["baseline"],
        },
    ]
    conflict_table = destination / "tables" / "stage6_conflict_precision.csv"
    _write_csv(conflict_table, conflict_rows, list(conflict_rows[0]))

    proxy = report["source_review_operation_proxy"]
    proxy_rows = [
        {
            "workflow": "orchestrated_artefact",
            "source_review_operation_count": proxy["orchestrated_unique_source_ingestions"],
            "interpretation": "Unique source ingestion events",
        },
        {
            "workflow": "structured_unorchestrated_baseline",
            "source_review_operation_count": proxy["baseline_cumulative_source_reviews"],
            "interpretation": "Accumulated source visibility across repeated worksheet reviews",
        },
    ]
    proxy_table = destination / "tables" / "stage6_source_review_operation_proxy.csv"
    _write_csv(proxy_table, proxy_rows, list(proxy_rows[0]))

    scenario_table = destination / "tables" / "stage6_scenario_comparison.csv"
    _write_csv(scenario_table, scenarios, list(scenarios[0]))

    figure = destination / "figures" / "stage6_metric_comparison.svg"
    _metric_svg(figure, metrics)

    generated = (
        primary_table,
        divergence_table,
        conflict_table,
        proxy_table,
        scenario_table,
        figure,
    )
    source_paths = (metric_source, scenario_source, divergence_source, report_source)
    script_path = Path(__file__).resolve()
    metadata = {
        "asset_status": "PILOT_BASELINE_NOT_FROZEN",
        "manuscript_eligible": False,
        "source_run_ids": ["STAGE6-MATCHED-BASELINE-PILOT-001"],
        "generation_script": "paper_assets/scripts/build_stage6_assets.py",
        "generation_script_hash": _sha256(script_path),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in source_paths
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
        "interpretation_boundary": report["interpretation_boundary"],
        "limitations": report["limitations"],
    }
    metadata_path = destination / "data" / "stage6_asset_manifest.json"
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        "metadata": str(metadata_path),
        "metric_figure": str(figure),
        "primary_metric_table": str(primary_table),
        "scenario_table": str(scenario_table),
        "divergence_table": str(divergence_table),
        "conflict_precision_table": str(conflict_table),
        "source_review_proxy_table": str(proxy_table),
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
