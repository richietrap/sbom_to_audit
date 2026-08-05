#!/usr/bin/env python3
"""Build deterministic candidate Stage 6.2 paper tables and SVG figures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import write_csv, write_json

RUN_ID = "STAGE6-2-ROBUSTNESS-CANDIDATE-001"
SCENARIO_ORDER = (
    "ghost_logger",
    "false_comfort",
    "false_comfort_control",
    "operational_outlier",
    "operational_outlier_control",
    "rapid_pivot",
    "rapid_pivot_control",
)
PROFILE_ORDER = (
    "threshold_minus_0_10",
    "threshold_minus_0_05",
    "threshold_baseline",
    "threshold_plus_0_05",
    "threshold_plus_0_10",
)
PROFILE_LABELS = {
    "threshold_minus_0_10": "-0.10",
    "threshold_minus_0_05": "-0.05",
    "threshold_baseline": "0",
    "threshold_plus_0_05": "+0.05",
    "threshold_plus_0_10": "+0.10",
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _threshold_summary(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["scenario_id"], row["profile_id"])].append(row)
    summary: list[dict[str, Any]] = []
    for scenario_id in SCENARIO_ORDER:
        for profile_id in PROFILE_ORDER:
            group = grouped[(scenario_id, profile_id)]
            changed = sum(row["state_changed"] == "True" for row in group)
            total = len(group)
            summary.append(
                {
                    "scenario_id": scenario_id,
                    "profile_id": profile_id,
                    "threshold_offset": group[0]["threshold_offset"] if group else "",
                    "event_count": total,
                    "state_change_count": changed,
                    "state_stability_ratio": round((total - changed) / total, 6) if total else None,
                }
            )
    return summary


def _clock_summary(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[(row["scenario_id"], row["profile_id"])].append(row)
    summary: list[dict[str, Any]] = []
    for key in sorted(grouped):
        scenario_id, profile_id = key
        group = grouped[key]
        trigger_ids = [
            row["event_id"] for row in group if row["clock_safeguard_triggered"] == "True"
        ]
        changed_ids = [row["event_id"] for row in group if row["state_changed"] == "True"]
        summary.append(
            {
                "scenario_id": scenario_id,
                "profile_id": profile_id,
                "tau_E_hours": group[0]["tau_E_hours"],
                "clock_trigger_event_ids": ";".join(trigger_ids),
                "state_change_event_ids": ";".join(changed_ids),
                "state_change_count": len(changed_ids),
            }
        )
    return summary


def _threshold_svg(path: Path, summary: list[dict[str, Any]]) -> None:
    width, height = 1120, 560
    left, top = 310, 105
    cell_width, cell_height = 135, 48
    lookup = {(str(row["scenario_id"]), str(row["profile_id"])): row for row in summary}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="40" y="42" font-family="sans-serif" font-size="23" '
        'font-weight="bold">Stage 6.2 threshold-sensitivity state changes</text>',
        '<text x="1080" y="68" text-anchor="end" font-family="sans-serif" '
        'font-size="12">CANDIDATE — not evaluation-frozen</text>',
        '<text x="40" y="90" font-family="sans-serif" font-size="12">Cells show changed '
        "event states / scenario events under a uniform numeric threshold offset.</text>",
    ]
    for column, profile_id in enumerate(PROFILE_ORDER):
        x = left + column * cell_width + cell_width / 2
        parts.append(
            f'<text x="{x}" y="{top - 18}" text-anchor="middle" '
            f'font-family="sans-serif" font-size="13">{PROFILE_LABELS[profile_id]}</text>'
        )
    for row_index, scenario_id in enumerate(SCENARIO_ORDER):
        y = top + row_index * cell_height
        label = scenario_id.replace("_", " ")
        parts.append(
            f'<text x="{left - 16}" y="{y + 30}" text-anchor="end" '
            f'font-family="sans-serif" font-size="13">{label}</text>'
        )
        for column, profile_id in enumerate(PROFILE_ORDER):
            item = lookup[(scenario_id, profile_id)]
            changed = int(item["state_change_count"])
            total = int(item["event_count"])
            shade = 248 - min(changed, 6) * 26
            x = left + column * cell_width
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_width - 5}" '
                f'height="{cell_height - 5}" fill="rgb({shade},{shade},{shade})" '
                'stroke="#777"/>'
            )
            parts.append(
                f'<text x="{x + (cell_width - 5) / 2}" y="{y + 28}" '
                f'text-anchor="middle" font-family="sans-serif" font-size="13">'
                f"{changed}/{total}</text>"
            )
    parts.extend(
        [
            '<text x="580" y="520" text-anchor="middle" font-family="sans-serif" '
            'font-size="11">Sensitivity is descriptive; the sweep does not validate or optimise '
            "the prototype thresholds.</text>",
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def _factor_svg(path: Path, stability_rows: list[dict[str, str]]) -> None:
    width, height = 1120, 570
    left, top, plot_width = 320, 100, 700
    bar_height, gap = 36, 22
    maximum = max(int(row["factor_state_changes"]) for row in stability_rows) or 1
    lookup = {row["scenario_id"]: row for row in stability_rows}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="40" y="42" font-family="sans-serif" font-size="23" '
        'font-weight="bold">Stage 6.2 final-event single-factor state changes</text>',
        '<text x="1080" y="68" text-anchor="end" font-family="sans-serif" '
        'font-size="12">38 registered variants per scenario — candidate</text>',
    ]
    for index, scenario_id in enumerate(SCENARIO_ORDER):
        row = lookup[scenario_id]
        value = int(row["factor_state_changes"])
        y = top + index * (bar_height + gap)
        width_value = plot_width * value / maximum
        label = scenario_id.replace("_", " ")
        parts.extend(
            [
                f'<text x="{left - 15}" y="{y + 24}" text-anchor="end" '
                f'font-family="sans-serif" font-size="13">{label}</text>',
                f'<rect x="{left}" y="{y}" width="{plot_width}" height="{bar_height}" '
                'fill="#f2f2f2" stroke="#bbb"/>',
                f'<rect x="{left}" y="{y}" width="{width_value:.2f}" '
                f'height="{bar_height}" fill="#555"/>',
                f'<text x="{left + width_value + 10:.2f}" y="{y + 24}" '
                f'font-family="sans-serif" font-size="13">{value}/38</text>',
            ]
        )
    parts.extend(
        [
            '<text x="580" y="540" text-anchor="middle" font-family="sans-serif" '
            'font-size="11">Each variant changes one registered input at the final event '
            "boundary; multivariate interactions are outside this figure.</text>",
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(results_root: Path, destination: Path) -> dict[str, Path]:
    threshold_rows = _read_csv(results_root / "stage6_2_threshold_sensitivity.csv")
    clock_rows = _read_csv(results_root / "stage6_2_clock_sensitivity.csv")
    factor_rows = _read_csv(results_root / "stage6_2_factor_sensitivity.csv")
    negative_rows = _read_csv(results_root / "stage6_2_negative_cases.csv")
    stability_rows = _read_csv(results_root / "stage6_2_scenario_stability.csv")
    report = json.loads(
        (results_root / "stage6_2_robustness_report.json").read_text(encoding="utf-8")
    )

    tables = destination / "tables"
    figures = destination / "figures"
    data = destination / "data"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    threshold_summary = _threshold_summary(threshold_rows)
    threshold_table = write_csv(
        tables / "stage6_2_threshold_summary.csv",
        threshold_summary,
        [
            "scenario_id",
            "profile_id",
            "threshold_offset",
            "event_count",
            "state_change_count",
            "state_stability_ratio",
        ],
    )
    clock_summary = _clock_summary(clock_rows)
    clock_table = write_csv(
        tables / "stage6_2_clock_summary.csv",
        clock_summary,
        [
            "scenario_id",
            "profile_id",
            "tau_E_hours",
            "clock_trigger_event_ids",
            "state_change_event_ids",
            "state_change_count",
        ],
    )
    changed_factors = [row for row in factor_rows if row["state_changed"] == "True"]
    factor_table = write_csv(
        tables / "stage6_2_factor_transitions.csv",
        changed_factors,
        list(changed_factors[0]) if changed_factors else list(factor_rows[0]),
    )
    negative_table = write_csv(
        tables / "stage6_2_negative_cases.csv",
        negative_rows,
        list(negative_rows[0]),
    )
    stability_table = write_csv(
        tables / "stage6_2_scenario_stability.csv",
        stability_rows,
        list(stability_rows[0]),
    )

    threshold_figure = figures / "stage6_2_threshold_stability.svg"
    _threshold_svg(threshold_figure, threshold_summary)
    factor_figure = figures / "stage6_2_factor_state_changes.svg"
    _factor_svg(factor_figure, stability_rows)

    source_paths = sorted(path for path in results_root.iterdir() if path.is_file())
    generated = [
        threshold_table,
        clock_table,
        factor_table,
        negative_table,
        stability_table,
        threshold_figure,
        factor_figure,
    ]
    manifest = {
        "asset_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "source_run_ids": [RUN_ID],
        "generation_script": "scripts/build_stage6_2_paper_assets.py",
        "generation_script_hash": _sha256(Path(__file__).resolve()),
        "source_data_hashes": {path.name: _sha256(path) for path in source_paths},
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
        "interpretation_boundary": report["interpretation_boundary"],
        "limitations": report["limitations"],
    }
    manifest_path = write_json(data / "stage6_2_asset_manifest.json", manifest)
    return {
        "threshold_figure": threshold_figure,
        "factor_figure": factor_figure,
        "threshold_table": threshold_table,
        "clock_table": clock_table,
        "factor_table": factor_table,
        "negative_table": negative_table,
        "stability_table": stability_table,
        "manifest": manifest_path,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    outputs = build(args.results.resolve(), args.destination.resolve())
    print("Stage 6.2 candidate paper assets generated:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
