#!/usr/bin/env python3
"""Build deterministic candidate paper assets from Stage 6.3 results."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

from sbom_to_audit.utils.hashing import sha256_file
from sbom_to_audit.utils.io import write_json

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = ROOT / "evaluation" / "stage6_3_candidate"
DEFAULT_DESTINATION = ROOT / "paper_assets"


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_family_figure(path: Path, rows: list[dict[str, str]]) -> None:
    width = 960
    height = 520
    left = 180
    right = 50
    top = 70
    bottom = 100
    plot_width = width - left - right
    plot_height = height - top - bottom
    family_count = max(1, len(rows))
    band = plot_width / family_count
    bar_width = min(32.0, band * 0.28)

    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="480" y="34" text-anchor="middle" font-family="sans-serif" '
        'font-size="20">Stage 6.3 mutation detection by logic family</text>',
        '<text x="480" y="58" text-anchor="middle" font-family="sans-serif" '
        'font-size="12">Candidate results; baseline tests versus strengthened safety tests</text>',
    ]
    for tick in range(0, 6):
        value = tick / 5
        y = top + plot_height - value * plot_height
        elements.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" '
            'stroke="#d9d9d9" stroke-width="1"/>'
        )
        elements.append(
            f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" '
            f'font-family="sans-serif" font-size="11">{value:.1f}</text>'
        )
    elements.append(
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_height}" '
        'stroke="#222" stroke-width="1.5"/>'
    )
    elements.append(
        f'<line x1="{left}" y1="{top + plot_height}" x2="{width - right}" '
        f'y2="{top + plot_height}" stroke="#222" stroke-width="1.5"/>'
    )

    for index, row in enumerate(rows):
        centre = left + band * (index + 0.5)
        baseline = float(row["baseline_score"] or 0.0)
        strengthened = float(row["strengthened_score"] or 0.0)
        baseline_height = baseline * plot_height
        strengthened_height = strengthened * plot_height
        baseline_x = centre - bar_width - 3
        strengthened_x = centre + 3
        baseline_y = top + plot_height - baseline_height
        strengthened_y = top + plot_height - strengthened_height
        elements.extend(
            [
                f'<rect x="{baseline_x:.1f}" y="{baseline_y:.1f}" width="{bar_width:.1f}" '
                f'height="{baseline_height:.1f}" fill="#6f6f6f"/>',
                f'<rect x="{strengthened_x:.1f}" y="{strengthened_y:.1f}" '
                f'width="{bar_width:.1f}" height="{strengthened_height:.1f}" '
                'fill="#1f4e79"/>',
                f'<text x="{baseline_x + bar_width / 2:.1f}" y="{baseline_y - 5:.1f}" '
                f'text-anchor="middle" font-family="sans-serif" font-size="10">'
                f"{baseline:.2f}</text>",
                f'<text x="{strengthened_x + bar_width / 2:.1f}" y="{strengthened_y - 5:.1f}" '
                f'text-anchor="middle" font-family="sans-serif" font-size="10">'
                f"{strengthened:.2f}</text>",
            ]
        )
        label = row["family"].replace("_", " ")
        elements.append(
            f'<text x="{centre:.1f}" y="{top + plot_height + 22:.1f}" '
            'text-anchor="end" transform="rotate(-38 '
            f'{centre:.1f} {top + plot_height + 22:.1f})" font-family="sans-serif" '
            f'font-size="10">{label}</text>'
        )

    legend_y = height - 22
    elements.extend(
        [
            f'<rect x="{left}" y="{legend_y - 11}" width="14" height="14" fill="#6f6f6f"/>',
            f'<text x="{left + 22}" y="{legend_y}" font-family="sans-serif" '
            'font-size="11">Pre-Stage 6.3 baseline tests</text>',
            f'<rect x="{left + 230}" y="{legend_y - 11}" width="14" height="14" fill="#1f4e79"/>',
            f'<text x="{left + 252}" y="{legend_y}" font-family="sans-serif" '
            'font-size="11">Strengthened safety suite</text>',
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(elements) + "\n", encoding="utf-8", newline="\n")


def build(results: Path, destination: Path) -> dict[str, Path]:
    summary_path = results / "stage6_3_mutation_summary.json"
    family_path = results / "stage6_3_family_summary.csv"
    survivor_path = results / "stage6_3_surviving_mutants.csv"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("evaluation_status") != "CANDIDATE_NOT_FROZEN":
        raise ValueError("Stage 6.3 paper assets require candidate-only results")
    if summary.get("manuscript_eligible") is not False:
        raise ValueError("Stage 6.3 results must not be manuscript-eligible")

    family_rows = _read_csv(family_path)
    tables = destination / "tables"
    figures = destination / "figures"
    data = destination / "data"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    family_output = tables / "stage6_3_family_summary.csv"
    survivor_output = tables / "stage6_3_baseline_survivors.csv"
    figure_output = figures / "stage6_3_mutation_detection.svg"
    shutil.copy2(family_path, family_output)
    shutil.copy2(survivor_path, survivor_output)
    _write_family_figure(figure_output, family_rows)

    generated = [family_output, survivor_output, figure_output]
    manifest = {
        "run_id": summary["run_id"],
        "asset_status": "CANDIDATE_NOT_FROZEN",
        "manuscript_eligible": False,
        "source_results": {
            summary_path.relative_to(ROOT).as_posix()
            if summary_path.is_relative_to(ROOT)
            else summary_path.name: sha256_file(summary_path),
            family_path.relative_to(ROOT).as_posix()
            if family_path.is_relative_to(ROOT)
            else family_path.name: sha256_file(family_path),
            survivor_path.relative_to(ROOT).as_posix()
            if survivor_path.is_relative_to(ROOT)
            else survivor_path.name: sha256_file(survivor_path),
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): sha256_file(path)
            for path in sorted(generated)
        },
        "interpretation_boundary": (
            "Mutation figures and tables are candidate evaluation assets and remain ineligible "
            "until exact-commit reproduction and final evaluation freeze."
        ),
    }
    manifest_path = write_json(data / "stage6_3_asset_manifest.json", manifest)
    return {
        "family_table": family_output,
        "survivor_table": survivor_output,
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
    print("Stage 6.3 candidate paper assets generated:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
