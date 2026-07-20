#!/usr/bin/env python3
"""Generate Stage 5 pilot assets for Rapid Pivot and its temporal control."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any

SCENARIOS = (
    "ghost_logger",
    "false_comfort",
    "false_comfort_control",
    "operational_outlier",
    "operational_outlier_control",
    "rapid_pivot",
    "rapid_pivot_control",
)


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


def _clock_svg(
    path: Path,
    main_rows: list[dict[str, str]],
    control_rows: list[dict[str, str]],
) -> None:
    width, height = 1120, 510
    x_positions = [120, 285, 450, 615, 780, 945]
    labels = ["T+2h", "T+12h", "T+18h", "T+20h", "T+22h", "T+72h"]
    tracks = [
        ("Rapid Pivot", main_rows, 155),
        ("Early-resolution control", control_rows, 325),
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="45" y="42" font-family="sans-serif" font-size="23" '
        'font-weight="bold">Rapid Pivot: uncertainty resolution before versus after the '
        "18-hour safeguard</text>",
        '<text x="1070" y="66" text-anchor="end" font-family="sans-serif" '
        'font-size="12">PILOT — not final paper evidence</text>',
        '<line x1="450" y1="75" x2="450" y2="430" stroke="#555" stroke-dasharray="6,5"/>',
        '<text x="450" y="67" text-anchor="middle" font-family="sans-serif" '
        'font-size="12" font-weight="bold">τE = 18h</text>',
    ]
    for x, label in zip(x_positions, labels, strict=True):
        parts.append(
            f'<text x="{x}" y="465" text-anchor="middle" font-family="sans-serif" '
            f'font-size="12">{label}</text>'
        )
    for title, rows, y in tracks:
        parts.append(
            f'<text x="42" y="{y - 35}" font-family="sans-serif" font-size="16" '
            f'font-weight="bold">{html.escape(title)}</text>'
        )
        parts.append(
            f'<line x1="{x_positions[0]}" y1="{y}" x2="{x_positions[-1]}" y2="{y}" stroke="#777"/>'
        )
        for index, (row, x) in enumerate(zip(rows, x_positions, strict=True)):
            state = row["observed_state"]
            uncertainty = float(row["U_t"])
            triggered = row["clock_safeguard_triggered"].lower() == "true"
            box_width = 130
            box_x = x - box_width / 2
            parts.append(
                f'<rect x="{box_x}" y="{y - 25}" width="{box_width}" height="50" '
                'rx="8" fill="#f4f4f4" stroke="#222"/>'
            )
            parts.append(
                f'<text x="{x}" y="{y - 3}" text-anchor="middle" '
                f'font-family="sans-serif" font-size="12" font-weight="bold">'
                f"{html.escape(state)}</text>"
            )
            parts.append(
                f'<text x="{x}" y="{y + 15}" text-anchor="middle" '
                f'font-family="sans-serif" font-size="11">Uₜ={uncertainty:.3f}</text>'
            )
            if triggered:
                parts.append(f'<circle cx="{x}" cy="{y - 43}" r="9" fill="white" stroke="#111"/>')
                parts.append(
                    f'<text x="{x}" y="{y - 39}" text-anchor="middle" '
                    'font-family="sans-serif" font-size="11" font-weight="bold">!</text>'
                )
            if index < len(rows) - 1:
                next_x = x_positions[index + 1]
                parts.append(
                    f'<path d="M {x + 66} {y} L {next_x - 68} {y}" stroke="#222" '
                    'marker-end="url(#arrow)"/>'
                )
    parts.insert(
        2,
        '<defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="5" '
        'refY="3.5" orient="auto"><path d="M0,0 L0,7 L7,3.5 z" fill="#222"/>'
        "</marker></defs>",
    )
    parts.extend(
        [
            '<text x="560" y="495" text-anchor="middle" font-family="sans-serif" '
            'font-size="12">Both replays use the same source bytes, target, deadline '
            "profile, and event clock; only the release time of uncertainty-resolving "
            "evidence differs.</text>",
            "</svg>",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build(output_root: Path, destination: Path) -> dict[str, str]:
    packs: dict[str, dict[str, Any]] = {}
    states: dict[str, list[dict[str, str]]] = {}
    metrics: dict[str, dict[str, Any]] = {}
    scenario_rows: list[dict[str, Any]] = []

    for scenario_id in SCENARIOS:
        packs[scenario_id] = json.loads(
            (output_root / "evidence_packs" / f"{scenario_id}.json").read_text(encoding="utf-8")
        )
        states[scenario_id] = _read_csv(output_root / "state_logs" / f"{scenario_id}.csv")
        metrics[scenario_id] = json.loads(
            (output_root / "metrics" / f"{scenario_id}_metrics.json").read_text(encoding="utf-8")
        )
        pack = packs[scenario_id]
        scenario_rows.append(
            {
                "scenario_id": scenario_id,
                "event_count": len(states[scenario_id]),
                "source_count": metrics[scenario_id]["supplemental"]["source_count"],
                "final_state": pack["decision_state"]["recommended_state"],
                "authorized_state": pack["decision_state"]["authorized_state"] or "",
                "E_t": pack["orchestration_metrics"]["E_t"],
                "A_t": pack["orchestration_metrics"]["A_t"],
                "I_t": pack["orchestration_metrics"]["I_t"],
                "U_t": pack["orchestration_metrics"]["U_t"],
                "C_t": pack["orchestration_metrics"]["C_t"],
                "CA": metrics[scenario_id]["CA"] if metrics[scenario_id]["CA"] is not None else "",
                "SC": metrics[scenario_id]["SC"],
                "TR": metrics[scenario_id]["TR"],
            }
        )

    summary_path = destination / "tables" / "stage5_scenario_summary.csv"
    _write_csv(summary_path, scenario_rows, list(scenario_rows[0]))

    event_fields = [
        "event_id",
        "delta_t_hours",
        "E_t",
        "A_t",
        "I_t",
        "M_t",
        "U_t",
        "C_t",
        "previous_state",
        "observed_state",
        "clock_safeguard_triggered",
        "deadline_posture",
        "state_match",
    ]
    event_path = destination / "tables" / "rapid_pivot_event_replay.csv"
    _write_csv(
        event_path,
        [{key: row[key] for key in event_fields} for row in states["rapid_pivot"]],
        event_fields,
    )

    comparison_rows: list[dict[str, Any]] = []
    for index, (main_row, control_row) in enumerate(
        zip(states["rapid_pivot"], states["rapid_pivot_control"], strict=True)
    ):
        comparison_rows.append(
            {
                "event_index": index + 1,
                "delta_t_hours": main_row["delta_t_hours"],
                "main_U_t": main_row["U_t"],
                "control_U_t": control_row["U_t"],
                "main_A_t": main_row["A_t"],
                "control_A_t": control_row["A_t"],
                "main_state": main_row["observed_state"],
                "control_state": control_row["observed_state"],
                "main_clock_safeguard": main_row["clock_safeguard_triggered"],
                "control_clock_safeguard": control_row["clock_safeguard_triggered"],
                "deadline_posture_equal": (
                    main_row["deadline_posture"] == control_row["deadline_posture"]
                ),
            }
        )
    comparison_path = destination / "tables" / "rapid_pivot_clock_comparison.csv"
    _write_csv(comparison_path, comparison_rows, list(comparison_rows[0]))

    figure_path = destination / "figures" / "rapid_pivot_clock_comparison.svg"
    _clock_svg(figure_path, states["rapid_pivot"], states["rapid_pivot_control"])

    generated = (summary_path, event_path, comparison_path, figure_path)
    source_paths = tuple(
        path
        for scenario_id in SCENARIOS
        for path in (
            output_root / "evidence_packs" / f"{scenario_id}.json",
            output_root / "state_logs" / f"{scenario_id}.csv",
            output_root / "metrics" / f"{scenario_id}_metrics.json",
        )
    )
    script_path = Path(__file__).resolve()
    metadata = {
        "asset_status": "PILOT",
        "manuscript_eligible": False,
        "source_run_ids": [
            "GL-STAGE2-0-1-PILOT-001",
            "FC-STAGE3-PILOT-001",
            "FCC-STAGE3-PILOT-001",
            "OO-STAGE4-PILOT-001",
            "OOC-STAGE4-PILOT-001",
            "RP-STAGE5-PILOT-001",
            "RPC-STAGE5-PILOT-001",
        ],
        "generation_script": "paper_assets/scripts/build_stage5_assets.py",
        "generation_script_hash": _sha256(script_path),
        "source_data_hashes": {
            path.relative_to(output_root).as_posix(): _sha256(path) for path in source_paths
        },
        "generated_asset_hashes": {
            path.relative_to(destination).as_posix(): _sha256(path) for path in generated
        },
    }
    metadata_path = destination / "data" / "stage5_asset_manifest.json"
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        "metadata": str(metadata_path),
        "stage5_scenario_summary": str(summary_path),
        "rapid_pivot_event_replay": str(event_path),
        "rapid_pivot_clock_comparison_table": str(comparison_path),
        "rapid_pivot_clock_comparison_figure": str(figure_path),
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
